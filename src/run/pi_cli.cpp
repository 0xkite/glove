#include "pi_cli.hpp"

#include "../host/runtime_snapshot.hpp"
#include "pi_catalog.hpp"
#include "pi_guest_config.hpp"
#include "pi_machine_authorities.hpp"
#include "pi_runtime_internal.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>

namespace glove::run {
namespace {

template<typename T> using result = std::expected<T, std::string>;

void usage() {
    std::fprintf(
        stderr,
        "usage: glove pi [--provider openai|anthropic] [--model ID] [--workspace DIR]\n"
        "       glove pi -- [--print|-p] [--thinking LEVEL] [--mode text|json] PROMPT\n"
        "       glove pi setup|refresh [--provider openai|anthropic] [--model ID] [--yes]\n\n"
        "Native macOS, API-key authentication only. Workspace must be owner-0700,\n"
        "outside host/runtime authority, with no .pi entry or case alias.\n"
        "Provider keys stay on the host; generated configuration uses a run nonce.\n"
        "Switching providers requires --model. Forwarded options are single-use;\n"
        "Pi's second -- ends option parsing. @file input is always refused.\n"
        "Extensions, MCP, skills, templates, themes and context-file discovery are disabled.\n"
        "Setup copies installed Pi/Node into a protected snapshot; refresh replaces\n"
        "the approved runtime/selection. Dependency inspection may run during staging.\n"
        "No OAuth, session import, automatic project trust or uncontained fallback.\n"
    );
}

#if defined(__APPLE__)
auto prompt(std::string_view label, std::size_t bound) -> result<std::string> {
    std::fprintf(stderr, "%.*s", static_cast<int>(label.size()), label.data());
    std::fflush(stderr);
    std::array<char, 256> buffer{};
    if (std::fgets(buffer.data(), static_cast<int>(buffer.size()), stdin) == nullptr) {
        return std::unexpected("Pi setup input unavailable");
    }
    std::string value{buffer.data()};
    if (!value.ends_with('\n')) {
        return std::unexpected("Pi setup input exceeds its bound");
    }
    value.pop_back();
    if (value.ends_with('\r')) {
        value.pop_back();
    }
    if (value.size() > bound) {
        return std::unexpected("Pi setup input exceeds its bound");
    }
    return value;
}
#endif

} // namespace

namespace detail {

auto parse_pi_command_line(std::span<const std::string_view> arguments) -> result<pi_command_line> {
    if (arguments.size() > 80) {
        return std::unexpected("too many Pi command arguments");
    }
    std::size_t total = 0;
    for (const auto argument : arguments) {
        if (argument.size() > 16384 || argument.size() > 65536 - total ||
            argument.find('\0') != std::string_view::npos) {
            return std::unexpected("Pi command arguments exceed bounds or contain NUL");
        }
        total += argument.size();
    }
    pi_command_line command;
    std::size_t index = 0;
    if (!arguments.empty() && (arguments.front() == "setup" || arguments.front() == "refresh")) {
        command.action =
            arguments.front() == "setup" ? pi_command_action::setup : pi_command_action::refresh;
        ++index;
    }
    if (index < arguments.size() && (arguments[index] == "--help" || arguments[index] == "-h")) {
        if (index + 1 != arguments.size()) {
            return std::unexpected("Pi help must stand alone");
        }
        command.action = pi_command_action::help;
        return command;
    }
    while (index < arguments.size()) {
        const auto option = arguments[index++];
        if (option == "--") {
            if (command.action != pi_command_action::launch) {
                return std::unexpected("Pi setup does not accept forwarded arguments");
            }
            for (; index < arguments.size(); ++index) {
                command.request.selection.arguments.emplace_back(arguments[index]);
            }
            break;
        }
        if (option == "--yes") {
            if (command.action == pi_command_action::launch || command.approved) {
                return std::unexpected("Pi approval is only valid once for setup or refresh");
            }
            command.approved = true;
            continue;
        }
        if (option != "--provider" && option != "--model" && option != "--workspace") {
            return std::unexpected(
                "unsupported Pi command option; use '--' for approved Pi arguments"
            );
        }
        if (index == arguments.size() || arguments[index].empty() ||
            arguments[index].starts_with("--")) {
            return std::unexpected("Pi command option requires a value");
        }
        const auto value = arguments[index++];
        if (option == "--workspace") {
            if (command.action != pi_command_action::launch || command.request.workspace ||
                value.size() > 4096) {
                return std::unexpected(
                    "Pi workspace is a bounded launch-only option supplied once"
                );
            }
            command.request.workspace = std::filesystem::path{value};
        } else {
            auto& target = option == "--provider" ? command.request.selection.provider
                                                  : command.request.selection.model;
            if (target) {
                return std::unexpected("duplicate Pi provider/model option");
            }
            target = value;
        }
    }
    auto checked = select_pi_launch(
        command.request.selection,
        pi_model_selection{
            .provider = command.request.selection.provider == "anthropic" ? pi_provider::anthropic
                                                                          : pi_provider::openai,
            .model = "validation-only"
        }
    );
    if (!checked) {
        return std::unexpected(checked.error());
    }
    return command;
}

auto configure_pi_runtime(const pi_command_line& command, const pi_setup_context& context)
    -> result<bool> {
    if ((command.action != pi_command_action::setup &&
         command.action != pi_command_action::refresh) ||
        !command.approved) {
        return std::unexpected("approve Pi setup/refresh before discovery, staging or writing");
    }
    if (command.request.workspace || !command.request.selection.arguments.empty() ||
        !command.request.selection.provider || !command.request.selection.model) {
        return std::unexpected("Pi setup requires only an explicit provider and model");
    }
    auto selected = select_pi_launch(command.request.selection);
    if (!selected) {
        return std::unexpected(selected.error());
    }
    const auto& directories = context.directories;
    for (const auto& path :
         {directories.config,
          directories.state,
          directories.data,
          directories.cache,
          directories.runtime}) {
        if (!path.is_absolute() || path == path.root_path() || path != path.lexically_normal() ||
            path.native().size() > 4096 || path.native().find('\0') != std::string::npos) {
            return std::unexpected("invalid protected Pi setup directory");
        }
    }
    auto source_authorities = load_pi_machine_authorities(directories);
    if (!source_authorities) {
        return std::unexpected(source_authorities.error());
    }
    const auto record = directories.config / "pi/selection.json";
    // Refresh admits the operator record, then stages fresh authority. Ordinary
    // setup/no-op and every launch still require the full source/snapshot binding.
    auto existing = command.action == pi_command_action::refresh
                        ? inspect_pi_operator_record(record)
                        : load_pi_runtime_with_exclusions(record, *source_authorities);
    if (!existing) {
        return std::unexpected(existing.error());
    }
    if (*existing && command.action == pi_command_action::setup) {
        if ((**existing).model != selected->model) {
            return std::unexpected("Pi selection differs; explicit refresh consent required");
        }
        return false;
    }
    if (auto admitted = host::snapshot::ensure_protected_directory(directories.config, true);
        !admitted) {
        return std::unexpected(admitted.error());
    }
    if (auto admitted = host::snapshot::ensure_protected_directory(directories.data, true);
        !admitted) {
        return std::unexpected(admitted.error());
    }
    if (auto admitted = host::snapshot::ensure_protected_directory(directories.config / "pi", true);
        !admitted) {
        return std::unexpected(admitted.error());
    }
    const auto detected =
        context.detect ? context.detect()
                       : host::detect_runtime_harnesses({"/opt/homebrew/bin", "/usr/local/bin"});
    const auto source = std::ranges::find_if(detected, [](const auto& candidate) {
        return candidate.runtime_id == "pi" && candidate.available;
    });
    if (source == detected.end()) {
        return std::unexpected(
            "Pi is not installed in supported host locations; install Pi and Node separately, then "
            "rerun setup"
        );
    }
    const host::runtime_harness_stage_options options{
        .runtime_id = "pi",
        .source_executable = source->resolved_executable,
        .protected_directory = directories.data / "pi/runtime",
        .dry_run = false,
        .source_exclusions = *source_authorities
    };
    auto staged = context.stage ? context.stage(options) : host::stage_runtime_harness(options);
    if (!staged) {
        return std::unexpected(staged.error());
    }
    pi_runtime_selection selection{.model = selected->model, .runtime = std::move(*staged)};
    auto catalog =
        load_pi_builtin_catalog(selection, selected->model.provider, *source_authorities);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    if (auto checked =
            make_pi_guest_config(*selected, 1, "glove-session-" + std::string(48, '0'), *catalog);
        !checked) {
        return std::unexpected(checked.error());
    }
    auto stored = store_pi_runtime_with_exclusions(
        record, selection, true, command.action == pi_command_action::refresh, *source_authorities
    );
    if (!stored) {
        return std::unexpected(stored.error());
    }
    return *stored || selection.runtime.changed;
}

} // namespace detail

auto pi_command(std::span<char* const> arguments) -> int {
    if (arguments.size() > 80) {
        std::fprintf(stderr, "glove pi: too many arguments\n");
        return 2;
    }
    std::vector<std::string_view> views;
    views.reserve(arguments.size());
    for (const auto* argument : arguments) {
        if (argument == nullptr || ::strnlen(argument, 16385) > 16384) {
            std::fprintf(stderr, "glove pi: invalid argument\n");
            return 2;
        }
        views.emplace_back(argument);
    }
    auto parsed = detail::parse_pi_command_line(views);
    if (!parsed) {
        std::fprintf(stderr, "glove pi: %s\n", parsed.error().c_str());
        return 2;
    }
    if (parsed->action == detail::pi_command_action::help) {
        usage();
        return 0;
    }
#if !defined(__APPLE__)
    std::fprintf(stderr, "glove pi: native macOS backend required\n");
    return 1;
#else
    if (parsed->action == detail::pi_command_action::launch) {
        std::fprintf(
            stderr,
            "glove pi: native macOS; host API-key mediation; private configuration; external "
            "resources disabled\n"
        );
        auto exited = launch_pi(parsed->request);
        if (!exited) {
            std::fprintf(stderr, "glove pi: %s\n", exited.error().c_str());
            return 1;
        }
        return *exited;
    }
    const bool interactive = ::isatty(STDIN_FILENO) == 1 && ::isatty(STDERR_FILENO) == 1;
    if (!parsed->approved) {
        if (!interactive) {
            std::fprintf(
                stderr,
                "glove pi: setup/refresh requires --yes (protected copy/dependency inspection and "
                "selection replacement on refresh)\n"
            );
            return 1;
        }
        auto consent = prompt(
            "Copy installed Pi/Node and inspect dependencies; replace selection on refresh? Type "
            "yes: ",
            3
        );
        if (!consent || *consent != "yes") {
            std::fprintf(stderr, "glove pi: setup not approved\n");
            return 1;
        }
        parsed->approved = true;
    }
    if (!parsed->request.selection.provider) {
        if (!interactive) {
            std::fprintf(stderr, "glove pi: setup requires --provider openai|anthropic\n");
            return 2;
        }
        auto provider = prompt("Provider (openai or anthropic): ", 9);
        if (!provider) {
            std::fprintf(stderr, "glove pi: %s\n", provider.error().c_str());
            return 2;
        }
        parsed->request.selection.provider = std::move(*provider);
    }
    if (!parsed->request.selection.model) {
        if (!interactive) {
            std::fprintf(stderr, "glove pi: setup requires --model ID\n");
            return 2;
        }
        auto model = prompt("Builtin model ID: ", 128);
        if (!model) {
            std::fprintf(stderr, "glove pi: %s\n", model.error().c_str());
            return 2;
        }
        parsed->request.selection.model = std::move(*model);
    }
    auto directories = host::resolve_directories(host::current_environment());
    if (!directories) {
        std::fprintf(stderr, "glove pi: %s\n", directories.error().c_str());
        return 1;
    }
    auto configured = detail::configure_pi_runtime(
        *parsed, {.directories = std::move(*directories), .detect = {}, .stage = {}}
    );
    if (!configured) {
        std::fprintf(stderr, "glove pi: %s\n", configured.error().c_str());
        return 1;
    }
    std::fprintf(
        stderr,
        "glove pi: protected runtime %s; API-key-only, no project trust or resource import\n",
        *configured ? "updated" : "unchanged"
    );
    return 0;
#endif
}

} // namespace glove::run
