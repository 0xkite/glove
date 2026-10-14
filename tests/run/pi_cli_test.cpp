#include "../support/descriptor_acl_fixture.hpp"
#include "pi_cli.hpp"
#include "pi_runtime_internal.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using glove::run::detail::configure_pi_runtime;
using glove::run::detail::parse_pi_command_line;
using glove::run::detail::pi_command_action;
using glove::run::detail::pi_command_line;
using glove::run::detail::pi_setup_context;

constexpr std::string_view catalog_suffix =
    "node_modules/@earendil-works/pi-ai/dist/providers/data";
// These identities are synthetic metadata, not evidence of live model availability.
constexpr std::string_view openai_catalog =
    R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})";
constexpr std::string_view anthropic_catalog =
    R"({"anthropic-messages":{"chat:claude-sonnet-4-6":{"id":"claude-sonnet-4-6","provider":"anthropic","api":"anthropic-messages","type":"chat"}}})";

auto parse(std::initializer_list<std::string_view> arguments)
    -> std::expected<pi_command_line, std::string> {
    return parse_pi_command_line({arguments.begin(), arguments.size()});
}

auto parser_cases() -> int {
    auto launch = parse({});
    REQUIRE(launch && launch->action == pi_command_action::launch && !launch->approved);
    REQUIRE(!launch->request.selection.provider && !launch->request.selection.model);
    REQUIRE(!launch->request.workspace && launch->request.selection.arguments.empty());
    for (const auto help : {"--help", "-h"}) {
        auto parsed = parse({help});
        REQUIRE(parsed && parsed->action == pi_command_action::help && !parsed->approved);
    }
    for (const auto action : {"setup", "refresh"}) {
        auto interactive = parse({action});
        REQUIRE(interactive && !interactive->approved);
        REQUIRE(
            interactive->action == (std::string_view{action} == "setup"
                                        ? pi_command_action::setup
                                        : pi_command_action::refresh)
        );
        REQUIRE(!interactive->request.selection.provider && !interactive->request.selection.model);
        auto approved =
            parse({action, "--provider", "anthropic", "--model", "claude-sonnet-4-6", "--yes"});
        REQUIRE(approved && approved->approved);
        REQUIRE(approved->request.selection.provider == "anthropic");
        REQUIRE(approved->request.selection.model == "claude-sonnet-4-6");
    }
    auto selected = parse(
        {"--provider",
         "openai",
         "--model",
         "gpt-5",
         "--workspace",
         "/fixture/workspace",
         "--",
         "--print",
         "--mode",
         "json",
         "--thinking",
         "high",
         "Summarize"}
    );
    REQUIRE(selected && selected->action == pi_command_action::launch && !selected->approved);
    REQUIRE(selected->request.selection.provider == "openai");
    REQUIRE(selected->request.selection.model == "gpt-5");
    REQUIRE(selected->request.workspace == std::filesystem::path{"/fixture/workspace"});
    REQUIRE(
        selected->request.selection.arguments ==
        (std::vector<std::string>{"--print", "--mode", "json", "--thinking", "high", "Summarize"})
    );
    // The outer delimiter is consumed; a second delimiter belongs to Pi and
    // makes following authority-shaped tokens literal prompt bytes.
    auto literal = parse({"--", "--", "--provider", "literal prompt"});
    REQUIRE(
        literal && literal->request.selection.arguments ==
                       (std::vector<std::string>{"--", "--provider", "literal prompt"})
    );
    REQUIRE(parse({"--provider", "anthropic"}));
    REQUIRE(parse({"--model", std::string(128U, 'a')}));

    for (const auto& arguments : std::vector<std::vector<std::string_view>>{
             {"--provider"},
             {"--model"},
             {"--workspace"},
             {"--provider", "OpenAI"},
             {"--provider", "openai-codex"},
             {"--provider", "openai", "--provider", "openai"},
             {"--model", "gpt-5", "--model", "gpt-5"},
             {"--workspace", "/a", "--workspace", "/a"},
             {"--model", ""},
             {"--model", "-gpt-5"},
             {"--model", "gpt-5:high"},
             {"--model", "gpt/5"},
             {"--model", "gpt 5"},
             {"--model", "gpt-\xc3\xa9"},
             {"--yes"},
             {"setup", "--yes", "--yes"},
             {"setup", "--workspace", "/a"},
             {"refresh", "--workspace", "/a"},
             {"setup", "--", "prompt"},
             {"refresh", "--", "--print"},
             {"--print"},
             {"prompt"},
             {"--", "--provider", "anthropic"},
             {"--", "--model", "other"},
             {"--", "--api-key=secret"},
             {"--", "--extension", "/host"},
             {"--", "--session-dir", "/host"},
             {"--", "--tools", "read"},
             {"--", "--mode", "rpc"},
             {"--", "--thinking", "unknown"},
             {"--", "--print", "-p"},
             {"--", "--", "@/host/auth.json"},
             {"--unknown"}
         }) {
        REQUIRE(!parse_pi_command_line(arguments));
    }
    for (const auto authority :
         {"--source",
          "--executable",
          "--search-path",
          "--env",
          "--grant",
          "--endpoint",
          "--config",
          "--session",
          "--import",
          "--oauth",
          "--service"}) {
        REQUIRE(!parse({authority, "/host"}));
        REQUIRE(!parse({"setup", authority, "/host"}));
        REQUIRE(!parse({"--", authority, "/host"}));
    }
    const std::string nul{"x\0y", 3U};
    REQUIRE(!parse({"--provider", nul}));
    REQUIRE(!parse({"--model", nul}));
    REQUIRE(!parse({"--workspace", nul}));
    REQUIRE(!parse({"--", nul}));
    REQUIRE(!parse({"--model", std::string(129U, 'a')}));
    REQUIRE(!parse({"--workspace", std::string(4097U, 'a')}));
    REQUIRE(!parse({"--", std::string(16385U, 'a')}));
    std::vector<std::string_view> too_many(34U, "prompt");
    too_many.front() = "--";
    REQUIRE(!parse_pi_command_line(too_many));
    const std::string large(16384U, 'a');
    REQUIRE(!parse({"--", large, large, large, large, large}));
    return 0;
}

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-pi-cli-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = std::filesystem::canonical(created);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        if (!root_.empty()) {
            for (const auto& entry :
                 std::filesystem::recursive_directory_iterator(root_, ignored)) {
                if (std::filesystem::is_directory(entry.symlink_status(ignored))) {
                    std::filesystem::permissions(
                        entry.path(),
                        std::filesystem::perms::owner_write,
                        std::filesystem::perm_options::add,
                        ignored
                    );
                }
            }
            std::filesystem::remove_all(root_, ignored);
        }
    }

    auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_file(const std::filesystem::path& path, std::string_view bytes, mode_t mode = 0600)
    -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto contents(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

struct fixture {
    std::filesystem::path root;
    std::size_t detections = 0;
    std::vector<glove::host::runtime_harness_stage_options> stages{};
    std::optional<glove::host::staged_runtime_harness> staged{};

    auto source() const -> std::filesystem::path { return root / "source"; }

    auto package() const -> std::filesystem::path {
        return source() / "lib/node_modules/@fixture/pi";
    }

    auto catalogs() const -> std::filesystem::path { return package() / catalog_suffix; }

    auto record() const -> std::filesystem::path { return root / "config/pi/selection.json"; }

    auto directories() const -> glove::host::directories {
        return {
            .config = root / "config",
            .state = root / "state",
            .data = root / "data",
            .cache = root / "cache",
            .runtime = root / "runtime"
        };
    }

    auto prepare() const -> bool {
        std::filesystem::create_directories(root);
        if (::chmod(root.c_str(), 0700) != 0) {
            return false;
        }
        std::filesystem::create_directories(source() / "bin");
        std::filesystem::create_directories(package() / "bin");
        std::filesystem::create_directories(catalogs());
        if (!write_file(source() / "bin/node", "#!/bin/sh\nexit 0\n", 0700) ||
            !write_file(package() / "bin/pi", "#!/usr/bin/env node\n", 0700) ||
            !write_file(package() / "package.json", "{}\n") ||
            !write_file(catalogs() / "openai.json", openai_catalog) ||
            !write_file(catalogs() / "anthropic.json", anthropic_catalog)) {
            return false;
        }
        std::filesystem::create_symlink(
            std::filesystem::relative(package() / "bin/pi", source() / "bin"), source() / "bin/pi"
        );
        if (::chmod(source().c_str(), 0770) != 0) {
            return false;
        }
        for (const auto& candidate : glove::host::detect_runtime_harnesses({source() / "bin"})) {
            if (candidate.runtime_id == "pi") {
                return candidate.available && candidate.resolved_executable == source() / "bin/pi";
            }
        }
        return false;
    }

    auto context() -> pi_setup_context {
        return {
            .directories = directories(),
            .detect =
                [this] {
                    ++detections;
                    // Real discovery preserves the named bin/pi alias: staging
                    // derives adjacent Node before canonicalizing the package.
                    // Decoys cannot substitute for an exact available Pi identity.
                    return std::vector<glove::host::detected_runtime_harness>{
                        {.runtime_id = "claude-code",
                         .executable_name = "claude",
                         .available = true,
                         .resolved_executable = source() / "bin/node",
                         .diagnostic = {}},
                        {.runtime_id = "pi",
                         .executable_name = "pi",
                         .available = false,
                         .resolved_executable = {},
                         .diagnostic = "fixture unavailable"},
                        {.runtime_id = "pi",
                         .executable_name = "pi",
                         .available = true,
                         .resolved_executable = source() / "bin/pi",
                         .diagnostic = {}}
                    };
                },
            .stage = [this](const glove::host::runtime_harness_stage_options& options)
                -> glove::host::result<glove::host::staged_runtime_harness> {
                auto observation = options;
                observation.source_exclusions = {};
                stages.push_back(std::move(observation));
                // This boundary can stage only the synthetic scripts above.
                // Script closure derivation needs no dependency command; neither
                // script is ever executed. No installed harness is inspected.
                if (options.runtime_id != "pi" ||
                    options.source_executable != source() / "bin/pi" ||
                    options.protected_directory != directories().data / "pi/runtime" ||
                    options.dry_run) {
                    return std::unexpected(std::string{"unexpected fixture staging authority"});
                }
                auto result = glove::host::stage_runtime_harness(options);
                if (result) {
                    staged = *result;
                }
                return result;
            },
        };
    }
};

auto setup_command(bool approved = true) -> pi_command_line {
    return {
        .action = pi_command_action::setup,
        .request =
            {.selection = {.provider = "openai", .model = "gpt-5", .arguments = {}},
             .workspace = std::nullopt},
        .approved = approved
    };
}

auto unchanged_record(
    const std::filesystem::path& path, const struct stat& before, const std::string& bytes
) -> bool {
    struct stat after{};
    return ::lstat(path.c_str(), &after) == 0 && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino && before.st_uid == after.st_uid &&
           before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
           before.st_size == after.st_size &&
#if defined(__APPLE__)
           before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec &&
#else
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
#endif
           contents(path) == bytes;
}

auto refusal_cases(const std::filesystem::path& root) -> int {
    const auto directories = fixture{.root = root / "refused"}.directories();
    pi_setup_context undefined{.directories = directories, .detect = {}, .stage = {}};
    // Refusal precedes default discovery and even creation of the context's
    // private root or selection parent.
    REQUIRE(!configure_pi_runtime(setup_command(false), undefined));
    auto refresh = setup_command(false);
    refresh.action = pi_command_action::refresh;
    REQUIRE(!configure_pi_runtime(refresh, undefined));
    REQUIRE(!std::filesystem::exists(root / "refused"));
    for (const auto kind :
         {"provider", "model", "missing-provider", "missing-model", "workspace", "arguments"}) {
        auto command = setup_command();
        const std::string_view value{kind};
        if (value == "provider")
            command.request.selection.provider = "openai-codex";
        if (value == "model")
            command.request.selection.model = "gpt-5:high";
        if (value == "missing-provider")
            command.request.selection.provider.reset();
        if (value == "missing-model")
            command.request.selection.model.reset();
        if (value == "workspace")
            command.request.workspace = root / "workspace";
        if (value == "arguments")
            command.request.selection.arguments = {"prompt"};
        REQUIRE(!configure_pi_runtime(command, undefined));
        REQUIRE(!std::filesystem::exists(root / "refused"));
    }
    fixture absent{.root = root / "no-detection"};
    REQUIRE(absent.prepare());
    auto unavailable = absent.context();
    unavailable.detect = [&absent] {
        ++absent.detections;
        return std::vector<glove::host::detected_runtime_harness>{
            {.runtime_id = "pi-other",
             .executable_name = "pi",
             .available = true,
             .resolved_executable = absent.source() / "bin/pi",
             .diagnostic = {}},
            {.runtime_id = "pi",
             .executable_name = "pi",
             .available = false,
             .resolved_executable = absent.source() / "bin/pi",
             .diagnostic = {}}
        };
    };
    REQUIRE(!configure_pi_runtime(setup_command(), unavailable));
    REQUIRE(absent.detections == 1U && absent.stages.empty());
    REQUIRE(!std::filesystem::exists(absent.record()));
    return 0;
}

auto setup_and_refresh_cases(const std::filesystem::path& root) -> int {
    fixture input{.root = root / "setup"};
    REQUIRE(input.prepare());
    auto context = input.context();
    const auto command = setup_command();
    auto created = configure_pi_runtime(command, context);
    if (!created) {
        std::fprintf(stderr, "synthetic setup refusal: %.1024s\n", created.error().c_str());
    }
    REQUIRE(created && *created);
    REQUIRE(input.detections == 1U && input.stages.size() == 1U && input.staged);
    REQUIRE(input.stages.front().runtime_id == "pi");
    REQUIRE(input.stages.front().source_executable == input.source() / "bin/pi");
    REQUIRE(input.stages.front().protected_directory == input.directories().data / "pi/runtime");
    REQUIRE(!input.stages.front().dry_run);
    REQUIRE(!input.staged->snapshot_digest.empty());
    REQUIRE(glove::host::validate_pi_runtime_harness(*input.staged));
    REQUIRE(input.staged->launch_executable.string().starts_with(
        (input.directories().data / "pi/runtime").string()
    ));
    auto saved = glove::run::load_pi_runtime_selection(input.record());
    REQUIRE(saved && *saved);
    REQUIRE(
        (*saved)->model ==
        (glove::run::pi_model_selection{glove::run::pi_provider::openai, "gpt-5"})
    );
    REQUIRE((*saved)->runtime.snapshot_digest == input.staged->snapshot_digest);
    struct stat config{}, parent{}, record_before{};
    REQUIRE(::lstat(input.directories().config.c_str(), &config) == 0);
    REQUIRE(
        S_ISDIR(config.st_mode) && config.st_uid == ::geteuid() &&
        (config.st_mode & 07777U) == 0700U
    );
    REQUIRE(::lstat(input.record().parent_path().c_str(), &parent) == 0);
    REQUIRE(
        S_ISDIR(parent.st_mode) && parent.st_uid == ::geteuid() &&
        (parent.st_mode & 07777U) == 0700U
    );
    REQUIRE(::lstat(input.record().c_str(), &record_before) == 0);
    REQUIRE(
        S_ISREG(record_before.st_mode) && record_before.st_uid == ::geteuid() &&
        record_before.st_nlink == 1 && (record_before.st_mode & 07777U) == 0600U
    );
    const auto original = contents(input.record());
    auto repeated = configure_pi_runtime(command, context);
    REQUIRE(repeated && !*repeated);
    REQUIRE(input.detections == 1U && input.stages.size() == 1U);
    REQUIRE(unchanged_record(input.record(), record_before, original));

    auto different = command;
    different.request.selection.provider = "anthropic";
    different.request.selection.model = "claude-sonnet-4-6";
    REQUIRE(!configure_pi_runtime(different, context));
    REQUIRE(input.detections == 1U && input.stages.size() == 1U);
    REQUIRE(unchanged_record(input.record(), record_before, original));
    different.action = pi_command_action::refresh;
    different.approved = false;
    REQUIRE(!configure_pi_runtime(different, context));
    REQUIRE(input.detections == 1U && input.stages.size() == 1U);
    REQUIRE(unchanged_record(input.record(), record_before, original));
    different.approved = true;
    auto refreshed = configure_pi_runtime(different, context);
    REQUIRE(refreshed && *refreshed);
    REQUIRE(input.detections == 2U && input.stages.size() == 2U && input.staged);
    saved = glove::run::load_pi_runtime_selection(input.record());
    REQUIRE(saved && *saved);
    REQUIRE(
        (*saved)->model ==
        (glove::run::pi_model_selection{glove::run::pi_provider::anthropic, "claude-sonnet-4-6"})
    );
    REQUIRE((*saved)->runtime.snapshot_digest == input.staged->snapshot_digest);
    REQUIRE(glove::host::validate_pi_runtime_harness((*saved)->runtime));

    // Refresh may inspect an admitted owner record without treating its stale
    // source binding as launch authority. The public loader must stay strict.
    const auto old_snapshot = (*saved)->runtime.snapshot_digest;
    REQUIRE(write_file(
        input.package() / "bin/pi", "#!/usr/bin/env node\n// refreshed synthetic fixture\n", 0700
    ));
    REQUIRE(!glove::run::load_pi_runtime_selection(input.record()));
    const auto admitted_stale = glove::run::detail::inspect_pi_operator_record(input.record());
    REQUIRE(admitted_stale && *admitted_stale);
    REQUIRE((*admitted_stale)->runtime.snapshot_digest == old_snapshot);
    auto source_refreshed = configure_pi_runtime(different, context);
    REQUIRE(source_refreshed && *source_refreshed);
    REQUIRE(input.detections == 3U && input.stages.size() == 3U && input.staged);
    saved = glove::run::load_pi_runtime_selection(input.record());
    REQUIRE(saved && *saved);
    REQUIRE(
        (*saved)->model ==
        (glove::run::pi_model_selection{glove::run::pi_provider::anthropic, "claude-sonnet-4-6"})
    );
    REQUIRE((*saved)->runtime.snapshot_digest != old_snapshot);
    REQUIRE((*saved)->runtime.snapshot_digest == input.staged->snapshot_digest);
    REQUIRE(glove::host::validate_pi_runtime_harness((*saved)->runtime));

    const auto refreshed_bytes = contents(input.record());
    for (const auto& malformed : {std::string{"{"}, std::string{"{}"}, " " + refreshed_bytes}) {
        REQUIRE(write_file(input.record(), malformed));
        struct stat malformed_before{};
        REQUIRE(::lstat(input.record().c_str(), &malformed_before) == 0);
        REQUIRE(!glove::run::load_pi_runtime_selection(input.record()));
        REQUIRE(!configure_pi_runtime(different, context));
        REQUIRE(input.detections == 3U && input.stages.size() == 3U);
        REQUIRE(unchanged_record(input.record(), malformed_before, malformed));
        REQUIRE(write_file(input.record(), refreshed_bytes));
    }
    REQUIRE(glove::run::load_pi_runtime_selection(input.record()));
#if defined(__APPLE__)
    for (const bool read_only : {false, true}) {
        REQUIRE(glove::test::set_fixture_acl(input.record(), false, ACL_EXTENDED_ALLOW, read_only));
        struct stat unsafe_acl_before{};
        REQUIRE(::lstat(input.record().c_str(), &unsafe_acl_before) == 0);
        REQUIRE(!glove::run::detail::inspect_pi_operator_record(input.record()));
        REQUIRE(!configure_pi_runtime(different, context));
        REQUIRE(input.detections == 3U && input.stages.size() == 3U);
        REQUIRE(unchanged_record(input.record(), unsafe_acl_before, refreshed_bytes));
    }
    REQUIRE(glove::test::set_fixture_acl(input.record(), false, ACL_EXTENDED_DENY));
    const auto admitted_deny = glove::run::detail::inspect_pi_operator_record(input.record());
    REQUIRE(admitted_deny && *admitted_deny);
    REQUIRE((*admitted_deny)->model == (*saved)->model);
#endif
    for (const bool hardlink : {false, true}) {
        if (hardlink) {
            std::filesystem::create_hard_link(
                input.record(), input.record().parent_path() / "hardlink"
            );
        } else {
            REQUIRE(::chmod(input.record().c_str(), 0640) == 0);
        }
        struct stat unsafe_before{};
        REQUIRE(::lstat(input.record().c_str(), &unsafe_before) == 0);
        REQUIRE(!glove::run::load_pi_runtime_selection(input.record()));
        REQUIRE(!configure_pi_runtime(different, context));
        REQUIRE(input.detections == 3U && input.stages.size() == 3U);
        REQUIRE(unchanged_record(input.record(), unsafe_before, refreshed_bytes));
        if (hardlink) {
            REQUIRE(std::filesystem::remove(input.record().parent_path() / "hardlink"));
        } else {
            REQUIRE(::chmod(input.record().c_str(), 0600) == 0);
        }
    }
    return 0;
}

auto catalog_and_stage_failure_cases(const std::filesystem::path& root) -> int {
    for (const auto kind : {"missing", "model", "api", "provider", "stage"}) {
        fixture input{.root = root / kind};
        REQUIRE(input.prepare());
        const std::string_view failure{kind};
        if (failure == "missing") {
            REQUIRE(std::filesystem::remove(input.catalogs() / "openai.json"));
        } else if (failure == "model") {
            REQUIRE(write_file(
                input.catalogs() / "openai.json",
                R"({"openai-responses":{"chat:gpt-50":{"id":"gpt-50","provider":"openai","api":"openai-responses","type":"chat"}}})"
            ));
        } else if (failure == "api") {
            REQUIRE(write_file(
                input.catalogs() / "openai.json",
                R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-completions","type":"chat"}}})"
            ));
        } else if (failure == "provider") {
            REQUIRE(write_file(
                input.catalogs() / "openai.json",
                R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"anthropic","api":"openai-responses","type":"chat"}}})"
            ));
        }
        auto context = input.context();
        if (failure == "stage") {
            context.stage = [&input](
                                const glove::host::runtime_harness_stage_options& options
                            ) -> glove::host::result<glove::host::staged_runtime_harness> {
                auto observation = options;
                observation.source_exclusions = {};
                input.stages.push_back(std::move(observation));
                return std::unexpected(std::string{"fixture staging failed"});
            };
        }
        auto rejected = configure_pi_runtime(setup_command(), context);
        REQUIRE(!rejected && !rejected.error().empty() && rejected.error().size() <= 4096U);
        REQUIRE(input.detections == 1U && input.stages.size() == 1U);
        REQUIRE(input.stages.front().source_exclusions.empty());
        REQUIRE(!std::filesystem::exists(input.record()));
        if (failure != "stage") {
            REQUIRE(input.staged && glove::host::validate_pi_runtime_harness(*input.staged));
        } else {
            REQUIRE(!input.staged);
        }
        // Staging may retain a valid cached snapshot/alias after metadata
        // refusal. This asserts no publication, not atomic rollback.
    }
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(parser_cases() == 0);
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    struct stat metadata{};
    REQUIRE(::lstat(temporary.root().c_str(), &metadata) == 0);
    REQUIRE(metadata.st_uid == ::geteuid() && (metadata.st_mode & 07777U) == 0700U);
    REQUIRE(refusal_cases(temporary.root()) == 0);
    REQUIRE(setup_and_refresh_cases(temporary.root()) == 0);
    REQUIRE(catalog_and_stage_failure_cases(temporary.root()) == 0);
    return 0;
}
