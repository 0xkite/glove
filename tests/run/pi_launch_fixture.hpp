#pragma once

#include "glove/audit/sink.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/run/pi_runtime.hpp"

#include "launch_command.hpp"
#include "pi_launch_internal.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::run::test_support {

#define GLOVE_PI_FIXTURE_REQUIRE(condition)                                                        \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using glove::net::credentialed_endpoint;
using glove::net::credentialed_endpoint_options;
using glove::net::endpoint_provider;
using glove::run::pi_provider;
using glove::run::detail::launch_pi_with_context;
using glove::run::detail::pi_launch_context;

constexpr std::string_view host_key = "host-key-sentinel-never-project-this";
constexpr std::uint16_t fixture_port = 32123;
constexpr std::string_view marker_name = ".glove-pi-lease";
constexpr std::string_view catalog_suffix =
    "node_modules/@earendil-works/pi-ai/dist/providers/data";
// These exact identities are fixture data, not assertions of model availability.
constexpr std::string_view openai_catalog =
    R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})";
constexpr std::string_view anthropic_catalog =
    R"({"anthropic-messages":{"chat:claude-sonnet-4-6":{"id":"claude-sonnet-4-6","provider":"anthropic","api":"anthropic-messages","type":"chat"}}})";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-pi-launch-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = fs::canonical(created);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        // All contents belong to this childless synthetic fixture, including any
        // uncertain roots retained by the adapter. Never sweep production state.
        std::error_code ignored;
        if (!root_.empty()) {
            for (const auto& entry : fs::recursive_directory_iterator(root_, ignored)) {
                if (fs::is_directory(entry.symlink_status(ignored))) {
                    fs::permissions(
                        entry.path(), fs::perms::owner_write, fs::perm_options::add, ignored
                    );
                }
            }
            fs::remove_all(root_, ignored);
        }
    }

    auto root() const -> const fs::path& { return root_; }

private:
    fs::path root_;
};

inline auto write_file(const fs::path& path, std::string_view bytes, mode_t mode = 0600) -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

inline auto read_file(const fs::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

inline auto named(const fs::path& path) noexcept -> bool {
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0;
}

inline auto private_directory(const fs::path& path) -> bool {
    fs::create_directories(path);
    return ::chmod(path.c_str(), 0700) == 0;
}

inline auto owned_mode(const fs::path& path, mode_t expected, bool directory) -> bool {
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0 && info.st_uid == ::geteuid() &&
           (info.st_mode & 07777U) == expected &&
           (directory ? S_ISDIR(info.st_mode) : S_ISREG(info.st_mode) && info.st_nlink == 1);
}

inline auto below(const fs::path& path, const fs::path& ancestor) -> bool {
    if (!path.is_absolute() || path.lexically_normal() != path) {
        return false;
    }
    const auto relative = path.lexically_relative(ancestor);
    if (relative.empty() || relative == "." || relative.is_absolute()) {
        return false;
    }
    return std::ranges::none_of(relative, [](const auto& component) { return component == ".."; });
}

// No throwing filesystem calls, path concatenation, REQUIRE, socket or thread
// operations in the virtual endpoint destructor. This only observes names.
inline auto named_run_count(const fs::path& parent) noexcept -> int {
    DIR* directory = ::opendir(parent.c_str());
    if (directory == nullptr) {
        return -1;
    }
    int count = 0;
    std::size_t visited = 0;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory);
        if (entry == nullptr) {
            const bool complete = errno == 0;
            return ::closedir(directory) == 0 && complete ? count : -1;
        }
        if (++visited > 65536U) {
            (void)::closedir(directory);
            return -1;
        }
        if (std::string_view{entry->d_name}.starts_with("run-")) {
            struct stat info{};
            if (::fstatat(::dirfd(directory), entry->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
                (void)::closedir(directory);
                return -1;
            }
            if (S_ISDIR(info.st_mode)) {
                ++count;
            }
        }
    }
}

struct observation {
    fs::path runs;
    fs::path root;
    std::string nonce;
    int credentials = 0;
    int starts = 0;
    int executions = 0;
    int roots_at_reset = -1;
    bool options_checked = false;
    bool inspection_failed = false;
    bool revoked = false;
    bool joined = false;
};

class synthetic_endpoint final : public credentialed_endpoint {
public:
    synthetic_endpoint(observation& observed, endpoint_provider provider, std::string prefix)
        : observed_{observed}, provider_{provider}, prefix_{std::move(prefix)} {}

    ~synthetic_endpoint() noexcept override {
        // Flags model revocation/join only: no listener or worker ever existed.
        observed_.revoked = true;
        observed_.joined = true;
        observed_.roots_at_reset = named_run_count(observed_.runs);
    }

    auto port() const -> std::uint16_t override { return fixture_port; }

    auto base_url(endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        if (provider != provider_) {
            return std::unexpected(std::string{"wrong synthetic provider"});
        }
        return "http://127.0.0.1:" + std::to_string(fixture_port) + prefix_;
    }

    auto session_nonce(endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        if (provider != provider_) {
            return std::unexpected(std::string{"wrong synthetic provider"});
        }
        return observed_.nonce;
    }

private:
    observation& observed_;
    endpoint_provider provider_;
    std::string prefix_;
};

struct fixture {
    explicit fixture(fs::path directory, pi_provider selected = pi_provider::openai)
        : root{std::move(directory)}, provider{selected} {}

    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;

    fs::path root;
    pi_provider provider = pi_provider::openai;
    pi_launch_context context;
    glove::run::pi_runtime_selection saved;
    observation observed;
    std::shared_ptr<glove::audit::memory_sink> audit = glove::audit::make_memory_sink();

    auto source() const -> fs::path { return root / "source"; }

    auto package() const -> fs::path { return source() / "lib/node_modules/@fixture/pi"; }

    auto workspace() const -> fs::path { return root / "workspace"; }

    auto record() const -> fs::path { return context.directories.config / "pi/selection.json"; }

    auto runtime_store() const -> fs::path { return context.directories.data / "pi/runtime"; }

    auto model() const -> std::string {
        return provider == pi_provider::openai ? "gpt-5" : "claude-sonnet-4-6";
    }

    auto request() const -> glove::run::pi_launch_request {
        return {
            .selection = {.arguments = {"--print", "--mode", "json", "--", "Fixture prompt"}},
            .workspace = workspace()
        };
    }

    auto prepare(bool stage = true) -> int {
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(root));
        context.directories = {
            root / "config", root / "state", root / "data", root / "cache", root / "runtime"
        };
        for (const auto& directory :
             {context.directories.config,
              context.directories.state,
              context.directories.data,
              context.directories.cache,
              context.directories.runtime,
              root / "host-auth",
              workspace()}) {
            GLOVE_PI_FIXTURE_REQUIRE(private_directory(directory));
        }
        context.protected_auth_roots = {root / "host-auth"};
        observed.runs = context.directories.runtime / "pi/runs";
        context.audit = audit;
        context.credential =
            [this](pi_provider selected) -> std::expected<std::string, std::string> {
            ++observed.credentials;
            if (selected != provider) {
                return std::unexpected(std::string{"wrong fixture credential provider"});
            }
            return std::string{host_key};
        };
        context.start_endpoint = [this](credentialed_endpoint_options options)
            -> std::expected<std::unique_ptr<credentialed_endpoint>, std::string> {
            ++observed.starts;
            if (check_options(options) != 0) {
                observed.inspection_failed = true;
                return std::unexpected(std::string{"synthetic endpoint options inspection failed"});
            }
            return endpoint();
        };
        // Never execute either script. A successful result models the owned
        // API's quiescence contract, not observed kernel/process-group death.
        context.execute_owned = [this](
                                    const glove::container::profile& profile,
                                    const std::vector<std::string>& argv,
                                    std::stop_token stop
                                ) -> std::expected<int, std::string> {
            ++observed.executions;
            if (stop.stop_requested() || inspect_launch(profile, argv) != 0) {
                observed.inspection_failed = true;
                return std::unexpected(std::string{"synthetic owned launch inspection failed"});
            }
            return 7;
        };
        if (!stage) {
            return 0;
        }
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(context.directories.config / "pi"));
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(context.directories.data / "pi"));
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(source() / "bin"));
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(package() / "bin"));
        GLOVE_PI_FIXTURE_REQUIRE(private_directory(package() / catalog_suffix));
        GLOVE_PI_FIXTURE_REQUIRE(write_file(source() / "bin/node", "#!/bin/sh\nexit 0\n", 0700));
        GLOVE_PI_FIXTURE_REQUIRE(write_file(package() / "bin/pi", "#!/usr/bin/env node\n", 0700));
        GLOVE_PI_FIXTURE_REQUIRE(write_file(package() / "package.json", "{}\n"));
        GLOVE_PI_FIXTURE_REQUIRE(
            write_file(package() / catalog_suffix / "openai.json", openai_catalog)
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            write_file(package() / catalog_suffix / "anthropic.json", anthropic_catalog)
        );
        fs::create_symlink(
            fs::relative(package() / "bin/pi", source() / "bin"), source() / "bin/pi"
        );
        GLOVE_PI_FIXTURE_REQUIRE(::chmod(source().c_str(), 0770) == 0);
        // Script-only synthetic closure: staging requires no dependency command.
        auto staged = glove::host::stage_runtime_harness(
            {.runtime_id = "pi",
             .source_executable = source() / "bin/pi",
             .protected_directory = runtime_store(),
             .dry_run = false}
        );
        GLOVE_PI_FIXTURE_REQUIRE(staged);
        GLOVE_PI_FIXTURE_REQUIRE(!staged->snapshot_digest.empty());
        GLOVE_PI_FIXTURE_REQUIRE(staged->launch_arguments.size() == 1);
        saved = {.model = {.provider = provider, .model = model()}, .runtime = *staged};
        auto stored = glove::run::store_pi_runtime_selection(record(), saved, true);
        GLOVE_PI_FIXTURE_REQUIRE(stored && *stored);
        GLOVE_PI_FIXTURE_REQUIRE(!named(observed.runs));
        return 0;
    }

    auto check_options(const credentialed_endpoint_options& options) -> int {
        const bool openai = provider == pi_provider::openai;
        GLOVE_PI_FIXTURE_REQUIRE(options.endpoints.size() == 1);
        GLOVE_PI_FIXTURE_REQUIRE(options.forward && options.on_event);
        const auto& rule = options.endpoints.front();
        GLOVE_PI_FIXTURE_REQUIRE(
            rule.provider == (openai ? endpoint_provider::openai : endpoint_provider::anthropic)
        );
        GLOVE_PI_FIXTURE_REQUIRE(rule.path_prefix == (openai ? "/openai" : "/anthropic"));
        GLOVE_PI_FIXTURE_REQUIRE(
            rule.upstream_host == (openai ? "api.openai.com" : "api.anthropic.com")
        );
        GLOVE_PI_FIXTURE_REQUIRE(rule.upstream_port == 443);
        GLOVE_PI_FIXTURE_REQUIRE(rule.allowed_methods == std::vector<std::string>{"POST"});
        GLOVE_PI_FIXTURE_REQUIRE(
            rule.allowed_paths ==
            std::vector<std::string>{openai ? "/v1/responses" : "/v1/messages"}
        );
        GLOVE_PI_FIXTURE_REQUIRE(rule.secret_token == host_key);
        GLOVE_PI_FIXTURE_REQUIRE(
            rule.session_nonce.size() == 62 && rule.session_nonce.starts_with("glove-session-")
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            rule.session_nonce.substr(14).find_first_not_of("0123456789abcdef") == std::string::npos
        );
        observed.nonce = rule.session_nonce;
        // Exercise audit composition with a synthetic event, never the forwarder.
        auto recorded = options.on_event(
            {.provider = rule.provider,
             .method = "POST",
             .path = rule.allowed_paths.front(),
             .allowed = true,
             .detail = "synthetic endpoint event"}
        );
        GLOVE_PI_FIXTURE_REQUIRE(recorded);
        observed.options_checked = true;
        return 0;
    }

    auto endpoint() -> std::unique_ptr<credentialed_endpoint> {
        return std::make_unique<synthetic_endpoint>(
            observed,
            provider == pi_provider::openai ? endpoint_provider::openai
                                            : endpoint_provider::anthropic,
            provider == pi_provider::openai ? "/openai" : "/anthropic"
        );
    }

    auto
    inspect_launch(const glove::container::profile& profile, const std::vector<std::string>& argv)
        -> int {
        GLOVE_PI_FIXTURE_REQUIRE(observed.options_checked && !observed.revoked && !observed.joined);
        GLOVE_PI_FIXTURE_REQUIRE(profile.home_dir && profile.temp_dir && profile.work_dir);
        const fs::path home{*profile.home_dir};
        const fs::path tmp{*profile.temp_dir};
        observed.root = home.parent_path();
        GLOVE_PI_FIXTURE_REQUIRE(observed.root.parent_path() == observed.runs);
        GLOVE_PI_FIXTURE_REQUIRE(*profile.work_dir == workspace().string());
        GLOVE_PI_FIXTURE_REQUIRE(tmp.parent_path() == observed.root);
        GLOVE_PI_FIXTURE_REQUIRE(read_file(observed.root / marker_name).ends_with("\nlaunching\n"));
        GLOVE_PI_FIXTURE_REQUIRE(
            read_file(observed.root / marker_name).find(host_key) == std::string::npos
        );
        GLOVE_PI_FIXTURE_REQUIRE(owned_mode(observed.root / marker_name, 0600, false));
        GLOVE_PI_FIXTURE_REQUIRE(
            profile.bridge_endpoint && profile.bridge_endpoint->port == fixture_port
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            !profile.proxy && !profile.required_limits && !profile.managed_home_dir
        );

        std::set<std::string> environment_names;
        const auto environment = [&](std::string_view name) -> std::string {
            const std::string prefix = std::string{name} + "=";
            for (const auto& entry : profile.environment) {
                if (entry.starts_with(prefix)) {
                    return entry.substr(prefix.size());
                }
            }
            return {};
        };
        auto libraries = glove::run::pi_runtime_library_environment(saved);
        GLOVE_PI_FIXTURE_REQUIRE(libraries);
        std::set<std::string> allowed_names{
            "HOME",
            "TMPDIR",
            "PI_CODING_AGENT_DIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "PATH"
        };
        for (const auto& entry : *libraries) {
            GLOVE_PI_FIXTURE_REQUIRE(
                std::ranges::find(profile.environment, entry) != profile.environment.end()
            );
            allowed_names.insert(entry.substr(0, entry.find('=')));
        }
        for (const auto& entry : profile.environment) {
            const auto equals = entry.find('=');
            GLOVE_PI_FIXTURE_REQUIRE(equals != std::string::npos);
            const auto name = entry.substr(0, equals);
            GLOVE_PI_FIXTURE_REQUIRE(allowed_names.contains(name));
            GLOVE_PI_FIXTURE_REQUIRE(environment_names.insert(name).second);
            GLOVE_PI_FIXTURE_REQUIRE(entry.find(host_key) == std::string::npos);
        }
        GLOVE_PI_FIXTURE_REQUIRE(environment("HOME").empty() && environment("TMPDIR").empty());
        // HOME/TMPDIR are managed profile fields, never environment overrides.
        // Read the actual native preparer's output without spawning anything.
        auto prepared = glove::container::macos_detail::prepare_launch_command(profile, argv, true);
        GLOVE_PI_FIXTURE_REQUIRE(prepared);
        GLOVE_PI_FIXTURE_REQUIRE(prepared->environment.size() == profile.environment.size() + 3U);
        GLOVE_PI_FIXTURE_REQUIRE(
            std::ranges::find(prepared->environment, "HOME=" + home.string()) !=
            prepared->environment.end()
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            std::ranges::find(prepared->environment, "TMPDIR=" + tmp.string()) !=
            prepared->environment.end()
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            std::ranges::find(prepared->environment, "GLOVE_SANDBOXED=1") !=
            prepared->environment.end()
        );
        for (const auto& entry : prepared->environment) {
            GLOVE_PI_FIXTURE_REQUIRE(entry.find(host_key) == std::string::npos);
        }
        const fs::path agent{environment("PI_CODING_AGENT_DIR")};
        GLOVE_PI_FIXTURE_REQUIRE(!agent.empty() && agent.parent_path() == observed.root);
        for (const auto* name : {"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"}) {
            GLOVE_PI_FIXTURE_REQUIRE(!environment(name).empty());
            GLOVE_PI_FIXTURE_REQUIRE(below(fs::path{environment(name)}, home));
        }
        for (const auto* name : {"XDG_STATE_HOME", "XDG_RUNTIME_DIR"}) {
            if (!environment(name).empty()) {
                GLOVE_PI_FIXTURE_REQUIRE(below(fs::path{environment(name)}, home));
            }
        }
        const auto path = environment("PATH");
        GLOVE_PI_FIXTURE_REQUIRE(!path.empty());
        std::size_t offset = 0;
        do {
            const auto end = path.find(':', offset);
            const auto part = path.substr(offset, end == std::string::npos ? end : end - offset);
            GLOVE_PI_FIXTURE_REQUIRE(
                part == "/usr/bin" || part == "/bin" || part == "/usr/sbin" || part == "/sbin"
            );
            if (end == std::string::npos) {
                break;
            }
            offset = end + 1;
        } while (offset <= path.size());

        const auto models = agent / "models.json";
        const auto settings = agent / "settings.json";
        const auto auth = agent / "auth.json";
        const fs::path sessions = observed.root / "sessions";
        for (const auto& directory : {observed.root, home, tmp, agent, sessions}) {
            GLOVE_PI_FIXTURE_REQUIRE(owned_mode(directory, 0700, true));
        }
        for (const auto& file : {models, settings, auth}) {
            GLOVE_PI_FIXTURE_REQUIRE(owned_mode(file, 0400, false));
            GLOVE_PI_FIXTURE_REQUIRE(read_file(file).find(host_key) == std::string::npos);
        }
        const auto model_bytes = read_file(models);
        const std::string key_prefix = "\"apiKey\":\"";
        const auto begin = model_bytes.find(key_prefix);
        GLOVE_PI_FIXTURE_REQUIRE(begin != std::string::npos);
        const auto value_begin = begin + key_prefix.size();
        const auto value_end = model_bytes.find('"', value_begin);
        GLOVE_PI_FIXTURE_REQUIRE(value_end != std::string::npos);
        const auto parsed_nonce = model_bytes.substr(value_begin, value_end - value_begin);
        GLOVE_PI_FIXTURE_REQUIRE(parsed_nonce == observed.nonce);
        const std::string name{glove::run::pi_provider_name(provider)};
        const auto url = "http://127.0.0.1:" + std::to_string(fixture_port) +
                         (provider == pi_provider::openai ? "/openai/v1" : "/anthropic");
        // Exact JSON equality also excludes metadata replacements and extra keys.
        GLOVE_PI_FIXTURE_REQUIRE(
            model_bytes == "{\"providers\":{\"" + name + "\":{\"baseUrl\":\"" + url +
                               "\",\"apiKey\":\"" + parsed_nonce + "\"}}}"
        );
        GLOVE_PI_FIXTURE_REQUIRE(
            read_file(settings) == "{\"defaultProvider\":\"" + name + "\",\"defaultModel\":\"" +
                                       model() +
                                       "\",\"packages\":[],\"extensions\":[],\"skills\":[],"
                                       "\"promptTemplates\":[],\"themes\":[]}"
        );
        GLOVE_PI_FIXTURE_REQUIRE(read_file(auth) == "{}");
        GLOVE_PI_FIXTURE_REQUIRE(fs::is_empty(sessions));
        GLOVE_PI_FIXTURE_REQUIRE(!named(workspace() / ".pi"));

        const std::set<std::string> immutable{models.string(), settings.string(), auth.string()};
        GLOVE_PI_FIXTURE_REQUIRE(profile.immutable_files.size() == immutable.size());
        GLOVE_PI_FIXTURE_REQUIRE(
            std::set<std::string>(profile.immutable_files.begin(), profile.immutable_files.end()) ==
            immutable
        );
        GLOVE_PI_FIXTURE_REQUIRE(profile.reserved_entries.size() == 1);
        GLOVE_PI_FIXTURE_REQUIRE(profile.reserved_entries.front().parent == workspace().string());
        GLOVE_PI_FIXTURE_REQUIRE(profile.reserved_entries.front().name == ".pi");
        const std::set<std::string> writable{
            workspace().string(), home.string(), tmp.string(), agent.string(), sessions.string()
        };
        GLOVE_PI_FIXTURE_REQUIRE(profile.filesystem.size() == writable.size());
        std::set<std::string> actual_writable;
        for (const auto& rule : profile.filesystem) {
            GLOVE_PI_FIXTURE_REQUIRE(rule.writable && actual_writable.insert(rule.path).second);
        }
        GLOVE_PI_FIXTURE_REQUIRE(actual_writable == writable);
        GLOVE_PI_FIXTURE_REQUIRE(
            profile.runtime_filesystem.size() == saved.runtime.read_only_paths.size()
        );
        std::set<std::string> runtime_paths;
        for (const auto& rule : profile.runtime_filesystem) {
            GLOVE_PI_FIXTURE_REQUIRE(!rule.writable && runtime_paths.insert(rule.path).second);
            GLOVE_PI_FIXTURE_REQUIRE(rule.path.find(source().string()) == std::string::npos);
        }
        for (const auto& runtime_path : saved.runtime.read_only_paths) {
            GLOVE_PI_FIXTURE_REQUIRE(runtime_paths.contains(runtime_path.string()));
        }

        std::vector<std::string> expected{
            saved.runtime.launch_executable.string(),
            saved.runtime.launch_arguments.front(),
            "--provider",
            name,
            "--model",
            model(),
            "--offline",
            "--no-approve",
            "--no-extensions",
            "--no-mcp",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files",
            "--session-dir",
            sessions.string()
        };
        const auto suffix = request().selection.arguments;
        expected.insert(expected.end(), suffix.begin(), suffix.end());
        GLOVE_PI_FIXTURE_REQUIRE(argv == expected);
        GLOVE_PI_FIXTURE_REQUIRE(argv.front() != (source() / "bin/node").string());
        GLOVE_PI_FIXTURE_REQUIRE(argv[1] != (package() / "bin/pi").string());
        for (const auto& argument : argv) {
            GLOVE_PI_FIXTURE_REQUIRE(argument.find(host_key) == std::string::npos);
            GLOVE_PI_FIXTURE_REQUIRE(argument != "--no-tools");
        }
        return 0;
    }

    auto audit_has_no_key() -> int {
        const auto events = audit->take();
        if (observed.options_checked) {
            GLOVE_PI_FIXTURE_REQUIRE(!events.empty());
        }
        for (const auto& event : events) {
            GLOVE_PI_FIXTURE_REQUIRE(event.tool_name.find(host_key) == std::string::npos);
            GLOVE_PI_FIXTURE_REQUIRE(event.arguments_json.find(host_key) == std::string::npos);
            GLOVE_PI_FIXTURE_REQUIRE(event.error_message.find(host_key) == std::string::npos);
        }
        return 0;
    }
};

#undef GLOVE_PI_FIXTURE_REQUIRE

} // namespace glove::run::test_support
