#pragma once

#include "glove/host/runtime_policy.hpp"
#include "glove/net/credentialed_endpoint.hpp"

#include "adapters/claude/native_harness.hpp"
#include "claude_history.hpp"
#include "claude_native_policy.hpp"
#include "native_session_supervisor.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace glove::run::test_support {

namespace fs = std::filesystem;
using namespace glove::run::detail;

inline constexpr std::string_view fixture_conversation = "0f3c1a2b-4d5e-4f60-8a71-92b3c4d5e6f7";
inline constexpr std::string_view fixture_version = "fixture-1";
inline constexpr std::string_view fixture_model = "claude-fixture-model";
inline constexpr std::string_view fixture_secret = "host-secret-sentinel-never-projected";

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

inline auto private_directory(const fs::path& path) -> bool {
    std::error_code error;
    fs::create_directories(path, error);
    return !error && ::chmod(path.c_str(), 0700) == 0;
}

inline auto environment_value(const std::vector<std::string>& environment, std::string_view name)
    -> std::string {
    const std::string prefix = std::string{name} + "=";
    for (const auto& entry : environment) {
        if (entry.starts_with(prefix)) {
            return entry.substr(prefix.size());
        }
    }
    return {};
}

inline auto fake_history_line(
    std::string type, std::string uuid, std::string parent, std::string_view session_id
) -> std::string {
    return "{\"type\":\"" + type + "\",\"uuid\":\"" + uuid +
           "\",\"parentUuid\":" + (parent.empty() ? "null" : "\"" + parent + "\"") +
           ",\"sessionId\":\"" + std::string{session_id} + "\",\"version\":\"" +
           std::string{fixture_version} + "\",\"message\":{\"role\":\"" + type +
           "\",\"content\":\"fixture\"}}\n";
}

inline auto uuid_for(unsigned index) -> std::string {
    char buffer[40];
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%08x-%04x-4%03x-8%03x-%012x",
        index,
        index & 0xffffU,
        index & 0xfffU,
        index & 0xfffU,
        index
    );
    return buffer;
}

// A synthetic endpoint with no listener: records the nonce the core bound.
class recording_endpoint final : public net::credentialed_endpoint {
public:
    recording_endpoint(std::string nonce, std::uint16_t port, std::vector<std::string>& revocations)
        : nonce_{std::move(nonce)}, port_{port}, revocations_{revocations} {}

    ~recording_endpoint() override { revocations_.push_back(nonce_); }

    auto port() const -> std::uint16_t override { return port_; }

    auto base_url(net::endpoint_provider) const
        -> std::expected<std::string, std::string> override {
        return "http://127.0.0.1:" + std::to_string(port_) + "/anthropic";
    }

    auto session_nonce(net::endpoint_provider) const
        -> std::expected<std::string, std::string> override {
        return nonce_;
    }

private:
    std::string nonce_;
    std::uint16_t port_;
    std::vector<std::string>& revocations_;
};

enum class history_mode { none, valid, invalid, foreign_session, user_only };

struct worker_script {
    history_mode history = history_mode::valid;
    bool hold = true;
    bool fail_outcome = false;
    bool block_admission = false;
    int exit_code = 0;
};

struct worker_observation {
    unsigned births = 0;
    std::vector<std::string> argv;
    std::string config_dir;
    std::string nonce;
    std::string base_url;
    std::string materialized;
    bool resumed = false;
    bool stop_seen = false;
};

// Fake owned worker. No process is spawned: it plays the role of the contained
// harness by writing the generation-local history file Claude would write and
// blocking until released or cancelled. It is not actual-Claude evidence.
class fake_claude_harness final : public native_session_harness {
public:
    explicit fake_claude_harness(fs::path root) : root_{std::move(root)} {}

    auto prepare() -> bool {
        if (!private_directory(root_ / "runtime") || !private_directory(root_ / "payload")) {
            return false;
        }
        if (!write_file(root_ / "runtime/claude-fake", "#!/bin/sh\nexit 0\n", 0700)) {
            return false;
        }
        if (::chmod((root_ / "payload").c_str(), 0500) != 0) {
            return false;
        }
        runtime_.runtime_id = "claude";
        runtime_.executable_name = "claude";
        runtime_.source_executable = root_ / "runtime/claude-fake";
        runtime_.canonical_source_executable = runtime_.source_executable;
        runtime_.source_launch_executable = runtime_.source_executable;
        runtime_.protected_entry_point = runtime_.source_executable;
        runtime_.launch_executable = runtime_.source_executable;
        runtime_.read_only_paths = {root_ / "payload"};
        runtime_.snapshot_digest = std::string(64, 'd');
        return true;
    }

    auto harness_id() const -> std::string_view override { return "claude"; }

    auto history_format() const -> std::string_view override { return claude_history_format; }

    auto policy() const -> const native_startup_policy& override { return policy_; }

    auto adapter() const -> const native_harness_adapter& override { return adapter_; }

    auto history_location(std::string_view workspace, std::string_view conversation_id) const
        -> std::expected<std::vector<std::string>, std::string> override {
        auto leaf = claude_project_leaf(workspace);
        if (!leaf) {
            return std::unexpected(leaf.error());
        }
        return std::vector<std::string>{"projects", *leaf, std::string{conversation_id} + ".jsonl"};
    }

    auto validator(std::string_view conversation_id) const -> history_validator override {
        return claude_history_validator(
            {.conversation_id = std::string{conversation_id},
             .runtime_version = std::string{fixture_version}}
        );
    }

    auto compose(native_launch_context& context) -> std::expected<void, std::string> override {
        context.admit_runtime = [this]() -> std::expected<native_launch_binding, std::string> {
            if (script.block_admission) {
                std::unique_lock lock{mutex_};
                admission_blocked_ = true;
                changed_.notify_all();
                changed_.wait(lock, [&] { return released_ || cancel_; });
            }
            return native_launch_binding{
                .runtime = runtime_,
                .provider = net::endpoint_provider::anthropic,
                .model = std::string{fixture_model},
                .arguments = {"Reply with the single word pong."}
            };
        };
        context.admit_assets = [](const native_launch_binding&) {
            return std::expected<native_launch_assets, std::string>{
                native_launch_assets{.catalog_json = {}, .library_environment = {}}
            };
        };
        context.revalidate = [this]() -> std::expected<native_launch_authority, std::string> {
            return native_launch_authority{
                .binding =
                    {.runtime = runtime_,
                     .provider = net::endpoint_provider::anthropic,
                     .model = std::string{fixture_model},
                     .arguments = {"Reply with the single word pong."}},
                .assets = {.catalog_json = {}, .library_environment = {}}
            };
        };
        context.credential = [](net::endpoint_provider) -> std::expected<std::string, std::string> {
            return std::string{fixture_secret};
        };
        context.start_endpoint = [this](net::credentialed_endpoint_options options)
            -> std::expected<std::unique_ptr<net::credentialed_endpoint>, std::string> {
            if (options.endpoints.size() != 1 ||
                options.endpoints.front().secret_token != fixture_secret) {
                return std::unexpected("unexpected endpoint options");
            }
            return std::make_unique<recording_endpoint>(
                options.endpoints.front().session_nonce, 40000, revocations
            );
        };
        context.execute_owned = [this](
                                    const container::profile& profile,
                                    const std::vector<std::string>& argv,
                                    std::stop_token stop
                                ) -> std::expected<int, std::string> {
            return work(profile, argv, stop);
        };
        return {};
    }

    // Test barriers: bounded condition waits, never shell sleep loops.
    auto wait_running(std::chrono::milliseconds limit) -> bool {
        std::unique_lock lock{mutex_};
        return changed_.wait_for(lock, limit, [&] { return running_; });
    }

    auto wait_admission_blocked(std::chrono::milliseconds limit) -> bool {
        std::unique_lock lock{mutex_};
        return changed_.wait_for(lock, limit, [&] { return admission_blocked_; });
    }

    void release() {
        std::scoped_lock lock{mutex_};
        released_ = true;
        changed_.notify_all();
    }

    void reset_barriers() {
        std::scoped_lock lock{mutex_};
        released_ = false;
        running_ = false;
        admission_blocked_ = false;
    }

    worker_script script;
    worker_observation observed;
    std::vector<std::string> revocations;
    std::mutex observation_mutex;

private:
    auto work(
        const container::profile& profile,
        const std::vector<std::string>& argv,
        std::stop_token stop
    ) -> std::expected<int, std::string> {
        {
            std::scoped_lock lock{observation_mutex};
            ++observed.births;
            observed.argv = argv;
            observed.config_dir = environment_value(profile.environment, "CLAUDE_CONFIG_DIR");
            observed.nonce = environment_value(profile.environment, "ANTHROPIC_API_KEY");
            observed.base_url = environment_value(profile.environment, "ANTHROPIC_BASE_URL");
            observed.resumed = std::ranges::find(argv, "--resume") != argv.end();
            observed.stop_seen = false;
        }
        const fs::path config{observed.config_dir};
        auto leaf = claude_project_leaf(profile.work_dir ? *profile.work_dir : "");
        if (!leaf || config.empty()) {
            return std::unexpected("fake worker cannot locate its history");
        }
        const auto directory = config / "projects" / *leaf;
        const auto file = directory / (std::string{fixture_conversation} + ".jsonl");
        std::error_code error;
        fs::create_directories(directory, error);
        std::string existing;
        if (fs::exists(file, error)) {
            existing = read_file(file);
            std::scoped_lock lock{observation_mutex};
            observed.materialized = existing;
        }
        const auto session_id = script.history == history_mode::foreign_session
                                    ? uuid_for(999)
                                    : std::string{fixture_conversation};
        const unsigned base =
            static_cast<unsigned>(std::count(existing.begin(), existing.end(), '\n'));
        std::string bytes = existing;
        switch (script.history) {
        case history_mode::none:
            break;
        case history_mode::valid:
        case history_mode::foreign_session:
            bytes += fake_history_line(
                "user", uuid_for(base + 1), base == 0 ? "" : uuid_for(base), session_id
            );
            bytes +=
                fake_history_line("assistant", uuid_for(base + 2), uuid_for(base + 1), session_id);
            break;
        case history_mode::user_only:
            bytes += fake_history_line(
                "user", uuid_for(base + 1), base == 0 ? "" : uuid_for(base), session_id
            );
            break;
        case history_mode::invalid:
            bytes += "{\"type\":\n";
            break;
        }
        if (script.history != history_mode::none && !write_file(file, bytes, 0600)) {
            return std::unexpected("fake worker cannot write history");
        }
        {
            std::unique_lock lock{mutex_};
            running_ = true;
            changed_.notify_all();
            if (script.hold) {
                // The callback only notifies: taking mutex_ inside it would
                // deadlock with this thread holding the lock while the
                // callback object is destroyed. The predicate reads the token.
                const std::stop_callback wake{stop, [&] { changed_.notify_all(); }};
                changed_.wait(lock, [&] { return released_ || cancel_ || stop.stop_requested(); });
            }
            cancel_ = false;
            running_ = false;
        }
        {
            std::scoped_lock lock{observation_mutex};
            observed.stop_seen = stop.stop_requested();
        }
        if (script.fail_outcome) {
            return std::unexpected("synthetic executor error: child exited, outcome unknown");
        }
        return stop.stop_requested() ? 128 + 15 : script.exit_code;
    }

    fs::path root_;
    glove::host::staged_runtime_harness runtime_;
    native_startup_policy policy_ = claude_native_startup_policy(claude_launch_mode::headless);
    glove::run::adapters::claude_harness_adapter adapter_;
    std::mutex mutex_;
    std::condition_variable changed_;
    bool running_ = false;
    bool released_ = false;
    bool cancel_ = false;
    bool admission_blocked_ = false;
};

struct supervisor_fixture {
    explicit supervisor_fixture(fs::path directory) : root{std::move(directory)}, harness{root} {}

    fs::path root;
    fake_claude_harness harness;
    glove::host::directories directories;
    std::vector<std::string> log;
    std::mutex log_mutex;

    auto prepare() -> bool {
        if (!private_directory(root)) {
            return false;
        }
        directories = {
            root / "config", root / "state", root / "data", root / "cache", root / "runtime-dir"
        };
        for (const auto& directory :
             {directories.config,
              directories.state,
              directories.data,
              directories.cache,
              directories.runtime,
              root / "workspace",
              root / "sessions",
              root / "host-auth"}) {
            if (!private_directory(directory)) {
                return false;
            }
        }
        return harness.prepare();
    }

    auto workspace() const -> fs::path { return root / "workspace"; }

    auto options(std::optional<std::string> session = std::nullopt)
        -> native_session_supervisor_options {
        return {
            .directories = directories,
            .protected_auth_roots = {root / "host-auth"},
            .workspace = workspace(),
            .sessions_parent = root / "sessions",
            .session = std::move(session),
            .runtime_digest = std::string(64, 'd'),
            .model = std::string{fixture_model},
            .provider = net::endpoint_provider::anthropic,
            .conversation_id = std::string{fixture_conversation},
            .display_name = "claude-fixture",
            .audit = {},
            .log = [this](std::string_view line) {
                std::scoped_lock lock{log_mutex};
                log.emplace_back(line);
            }
        };
    }

    auto runs() const -> fs::path { return directories.runtime / "claude/runs"; }

    auto run_count() const -> std::size_t {
        std::error_code error;
        std::size_t count = 0;
        for (const auto& entry : fs::directory_iterator(runs(), error)) {
            if (entry.path().filename().string().starts_with("run-")) {
                ++count;
            }
        }
        return count;
    }
};

} // namespace glove::run::test_support
