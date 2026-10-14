#pragma once

#include "glove/container/owned_passthrough.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/net/credentialed_endpoint.hpp"

#include "../support/anthropic_fixture_responder.hpp"
#include "adapters/claude/native_harness.hpp"
#include "claude_history.hpp"
#include "claude_native_policy.hpp"
#include "native_session_supervisor.hpp"
#include "sha256.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::test_support {

// Composition for the ACTUAL Claude Code executable: the exact file is
// admitted by content digest on every generation, the provider endpoint is
// the real credentialed endpoint whose only transport is the fixture
// responder, and execution is the real owned contained passthrough.
struct claude_lane_binding {
    std::filesystem::path executable;
    std::string sha256;
    std::string version;
    std::filesystem::path payload; // sealed empty directory (runtime read-only root)
};

struct lane_observation {
    unsigned births = 0;
    std::vector<std::string> environment;
    std::vector<std::string> argv;
    std::string config_dir;
    std::string nonce;
    std::uint16_t port = 0;
    std::vector<std::string> revoked_nonces;
};

class claude_lane_harness final : public detail::native_session_harness {
public:
    claude_lane_harness(claude_lane_binding binding, detail::claude_launch_mode mode)
        : binding_{std::move(binding)}, policy_{detail::claude_native_startup_policy(mode)} {}

    auto harness_id() const -> std::string_view override { return "claude"; }

    auto history_format() const -> std::string_view override {
        return detail::claude_history_format;
    }

    auto policy() const -> const detail::native_startup_policy& override { return policy_; }

    auto adapter() const -> const detail::native_harness_adapter& override { return adapter_; }

    auto history_location(std::string_view workspace, std::string_view conversation_id) const
        -> std::expected<std::vector<std::string>, std::string> override {
        auto leaf = detail::claude_project_leaf(workspace);
        if (!leaf) {
            return std::unexpected(leaf.error());
        }
        return std::vector<std::string>{"projects", *leaf, std::string{conversation_id} + ".jsonl"};
    }

    auto validator(std::string_view conversation_id) const -> detail::history_validator override {
        return detail::claude_history_validator(
            {.conversation_id = std::string{conversation_id}, .runtime_version = binding_.version}
        );
    }

    // Exact runtime admission: regular owner-readable file whose full content
    // digest equals the pinned value. The symlink spelling is never used.
    auto admit_executable() const
        -> std::expected<glove::host::staged_runtime_harness, std::string> {
        const int fd = ::open(binding_.executable.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return std::unexpected("cannot open admitted Claude executable");
        }
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || (info.st_mode & 0111U) == 0) {
            ::close(fd);
            return std::unexpected("admitted Claude executable is not a regular executable file");
        }
        auto digest = container::detail::sha256_fd_hex(fd, 1024ULL * 1024ULL * 1024ULL);
        ::close(fd);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        if (*digest != binding_.sha256) {
            return std::unexpected("admitted Claude executable content digest mismatch");
        }
        glove::host::staged_runtime_harness runtime;
        runtime.runtime_id = "claude";
        runtime.executable_name = "claude";
        runtime.source_executable = binding_.executable;
        runtime.canonical_source_executable = binding_.executable;
        runtime.source_launch_executable = binding_.executable;
        runtime.protected_entry_point = binding_.executable;
        runtime.launch_executable = binding_.executable;
        runtime.read_only_paths = {binding_.payload};
        runtime.snapshot_digest = *digest;
        return runtime;
    }

    auto compose(detail::native_launch_context& context)
        -> std::expected<void, std::string> override {
        context.admit_runtime =
            [this]() -> std::expected<detail::native_launch_binding, std::string> {
            auto runtime = admit_executable();
            if (!runtime) {
                return std::unexpected(runtime.error());
            }
            return detail::native_launch_binding{
                .runtime = *runtime,
                .provider = net::endpoint_provider::anthropic,
                .model = model,
                .arguments = {prompt}
            };
        };
        context.admit_assets = [](const detail::native_launch_binding&) {
            return std::expected<detail::native_launch_assets, std::string>{
                detail::native_launch_assets{.catalog_json = {}, .library_environment = {}}
            };
        };
        context.revalidate =
            [this]() -> std::expected<detail::native_launch_authority, std::string> {
            auto runtime = admit_executable();
            if (!runtime) {
                return std::unexpected(runtime.error());
            }
            return detail::native_launch_authority{
                .binding =
                    {.runtime = *runtime,
                     .provider = net::endpoint_provider::anthropic,
                     .model = model,
                     .arguments = {prompt}},
                .assets = {.catalog_json = {}, .library_environment = {}}
            };
        };
        // The host "credential" is a synthetic sentinel: the fixture responder
        // never forwards it anywhere and no real provider is reachable.
        context.credential = [](net::endpoint_provider) -> std::expected<std::string, std::string> {
            return std::string{"fixture-sentinel-not-a-credential"};
        };
        context.start_endpoint = [this](net::credentialed_endpoint_options options)
            -> std::expected<std::unique_ptr<net::credentialed_endpoint>, std::string> {
            // Replace the production TLS transport with the in-process responder.
            options.forward = responder.forwarder();
            options.upstream_deadline_ms = 120000;
            auto started = net::start_credentialed_endpoint(std::move(options));
            if (!started) {
                return started;
            }
            std::scoped_lock lock{mutex};
            observed.port = (*started)->port();
            return started;
        };
        context.execute_owned = [this](
                                    const container::profile& profile,
                                    const std::vector<std::string>& argv,
                                    std::stop_token stop
                                ) -> std::expected<int, std::string> {
            {
                std::scoped_lock lock{mutex};
                ++observed.births;
                observed.environment = profile.environment;
                observed.argv = argv;
                for (const auto& entry : profile.environment) {
                    if (entry.starts_with("CLAUDE_CONFIG_DIR=")) {
                        observed.config_dir = entry.substr(18);
                    } else if (entry.starts_with("ANTHROPIC_API_KEY=")) {
                        observed.nonce = entry.substr(18);
                    }
                }
            }
            auto exited = container::exec_contained_owned(profile, argv, stop);
            dump_history(profile);
            return exited;
        };
        return {};
    }

    // Diagnostic only: copies the generation-local transcript bytes (bounded)
    // into `transcripts` before finalization so a refused history can be read.
    void dump_history(const container::profile& profile) {
        std::string config;
        for (const auto& entry : profile.environment) {
            if (entry.starts_with("CLAUDE_CONFIG_DIR=")) {
                config = entry.substr(18);
            }
        }
        std::error_code error;
        for (const auto& project : std::filesystem::directory_iterator(
                 std::filesystem::path{config} / "projects", error
             )) {
            for (const auto& file : std::filesystem::directory_iterator(project.path(), error)) {
                std::ifstream input{file.path(), std::ios::binary};
                std::string bytes{
                    std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}
                };
                std::scoped_lock lock{mutex};
                transcripts.emplace_back(file.path().string(), bytes.substr(0, 262144));
            }
        }
    }

    std::vector<std::pair<std::string, std::string>> transcripts;

    std::string model = "claude-fixture-model";
    std::string prompt = "Reply with exactly the single word pong and nothing else.";
    anthropic_fixture_responder responder;
    lane_observation observed;
    std::mutex mutex;

private:
    claude_lane_binding binding_;
    detail::native_startup_policy policy_;
    glove::run::adapters::claude_harness_adapter adapter_;
};

} // namespace glove::run::test_support
