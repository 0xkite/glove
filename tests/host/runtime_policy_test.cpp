#include "glove/host/runtime_policy.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-runtime-policy-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_owner_file(const std::filesystem::path& path, std::string_view contents, mode_t mode)
    -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto run() -> int {
    using namespace glove::host;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto harness_bin = temporary.root() / "harness-bin";
    const auto dependencies = temporary.root() / "runtime-dependencies";
    const auto workspace = temporary.root() / "workspace";
    REQUIRE(std::filesystem::create_directory(harness_bin));
    REQUIRE(std::filesystem::create_directory(dependencies));
    REQUIRE(std::filesystem::create_directory(workspace));
    REQUIRE(::chmod(harness_bin.c_str(), 0700) == 0);

    const auto codex = harness_bin / "codex";
    REQUIRE(write_owner_file(codex, "#!/bin/sh\nexit 0\n", 0700));

    const auto detected = detect_runtime_harnesses({harness_bin});
    REQUIRE(detected.size() == 5U);
    const auto codex_detection = std::ranges::find_if(detected, [](const auto& candidate) {
        return candidate.runtime_id == "codex";
    });
    REQUIRE(codex_detection != detected.end());
    REQUIRE(codex_detection->available);
    REQUIRE(codex_detection->resolved_executable == std::filesystem::canonical(codex));
    const auto claude_detection = std::ranges::find_if(detected, [](const auto& candidate) {
        return candidate.runtime_id == "claude-code";
    });
    REQUIRE(claude_detection != detected.end());
    REQUIRE(!claude_detection->available);
    REQUIRE(claude_detection->diagnostic.find("expected executable") != std::string::npos);

    const auto staged_directory = temporary.root() / "protected" / "codex";
    runtime_harness_stage_options stage_options{
        .runtime_id = "codex",
        .source_executable = codex,
        .protected_directory = staged_directory,
        .dry_run = true,
    };
    auto dry_stage = stage_runtime_harness(stage_options);
    REQUIRE(dry_stage.has_value());
    REQUIRE(!dry_stage->changed);
    REQUIRE(!std::filesystem::exists(staged_directory));
    stage_options.dry_run = false;
    auto staged = stage_runtime_harness(stage_options);
    if (!staged) {
        std::fprintf(stderr, "staging failed: %s\n", staged.error().c_str());
    }
    REQUIRE(staged.has_value());
    REQUIRE(staged->changed);
    REQUIRE(std::filesystem::is_symlink(staged->protected_entry_point));
    auto repeated_stage = stage_runtime_harness(stage_options);
    REQUIRE(repeated_stage.has_value());
    REQUIRE(!repeated_stage->changed);
    const auto staged_detection = detect_runtime_harnesses({staged_directory});
    REQUIRE(staged_detection.front().runtime_id == "codex");
    REQUIRE(staged_detection.front().available);
    REQUIRE(staged_detection.front().resolved_executable == std::filesystem::canonical(codex));

    runtime_policy_generation_options options{
        .runtime_id = "codex",
        .runtime_template_id = "codex-safe",
        .backend = glove::supervisor::sandbox_backend::linux_production,
        .executable_path = {},
        .executable_search_paths = {harness_bin},
        .arguments = {"--version"},
        .environment = {"TERM=xterm-256color", "PATH=/usr/bin:/bin"},
        .read_only_paths = {dependencies},
        .allowed_path_aliases = {"workspace"},
        .allowed_projection_destinations = {"libraries"},
    };
    auto generated = generate_runtime_policy(options);
    if (!generated) {
        std::fprintf(stderr, "generation failed: %s\n", generated.error().c_str());
    }
    REQUIRE(generated.has_value());
    REQUIRE(generated->resolved_executable == std::filesystem::canonical(codex));
    REQUIRE(generated->adapter_command_digest.size() == 64U);
    REQUIRE(
        generated->policy_template_json.find("\"runtime_discovery\":\"codex\"") != std::string::npos
    );
    REQUIRE(
        generated->policy_template_json.find(
            "\"environment\":[\"PATH=/usr/bin:/bin\",\"TERM=xterm-256color\"]"
        ) != std::string::npos
    );

    auto pinned_options = options;
    pinned_options.executable_path = codex;
    pinned_options.executable_search_paths.clear();
    auto pinned = generate_runtime_policy(pinned_options);
    REQUIRE(pinned.has_value());
    REQUIRE(pinned->policy_template_json.find("\"runtime_discovery\":\"\"") != std::string::npos);
    REQUIRE(
        pinned->policy_template_json.find(
            "\"executable_path\":\"" + std::filesystem::canonical(codex).string() + "\""
        ) != std::string::npos
    );
    auto conflicting_options = pinned_options;
    conflicting_options.executable_search_paths = {harness_bin};
    auto conflicting = generate_runtime_policy(conflicting_options);
    REQUIRE(!conflicting.has_value());
    REQUIRE(conflicting.error().find("mutually exclusive") != std::string::npos);

    auto runtime_fragment = generated->policy_template_json;
    REQUIRE(!runtime_fragment.empty() && runtime_fragment.back() == '\n');
    runtime_fragment.pop_back();
    const std::string policy =
        R"({"schema_version":1,"revision":1,"max_plan_ttl_ms":120000,"runtime_templates":[)" +
        runtime_fragment + R"(],"path_aliases":[{"alias":"workspace","host_path":")" +
        std::filesystem::canonical(workspace).string() +
        R"(","target_path":"/workspace","max_ttl_secs":120,"access":[{"access":"ephemeral_write","materialization":"copy","create_policy":"empty_directory","cleanup_policy":"remove","max_bytes":2097152}]}],"library_projection_destinations":[{"alias":"libraries","target_path":"/opt/sage/library-bundles"}],"resource_profiles":[{"profile_id":"small","cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576}],"egress_policy_ids":["no-network"],"tool_policy_ids":["sage-readonly"],"secret_handles":[]})";
    const auto policy_path = temporary.root() / "session-policy.json";
    REQUIRE(write_owner_file(policy_path, policy, 0600));
    auto valid = validate_session_policy_file(std::filesystem::canonical(policy_path));
    if (!valid) {
        std::fprintf(stderr, "validation failed: %s\n", valid.error().c_str());
    }
    REQUIRE(valid.has_value());

    auto mismatched = policy;
    const auto digest_offset = mismatched.find(generated->adapter_command_digest);
    REQUIRE(digest_offset != std::string::npos);
    mismatched.replace(digest_offset, generated->adapter_command_digest.size(), 64U, 'a');
    const auto invalid_path = temporary.root() / "invalid-policy.json";
    REQUIRE(write_owner_file(invalid_path, mismatched, 0600));
    auto invalid = validate_session_policy_file(std::filesystem::canonical(invalid_path));
    REQUIRE(!invalid.has_value());
    REQUIRE(invalid.error().find("runtime_templates[0]") != std::string::npos);
    REQUIRE(invalid.error().find("adapter_command_digest mismatch") != std::string::npos);

    auto unsupported = options;
    unsupported.runtime_id = "unknown";
    auto unsupported_result = generate_runtime_policy(unsupported);
    REQUIRE(!unsupported_result.has_value());
    REQUIRE(unsupported_result.error().find("unsupported runtime adapter") != std::string::npos);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
