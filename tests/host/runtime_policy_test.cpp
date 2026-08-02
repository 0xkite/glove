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
    REQUIRE(codex_detection->resolved_executable == codex);
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
    REQUIRE(staged_detection.front().resolved_executable == staged_directory / "codex");

    const auto managed_runtime = temporary.root() / "managed-node";
    const auto managed_bin = managed_runtime / "bin";
    const auto managed_package = managed_runtime / "lib" / "node_modules" / "vendor" / "bin";
    REQUIRE(std::filesystem::create_directories(managed_bin));
    REQUIRE(std::filesystem::create_directories(managed_package));
    // Launch-trust tests must not inherit the operator's umask. These
    // directories model an owner-only managed runtime closure.
    for (const auto& directory : {
             managed_runtime,
             managed_bin,
             managed_runtime / "lib",
             managed_runtime / "lib" / "node_modules",
             managed_runtime / "lib" / "node_modules" / "vendor",
             managed_package,
         }) {
        REQUIRE(::chmod(directory.c_str(), 0700) == 0);
    }
    const auto managed_node = managed_bin / "node";
    const auto managed_script = managed_package / "codex.js";
    REQUIRE(write_owner_file(managed_node, "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(write_owner_file(managed_script, "#!/usr/bin/env node\n", 0700));
    REQUIRE(write_owner_file(managed_runtime / "empty-package-marker", "", 0600));
    const auto managed_entry = managed_bin / "codex";
    REQUIRE(::symlink("../lib/node_modules/vendor/bin/codex.js", managed_entry.c_str()) == 0);
    auto managed_stage_options = stage_options;
    managed_stage_options.source_executable = managed_entry;
    managed_stage_options.protected_directory = temporary.root() / "protected" / "managed-codex";
    managed_stage_options.dry_run = true;
    auto managed_stage = stage_runtime_harness(managed_stage_options);
    REQUIRE(managed_stage.has_value());
    if (managed_stage->launch_executable != std::filesystem::canonical(managed_node)) {
        std::fprintf(
            stderr,
            "managed interpreter mismatch: got=%s expected=%s\n",
            managed_stage->launch_executable.c_str(),
            std::filesystem::canonical(managed_node).c_str()
        );
    }
    REQUIRE(managed_stage->launch_executable == std::filesystem::canonical(managed_node));
    REQUIRE(
        managed_stage->launch_arguments ==
        std::vector<std::string>{std::filesystem::canonical(managed_script).string()}
    );
    REQUIRE(
        managed_stage->read_only_paths ==
        std::vector<std::filesystem::path>{std::filesystem::canonical(managed_runtime)}
    );

    REQUIRE(::chmod(managed_runtime.c_str(), 0770) == 0);
    auto snapshot_stage_options = managed_stage_options;
    snapshot_stage_options.protected_directory =
        temporary.root() / "protected" / "snapshotted-codex";
    auto snapshot_dry_run = stage_runtime_harness(snapshot_stage_options);
    REQUIRE(snapshot_dry_run.has_value());
    REQUIRE(snapshot_dry_run->snapshot_digest.size() == 64U);
    REQUIRE(snapshot_dry_run->snapshot_logical_bytes > 0U);
    REQUIRE(snapshot_dry_run->snapshot_entries > 3U);
    REQUIRE(
        snapshot_dry_run->launch_executable.string().find(
            "snapshots/" + snapshot_dry_run->snapshot_digest + "/payload"
        ) != std::string::npos
    );
    REQUIRE(!std::filesystem::exists(snapshot_stage_options.protected_directory));
    snapshot_stage_options.dry_run = false;
    auto snapshot_stage = stage_runtime_harness(snapshot_stage_options);
    if (!snapshot_stage) {
        std::fprintf(stderr, "snapshot staging failed: %s\n", snapshot_stage.error().c_str());
    }
    REQUIRE(snapshot_stage.has_value());
    REQUIRE(snapshot_stage->changed);
    REQUIRE(snapshot_stage->snapshot_digest == snapshot_dry_run->snapshot_digest);
    REQUIRE(snapshot_stage->launch_executable != std::filesystem::canonical(managed_node));
    REQUIRE(std::filesystem::is_regular_file(snapshot_stage->launch_executable));
    REQUIRE(
        std::filesystem::canonical(snapshot_stage->protected_entry_point) !=
        std::filesystem::canonical(managed_script)
    );
    struct stat snapshot_metadata{};
    REQUIRE(::stat(snapshot_stage->read_only_paths.front().c_str(), &snapshot_metadata) == 0);
    REQUIRE((snapshot_metadata.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0);
    struct stat snapshot_root_metadata{};
    REQUIRE(
        ::stat(
            snapshot_stage->read_only_paths.front().parent_path().c_str(), &snapshot_root_metadata
        ) == 0
    );
    REQUIRE((snapshot_root_metadata.st_mode & 0777U) == 0500U);
    auto repeated_snapshot = stage_runtime_harness(snapshot_stage_options);
    REQUIRE(repeated_snapshot.has_value());
    REQUIRE(!repeated_snapshot->changed);
    const auto old_snapshot_target =
        std::filesystem::canonical(snapshot_stage->protected_entry_point);
    {
        std::ofstream changed_marker{managed_runtime / "empty-package-marker"};
        changed_marker << "v2\n";
        REQUIRE(changed_marker.good());
    }
    auto upgraded_snapshot = stage_runtime_harness(snapshot_stage_options);
    REQUIRE(upgraded_snapshot.has_value());
    REQUIRE(upgraded_snapshot->changed);
    REQUIRE(upgraded_snapshot->snapshot_digest != snapshot_stage->snapshot_digest);
    REQUIRE(
        std::filesystem::canonical(upgraded_snapshot->protected_entry_point) != old_snapshot_target
    );
    auto repeated_upgrade = stage_runtime_harness(snapshot_stage_options);
    REQUIRE(repeated_upgrade.has_value());
    REQUIRE(!repeated_upgrade->changed);

    const auto split_runtime = temporary.root() / "split-runtime";
    const auto split_package = temporary.root() / "split-package";
    REQUIRE(std::filesystem::create_directory(split_runtime));
    REQUIRE(std::filesystem::create_directories(split_package / "bin"));
    const auto split_interpreter = split_runtime / "node";
    const auto split_entry = split_package / "bin" / "codex";
    REQUIRE(write_owner_file(split_interpreter, "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(write_owner_file(split_package / "package.json", "{}\n", 0600));
    REQUIRE(write_owner_file(split_entry, "#!" + split_interpreter.string() + "\n", 0700));
    REQUIRE(::chmod(split_runtime.c_str(), 0770) == 0);
    auto split_stage_options = stage_options;
    split_stage_options.source_executable = split_entry;
    split_stage_options.protected_directory =
        temporary.root() / "protected" / "split-runtime-codex";
    split_stage_options.dry_run = false;
    auto split_stage = stage_runtime_harness(split_stage_options);
    if (!split_stage) {
        std::fprintf(stderr, "split-root snapshot failed: %s\n", split_stage.error().c_str());
    }
    REQUIRE(split_stage.has_value());
    REQUIRE(split_stage->snapshot_digest.size() == 64U);
    REQUIRE(split_stage->launch_executable != std::filesystem::canonical(split_interpreter));
    REQUIRE(std::filesystem::is_regular_file(split_stage->launch_executable));
    REQUIRE(split_stage->launch_arguments.size() == 1U);
    REQUIRE(std::filesystem::is_regular_file(split_stage->launch_arguments.front()));
    REQUIRE(split_stage->read_only_paths.size() == 1U);
    REQUIRE(split_stage->launch_executable.string().starts_with(
        split_stage->read_only_paths.front().string()
    ));
    REQUIRE(split_stage->launch_arguments.front().starts_with(
        split_stage->read_only_paths.front().string()
    ));

    // Pi adoption must treat the explicitly selected package-manager closure
    // as discovery input only: even an otherwise owner-trusted source is
    // snapshotted, and a nearby host Pi home never becomes launch authority.
    const auto pi_runtime = temporary.root() / "pi-runtime";
    const auto pi_package = pi_runtime / "lib" / "node_modules" / "@pi" / "agent";
    const auto host_pi_home = temporary.root() / "host-pi-home";
    REQUIRE(std::filesystem::create_directories(pi_package / "bin"));
    REQUIRE(std::filesystem::create_directories(host_pi_home / "agent" / "sessions"));
    REQUIRE(write_owner_file(pi_package / "bin" / "node", "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(write_owner_file(pi_package / "package.json", "{}\n", 0600));
    REQUIRE(write_owner_file(pi_package / "bin" / "pi", "#!/usr/bin/env node\n", 0700));
    REQUIRE(
        write_owner_file(host_pi_home / "agent" / "auth.json", R"({\"token\":\"host-only\"})", 0600)
    );
    REQUIRE(write_owner_file(
        host_pi_home / "agent" / "settings.json", R"({\"packages\":[\"host-extension\"]})", 0600
    ));
    REQUIRE(write_owner_file(host_pi_home / "agent" / "sessions" / "active.json", "{}\n", 0600));
    const auto pi_entry = pi_package / "bin" / "pi";
    auto pi_stage_options = stage_options;
    pi_stage_options.runtime_id = "pi";
    pi_stage_options.source_executable = pi_entry;
    pi_stage_options.protected_directory = temporary.root() / "protected" / "pi";
    pi_stage_options.dry_run = true;
    auto pi_dry_stage = stage_runtime_harness(pi_stage_options);
    if (!pi_dry_stage) {
        std::fprintf(stderr, "Pi dry staging failed: %s\n", pi_dry_stage.error().c_str());
    }
    REQUIRE(pi_dry_stage.has_value());
    REQUIRE(pi_dry_stage->snapshot_digest.size() == 64U);
    REQUIRE(pi_dry_stage->adoption_manifest_digest.size() == 64U);
    REQUIRE(pi_dry_stage->launch_executable.string().find("snapshots/") != std::string::npos);
    REQUIRE(pi_dry_stage->read_only_paths.size() == 1U);
    REQUIRE(
        pi_dry_stage->read_only_paths.front().string().find(host_pi_home.string()) ==
        std::string::npos
    );
    REQUIRE(!std::filesystem::exists(pi_stage_options.protected_directory));
    pi_stage_options.dry_run = false;
    auto pi_stage = stage_runtime_harness(pi_stage_options);
    REQUIRE(pi_stage.has_value());
    REQUIRE(pi_stage->snapshot_digest == pi_dry_stage->snapshot_digest);
    REQUIRE(pi_stage->adoption_manifest_digest == pi_dry_stage->adoption_manifest_digest);
    REQUIRE(
        std::filesystem::canonical(pi_stage->protected_entry_point) !=
        std::filesystem::canonical(pi_package / "bin" / "pi")
    );
    REQUIRE(
        !std::filesystem::exists(pi_stage->read_only_paths.front() / "host-pi-home/agent/auth.json")
    );

    // Explicit Pi configuration is discovery input only. The generated
    // sandbox settings retain only selected package closures at private-home
    // relative paths; host auth/settings/sessions never enter the manifest.
    const auto pi_settings = host_pi_home / "agent" / "adoption-settings.json";
    const auto pi_store = temporary.root() / "pi-package-store";
    const auto pi_extension = pi_store / "example-extension";
    const auto pi_dependency = pi_store / "dependency-extension";
    REQUIRE(std::filesystem::create_directories(pi_extension));
    REQUIRE(std::filesystem::create_directories(pi_dependency));
    REQUIRE(write_owner_file(pi_settings, R"({"packages":["npm:example-extension"]})", 0600));
    REQUIRE(write_owner_file(
        pi_extension / "package.json",
        R"({"name":"example-extension","dependencies":{"dependency-extension":"1.0.0"}})",
        0600
    ));
    REQUIRE(write_owner_file(pi_extension / "index.js", "export default {};\n", 0600));
    REQUIRE(
        write_owner_file(pi_dependency / "package.json", R"({"name":"dependency-extension"})", 0600)
    );
    REQUIRE(write_owner_file(pi_dependency / "index.js", "export default {};\n", 0600));
    pi_adoption_manifest_options pi_manifest_options{
        .settings_path = pi_settings,
        .package_store_root = pi_store,
        .protected_directory = temporary.root() / "protected" / "pi-manifest",
        .dry_run = true,
    };
    auto pi_manifest = generate_pi_adoption_manifest(pi_manifest_options);
    if (!pi_manifest) {
        std::fprintf(stderr, "Pi manifest generation failed: %s\n", pi_manifest.error().c_str());
    }
    REQUIRE(pi_manifest.has_value());
    REQUIRE(pi_manifest->manifest_digest.size() == 64U);
    REQUIRE(pi_manifest->snapshot_digest.size() == 64U);
    const std::vector<std::string> expected_pi_packages{
        "dependency-extension", "example-extension"
    };
    REQUIRE(pi_manifest->package_ids == expected_pi_packages);
    REQUIRE(pi_manifest->generated_settings_json.find("./extensions/0") != std::string::npos);
    REQUIRE(pi_manifest->generated_settings_json.find("host-only") == std::string::npos);
    REQUIRE(!std::filesystem::exists(pi_manifest_options.protected_directory));
    pi_manifest_options.dry_run = false;
    auto applied_pi_manifest = generate_pi_adoption_manifest(pi_manifest_options);
    if (!applied_pi_manifest) {
        std::fprintf(stderr, "Apply Pi manifest failed: %s\n", applied_pi_manifest.error().c_str());
    }
    REQUIRE(applied_pi_manifest.has_value());
    REQUIRE(applied_pi_manifest->changed);
    REQUIRE(applied_pi_manifest->manifest_digest == pi_manifest->manifest_digest);
    REQUIRE(std::filesystem::is_directory(applied_pi_manifest->snapshot_root / "payload"));
    REQUIRE(std::filesystem::is_regular_file(applied_pi_manifest->manifest_path));
    struct stat pi_manifest_metadata{};
    REQUIRE(::lstat(applied_pi_manifest->manifest_path.c_str(), &pi_manifest_metadata) == 0);
    REQUIRE((static_cast<unsigned int>(pi_manifest_metadata.st_mode) & 0777U) == 0600U);
    struct stat pi_snapshot_metadata{};
    REQUIRE(
        ::stat((applied_pi_manifest->snapshot_root / "payload").c_str(), &pi_snapshot_metadata) == 0
    );
    REQUIRE((pi_snapshot_metadata.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0);
    auto repeated_pi_manifest = generate_pi_adoption_manifest(pi_manifest_options);
    REQUIRE(repeated_pi_manifest.has_value());
    REQUIRE(!repeated_pi_manifest->changed);

    const auto missing_interpreter = managed_package / "missing.js";
    REQUIRE(write_owner_file(missing_interpreter, "#!/usr/bin/env missing-runtime\n", 0700));
    managed_stage_options.source_executable = missing_interpreter;
    REQUIRE(!stage_runtime_harness(managed_stage_options).has_value());

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

    auto impossible_ttl = policy;
    const auto ttl_offset = impossible_ttl.find("\"max_plan_ttl_ms\":120000");
    REQUIRE(ttl_offset != std::string::npos);
    impossible_ttl.replace(
        ttl_offset,
        std::string_view{"\"max_plan_ttl_ms\":120000"}.size(),
        "\"max_plan_ttl_ms\":2000"
    );
    const auto impossible_ttl_path = temporary.root() / "impossible-ttl-policy.json";
    REQUIRE(write_owner_file(impossible_ttl_path, impossible_ttl, 0600));
    auto impossible_ttl_result =
        validate_session_policy_file(std::filesystem::canonical(impossible_ttl_path));
    REQUIRE(!impossible_ttl_result.has_value());
    REQUIRE(impossible_ttl_result.error().find("TTL must outlive") != std::string::npos);

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

    const auto prepared_harness_root = temporary.root() / "prepared-harnesses";
    const auto prepared_policy_path = temporary.root() / "policy" / "session-policy.json";
    session_policy_prepare_options prepare_options{
        .executable_search_paths = {harness_bin},
        .protected_harness_root = prepared_harness_root,
        .workspace_root = workspace,
        .policy_path = prepared_policy_path,
        .backend = glove::supervisor::sandbox_backend::linux_production,
        .egress_policies = {},
        .secret_mounts = {},
        .selected_runtime_ids = {},
        .hostile_content_analysis = false,
        .dry_run = true,
    };
    auto prepared_dry_run = prepare_session_policy(prepare_options);
    if (!prepared_dry_run) {
        std::fprintf(
            stderr, "policy preparation dry run failed: %s\n", prepared_dry_run.error().c_str()
        );
    }
    REQUIRE(prepared_dry_run.has_value());
    REQUIRE(prepared_dry_run->dry_run);
    REQUIRE(prepared_dry_run->changed);
    REQUIRE(prepared_dry_run->runtimes.size() == 1U);
    REQUIRE(prepared_dry_run->runtimes.front().runtime_id == "codex");
    REQUIRE(
        prepared_dry_run->policy_json.find("\"egress_policy_ids\":[\"no-network\"]") !=
        std::string::npos
    );
    REQUIRE(prepared_dry_run->policy_json.find("\"max_plan_ttl_ms\":600000") != std::string::npos);
    REQUIRE(!std::filesystem::exists(prepared_harness_root));
    REQUIRE(!std::filesystem::exists(prepared_policy_path));

    auto hostile_options = prepare_options;
    hostile_options.hostile_content_analysis = true;
    auto prepared_hostile = prepare_session_policy(hostile_options);
    REQUIRE(prepared_hostile.has_value());
    REQUIRE(
        prepared_hostile->policy_json.find("\"runtime_template_id\":\"codex-hostile-analysis\"") !=
        std::string::npos
    );
    REQUIRE(
        prepared_hostile->policy_json.find("\"egress_policy_ids\":[\"no-network\"]") !=
        std::string::npos
    );
    REQUIRE(prepared_hostile->policy_json.find("\"access\":\"read\"") == std::string::npos);
    REQUIRE(
        prepared_hostile->policy_json.find("\"access\":\"retained_write\"") == std::string::npos
    );
    REQUIRE(
        prepared_hostile->policy_json.find(
            R"("profile_id":"hostile-analysis","cpu_time_ms":30000,"memory_bytes":536870912,"pids":64,"wall_time_ms":60000,"disk_bytes":134217728,"terminal_output_bytes":1048576)"
        ) != std::string::npos
    );
    auto hostile_apple = hostile_options;
    hostile_apple.backend = glove::supervisor::sandbox_backend::apple_container;
    REQUIRE(!prepare_session_policy(hostile_apple).has_value());

    const auto pi_harness_bin = temporary.root() / "pi-harness-bin";
    REQUIRE(std::filesystem::create_directory(pi_harness_bin));
    REQUIRE(::chmod(pi_harness_bin.c_str(), 0700) == 0);
    std::error_code pi_harness_error;
    std::filesystem::create_symlink(pi_entry, pi_harness_bin / "pi", pi_harness_error);
    REQUIRE(!pi_harness_error);
    std::filesystem::create_symlink(
        pi_package / "bin" / "node", pi_harness_bin / "node", pi_harness_error
    );
    REQUIRE(!pi_harness_error);
    auto pi_prepare_options = prepare_options;
    pi_prepare_options.executable_search_paths = {pi_harness_bin};
    pi_prepare_options.protected_harness_root = temporary.root() / "prepared-pi-harnesses";
    pi_prepare_options.policy_path = temporary.root() / "policy" / "pi-session-policy.json";
    pi_prepare_options.selected_runtime_ids = {"pi"};
    pi_prepare_options.pi_adoption = pi_manifest_options;
    pi_prepare_options.dry_run = true;
    auto prepared_pi = prepare_session_policy(pi_prepare_options);
    if (!prepared_pi) {
        std::fprintf(stderr, "Pi policy preparation failed: %s\n", prepared_pi.error().c_str());
    }
    REQUIRE(prepared_pi.has_value());
    REQUIRE(
        prepared_pi->policy_json.find(
            "\"manifest_digest\":\"" + pi_manifest->manifest_digest + "\""
        ) != std::string::npos
    );
    REQUIRE(
        prepared_pi->policy_json.find(
            "\"snapshot_digest\":\"" + pi_manifest->snapshot_digest + "\""
        ) != std::string::npos
    );
    REQUIRE(prepared_pi->policy_json.find(host_pi_home.string()) == std::string::npos);
    REQUIRE(prepared_pi->policy_json.find("host-only") == std::string::npos);
    pi_prepare_options.dry_run = false;
    auto applied_pi_policy = prepare_session_policy(pi_prepare_options);
    REQUIRE(applied_pi_policy.has_value());
    REQUIRE(std::filesystem::is_regular_file(pi_prepare_options.policy_path));
    REQUIRE(
        validate_session_policy_file(std::filesystem::canonical(pi_prepare_options.policy_path))
    );
    auto missing_pi_adoption = pi_prepare_options;
    missing_pi_adoption.pi_adoption.reset();
    REQUIRE(!prepare_session_policy(missing_pi_adoption).has_value());
    auto unused_pi_adoption = prepare_options;
    unused_pi_adoption.pi_adoption = pi_manifest_options;
    REQUIRE(!prepare_session_policy(unused_pi_adoption).has_value());

    const auto codex_auth = temporary.root() / "codex-auth.json";
    REQUIRE(write_owner_file(codex_auth, R"({"token":"test-only"})", 0600));
    auto online_options = prepare_options;
    online_options.egress_policies = {{
        .policy_id = "openai-online",
        .targets = {
            {.host = "api.openai.com", .port = 443, .allow_private = false},
            {.host = "chatgpt.com", .port = 443, .allow_private = false},
            {.host = "auth.openai.com", .port = 443, .allow_private = false},
            {.host = "ab.chatgpt.com", .port = 443, .allow_private = false},
        },
    }};
    online_options.secret_mounts = {{
        .handle = "codex-auth",
        .runtime_id = "codex",
        .source_path = codex_auth.string(),
        .target_path = "/home/agent/.codex/auth.json",
    }};
    auto prepared_online = prepare_session_policy(online_options);
    REQUIRE(prepared_online.has_value());
    auto hostile_online = online_options;
    hostile_online.hostile_content_analysis = true;
    REQUIRE(!prepare_session_policy(hostile_online).has_value());
    REQUIRE(
        prepared_online->policy_json.find(
            "\"egress_policy_ids\":[\"no-network\",\"openai-online\"]"
        ) != std::string::npos
    );
    REQUIRE(prepared_online->policy_json.find("\"pids\":256") != std::string::npos);
    REQUIRE(
        prepared_online->policy_json.find(
            R"("profile_id":"interactive","cpu_time_ms":120000,"memory_bytes":1073741824,"pids":256,"wall_time_ms":300000)"
        ) != std::string::npos
    );
    REQUIRE(
        prepared_online->policy_json.find(
            R"("secret_handles":["codex-auth"],"egress_policies":[{"policy_id":"openai-online")"
        ) != std::string::npos
    );
    REQUIRE(
        prepared_online->policy_json.find(R"("target_path":"/home/agent/.codex/auth.json")") !=
        std::string::npos
    );
    REQUIRE(prepared_online->policy_json.find(R"("token":"test-only")") == std::string::npos);

    auto insecure_online_options = online_options;
    REQUIRE(::chmod(codex_auth.c_str(), 0644) == 0);
    REQUIRE(!prepare_session_policy(insecure_online_options).has_value());
    REQUIRE(::chmod(codex_auth.c_str(), 0600) == 0);

    prepare_options.dry_run = false;
    auto prepared = prepare_session_policy(prepare_options);
    if (!prepared) {
        std::fprintf(stderr, "policy preparation failed: %s\n", prepared.error().c_str());
    }
    REQUIRE(prepared.has_value());
    REQUIRE(prepared->changed);
    REQUIRE(std::filesystem::is_symlink(prepared_harness_root / "codex" / "codex"));
    REQUIRE(validate_session_policy_file(prepared_policy_path).has_value());
    struct stat prepared_policy_metadata{};
    REQUIRE(::lstat(prepared_policy_path.c_str(), &prepared_policy_metadata) == 0);
    REQUIRE((static_cast<unsigned int>(prepared_policy_metadata.st_mode) & 0777U) == 0600U);
    auto repeated_preparation = prepare_session_policy(prepare_options);
    REQUIRE(repeated_preparation.has_value());
    REQUIRE(!repeated_preparation->changed);

    auto revised_options = prepare_options;
    revised_options.egress_policies = {{
        .policy_id = "revision-test-online",
        .targets = {{.host = "example.com", .port = 443, .allow_private = false}},
    }};
    revised_options.dry_run = true;
    auto revised_dry_run = prepare_session_policy(revised_options);
    REQUIRE(revised_dry_run.has_value());
    REQUIRE(revised_dry_run->changed);
    REQUIRE(revised_dry_run->policy_json.find(R"("revision":2)") != std::string::npos);
    {
        std::ifstream unchanged_policy{prepared_policy_path};
        const std::string contents{
            std::istreambuf_iterator<char>{unchanged_policy},
            std::istreambuf_iterator<char>{},
        };
        REQUIRE(contents.find(R"("revision":1)") != std::string::npos);
    }
    revised_options.dry_run = false;
    auto revised = prepare_session_policy(revised_options);
    REQUIRE(revised.has_value());
    REQUIRE(revised->changed);
    REQUIRE(revised->policy_json.find(R"("revision":2)") != std::string::npos);
    auto repeated_revision = prepare_session_policy(revised_options);
    REQUIRE(repeated_revision.has_value());
    REQUIRE(!repeated_revision->changed);
    REQUIRE(repeated_revision->policy_json.find(R"("revision":2)") != std::string::npos);

    auto snapshotted_prepare_options = prepare_options;
    snapshotted_prepare_options.executable_search_paths = {managed_bin};
    snapshotted_prepare_options.selected_runtime_ids = {"codex"};
    snapshotted_prepare_options.protected_harness_root =
        temporary.root() / "prepared-snapshotted-harnesses";
    snapshotted_prepare_options.policy_path =
        temporary.root() / "snapshotted-policy" / "session-policy.json";
    snapshotted_prepare_options.dry_run = true;
    auto snapshotted_prepare_dry_run = prepare_session_policy(snapshotted_prepare_options);
    if (!snapshotted_prepare_dry_run) {
        std::fprintf(
            stderr,
            "snapshotted policy dry run failed: %s\n",
            snapshotted_prepare_dry_run.error().c_str()
        );
    }
    REQUIRE(snapshotted_prepare_dry_run.has_value());
    REQUIRE(snapshotted_prepare_dry_run->runtimes.size() == 1U);
    REQUIRE(snapshotted_prepare_dry_run->runtimes.front().snapshot_digest.size() == 64U);
    REQUIRE(
        snapshotted_prepare_dry_run->policy_json.find(
            snapshotted_prepare_dry_run->runtimes.front().snapshot_digest
        ) != std::string::npos
    );
    snapshotted_prepare_options.dry_run = false;
    auto snapshotted_prepare = prepare_session_policy(snapshotted_prepare_options);
    if (!snapshotted_prepare) {
        std::fprintf(
            stderr,
            "snapshotted policy preparation failed: %s\n",
            snapshotted_prepare.error().c_str()
        );
    }
    REQUIRE(snapshotted_prepare.has_value());
    REQUIRE(snapshotted_prepare->changed);
    REQUIRE(validate_session_policy_file(snapshotted_prepare_options.policy_path).has_value());
    REQUIRE(
        std::filesystem::canonical(
            snapshotted_prepare_options.protected_harness_root / "codex" / "codex"
        ) != std::filesystem::canonical(managed_script)
    );

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
