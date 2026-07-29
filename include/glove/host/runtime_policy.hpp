#pragma once

#include "glove/host/config.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace glove::host {

struct runtime_policy_generation_options {
    std::string runtime_id;
    std::string runtime_template_id;
    supervisor::sandbox_backend backend = supervisor::sandbox_backend::macos_experimental;
    std::filesystem::path executable_path;
    std::vector<std::filesystem::path> executable_search_paths;
    std::vector<std::string> arguments;
    std::vector<std::string> environment;
    std::vector<std::filesystem::path> read_only_paths;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
};

struct generated_runtime_policy {
    std::string runtime_id;
    std::string runtime_template_id;
    std::string executable_name;
    std::filesystem::path resolved_executable;
    std::string adapter_command_digest;
    std::string policy_template_json;
};

struct detected_runtime_harness {
    std::string runtime_id;
    std::string executable_name;
    bool available = false;
    std::filesystem::path resolved_executable;
    std::string diagnostic;
};

struct runtime_harness_stage_options {
    std::string runtime_id;
    std::filesystem::path source_executable;
    std::filesystem::path protected_directory;
    bool dry_run = false;
};

struct staged_runtime_harness {
    std::string runtime_id;
    std::string executable_name;
    std::filesystem::path source_executable;
    std::filesystem::path protected_entry_point;
    // Canonical launch closure derived locally from the staged entry point.
    // Script harnesses launch their pinned interpreter with source_executable
    // as the first argument; native harnesses launch source_executable
    // directly. These paths never include an operator credential/config home.
    std::filesystem::path launch_executable;
    std::vector<std::string> launch_arguments;
    std::vector<std::filesystem::path> read_only_paths;
    bool changed = false;
};

// Detect only through explicit operator-supplied directories. The inherited
// process PATH is never consulted and no credential/config home is inspected.
[[nodiscard]] auto
detect_runtime_harnesses(const std::vector<std::filesystem::path>& executable_search_paths)
    -> std::vector<detected_runtime_harness>;

// Create an adapter-named symlink inside an owner-controlled directory. The
// source is canonicalized first, existing entries are never overwritten, and
// the completed result must pass the same trusted-root resolver used at launch.
[[nodiscard]] auto stage_runtime_harness(const runtime_harness_stage_options& options)
    -> result<staged_runtime_harness>;

// Emit one strict session-policy runtime_templates[] entry. The generator
// canonicalizes local paths, resolves the adapter executable through the same
// enforcement code used at launch, and calculates the canonical digest.
[[nodiscard]] auto generate_runtime_policy(const runtime_policy_generation_options& options)
    -> result<generated_runtime_policy>;

// Strictly load a protected owner-only policy through the production
// session-plan validator. Success means schema and local policy invariants are
// valid; it does not start or advertise the service.
[[nodiscard]] auto validate_session_policy_file(const std::filesystem::path& path) -> result<void>;

} // namespace glove::host
