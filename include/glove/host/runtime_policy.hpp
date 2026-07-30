#pragma once

#include "glove/host/config.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace glove::host {

struct runtime_policy_generation_options {
    std::string runtime_id;
    std::string runtime_template_id;
    supervisor::sandbox_backend backend = supervisor::sandbox_backend::apple_container;
    std::filesystem::path executable_path;
    std::vector<std::filesystem::path> executable_search_paths;
    std::vector<std::string> arguments;
    std::vector<std::string> environment;
    std::vector<std::filesystem::path> read_only_paths;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
    // Setup uses this only for content-addressed snapshot paths that have been
    // fully planned but are materialized after policy encoding.
    bool allow_planned_snapshot_paths = false;
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
    // Set when setup copied an otherwise untrusted package/interpreter tree
    // into a content-addressed owner-protected snapshot.
    std::string snapshot_digest;
    std::uint64_t snapshot_logical_bytes = 0;
    std::uint64_t snapshot_entries = 0;
    bool changed = false;
};

struct session_policy_prepare_options {
    std::vector<std::filesystem::path> executable_search_paths;
    std::filesystem::path protected_harness_root;
    std::filesystem::path workspace_root;
    std::filesystem::path policy_path;
    supervisor::sandbox_backend backend = supervisor::sandbox_backend::apple_container;
    // Advanced online enrollment remains an owner-local setup concern. Sage
    // sees only the identifiers emitted into the resulting policy.
    std::vector<supervisor::egress_policy> egress_policies;
    std::vector<supervisor::secret_mount_policy> secret_mounts;
    // Empty preserves the all-detected behavior. Otherwise only the explicit
    // adapter IDs are staged and emitted.
    std::vector<std::string> selected_runtime_ids;
    bool dry_run = false;
};

struct prepared_session_policy {
    std::filesystem::path policy_path;
    std::vector<detected_runtime_harness> detections;
    std::vector<staged_runtime_harness> runtimes;
    std::string policy_json;
    bool changed = false;
    bool dry_run = false;
};

// Detect only through explicit operator-supplied directories. The inherited
// process PATH is never consulted and no credential/config home is inspected.
[[nodiscard]] auto
detect_runtime_harnesses(const std::vector<std::filesystem::path>& executable_search_paths)
    -> std::vector<detected_runtime_harness>;

// Create an adapter-named entry inside an owner-controlled directory. A source
// that already passes launch trust is linked directly. Otherwise, a supported
// single-root interpreter/package closure is copied into a content-addressed,
// read-only snapshot and revalidated. Existing entries are never overwritten.
[[nodiscard]] auto stage_runtime_harness(const runtime_harness_stage_options& options)
    -> result<staged_runtime_harness>;

// Emit one strict session-policy runtime_templates[] entry. The generator
// canonicalizes local paths, resolves the adapter executable through the same
// enforcement code used at launch, and calculates the canonical digest.
[[nodiscard]] auto generate_runtime_policy(const runtime_policy_generation_options& options)
    -> result<generated_runtime_policy>;

// Detect all supported harnesses through explicit directories, derive each
// immutable launch closure, and emit one complete deny-network session policy.
// Applying the plan requires an explicit caller confirmation; existing policy
// files are accepted only when their protected contents match exactly.
[[nodiscard]] auto prepare_session_policy(const session_policy_prepare_options& options)
    -> result<prepared_session_policy>;

// Strictly load a protected owner-only policy through the production
// session-plan validator. Success means schema and local policy invariants are
// valid; it does not start or advertise the service.
[[nodiscard]] auto validate_session_policy_file(const std::filesystem::path& path) -> result<void>;

} // namespace glove::host
