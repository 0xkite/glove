#pragma once

#include "runtime_policy.hpp"
#include "setup.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace glove::host {

// Inputs for the read-only guided setup layer. Every harness discovery path is
// supplied by the operator; it never falls back to PATH or a host config home.
struct onboarding_plan_options {
    std::optional<std::filesystem::path> config_path;
    std::filesystem::path protected_root;
    std::vector<std::filesystem::path> executable_search_paths;
    std::vector<std::string> selected_runtime_ids;
    std::optional<pi_adoption_manifest_options> pi_adoption;
    supervisor::sandbox_backend backend = supervisor::sandbox_backend::apple_container;
    bool hostile_content_analysis = false;
};

struct onboarding_plan {
    setup_plan setup;
    std::filesystem::path protected_harness_root;
    prepared_session_policy session_policy;
};

// Plans a managed-session setup without creating configuration, snapshots, or
// policy files. The generated policy location and harness root are Glove-owned
// siblings of the selected configuration file, so later explicit apply steps
// cannot silently adopt arbitrary host paths.
[[nodiscard]] auto
plan_onboarding(const onboarding_plan_options& options, const environment& values)
    -> result<onboarding_plan>;

} // namespace glove::host
