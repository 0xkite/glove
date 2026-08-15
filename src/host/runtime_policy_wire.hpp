#pragma once

#include "glove/supervisor/harness_adoption.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace glove::host::runtime_policy_wire {

struct pi_settings_discovery {
    std::vector<std::string> packages;
};

struct pi_package_metadata {
    std::string name;
    std::map<std::string, std::string> dependencies;
};

struct runtime_template {
    std::string runtime_template_id;
    std::string runtime_id;
    std::string adapter_command_digest;
    std::string sandbox_backend;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
    supervisor::runtime_launch_template launch;
    std::optional<supervisor::native_harness_adoption_policy> adoption;
};

struct path_access {
    std::string access;
    std::string materialization;
    std::string create_policy;
    std::string cleanup_policy;
    std::uint64_t max_bytes = 0;
};

struct path_alias {
    std::string alias;
    std::string host_path;
    std::string target_path;
    std::uint64_t max_ttl_secs = 0;
    std::vector<path_access> access;
};

struct projection_destination {
    std::string alias;
    std::string target_path;
};

struct resource_profile {
    std::string profile_id;
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t memory_bytes = 0;
    std::uint64_t pids = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t terminal_output_bytes = 0;
};

struct egress_target_policy {
    std::string host;
    std::uint16_t port = 443;
    bool allow_private = false;
};

struct egress_policy {
    std::string policy_id;
    std::vector<egress_target_policy> targets;
};

struct secret_mount_policy {
    std::string handle;
    std::string runtime_id;
    std::string source_path;
    std::string target_path;
};

struct session_policy {
    std::uint8_t schema_version = 1;
    std::uint64_t revision = 1;
    // The plan lifetime includes an operator-approval window in addition to
    // the sandbox wall limit. Keep the generated policy usable without
    // weakening either bound.
    std::uint64_t max_plan_ttl_ms = 600'000;
    std::vector<runtime_template> runtime_templates;
    std::vector<path_alias> path_aliases;
    std::vector<projection_destination> library_projection_destinations;
    std::vector<resource_profile> resource_profiles;
    std::vector<std::string> egress_policy_ids = {"no-network"};
    std::vector<std::string> tool_policy_ids = {"sage-readonly"};
    std::vector<std::string> secret_handles;
    std::vector<egress_policy> egress_policies;
    std::vector<secret_mount_policy> secret_mounts;
};

} // namespace glove::host::runtime_policy_wire
