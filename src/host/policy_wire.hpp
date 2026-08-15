#pragma once

#include "glove/host/config.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace glove::host::policy_wire {

struct harness {
    std::string runtime_id;
    std::string executable_name;
    bool available = false;
    std::string resolved_executable;
    std::string diagnostic;
};

struct detection_report {
    std::uint8_t schema_version = 1;
    std::vector<std::string> search_paths;
    std::vector<harness> harnesses;
};

struct stage_report {
    std::uint8_t schema_version = 1;
    std::string runtime_id;
    std::string protected_entry_point;
    std::string source_executable;
    std::string launch_executable;
    std::vector<std::string> launch_arguments;
    std::vector<std::string> read_only_paths;
    std::string snapshot_digest;
    std::string adoption_manifest_digest;
    std::uint64_t snapshot_logical_bytes = 0;
    std::uint64_t snapshot_entries = 0;
    bool changed = false;
    bool dry_run = false;
};

struct pi_adoption_report {
    std::uint8_t schema_version = 1;
    std::string runtime_id;
    std::string manifest_digest;
    std::string snapshot_digest;
    std::vector<std::string> package_ids;
    bool changed = false;
    bool dry_run = false;
};

struct validation_report {
    std::uint8_t schema_version = 1;
    bool valid = false;
    std::string policy_path;
    std::string code;
    std::string message;
    std::string recovery;
};

struct prepared_policy_report {
    std::uint8_t schema_version = 1;
    std::string policy_path;
    std::vector<harness> detections;
    std::vector<stage_report> runtimes;
    std::string session_policy_json;
    bool changed = false;
    bool dry_run = false;
};

struct onboarding_plan_report {
    std::uint8_t schema_version = 1;
    std::string mode = "read_only";
    std::string platform;
    std::string recommended_path;
    std::string config_path;
    std::string policy_path;
    std::string protected_harness_root;
    std::string protected_project_root;
    std::vector<std::string> runtime_template_ids;
    std::vector<harness> detections;
    std::string sandbox_backend;
    bool network_denied = true;
    bool credentials_configured = false;
    bool hostile_content = false;
    std::optional<std::string> session_policy_json;
    std::vector<std::string> next_actions;
    bool writes_performed = false;
    bool inherited_host_state = false;
};

[[nodiscard]] auto encode(const detection_report& report) -> result<std::string>;
[[nodiscard]] auto encode(const stage_report& report) -> result<std::string>;
[[nodiscard]] auto encode(const pi_adoption_report& report) -> result<std::string>;
[[nodiscard]] auto encode(const validation_report& report) -> result<std::string>;
[[nodiscard]] auto encode(const prepared_policy_report& report) -> result<std::string>;
[[nodiscard]] auto encode(const onboarding_plan_report& report) -> result<std::string>;

} // namespace glove::host::policy_wire
