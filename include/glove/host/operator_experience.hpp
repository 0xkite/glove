#pragma once

#include "glove/host/control_client.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {

struct setup_path {
    std::string id;
    std::string goal;
    std::string isolation;
    std::string cost;
    std::string receipts;
    std::string limitation;
    std::string next_command;
    bool eligible = false;
    bool recommended = false;
};

struct setup_guidance {
    std::uint8_t schema_version = 1;
    std::string platform;
    std::string recommended_path;
    std::vector<setup_path> paths;
};

enum class project_purpose : unsigned char {
    inspect,
    experiment,
    retain,
};

struct project_purpose_defaults {
    project_access access = project_access::read;
    std::uint64_t max_bytes = 0;
    std::uint64_t ttl_secs = 3'600;
    std::string_view write_scope;
    std::string_view cleanup;
};

[[nodiscard]] auto operator_setup_guidance() -> setup_guidance;
[[nodiscard]] auto parse_project_purpose(std::string_view value) -> project_purpose;
[[nodiscard]] auto defaults_for(project_purpose purpose) -> project_purpose_defaults;
[[nodiscard]] auto project_purpose_name(project_purpose purpose) -> std::string_view;

} // namespace glove::host
