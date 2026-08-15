#pragma once

#include "glove/host/doctor.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace glove::host::doctor_wire {

struct doctor_check_wire {
    std::string code;
    std::string status;
    std::string message;
    std::string recovery;
};

struct doctor_report_wire {
    std::uint8_t schema_version = 1;
    std::string config_path;
    bool healthy = false;
    std::vector<doctor_check_wire> checks;
};

[[nodiscard]] auto encode_report(const doctor_report& report) -> result<std::string>;

} // namespace glove::host::doctor_wire
