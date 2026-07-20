#pragma once

#include "glove/host/config.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace glove::host {

enum class doctor_status : unsigned char {
    passed,
    warning,
    failed,
};

struct doctor_check {
    std::string code;
    doctor_status status = doctor_status::failed;
    std::string message;
    std::string recovery;
};

struct doctor_report {
    std::filesystem::path config_path;
    std::vector<doctor_check> checks;

    [[nodiscard]] auto healthy() const -> bool;
};

[[nodiscard]] auto diagnose(const std::filesystem::path& config_path) -> doctor_report;

} // namespace glove::host
