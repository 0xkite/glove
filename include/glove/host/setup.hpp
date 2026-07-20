#pragma once

#include "glove/host/config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace glove::host {

struct setup_options {
    std::optional<std::filesystem::path> config_path;
    std::optional<std::filesystem::path> protected_root;
    std::optional<std::filesystem::path> session_policy;
    std::string root_id = "projects";
    std::vector<std::string> runtime_template_ids = {"codex-safe", "pi-safe"};
    bool dry_run = false;
};

struct setup_plan {
    config service;
    std::filesystem::path config_path;
    std::optional<std::filesystem::path> canonical_protected_root;
    std::string root_id;
    std::vector<std::string> runtime_template_ids;
    bool dry_run = false;
};

[[nodiscard]] auto plan_setup(const setup_options& options, const environment& values)
    -> result<setup_plan>;
[[nodiscard]] auto execute_setup(const setup_plan& plan) -> result<void>;

} // namespace glove::host
