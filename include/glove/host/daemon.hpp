#pragma once

#include "glove/host/config.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace glove::host {

enum class daemon_service_manager : unsigned char {
    systemd_user,
    launchd_user,
};

struct daemon_options {
    std::optional<std::filesystem::path> config_path{};
    std::optional<std::filesystem::path> gloved_path{};
};

struct daemon_service_plan {
    daemon_service_manager manager = daemon_service_manager::systemd_user;
    std::filesystem::path config_path{};
    std::filesystem::path gloved_path{};
    std::filesystem::path service_path{};
    std::string service_name{};
    std::string service_definition{};
    unsigned long user_id = 0;
};

[[nodiscard]] auto plan_daemon_service(const daemon_options& options, const environment& values)
    -> result<daemon_service_plan>;
[[nodiscard]] auto install_daemon_service(const daemon_service_plan& plan) -> result<void>;
[[nodiscard]] auto start_daemon_service(const daemon_service_plan& plan) -> result<void>;
[[nodiscard]] auto stop_daemon_service(const daemon_service_plan& plan) -> result<void>;
[[nodiscard]] auto restart_daemon_service(const daemon_service_plan& plan) -> result<void>;
[[nodiscard]] auto daemon_service_is_active(const daemon_service_plan& plan) -> result<bool>;

} // namespace glove::host
