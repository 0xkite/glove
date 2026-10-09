#pragma once

#include "glove/host/config.hpp"
#include "glove/run/pi_launch.hpp"
#include "glove/run/pi_runtime.hpp"

#include <expected>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run {

auto pi_command(std::span<char* const> arguments) -> int;

namespace detail {

enum class pi_command_action { launch, setup, refresh, help };

struct pi_command_line {
    pi_command_action action = pi_command_action::launch;
    pi_launch_request request;
    bool approved = false;
};

[[nodiscard]] auto parse_pi_command_line(std::span<const std::string_view> arguments)
    -> std::expected<pi_command_line, std::string>;

// Only host policy and synthetic fixtures supply discovery/staging boundaries.
// The CLI cannot supply an executable, search path or runtime destination.
struct pi_setup_context {
    host::directories directories;
    std::function<std::vector<host::detected_runtime_harness>()> detect;
    std::function<
        host::result<host::staged_runtime_harness>(const host::runtime_harness_stage_options&)>
        stage;
};

[[nodiscard]] auto
configure_pi_runtime(const pi_command_line& command, const pi_setup_context& context)
    -> std::expected<bool, std::string>;

} // namespace detail
} // namespace glove::run
