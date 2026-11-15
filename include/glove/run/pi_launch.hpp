#pragma once

#include "glove/run/pi_selection.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <stop_token>
#include <string>

namespace glove::run {

// Native API-key Pi only. No executable, environment, capability, endpoint,
// config-byte or session-import overrides. Forwarded arguments are closed by
// select_pi_launch; the operator's protected runtime supplies launch authority.
struct pi_launch_request {
    pi_launch_options selection;
    // Missing means the current directory, not an imported/trusted project.
    // The adapter reserves an absent case-aware .pi entry before startup.
    std::optional<std::filesystem::path> workspace;
};

// Uses the host's protected Glove directories. Never performs setup/refresh or
// dependency discovery implicitly. Unsupported backends fail closed.
[[nodiscard]] auto launch_pi(const pi_launch_request& request, std::stop_token stop = {})
    -> std::expected<int, std::string>;

} // namespace glove::run
