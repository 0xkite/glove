#pragma once

#include "glove/container/profile.hpp"

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace glove::container::macos_detail {

struct launch_command {
    std::vector<std::string> arguments;
    std::vector<std::string> environment;
    std::optional<std::string> start_directory;
};

// Owns no process or descriptors. Reuses the backend's policy and program
// resolution before the owned passthrough installs checked spawn state.
auto prepare_launch_command(
    const profile& prof, const std::vector<std::string>& argv, bool terminal_stdio = false
) -> std::expected<launch_command, std::string>;

} // namespace glove::container::macos_detail
