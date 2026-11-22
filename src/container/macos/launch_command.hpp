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
    // The tag every deny rule of arguments[2] carries; not a secret from the
    // launched process.
    std::string denial_tag;
};

// Owns no process or descriptors. Reuses the backend's policy and program
// resolution before the owned passthrough installs checked spawn state.
// `stdio_files` are paths of regular files the child inherits as stdio; each
// gets a metadata-only grant, because runtimes stat their stdio.
auto prepare_launch_command(
    const profile& prof,
    const std::vector<std::string>& argv,
    bool terminal_stdio = false,
    const std::vector<std::string>& stdio_files = {}
) -> std::expected<launch_command, std::string>;

// exec_contained_owned with the `stdio_files` grant above. For launches whose
// stdio the operator redirected to a file.
[[nodiscard]] auto exec_owned_with_stdio_files(
    const profile& prof, const std::vector<std::string>& argv, std::vector<std::string> stdio_files
) -> std::expected<int, std::string>;

} // namespace glove::container::macos_detail
