#pragma once

#include "config.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {

struct remote_ssh_artifacts {
    std::filesystem::path config_path;
    std::filesystem::path known_hosts_path;
    std::vector<std::string> argv;

    auto operator==(const remote_ssh_artifacts&) const -> bool = default;
};

[[nodiscard]] auto openssh_host_key_fingerprint(std::string_view public_key) -> result<std::string>;

// Materialize only Glove-owned SSH client state. This performs no name
// resolution, network probe, authentication, or process launch.
[[nodiscard]] auto prepare_remote_ssh_artifacts(
    const remote_backend_config& configured, const std::filesystem::path& runtime_directory
) -> result<remote_ssh_artifacts>;

} // namespace glove::host
