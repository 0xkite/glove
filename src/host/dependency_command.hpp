#pragma once

#include <chrono>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace glove::host::detail {

// For explicitly approved owner-local dependency tooling, never guest requests.
// Owns a fresh process group and its sole child wait. Execution and stdout share
// one absolute deadline (1 ms to 30 s); stdout is capped at 1 MiB. Ordinary group
// members are killed before the leader is reaped, even on successful exit.
// This does not contain tooling or terminate descendants that detach themselves.
[[nodiscard]] auto capture_dependency_command(
    const std::filesystem::path& executable,
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout = std::chrono::seconds{15}
) -> std::expected<std::string, std::string>;

} // namespace glove::host::detail
