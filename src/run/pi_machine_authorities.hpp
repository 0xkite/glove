#pragma once

#include "glove/host/config.hpp"

#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace glove::run::detail {

// Additional deny-only source policy, borrowed by synchronous host operations.
// Directory authorities stay included even when optional configuration is absent.
auto pi_source_authorities(
    const host::directories& directories, std::span<const std::filesystem::path> additional
) -> std::expected<std::vector<std::filesystem::path>, std::string>;

// Decode only descriptor-admitted optional control bytes; never reopen config.
auto load_pi_machine_authorities(const host::directories& directories)
    -> std::expected<std::vector<std::filesystem::path>, std::string>;

} // namespace glove::run::detail
