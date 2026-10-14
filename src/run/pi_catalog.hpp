#pragma once

#include "glove/run/pi_runtime.hpp"

#include <expected>
#include <span>
#include <string>

namespace glove::run::detail {

// Copies only the selected provider's immutable approved-snapshot catalog.
// No discovery commands, source-package reads, or JSON/identity interpretation.
[[nodiscard]] auto load_pi_builtin_catalog(
    const pi_runtime_selection& selection,
    pi_provider provider,
    std::span<const std::filesystem::path> source_exclusions = {}
) -> std::expected<std::string, std::string>;

} // namespace glove::run::detail
