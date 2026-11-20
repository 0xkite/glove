#pragma once

#include "glove/run/secret_reference.hpp"

#include <expected>
#include <filesystem>
#include <span>
#include <string>

namespace glove::run::detail {

// The secret's value, or an error that names the reference and never the
// value. A file secret must be a regular, single-link, owner-only file
// outside every path in EXPOSED (the launch's filesystem grants), holding
// one token. Keychain secrets are available on macOS only.
[[nodiscard]] auto resolve_secret(
    const secret_reference& reference,
    const std::filesystem::path& home,
    std::span<const std::string> exposed
) -> std::expected<std::string, std::string>;

// A secret value must be one printable token: no whitespace or controls.
[[nodiscard]] auto valid_secret_value(std::string_view value) -> bool;

} // namespace glove::run::detail
