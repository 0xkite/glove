#pragma once

#include "glove/run/pi_selection.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

struct pi_guest_config {
    std::string models_json;
    std::string settings_json;
    std::vector<std::string> arguments;
    std::string base_url;
};

// Pure configuration construction, not catalog discovery or launch authority.
// Production must supply revalidated protected-snapshot catalog bytes, never an
// ambient installed catalog. The future adapter inserts its owned private
// session directory arguments before the forwarded suffix of `arguments`.
[[nodiscard]] auto make_pi_guest_config(
    const pi_launch_selection& selection,
    std::uint16_t endpoint_port,
    std::string_view nonce,
    std::string_view catalog_json
) -> std::expected<pi_guest_config, std::string>;

} // namespace glove::run::detail
