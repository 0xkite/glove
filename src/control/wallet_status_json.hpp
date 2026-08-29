#pragma once

#include <string_view>

namespace glove::control {

// Performs a bounded structural JSON scan and rejects repeated decoded object
// keys before a typed decoder can apply first-key or last-key semantics.
[[nodiscard]] auto valid_wallet_status_json(std::string_view frame) noexcept -> bool;

} // namespace glove::control
