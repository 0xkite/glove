#pragma once

#include <algorithm>
#include <cstddef>
#include <string_view>

namespace glove::control::detail {

// Same bounded identifier grammar the session registry enforces for durable
// channel and schema identifiers: non-empty, at most 128 bytes, restricted to
// [A-Za-z0-9_-.:]. Internal-only: shared by guest_channel, the session
// registry implementation, and the observation intent unix server.
inline auto valid_identifier(std::string_view value) noexcept -> bool {
    constexpr std::size_t max_identifier_bytes = 128U;
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

// Same lowercase 64-hex digest commitment grammar (SHA-256 sized) the session
// registry enforces for durable request/intent commitments.
inline auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

} // namespace glove::control::detail
