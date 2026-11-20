#pragma once

// Per-launch tag that every generated deny rule carries as
// `(with message "<tag>")`. The kernel appends it to each denial the rule
// decides, so it marks a denial as coming from that launch's sandbox. It is
// random, not secret: processes inside the sandbox can read it.

#include <stdlib.h>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace glove::container::macos_detail {

// 16 bytes from arc4random_buf as 32 lowercase hex characters.
[[nodiscard]] inline auto make_denial_tag() -> std::string {
    constexpr std::size_t tag_random_bytes = 16;
    std::array<unsigned char, tag_random_bytes> bytes{};
    ::arc4random_buf(bytes.data(), bytes.size());
    constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char byte : bytes) {
        out.push_back(hex.at(byte >> 4U));
        out.push_back(hex.at(byte & 0x0FU));
    }
    return out;
}

} // namespace glove::container::macos_detail
