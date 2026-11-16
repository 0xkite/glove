#include "src/net/http_syntax.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

constexpr std::size_t kMaxInputBytes = 32U * 1024U;

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > kMaxInputBytes) {
        return 0;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view input{reinterpret_cast<const char*>(data), size};
    const std::size_t split = input.find(':');
    const std::string_view key = split == std::string_view::npos ? input : input.substr(0, split);
    const std::string_view val =
        split == std::string_view::npos ? std::string_view{} : input.substr(split + 1U);

    const bool token_ok = glove::net::http::is_token(key);
    const bool value_ok = glove::net::http::is_valid_field_value(val);
    const bool bare_lb = glove::net::http::has_bare_line_break(input);
    const auto trimmed = glove::net::http::trim_ows(val);
    const auto parsed_len = glove::net::http::parse_content_length(trimmed, 8U * 1024U * 1024U);
    const auto lowered = glove::net::http::lower_ascii(std::string{key});

    // Invariant: valid tokens and field values must never contain bare CR/LF.
    if (token_ok && glove::net::http::has_bare_line_break(key)) {
        __builtin_trap();
    }
    if (value_ok && glove::net::http::has_bare_line_break(val)) {
        __builtin_trap();
    }
    if (parsed_len && *parsed_len > 8U * 1024U * 1024U) {
        __builtin_trap();
    }
    if (lowered.size() != key.size()) {
        __builtin_trap();
    }
    (void)bare_lb;
    return 0;
}
