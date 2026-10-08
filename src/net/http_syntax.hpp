#pragma once

// HTTP/1.1 field syntax and size budgets shared by the credentialed endpoint
// (which parses agent requests) and the upstream client (which parses provider
// responses). Both sides must agree, or a field one accepts could be re-emitted
// by the other into a head it frames itself.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

namespace glove::net::http {

inline constexpr std::size_t max_head_bytes = 16384;
inline constexpr std::size_t max_header_count = 100;
inline constexpr std::size_t max_response_body_bytes = std::size_t{32} * 1024U * 1024U;

inline auto lower_ascii(std::string value) -> std::string {
    std::ranges::transform(value, value.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return value;
}

// RFC 7230 tchar. Header names must be tokens, or a name containing a space or
// a control character could be smuggled past a field list.
constexpr auto is_tchar(char c) noexcept -> bool {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return true;
    }
    switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return true;
    default:
        return false;
    }
}

inline auto is_token(std::string_view value) -> bool {
    return !value.empty() && std::ranges::all_of(value, [](char c) { return is_tchar(c); });
}

// Message framing is CRLF only. A bare CR or LF inside a head is either a
// smuggling primitive or an injection into the next hop, so reject it rather
// than normalising it.
inline auto has_bare_line_break(std::string_view raw) -> bool {
    for (std::size_t index = 0; index < raw.size(); ++index) {
        if (raw[index] == '\r') {
            if (index + 1 >= raw.size() || raw[index + 1] != '\n') {
                return true;
            }
            ++index;
        } else if (raw[index] == '\n') {
            return true;
        }
    }
    return false;
}

// A field value may contain visible characters, space, horizontal tab, and
// obs-text; nothing else (no CR, LF, or other control characters).
inline auto is_valid_field_value(std::string_view value) -> bool {
    return std::ranges::all_of(value, [](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return c == '\t' || (byte >= 0x20U && byte != 0x7fU);
    });
}

inline auto trim_ows(std::string_view value) -> std::string_view {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

// A Content-Length value: digits only, single-valued, and no larger than
// `cap`. Leading OWS must already be trimmed.
inline auto parse_content_length(std::string_view value, std::size_t cap)
    -> std::expected<std::size_t, std::string> {
    if (value.empty()) {
        return std::unexpected(std::string{"empty content-length"});
    }
    std::size_t length = 0;
    for (const char c : value) {
        if (c < '0' || c > '9') {
            return std::unexpected(std::string{"non-numeric content-length"});
        }
        const auto digit = static_cast<std::size_t>(c - '0');
        if (digit > cap || length > (cap - digit) / 10U) {
            return std::unexpected(std::string{"content-length out of range"});
        }
        length = length * 10U + digit;
    }
    return length;
}

} // namespace glove::net::http
