#pragma once

#include "glove/net/egress_proxy.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::net::detail {

inline auto lower_ascii(std::string value) -> std::string {
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return value;
}

inline auto iequals_ascii(std::string_view left, std::string_view right) noexcept -> bool {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t i = 0; i < left.size(); ++i) {
        const auto a = static_cast<unsigned char>(left[i]);
        const auto b = static_cast<unsigned char>(right[i]);
        if (std::tolower(a) != std::tolower(b)) {
            return false;
        }
    }
    return true;
}

inline auto normalise_host(std::string host) -> std::expected<std::string, std::string> {
    host = lower_ascii(std::move(host));
    while (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    const std::size_t start = !host.empty() && host.front() == '.' ? 1 : 0;
    if (start == host.size() || host.find_first_of("/@?#[]\\", start) != std::string::npos ||
        host.find("..", start) != std::string::npos) {
        return std::unexpected(std::string{"invalid egress host: '"} + host + "'");
    }
    for (std::size_t i = start; i < host.size(); ++i) {
        const auto c = static_cast<unsigned char>(host[i]);
        if (!(std::isalnum(c) || host[i] == '-' || host[i] == '.' || host[i] == ':')) {
            return std::unexpected(std::string{"invalid egress host: '"} + host + "'");
        }
    }
    return host;
}

inline auto host_matches(std::string_view allowed, std::string_view host) noexcept -> bool {
    if (allowed.starts_with('.')) {
        allowed.remove_prefix(1);
        return host == allowed || (host.size() > allowed.size() && host.ends_with(allowed) &&
                                   host[host.size() - allowed.size() - 1] == '.');
    }
    return host == allowed;
}

inline auto matching_rule(
    const std::vector<egress_rule>& allow, std::string_view host, std::uint16_t port
) noexcept -> const egress_rule* {
    for (const auto& rule : allow) {
        if (rule.port == port && host_matches(rule.host, host)) {
            return &rule;
        }
    }
    return nullptr;
}

inline auto parse_connect(std::string_view request, std::string& host, std::uint16_t& port)
    -> bool {
    const auto eol = request.find("\r\n");
    std::string_view line = request.substr(0, eol);
    constexpr std::string_view verb = "CONNECT ";
    if (!line.starts_with(verb)) {
        return false;
    }
    line.remove_prefix(verb.size());
    const auto space = line.find(' ');
    if (space == std::string_view::npos) {
        return false;
    }
    const std::string_view authority = line.substr(0, space);
    std::string_view port_text;
    std::string raw_host;
    if (authority.starts_with('[')) {
        const auto bracket = authority.find(']');
        if (bracket == std::string_view::npos || bracket + 1 >= authority.size() ||
            authority[bracket + 1] != ':') {
            return false;
        }
        raw_host = std::string{authority.substr(1, bracket - 1)};
        port_text = authority.substr(bracket + 2);
    } else {
        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) {
            return false;
        }
        raw_host = std::string{authority.substr(0, colon)};
        port_text = authority.substr(colon + 1);
    }
    unsigned parsed = 0;
    if (raw_host.empty() || port_text.empty()) {
        return false;
    }
    for (const char c : port_text) {
        if (c < '0' || c > '9') {
            return false;
        }
        parsed = parsed * 10U + static_cast<unsigned>(c - '0');
        if (parsed > 65535U) {
            return false;
        }
    }
    port = static_cast<std::uint16_t>(parsed);
    auto normal = normalise_host(std::move(raw_host));
    if (!normal || port == 0) {
        return false;
    }
    host = std::move(*normal);
    return true;
}

inline auto constant_time_equal(std::string_view provided, std::string_view expected) noexcept
    -> bool {
    unsigned difference = static_cast<unsigned>(provided.size() ^ expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const unsigned provided_byte =
            index < provided.size() ? static_cast<unsigned char>(provided[index]) : 0U;
        difference |= (provided_byte ^ static_cast<unsigned char>(expected[index]));
    }
    return difference == 0U;
}

inline auto authenticated(std::string_view request, std::string_view expected) noexcept -> bool {
    const auto request_line_end = request.find("\r\n");
    if (request_line_end == std::string_view::npos) {
        return false;
    }
    auto cursor = request_line_end + 2U;
    while (cursor < request.size()) {
        const auto end = request.find("\r\n", cursor);
        if (end == cursor || end == std::string_view::npos) {
            break;
        }
        const auto line = request.substr(cursor, end - cursor);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos &&
            iequals_ascii(line.substr(0, colon), "proxy-authorization")) {
            auto value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            return constant_time_equal(value, expected);
        }
        cursor = end + 2;
    }
    return false;
}

} // namespace glove::net::detail
