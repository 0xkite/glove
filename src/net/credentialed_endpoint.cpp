#include "glove/net/credentialed_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace glove::net {

namespace {

constexpr std::size_t max_request_headers_bytes = 16384;
constexpr std::size_t max_request_body_bytes = 8U * 1024U * 1024U;
constexpr std::size_t max_header_count = 100;
// One absolute deadline for reading a complete request head. A peer that
// trickles bytes must not hold the single worker, or shutdown, indefinitely.
constexpr int head_deadline_ms = 5000;
constexpr int poll_tick_ms = 100;

auto lower_ascii(std::string value) -> std::string {
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return value;
}

auto constant_time_equal(std::string_view provided, std::string_view expected) noexcept -> bool {
    unsigned difference = static_cast<unsigned>(provided.size() ^ expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const unsigned provided_byte =
            index < provided.size() ? static_cast<unsigned char>(provided[index]) : 0U;
        difference |= (provided_byte ^ static_cast<unsigned char>(expected[index]));
    }
    return difference == 0U;
}

auto write_all(int fd, std::string_view data) -> bool {
    const char* cursor = data.data();
    std::size_t remaining = data.size();
    while (remaining > 0) {
        const auto n = ::write(fd, cursor, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        cursor += n;
        remaining -= static_cast<std::size_t>(n);
    }
    return true;
}

// Hop-by-hop, routing, and credential fields are never forwarded. The
// transport owns Host, framing, and the credential; anything that could let a
// sandboxed agent pick a different destination, smuggle framing, or attach its
// own credential is dropped here rather than trusted downstream.
constexpr auto request_header_denylist = std::to_array<std::string_view>({
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "expect",
    "x-api-key",
    "authorization",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "via",
    "cookie",
});

constexpr auto response_header_denylist = std::to_array<std::string_view>({
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    // The endpoint sets its own Content-Length for the buffered body.
    "content-length",
});

auto in_denylist(std::span<const std::string_view> denylist, std::string_view name) -> bool {
    return std::ranges::find(denylist, name) != denylist.end();
}

auto is_forwardable_request_header(std::string_view name) -> bool {
    return !in_denylist(request_header_denylist, name);
}

auto is_forwardable_response_header(std::string_view name) -> bool {
    return !in_denylist(response_header_denylist, name);
}

// A reason phrase for the codes a provider API returns. An unknown code is sent
// with an empty reason, which is valid (RFC 7230 3.1.2).
auto reason_phrase(int status_code) -> std::string_view {
    switch (status_code) {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 409:
        return "Conflict";
    case 413:
        return "Payload Too Large";
    case 429:
        return "Too Many Requests";
    case 500:
        return "Internal Server Error";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    default:
        return "";
    }
}

struct parsed_request_head {
    std::string method;
    std::string uri;
    std::string http_version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string provided_nonce;
    std::size_t content_length = 0;
    bool has_content_length = false;
};

// RFC 3986 path/query characters, with no dot segment an upstream would
// normalise away. The target is not a header value: tab, other controls, and
// bytes >= 0x80 have no place in a path, and a path that normalises to a
// different route would defeat the path allowlist.
auto is_valid_request_target(std::string_view target) -> bool {
    if (target.empty() || target.front() != '/') {
        return false;
    }
    for (const char c : target) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte <= 0x20U || byte >= 0x7fU) {
            return false;
        }
        switch (c) {
        case '#':
        case '"':
        case '<':
        case '>':
        case '\\':
        case '{':
        case '}':
        case '^':
        case '`':
        case '|':
            return false;
        default:
            break;
        }
    }
    std::string lowered;
    lowered.reserve(target.size());
    for (const char c : target) {
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    // Reject encoded separators and dot segments: the upstream decodes and
    // normalises them, so the allowlist would be checking a different path than
    // the one that is fetched.
    if (lowered.find("%2e") != std::string::npos || lowered.find("%2f") != std::string::npos ||
        lowered.find("%5c") != std::string::npos) {
        return false;
    }
    std::size_t start = 1;
    while (start <= target.size()) {
        const auto slash = target.find('/', start);
        auto segment = target.substr(
            start, slash == std::string_view::npos ? std::string_view::npos : slash - start
        );
        if (const auto query = segment.find('?'); query != std::string_view::npos) {
            segment = segment.substr(0, query);
        }
        if (segment == "." || segment == "..") {
            return false;
        }
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
    return true;
}

// RFC 7230 tchar. Header names must be tokens, or a name containing a space or
// a control character could be smuggled past the forwarder's field list.
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

auto is_token(std::string_view value) -> bool {
    return !value.empty() && std::ranges::all_of(value, [](char c) { return is_tchar(c); });
}

// Message framing is CRLF only. A bare CR or LF inside the head is either a
// request-smuggling primitive or an injection into the upstream request, so
// reject it rather than normalising it.
auto has_bare_line_break(std::string_view raw) -> bool {
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
auto is_valid_field_value(std::string_view value) -> bool {
    return std::ranges::all_of(value, [](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return c == '\t' || (byte >= 0x20U && byte != 0x7fU);
    });
}

auto parse_http_head(std::string_view raw) -> std::expected<parsed_request_head, std::string> {
    if (has_bare_line_break(raw)) {
        return std::unexpected(std::string{"bare CR or LF in request head"});
    }
    const auto line_end = raw.find("\r\n");
    if (line_end == std::string_view::npos) {
        return std::unexpected(std::string{"malformed request line"});
    }
    const auto request_line = raw.substr(0, line_end);
    const auto first_space = request_line.find(' ');
    const auto second_space = first_space == std::string_view::npos
                                  ? std::string_view::npos
                                  : request_line.find(' ', first_space + 1);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos) {
        return std::unexpected(std::string{"invalid HTTP request line format"});
    }

    parsed_request_head parsed;
    parsed.method = std::string{request_line.substr(0, first_space)};
    parsed.uri = std::string{request_line.substr(first_space + 1, second_space - first_space - 1)};
    parsed.http_version = std::string{request_line.substr(second_space + 1)};

    if (!is_token(parsed.method)) {
        return std::unexpected(std::string{"invalid HTTP method"});
    }
    // Origin-form only: this is a direct HTTP server, not a forward proxy, so
    // an absolute-form target or an authority-form CONNECT is not accepted.
    if (parsed.uri.empty() || parsed.uri.front() != '/' || !is_valid_field_value(parsed.uri)) {
        return std::unexpected(std::string{"invalid request target"});
    }
    if (parsed.http_version != "HTTP/1.1" && parsed.http_version != "HTTP/1.0") {
        return std::unexpected(std::string{"unsupported HTTP version"});
    }

    auto cursor = line_end + 2U;
    bool has_host = false;
    bool has_api_key = false;
    bool has_authorization = false;
    while (cursor < raw.size()) {
        const auto next = raw.find("\r\n", cursor);
        if (next == std::string_view::npos || next == cursor) {
            break;
        }
        const auto header_line = raw.substr(cursor, next - cursor);
        cursor = next + 2U;

        if (parsed.headers.size() >= max_header_count) {
            return std::unexpected(std::string{"too many header fields"});
        }
        const auto colon = header_line.find(':');
        if (colon == std::string_view::npos) {
            return std::unexpected(std::string{"header field without a colon"});
        }
        const auto raw_name = header_line.substr(0, colon);
        if (!is_token(raw_name)) {
            return std::unexpected(std::string{"invalid header field name"});
        }
        auto name = lower_ascii(std::string{raw_name});
        auto val = header_line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) {
            val.remove_prefix(1);
        }
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) {
            val.remove_suffix(1);
        }
        if (!is_valid_field_value(val)) {
            return std::unexpected(std::string{"invalid header field value"});
        }

        // Content-Length is single-valued and numeric, with a hard cap. Chunked
        // framing is not accepted: mixing it with a length is a smuggling
        // primitive, and this endpoint always knows the request size.
        if (name == "transfer-encoding") {
            return std::unexpected(std::string{"transfer-encoding is not accepted"});
        }
        if (name == "content-length") {
            if (parsed.has_content_length) {
                return std::unexpected(std::string{"duplicate content-length"});
            }
            if (val.empty()) {
                return std::unexpected(std::string{"empty content-length"});
            }
            std::size_t length = 0;
            for (const char c : val) {
                if (c < '0' || c > '9') {
                    return std::unexpected(std::string{"non-numeric content-length"});
                }
                const auto digit = static_cast<std::size_t>(c - '0');
                if (length > (max_request_body_bytes - digit) / 10U) {
                    return std::unexpected(std::string{"content-length out of range"});
                }
                length = length * 10U + digit;
            }
            parsed.content_length = length;
            parsed.has_content_length = true;
        } else if (name == "x-api-key") {
            // Exactly one credential source may name the nonce. A second one is
            // ambiguous, and a request carrying both would forward two
            // credentials once injection is implemented.
            if (has_api_key || has_authorization) {
                return std::unexpected(std::string{"duplicate credential header"});
            }
            has_api_key = true;
            parsed.provided_nonce = std::string{val};
        } else if (name == "authorization") {
            if (has_api_key || has_authorization) {
                return std::unexpected(std::string{"duplicate credential header"});
            }
            constexpr std::string_view bearer_prefix = "Bearer ";
            if (!val.starts_with(bearer_prefix)) {
                return std::unexpected(std::string{"unsupported authorization scheme"});
            }
            has_authorization = true;
            parsed.provided_nonce = std::string{val.substr(bearer_prefix.size())};
        } else if (name == "host") {
            if (has_host) {
                return std::unexpected(std::string{"duplicate host header"});
            }
            has_host = true;
        }
        parsed.headers.emplace_back(std::move(name), std::string{val});
    }

    // HTTP/1.1 requires exactly one Host field (RFC 7230 5.4).
    if (parsed.http_version == "HTTP/1.1" && !has_host) {
        return std::unexpected(std::string{"missing host header"});
    }

    return parsed;
}

class credentialed_endpoint_impl final : public credentialed_endpoint {
public:
    explicit credentialed_endpoint_impl(
        credentialed_endpoint_options options, int listen_fd, std::uint16_t port
    )
        : options_{std::move(options)}, listen_fd_{listen_fd}, port_{port} {
        worker_ = std::jthread([this](std::stop_token st) { run(std::move(st)); });
    }

    ~credentialed_endpoint_impl() override {
        // Stop and join the worker before touching listen_fd_. Closing the
        // descriptor while the worker may still be polling it is both a data
        // race and a descriptor-reuse hazard.
        worker_.request_stop();
        if (worker_.joinable()) {
            worker_.join();
        }
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }

    [[nodiscard]] auto port() const -> std::uint16_t override { return port_; }

    [[nodiscard]] auto base_url(endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        for (const auto& ep : options_.endpoints) {
            if (ep.provider == provider) {
                return "http://127.0.0.1:" + std::to_string(port_) + ep.path_prefix;
            }
        }
        return std::unexpected(std::string{"provider endpoint not configured"});
    }

    [[nodiscard]] virtual auto session_nonce(endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        for (const auto& ep : options_.endpoints) {
            if (ep.provider == provider) {
                return ep.session_nonce;
            }
        }
        return std::unexpected(std::string{"provider endpoint not configured"});
    }

private:
    void run(std::stop_token stop) {
        while (!stop.stop_requested()) {
            ::pollfd pfd{.fd = listen_fd_, .events = POLLIN, .revents = 0};
            const int rc = ::poll(&pfd, 1, poll_tick_ms);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (rc == 0 || !(pfd.revents & POLLIN)) {
                continue;
            }

            ::sockaddr_in client_addr{};
            ::socklen_t addr_len = sizeof(client_addr);
            const int client_fd =
                ::accept(listen_fd_, reinterpret_cast<::sockaddr*>(&client_addr), &addr_len);
            if (client_fd < 0) {
                continue;
            }

            handle_client(client_fd, stop);
            ::close(client_fd);
        }
    }

    // Every response closes the connection, so say so explicitly; an HTTP/1.1
    // client otherwise assumes keep-alive and may reuse a socket we are closing.
    static void write_status(int client_fd, std::string_view status_line) {
        std::string response{status_line};
        response += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        static_cast<void>(write_all(client_fd, response));
    }

    // Discard an unread request body before closing. Closing a socket while the
    // peer is still sending makes the kernel send RST, which can destroy the
    // response we just wrote. Bounded by the declared length and the deadline.
    static void drain_body(int client_fd, std::size_t length, std::stop_token stop) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{1000};
        std::size_t remaining = length;
        while (remaining > 0 && !stop.stop_requested() &&
               std::chrono::steady_clock::now() < deadline) {
            ::pollfd pfd{.fd = client_fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, poll_tick_ms) <= 0) {
                continue;
            }
            std::array<char, 4096> chunk{};
            const auto got = ::read(client_fd, chunk.data(), std::min(chunk.size(), remaining));
            if (got <= 0) {
                break;
            }
            remaining -= static_cast<std::size_t>(got);
        }
    }

    void handle_client(int client_fd, std::stop_token stop) {
        std::string buffer;
        std::size_t header_end = std::string::npos;
        // One absolute deadline for the whole head. Without it a peer that
        // trickles one byte per poll interval holds the single worker (and
        // shutdown) for as long as it likes.
        const auto head_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{head_deadline_ms};
        while (buffer.size() < max_request_headers_bytes) {
            if (stop.stop_requested() || std::chrono::steady_clock::now() >= head_deadline) {
                break;
            }
            ::pollfd pfd{.fd = client_fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, poll_tick_ms) <= 0) {
                continue;
            }
            std::array<char, 1024> chunk{};
            const auto n = ::read(client_fd, chunk.data(), chunk.size());
            if (n <= 0) {
                break;
            }
            buffer.append(chunk.data(), static_cast<std::size_t>(n));
            header_end = buffer.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                break;
            }
        }

        // The cap must cover the terminator too, or a head slightly over the
        // limit is accepted (the size check is only evaluated between reads).
        if (header_end == std::string_view::npos || header_end + 4U > max_request_headers_bytes) {
            write_status(client_fd, "HTTP/1.1 400 Bad Request");
            return;
        }

        auto head = parse_http_head(buffer.substr(0, header_end + 2));
        if (!head || !is_valid_request_target(head->uri)) {
            write_status(client_fd, "HTTP/1.1 400 Bad Request");
            return;
        }

        // Split the origin-form request target so a query string cannot bypass
        // the prefix match or the path allowlist (for example ?beta=true).
        const auto query_pos = head->uri.find('?');
        const std::string path_only =
            query_pos == std::string::npos ? head->uri : head->uri.substr(0, query_pos);

        // Match against endpoint rules. A prefix must end at a segment
        // boundary, or "/anthropic" would also claim "/anthropicX".
        const credentialed_endpoint_rule* matched_rule = nullptr;
        for (const auto& rule : options_.endpoints) {
            if (path_only == rule.path_prefix || path_only.starts_with(rule.path_prefix + "/")) {
                matched_rule = &rule;
                break;
            }
        }

        if (matched_rule == nullptr) {
            if (!audit_or_unavailable(
                    client_fd,
                    endpoint_provider::custom,
                    head->method,
                    head->uri,
                    false,
                    "unknown_endpoint_prefix"
                )) {
                return;
            }
            write_status(client_fd, "HTTP/1.1 404 Not Found");
            return;
        }

        // Check method
        bool method_allowed = false;
        for (const auto& allowed_m : matched_rule->allowed_methods) {
            if (head->method == allowed_m) {
                method_allowed = true;
                break;
            }
        }
        if (!method_allowed) {
            if (!audit_or_unavailable(
                    client_fd,
                    matched_rule->provider,
                    head->method,
                    head->uri,
                    false,
                    "method_not_allowed"
                )) {
                return;
            }
            drain_body(client_fd, head->content_length, stop);
            write_status(client_fd, "HTTP/1.1 405 Method Not Allowed");
            return;
        }

        // Validate session nonce
        if (head->provided_nonce.empty() ||
            !constant_time_equal(head->provided_nonce, matched_rule->session_nonce)) {
            if (!audit_or_unavailable(
                    client_fd,
                    matched_rule->provider,
                    head->method,
                    head->uri,
                    false,
                    "invalid_session_nonce"
                )) {
                return;
            }
            drain_body(client_fd, head->content_length, stop);
            constexpr std::string_view unauthorized_body =
                "{\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid_session_"
                "nonce\"}}";
            std::string response =
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ";
            response += std::to_string(unauthorized_body.size());
            response += "\r\nConnection: close\r\n\r\n";
            response += unauthorized_body;
            static_cast<void>(write_all(client_fd, response));
            return;
        }

        // Target path after stripping prefix
        std::string rewritten_path = path_only.substr(matched_rule->path_prefix.size());
        if (rewritten_path.empty() || rewritten_path.front() != '/') {
            rewritten_path.insert(rewritten_path.begin(), '/');
        }

        // Check path allowlist. The wildcard keeps its trailing slash so
        // "/v1/*" means a child of /v1/, not a string prefix of "/v1".
        if (!matched_rule->allowed_paths.empty()) {
            bool path_allowed = false;
            for (const auto& ap : matched_rule->allowed_paths) {
                if (ap.ends_with("/*")) {
                    const auto stem = ap.substr(0, ap.size() - 1);
                    if (rewritten_path.starts_with(stem)) {
                        path_allowed = true;
                        break;
                    }
                } else if (rewritten_path == ap) {
                    path_allowed = true;
                    break;
                }
            }
            if (!path_allowed) {
                if (!audit_or_unavailable(
                        client_fd,
                        matched_rule->provider,
                        head->method,
                        head->uri,
                        false,
                        "path_not_allowed"
                    )) {
                    return;
                }
                drain_body(client_fd, head->content_length, stop);
                write_status(client_fd, "HTTP/1.1 403 Forbidden");
                return;
            }
        }

        // Audit the allow decision before any upstream work. A decision that
        // cannot be recorded is not served, so the trail can never understate
        // what the endpoint forwarded.
        if (!audit_or_unavailable(
                client_fd, matched_rule->provider, head->method, head->uri, true, "allowed"
            )) {
            return;
        }

        // Read the declared body when there is a transport to hand it to, or
        // discard it so closing does not reset the connection.
        std::string body;
        if (options_.forward && head->content_length > 0) {
            body = buffer.substr(header_end + 4U);
            if (body.size() > head->content_length) {
                body.resize(head->content_length);
            }
            std::size_t remaining = head->content_length - body.size();
            while (remaining > 0 && !stop.stop_requested()) {
                std::array<char, 4096> chunk{};
                const auto wanted = std::min(chunk.size(), remaining);
                const auto got = ::read(client_fd, chunk.data(), wanted);
                if (got <= 0) {
                    break;
                }
                body.append(chunk.data(), static_cast<std::size_t>(got));
                remaining -= static_cast<std::size_t>(got);
            }
            if (remaining != 0) {
                // A truncated body is not something to forward as if complete.
                write_status(client_fd, "HTTP/1.1 400 Bad Request");
                return;
            }
        } else {
            drain_body(client_fd, head->content_length, stop);
        }

        if (!options_.forward) {
            // No provider transport is configured (the TLS client is not built
            // yet). Say so plainly rather than implying a forwarding attempt.
            write_status(client_fd, "HTTP/1.1 501 Not Implemented");
            return;
        }

        upstream_request request;
        request.provider = matched_rule->provider;
        request.upstream_host = matched_rule->upstream_host;
        request.upstream_port = matched_rule->upstream_port;
        request.method = head->method;
        request.target = rewritten_path;
        if (query_pos != std::string::npos) {
            request.target += head->uri.substr(query_pos);
        }
        request.body = std::move(body);
        request.secret_token = matched_rule->secret_token;
        for (const auto& [name, value] : head->headers) {
            if (is_forwardable_request_header(name)) {
                request.headers.emplace_back(name, value);
            }
        }

        auto forwarded = options_.forward(request);
        if (!forwarded) {
            if (!audit_or_unavailable(
                    client_fd,
                    matched_rule->provider,
                    head->method,
                    head->uri,
                    true,
                    "upstream_error"
                )) {
                return;
            }
            write_status(client_fd, "HTTP/1.1 502 Bad Gateway");
            return;
        }

        std::string response = "HTTP/1.1 " + std::to_string(forwarded->status_code) + " " +
                               std::string{reason_phrase(forwarded->status_code)} + "\r\n";
        for (const auto& [name, value] : forwarded->headers) {
            if (is_forwardable_response_header(lower_ascii(name))) {
                response += name + ": " + value + "\r\n";
            }
        }
        response += "Content-Length: " + std::to_string(forwarded->body.size()) + "\r\n";
        response += "Connection: close\r\n\r\n";
        response += forwarded->body;
        static_cast<void>(write_all(client_fd, response));
    }

    auto record_event(
        endpoint_provider provider,
        std::string_view method,
        std::string_view path,
        bool allowed,
        std::string_view detail,
        std::size_t req_bytes = 0,
        std::size_t resp_bytes = 0
    ) -> std::expected<void, std::string> {
        if (!options_.on_event) {
            return {};
        }
        return options_.on_event(
            endpoint_event{
                .provider = provider,
                .method = std::string{method},
                .path = std::string{path},
                .allowed = allowed,
                .detail = std::string{detail},
                .request_bytes = req_bytes,
                .response_bytes = resp_bytes,
            }
        );
    }

    // Audit the decision and fail closed when the sink rejects the event. A
    // decision that cannot be recorded must not be served, or the audit trail
    // could understate what the endpoint actually forwarded. Returns true only
    // when the caller may proceed to emit its response.
    auto audit_or_unavailable(
        int client_fd,
        endpoint_provider provider,
        std::string_view method,
        std::string_view path,
        bool allowed,
        std::string_view detail,
        std::size_t req_bytes = 0,
        std::size_t resp_bytes = 0
    ) -> bool {
        auto recorded =
            record_event(provider, method, path, allowed, detail, req_bytes, resp_bytes);
        if (!recorded) {
            write_all(client_fd, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
            return false;
        }
        return true;
    }

    credentialed_endpoint_options options_;
    int listen_fd_ = -1;
    std::uint16_t port_ = 0;
    std::jthread worker_;
};

} // namespace

auto start_credentialed_endpoint(credentialed_endpoint_options opts)
    -> std::expected<std::unique_ptr<credentialed_endpoint>, std::string> {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::unexpected(std::string{"socket: "} + std::strerror(errno));
    }
    const int opt = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ::close(fd);
        return std::unexpected(std::string{"setsockopt(SO_REUSEADDR): "} + std::strerror(errno));
    }

    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (::bind(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return std::unexpected(std::string{"bind loopback: "} + std::strerror(errno));
    }
    if (::listen(fd, 64) < 0) {
        ::close(fd);
        return std::unexpected(std::string{"listen: "} + std::strerror(errno));
    }

    ::socklen_t addr_len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<::sockaddr*>(&addr), &addr_len) < 0) {
        ::close(fd);
        return std::unexpected(std::string{"getsockname: "} + std::strerror(errno));
    }

    const auto assigned_port = ntohs(addr.sin_port);
    return std::unique_ptr<credentialed_endpoint>{
        new credentialed_endpoint_impl(std::move(opts), fd, assigned_port)
    };
}

} // namespace glove::net
