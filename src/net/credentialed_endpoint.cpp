#include "glove/net/credentialed_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace glove::net {

namespace {

constexpr std::size_t max_request_headers_bytes = 16384;
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

struct parsed_request_head {
    std::string method;
    std::string uri;
    std::string http_version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string provided_nonce;
    std::size_t content_length = 0;
};

auto parse_http_head(std::string_view raw) -> std::expected<parsed_request_head, std::string> {
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

    auto cursor = line_end + 2U;
    while (cursor < raw.size()) {
        const auto next = raw.find("\r\n", cursor);
        if (next == std::string_view::npos || next == cursor) {
            break;
        }
        const auto header_line = raw.substr(cursor, next - cursor);
        cursor = next + 2U;

        const auto colon = header_line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        auto name = lower_ascii(std::string{header_line.substr(0, colon)});
        auto val = header_line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) {
            val.remove_prefix(1);
        }
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) {
            val.remove_suffix(1);
        }

        if (name == "x-api-key") {
            parsed.provided_nonce = std::string{val};
        } else if (name == "authorization") {
            constexpr std::string_view bearer_prefix = "Bearer ";
            if (val.starts_with(bearer_prefix)) {
                parsed.provided_nonce = std::string{val.substr(bearer_prefix.size())};
            }
        } else if (name == "content-length") {
            std::size_t cl = 0;
            for (char c : val) {
                if (c >= '0' && c <= '9') {
                    cl = cl * 10U + static_cast<std::size_t>(c - '0');
                }
            }
            parsed.content_length = cl;
        }
        parsed.headers.emplace_back(std::move(name), std::string{val});
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

            handle_client(client_fd);
            ::close(client_fd);
        }
    }

    void handle_client(int client_fd) {
        std::string buffer;
        std::size_t header_end = std::string::npos;
        while (buffer.size() < max_request_headers_bytes) {
            ::pollfd pfd{.fd = client_fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 1000) <= 0) {
                break;
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

        if (header_end == std::string_view::npos) {
            write_all(client_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }

        auto head = parse_http_head(buffer.substr(0, header_end + 2));
        if (!head) {
            write_all(client_fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }

        // Split the origin-form request target so a query string cannot bypass
        // the prefix match or the path allowlist (for example ?beta=true).
        const auto query_pos = head->uri.find('?');
        const std::string path_only =
            query_pos == std::string::npos ? head->uri : head->uri.substr(0, query_pos);

        // Match against endpoint rules
        const credentialed_endpoint_rule* matched_rule = nullptr;
        for (const auto& rule : options_.endpoints) {
            if (path_only.starts_with(rule.path_prefix)) {
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
            write_all(client_fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
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
            write_all(client_fd, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
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
            constexpr std::string_view unauthorized_body =
                "{\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid_session_"
                "nonce\"}}";
            std::string response =
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ";
            response += std::to_string(unauthorized_body.size());
            response += "\r\n\r\n";
            response += unauthorized_body;
            write_all(client_fd, response);
            return;
        }

        // Target path after stripping prefix
        std::string rewritten_path = path_only.substr(matched_rule->path_prefix.size());
        if (rewritten_path.empty() || rewritten_path.front() != '/') {
            rewritten_path.insert(rewritten_path.begin(), '/');
        }

        // Check path allowlist
        if (!matched_rule->allowed_paths.empty()) {
            bool path_allowed = false;
            for (const auto& ap : matched_rule->allowed_paths) {
                if (rewritten_path == ap ||
                    (ap.ends_with("/*") &&
                     rewritten_path.starts_with(ap.substr(0, ap.size() - 2)))) {
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
                write_all(client_fd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
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

        // For unit tests / mock mode: if upstream_host starts with "mock:", reply with 200 OK
        if (matched_rule->upstream_host.starts_with("mock:")) {
            constexpr std::string_view mock_response_body =
                "{\"id\":\"msg_mock\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{"
                "\"type\":\"text\",\"text\":\"mock response\"}]}";
            std::string resp =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ";
            resp += std::to_string(mock_response_body.size());
            resp += "\r\n\r\n";
            resp += mock_response_body;
            write_all(client_fd, resp);
            return;
        }

        // Real upstream forwarding (bounded TLS client, request-body forward,
        // and response streaming) is not constructed yet. Report that plainly
        // rather than a 502, which would imply an upstream attempt occurred.
        write_all(client_fd, "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
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
