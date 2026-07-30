#include "glove/net/egress_proxy.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <expected>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace glove::net {

namespace {

constexpr std::size_t max_request_bytes = 8192;
constexpr int poll_tick_ms = 200;
constexpr std::size_t relay_chunk = 16384;

auto lower_ascii(std::string value) -> std::string {
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
    return value;
}

auto normalise_host(std::string host) -> std::expected<std::string, std::string> {
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

auto host_matches(std::string_view allowed, std::string_view host) -> bool {
    if (allowed.starts_with('.')) {
        allowed.remove_prefix(1);
        return host == allowed || (host.size() > allowed.size() && host.ends_with(allowed) &&
                                   host[host.size() - allowed.size() - 1] == '.');
    }
    return host == allowed;
}

auto matching_rule(
    const std::vector<egress_rule>& allow, const std::string& host, std::uint16_t port
) -> const egress_rule* {
    for (const auto& rule : allow) {
        if (rule.port == port && host_matches(rule.host, host)) {
            return &rule;
        }
    }
    return nullptr;
}

auto base64(std::string_view input) -> std::string {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < input.size(); i += 3) {
        const auto a = static_cast<unsigned char>(input[i]);
        const auto b = i + 1 < input.size()
                           ? static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1]))
                           : 0U;
        const auto c = i + 2 < input.size()
                           ? static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]))
                           : 0U;
        const std::uint32_t value = (static_cast<std::uint32_t>(a) << 16U) | (b << 8U) | c;
        out.push_back(alphabet[(value >> 18U) & 0x3fU]);
        out.push_back(alphabet[(value >> 12U) & 0x3fU]);
        out.push_back(i + 1 < input.size() ? alphabet[(value >> 6U) & 0x3fU] : '=');
        out.push_back(i + 2 < input.size() ? alphabet[value & 0x3fU] : '=');
    }
    return out;
}

auto random_token() -> std::expected<std::string, std::string> {
    std::array<unsigned char, 32> bytes{};
    if (::getentropy(bytes.data(), bytes.size()) != 0) {
        return std::unexpected(std::string{"getentropy: "} + std::strerror(errno));
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(64);
    for (const auto byte : bytes) {
        token.push_back(hex[byte >> 4U]);
        token.push_back(hex[byte & 0x0fU]);
    }
    return token;
}

auto write_all(int fd, std::string_view data) -> bool {
    const char* cursor = data.data();
    std::size_t remaining = data.size();
    while (remaining > 0) {
        const ::ssize_t n = ::write(fd, cursor, remaining);
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

auto read_request(int fd, const std::atomic<bool>& stop) -> std::string {
    std::string buffer;
    while (buffer.find("\r\n\r\n") == std::string::npos) {
        if (stop.load() || buffer.size() > max_request_bytes) {
            return {};
        }
        ::pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        const int result = ::poll(&pfd, 1, poll_tick_ms);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {};
        }
        if (result == 0) {
            continue;
        }
        std::array<char, 1024> chunk{};
        const ::ssize_t got = ::read(fd, chunk.data(), chunk.size());
        if (got <= 0) {
            return {};
        }
        buffer.append(chunk.data(), static_cast<std::size_t>(got));
    }
    return buffer;
}

auto parse_connect(std::string_view request, std::string& host, std::uint16_t& port) -> bool {
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
    if (authority.starts_with('[')) {
        const auto bracket = authority.find(']');
        if (bracket == std::string_view::npos || bracket + 1 >= authority.size() ||
            authority[bracket + 1] != ':') {
            return false;
        }
        host = std::string{authority.substr(1, bracket - 1)};
        port_text = authority.substr(bracket + 2);
    } else {
        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) {
            return false;
        }
        host = std::string{authority.substr(0, colon)};
        port_text = authority.substr(colon + 1);
    }
    unsigned parsed = 0;
    if (host.empty() || port_text.empty()) {
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
    auto normal = normalise_host(std::move(host));
    if (!normal || port == 0) {
        return false;
    }
    host = std::move(*normal);
    return true;
}

auto authenticated(std::string_view request, std::string_view expected) -> bool {
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
            lower_ascii(std::string{line.substr(0, colon)}) == "proxy-authorization") {
            auto value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            return value == expected;
        }
        cursor = end + 2;
    }
    return false;
}

auto private_ipv4(std::uint32_t address) -> bool {
    const auto value = ntohl(address);
    const auto in = [value](std::uint32_t network, std::uint32_t mask) {
        return (value & mask) == network;
    };
    return in(0x00000000U, 0xff000000U) || in(0x0a000000U, 0xff000000U) ||
           in(0x64400000U, 0xffc00000U) || in(0x7f000000U, 0xff000000U) ||
           in(0xa9fe0000U, 0xffff0000U) || in(0xac100000U, 0xfff00000U) ||
           in(0xc0000000U, 0xffffff00U) || in(0xc0a80000U, 0xffff0000U) ||
           in(0xc0000200U, 0xffffff00U) || in(0xc0586300U, 0xffffff00U) ||
           in(0xc6120000U, 0xfffe0000U) || in(0xc6336400U, 0xffffff00U) ||
           in(0xcb007100U, 0xffffff00U) || in(0xe0000000U, 0xf0000000U) ||
           in(0xf0000000U, 0xf0000000U);
}

auto private_address(const ::sockaddr* address) -> bool {
    if (address == nullptr) {
        return true;
    }
    if (address->sa_family == AF_INET) {
        return private_ipv4(reinterpret_cast<const ::sockaddr_in*>(address)->sin_addr.s_addr);
    }
    if (address->sa_family != AF_INET6) {
        return true;
    }
    const auto& ipv6 = reinterpret_cast<const ::sockaddr_in6*>(address)->sin6_addr;
    const auto& bytes = ipv6.s6_addr;
    if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
        std::uint32_t embedded = 0;
        std::memcpy(&embedded, bytes + 12, sizeof(embedded));
        return private_ipv4(embedded);
    }
    const bool unspecified = std::all_of(bytes, bytes + 16, [](unsigned char c) { return c == 0; });
    const bool loopback =
        std::all_of(bytes, bytes + 15, [](unsigned char c) { return c == 0; }) && bytes[15] == 1;
    const bool unique_local = (bytes[0] & 0xfeU) == 0xfcU;
    const bool link_local = bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U;
    const bool site_local = bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0xc0U;
    const bool multicast = bytes[0] == 0xffU;
    return unspecified || loopback || unique_local || link_local || site_local || multicast;
}

auto dial(const std::string& host, std::uint16_t port, bool allow_private)
    -> std::expected<int, std::string> {
    ::addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ::addrinfo* results = nullptr;
    const std::string port_string = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_string.c_str(), &hints, &results) != 0) {
        return std::unexpected(std::string{"DNS resolution failed"});
    }
    int connected = -1;
    bool rejected_private = false;
    for (auto* item = results; item != nullptr; item = item->ai_next) {
        if (!allow_private && private_address(item->ai_addr)) {
            rejected_private = true;
            continue;
        }
        const int fd = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, item->ai_addr, item->ai_addrlen) == 0) {
            connected = fd;
            break;
        }
        ::close(fd);
    }
    ::freeaddrinfo(results);
    if (connected >= 0) {
        return connected;
    }
    return std::unexpected(
        rejected_private ? std::string{"destination resolved only to non-public addresses"}
                         : std::string{"dial failed"}
    );
}

void relay(int first, int second, const std::atomic<bool>& stop) {
    std::array<::pollfd, 2> descriptors{
        ::pollfd{.fd = first, .events = POLLIN, .revents = 0},
        ::pollfd{.fd = second, .events = POLLIN, .revents = 0},
    };
    std::array<char, relay_chunk> buffer{};
    while (!stop.load()) {
        for (auto& descriptor : descriptors) {
            descriptor.revents = 0;
        }
        const int result = ::poll(descriptors.data(), descriptors.size(), poll_tick_ms);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (result == 0) {
            continue;
        }
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            if ((descriptors[i].revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
                continue;
            }
            const ::ssize_t got = ::read(descriptors[i].fd, buffer.data(), buffer.size());
            if (got <= 0 || !write_all(
                                descriptors[1 - i].fd,
                                std::string_view{buffer.data(), static_cast<std::size_t>(got)}
                            )) {
                return;
            }
        }
    }
}

class proxy_impl final : public egress_proxy {
public:
    proxy_impl(
        int listen_fd,
        std::uint16_t port,
        egress_options opts,
        std::string token,
        std::filesystem::path unix_socket = {}
    )
        : listen_fd_{listen_fd},
          port_{port},
          opts_{std::move(opts)},
          token_{std::move(token)},
          authorization_{"Basic " + base64("glove:" + token_)},
          unix_socket_{std::move(unix_socket)} {
        accept_thread_ = std::thread([this] { accept_loop(); });
    }

    ~proxy_impl() override {
        stopping_.store(true);
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
        }
        std::vector<std::thread> connections;
        {
            std::scoped_lock lock{connections_mutex_};
            connections.swap(connections_);
        }
        for (auto& connection : connections) {
            if (connection.joinable()) {
                connection.join();
            }
        }
        if (!unix_socket_.empty()) {
            (void)::unlink(unix_socket_.c_str());
        }
    }

    auto port() const -> std::uint16_t override { return port_; }

    auto proxy_url() const -> std::string override {
        return "http://glove:" + token_ + "@127.0.0.1:" + std::to_string(port_);
    }

    auto proxy_authorization() const -> std::string override { return authorization_; }

    auto host_allowed(const std::string& host, std::uint16_t port) const -> bool override {
        auto normal = normalise_host(host);
        return normal && matching_rule(opts_.allow, *normal, port) != nullptr;
    }

private:
    auto emit(const egress_event& event) -> std::expected<void, std::string> {
        if (opts_.on_event) {
            return opts_.on_event(event);
        }
        return {};
    }

    void accept_loop() {
        while (!stopping_.load()) {
            ::pollfd descriptor{.fd = listen_fd_, .events = POLLIN, .revents = 0};
            const int result = ::poll(&descriptor, 1, poll_tick_ms);
            if (result <= 0) {
                if (result < 0 && errno != EINTR) {
                    return;
                }
                continue;
            }
            const int connection = ::accept(listen_fd_, nullptr, nullptr);
            if (connection < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return;
            }
            std::scoped_lock lock{connections_mutex_};
            connections_.emplace_back([this, connection] { handle(connection); });
        }
    }

    void deny(int client, egress_event& event, std::string detail, std::string_view response) {
        event.detail = std::move(detail);
        (void)emit(event);
        (void)write_all(client, response);
        ::close(client);
    }

    void handle(int client) {
        const std::string request = read_request(client, stopping_);
        std::string host;
        std::uint16_t port = 0;
        if (request.empty() || !parse_connect(request, host, port)) {
            ::close(client);
            return;
        }
        egress_event event{.host = host, .port = port, .allowed = false, .detail = {}};
        if (!authenticated(request, authorization_)) {
            deny(
                client,
                event,
                "proxy authentication required",
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"glove\"\r\n\r\n"
            );
            return;
        }
        const auto* rule = matching_rule(opts_.allow, host, port);
        if (rule == nullptr) {
            deny(client, event, "host or port not in allow-list", "HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        auto upstream = dial(host, port, rule->allow_private);
        if (!upstream) {
            deny(client, event, upstream.error(), "HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
        event.allowed = true;
        if (auto audited = emit(event); !audited) {
            (void)write_all(client, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
            ::close(client);
            ::close(*upstream);
            return;
        }
        if (write_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n")) {
            relay(client, *upstream, stopping_);
        }
        ::close(client);
        ::close(*upstream);
    }

    int listen_fd_;
    std::uint16_t port_;
    egress_options opts_;
    std::string token_;
    std::string authorization_;
    std::filesystem::path unix_socket_;
    std::atomic<bool> stopping_{false};
    std::thread accept_thread_;
    std::mutex connections_mutex_;
    std::vector<std::thread> connections_;
};

} // namespace

auto start_egress_proxy(egress_options opts)
    -> std::expected<std::unique_ptr<egress_proxy>, std::string> {
    std::set<std::pair<std::string, std::uint16_t>> seen;
    for (auto& rule : opts.allow) {
        auto host = normalise_host(std::move(rule.host));
        if (!host) {
            return std::unexpected(host.error());
        }
        rule.host = std::move(*host);
        if (rule.port == 0) {
            return std::unexpected(std::string{"egress rule port must be non-zero"});
        }
        if (!seen.emplace(rule.host, rule.port).second) {
            return std::unexpected(
                std::string{"duplicate egress rule: "} + rule.host + ":" + std::to_string(rule.port)
            );
        }
    }

    auto token = random_token();
    if (!token) {
        return std::unexpected(token.error());
    }

    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return std::unexpected(std::string{"socket: "} + std::strerror(errno));
    }
    const int one = 1;
    (void)::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    ::sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener, 16) != 0) {
        const int saved = errno;
        ::close(listener);
        return std::unexpected(std::string{"bind/listen: "} + std::strerror(saved));
    }
    ::sockaddr_in bound{};
    ::socklen_t length = sizeof(bound);
    if (::getsockname(listener, reinterpret_cast<::sockaddr*>(&bound), &length) != 0) {
        const int saved = errno;
        ::close(listener);
        return std::unexpected(std::string{"getsockname: "} + std::strerror(saved));
    }
    std::unique_ptr<egress_proxy> proxy = std::make_unique<proxy_impl>(
        listener, ntohs(bound.sin_port), std::move(opts), std::move(*token)
    );
    return proxy;
}

auto start_egress_proxy_on_unix_socket(
    egress_options opts,
    const std::filesystem::path& socket_path,
    std::uint16_t advertised_guest_port
) -> std::expected<std::unique_ptr<egress_proxy>, std::string> {
    if (!socket_path.is_absolute() || socket_path.lexically_normal() != socket_path ||
        socket_path.string().size() >= sizeof(::sockaddr_un::sun_path) ||
        advertised_guest_port == 0) {
        return std::unexpected(std::string{"invalid egress Unix socket configuration"});
    }
    std::set<std::pair<std::string, std::uint16_t>> seen;
    for (auto& rule : opts.allow) {
        auto host = normalise_host(std::move(rule.host));
        if (!host || rule.port == 0) {
            return std::unexpected(
                host ? std::string{"egress rule port must be non-zero"} : host.error()
            );
        }
        rule.host = std::move(*host);
        if (!seen.emplace(rule.host, rule.port).second) {
            return std::unexpected(
                std::string{"duplicate egress rule: "} + rule.host + ":" +
                std::to_string(rule.port)
            );
        }
    }
    auto token = random_token();
    if (!token) {
        return std::unexpected(token.error());
    }
    const int listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) {
        return std::unexpected(std::string{"create egress Unix socket: "} + std::strerror(errno));
    }
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socket_path.c_str(), socket_path.string().size() + 1U);
    if (::bind(listener, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0 ||
        ::chmod(socket_path.c_str(), 0600) != 0 || ::listen(listener, 16) != 0) {
        const int saved = errno;
        ::close(listener);
        (void)::unlink(socket_path.c_str());
        return std::unexpected(
            std::string{"bind/listen egress Unix socket: "} + std::strerror(saved)
        );
    }
    std::unique_ptr<egress_proxy> proxy = std::make_unique<proxy_impl>(
        listener,
        advertised_guest_port,
        std::move(opts),
        std::move(*token),
        socket_path
    );
    return proxy;
}

} // namespace glove::net
