// Stage 2: the egress proxy must tunnel an allowlisted CONNECT through to the
// real destination and refuse everything else, auditing each decision. We
// stand up a loopback "origin" server, then drive the proxy as an HTTP client
// would: send a CONNECT line and check the response. The allowed target is the
// origin itself (by the literal host "localhost"); a different host is denied.

#include "glove/net/egress_proxy.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

// A loopback server that, on the first connection, sends a marker and closes.
struct origin_server {
    int fd = -1;
    std::uint16_t port = 0;
    std::thread thread;

    auto start() -> bool {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return false;
        }
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        ::sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(fd, reinterpret_cast<::sockaddr*>(&a), sizeof(a)) != 0) {
            return false;
        }
        if (::listen(fd, 4) != 0) {
            return false;
        }
        ::sockaddr_in bound{};
        ::socklen_t len = sizeof(bound);
        ::getsockname(fd, reinterpret_cast<::sockaddr*>(&bound), &len);
        port = ntohs(bound.sin_port);
        thread = std::thread([this] {
            int c = ::accept(fd, nullptr, nullptr);
            if (c >= 0) {
                const char* msg = "ORIGIN_HELLO";
                (void)::write(c, msg, std::strlen(msg));
                ::close(c);
            }
        });
        return true;
    }

    ~origin_server() {
        if (fd >= 0) {
            ::shutdown(fd, SHUT_RDWR); // unblocks a pending accept()
            ::close(fd);
        }
        if (thread.joinable()) {
            thread.join();
        }
    }
};

auto connect_loopback(std::uint16_t port) -> int {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return -1;
    }
    ::sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(s, reinterpret_cast<::sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(s);
        return -1;
    }
    return s;
}

auto connect_unix(const std::filesystem::path& path) -> int {
    const int socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket < 0 || path.string().size() >= sizeof(::sockaddr_un::sun_path)) {
        return -1;
    }
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.string().size() + 1U);
    if (::connect(socket, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(socket);
        return -1;
    }
    return socket;
}

auto read_some(int fd) -> std::string {
    std::string out;
    char buf[256];
    for (int i = 0; i < 50; ++i) {
        ::ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
        if (out.find("ORIGIN_HELLO") != std::string::npos ||
            out.find("\r\n\r\n") != std::string::npos) {
            // keep reading a touch in case body trails the 200 line
            if (out.find("ORIGIN_HELLO") != std::string::npos) {
                break;
            }
        }
    }
    return out;
}

auto run() -> int {
    origin_server origin;
    REQUIRE(origin.start());

    std::atomic<int> allowed_events{0};
    std::atomic<int> denied_events{0};
    glove::net::egress_options opts;
    opts.allow = {{.host = "localhost", .port = origin.port, .allow_private = true}};
    opts.on_event = [&](const glove::net::egress_event& e) -> std::expected<void, std::string> {
        if (e.allowed) {
            allowed_events.fetch_add(1);
        } else {
            denied_events.fetch_add(1);
        }
        return {};
    };

    auto proxy_or = glove::net::start_egress_proxy(opts);
    REQUIRE(proxy_or.has_value());
    auto proxy = std::move(*proxy_or);
    REQUIRE(proxy->port() != 0);
    REQUIRE(proxy->host_allowed("localhost", origin.port));
    REQUIRE(!proxy->host_allowed("localhost", 443));
    REQUIRE(!proxy->host_allowed("evil.example.com", origin.port));

    // The loopback listener is not an ambient capability: unauthenticated
    // host processes cannot borrow the agent's egress grants.
    {
        int c = connect_loopback(proxy->port());
        REQUIRE(c >= 0);
        std::string req = "CONNECT localhost:" + std::to_string(origin.port) +
                          " HTTP/1.1\r\nHost: localhost\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        REQUIRE(resp.find("407 Proxy Authentication Required") != std::string::npos);
    }

    // Allowed: CONNECT localhost:<origin> → 200, then origin's marker tunnels.
    {
        int c = connect_loopback(proxy->port());
        REQUIRE(c >= 0);
        std::string req =
            "CONNECT localhost:" + std::to_string(origin.port) +
            " HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: " + proxy->proxy_authorization() +
            "\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        std::fprintf(stderr, "allowed resp: %s\n", resp.c_str());
        REQUIRE(resp.find("200 Connection Established") != std::string::npos);
        REQUIRE(resp.find("ORIGIN_HELLO") != std::string::npos);
    }

    // Denied: a host not on the allow-list → 403, no tunnel.
    {
        int c = connect_loopback(proxy->port());
        REQUIRE(c >= 0);
        std::string req = "CONNECT evil.example.com:443 HTTP/1.1\r\nProxy-Authorization: " +
                          proxy->proxy_authorization() + "\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        std::fprintf(stderr, "denied resp: %s\n", resp.c_str());
        REQUIRE(resp.find("403 Forbidden") != std::string::npos);
    }

    REQUIRE(allowed_events.load() == 1);
    REQUIRE(denied_events.load() == 2);

    // Apple Container receives this broker through a forwarded Unix socket;
    // authentication and allow-list behavior are identical to the loopback
    // listener, while the advertised port names only the guest relay.
    {
        origin_server unix_origin;
        REQUIRE(unix_origin.start());
        std::string temporary = "/tmp/glove-egress-unix-test-XXXXXX";
        REQUIRE(::mkdtemp(temporary.data()) != nullptr);
        REQUIRE(::chmod(temporary.c_str(), 0700) == 0);
        const auto socket_path = std::filesystem::path{temporary} / "egress.sock";
        glove::net::egress_options unix_options;
        unix_options.allow = {
            {.host = "localhost", .port = unix_origin.port, .allow_private = true}
        };
        auto unix_proxy_or = glove::net::start_egress_proxy_on_unix_socket(
            std::move(unix_options), socket_path, 31'820
        );
        REQUIRE(unix_proxy_or.has_value());
        auto unix_proxy = std::move(*unix_proxy_or);
        REQUIRE(unix_proxy->port() == 31'820);
        int connection = connect_unix(socket_path);
        REQUIRE(connection >= 0);
        std::string request =
            "CONNECT localhost:" + std::to_string(unix_origin.port) +
            " HTTP/1.1\r\nProxy-Authorization: " + unix_proxy->proxy_authorization() + "\r\n\r\n";
        REQUIRE(
            ::write(connection, request.data(), request.size()) ==
            static_cast<::ssize_t>(request.size())
        );
        const std::string response = read_some(connection);
        ::close(connection);
        REQUIRE(response.find("200 Connection Established") != std::string::npos);
        REQUIRE(response.find("ORIGIN_HELLO") != std::string::npos);
        unix_proxy.reset();
        REQUIRE(!std::filesystem::exists(socket_path));
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
    }

    // A hostname grant still cannot target loopback/private space unless the
    // rule says so explicitly.
    {
        glove::net::egress_options private_opts;
        private_opts.allow = {{.host = "localhost", .port = origin.port}};
        auto private_proxy_or = glove::net::start_egress_proxy(std::move(private_opts));
        REQUIRE(private_proxy_or.has_value());
        auto private_proxy = std::move(*private_proxy_or);
        int c = connect_loopback(private_proxy->port());
        REQUIRE(c >= 0);
        std::string req =
            "CONNECT localhost:" + std::to_string(origin.port) +
            " HTTP/1.1\r\nProxy-Authorization: " + private_proxy->proxy_authorization() +
            "\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        REQUIRE(resp.find("502 Bad Gateway") != std::string::npos);
    }

    // IPv4-mapped IPv6 must be classified using the embedded IPv4 address;
    // otherwise ::ffff:127.0.0.1 bypasses the loopback/private check.
    {
        origin_server mapped_origin;
        REQUIRE(mapped_origin.start());
        glove::net::egress_options mapped_opts;
        mapped_opts.allow = {{.host = "::ffff:127.0.0.1", .port = mapped_origin.port}};
        auto mapped_proxy_or = glove::net::start_egress_proxy(std::move(mapped_opts));
        REQUIRE(mapped_proxy_or.has_value());
        auto mapped_proxy = std::move(*mapped_proxy_or);
        int c = connect_loopback(mapped_proxy->port());
        REQUIRE(c >= 0);
        std::string req =
            "CONNECT [::ffff:127.0.0.1]:" + std::to_string(mapped_origin.port) +
            " HTTP/1.1\r\nProxy-Authorization: " + mapped_proxy->proxy_authorization() + "\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        REQUIRE(resp.find("502 Bad Gateway") != std::string::npos);
    }

    // An allowed connection is not released when its mandatory audit record
    // cannot be committed.
    {
        origin_server audited_origin;
        REQUIRE(audited_origin.start());
        glove::net::egress_options failing_audit;
        failing_audit.allow = {
            {.host = "localhost", .port = audited_origin.port, .allow_private = true}
        };
        failing_audit.on_event =
            [](const glove::net::egress_event& e) -> std::expected<void, std::string> {
            if (e.allowed) {
                return std::unexpected(std::string{"audit unavailable"});
            }
            return {};
        };
        auto audited_proxy_or = glove::net::start_egress_proxy(std::move(failing_audit));
        REQUIRE(audited_proxy_or.has_value());
        auto audited_proxy = std::move(*audited_proxy_or);
        int c = connect_loopback(audited_proxy->port());
        REQUIRE(c >= 0);
        std::string req =
            "CONNECT localhost:" + std::to_string(audited_origin.port) +
            " HTTP/1.1\r\nProxy-Authorization: " + audited_proxy->proxy_authorization() +
            "\r\n\r\n";
        REQUIRE(::write(c, req.data(), req.size()) == static_cast<::ssize_t>(req.size()));
        std::string resp = read_some(c);
        ::close(c);
        REQUIRE(resp.find("503 Service Unavailable") != std::string::npos);
        REQUIRE(resp.find("ORIGIN_HELLO") == std::string::npos);
    }
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
