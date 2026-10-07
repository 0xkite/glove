#include "glove/net/credentialed_endpoint.hpp"
#include "glove/net/tls_forwarder.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view secret = "sk-ant-forwarder-test-secret";

// A loopback listener that counts accepted connections. In `reply` mode it
// answers every connection with a plaintext HTTP response (which a TLS client
// must refuse); otherwise it accepts and stays silent.
class loopback_server {
public:
    explicit loopback_server(bool reply) : reply_{reply} {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        ::sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (fd_ < 0 || ::bind(fd_, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(fd_, 8) != 0) {
            return;
        }
        ::socklen_t length = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<::sockaddr*>(&addr), &length);
        port_ = ntohs(addr.sin_port);
        worker_ = std::jthread{[this](std::stop_token stop) { serve(std::move(stop)); }};
    }

    loopback_server(const loopback_server&) = delete;
    loopback_server& operator=(const loopback_server&) = delete;
    loopback_server(loopback_server&&) = delete;
    loopback_server& operator=(loopback_server&&) = delete;

    ~loopback_server() {
        worker_.request_stop();
        if (worker_.joinable()) {
            worker_.join();
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] auto port() const -> std::uint16_t { return port_; }

    [[nodiscard]] auto accepted() const -> int { return accepted_.load(); }

private:
    void serve(std::stop_token stop) {
        std::array<int, 8> held{};
        std::size_t held_count = 0;
        while (!stop.stop_requested()) {
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 20) <= 0) {
                continue;
            }
            const int client = ::accept(fd_, nullptr, nullptr);
            if (client < 0) {
                continue;
            }
            accepted_.fetch_add(1);
            if (reply_) {
                answer_in_plaintext(client);
                ::close(client);
            } else if (held_count < held.size()) {
                held.at(held_count++) = client;
            } else {
                ::close(client);
            }
        }
        for (std::size_t index = 0; index < held_count; ++index) {
            ::close(held.at(index));
        }
    }

    // Wait for the ClientHello, answer it with plaintext HTTP, then keep the
    // socket open until the client gives up. Closing straight away would let
    // the client see a reset before it parses the reply, and the failure
    // would no longer be deterministically a handshake failure.
    static void answer_in_plaintext(int client) {
        ::pollfd pfd{.fd = client, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, 2000) <= 0) {
            return;
        }
        std::array<char, 4096> hello{};
        static_cast<void>(::read(client, hello.data(), hello.size()));
        constexpr std::string_view plaintext =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        static_cast<void>(::write(client, plaintext.data(), plaintext.size()));
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (std::chrono::steady_clock::now() < until) {
            pfd.revents = 0;
            if (::poll(&pfd, 1, 50) > 0 && ::read(client, hello.data(), hello.size()) <= 0) {
                return;
            }
        }
    }

    bool reply_;
    int fd_ = -1;
    std::uint16_t port_ = 0;
    std::atomic<int> accepted_{0};
    std::jthread worker_;
};

auto request_for(std::string host, std::uint16_t port) -> glove::net::upstream_request {
    glove::net::upstream_request request;
    request.provider = glove::net::endpoint_provider::anthropic;
    request.upstream_host = std::move(host);
    request.upstream_port = port;
    request.method = "POST";
    request.target = "/v1/messages";
    request.headers = {{"content-type", "application/json"}};
    request.body = "{}";
    request.secret_token = std::string{secret};
    return request;
}

auto soon(int ms) -> std::chrono::steady_clock::time_point {
    return std::chrono::steady_clock::now() + std::chrono::milliseconds{ms};
}

auto allowlist_cases() -> int {
    loopback_server server{true};
    REQUIRE(server.port() != 0);
    auto forward = glove::net::make_tls_forwarder({
        .allowed_upstreams = {{"api.anthropic.com", 443}},
    });

    // A host outside the allowlist is refused before any dial: the loopback
    // listener it names never sees a connection.
    auto other_host = forward(request_for("127.0.0.1", server.port()), {}, soon(2000));
    REQUIRE(!other_host);
    REQUIRE(other_host.error().find("allowlist") != std::string::npos);
    // The right host on the wrong port is refused too.
    auto other_port = forward(request_for("api.anthropic.com", 8443), {}, soon(2000));
    REQUIRE(!other_port);
    REQUIRE(other_port.error().find("allowlist") != std::string::npos);
    // Host matching ignores case, so this reaches the provider check, which
    // refuses a provider with no defined credential field.
    auto custom = request_for("API.Anthropic.COM", 443);
    custom.provider = glove::net::endpoint_provider::custom;
    auto no_scheme = forward(custom, {}, soon(2000));
    REQUIRE(!no_scheme);
    REQUIRE(no_scheme.error().find("credential scheme") != std::string::npos);

    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    REQUIRE(server.accepted() == 0);
    return 0;
}

auto fail_closed_cases() -> int {
    // A plaintext server on an allowlisted destination must fail the TLS
    // handshake; there is no fallback that would send the request in clear.
    {
        loopback_server server{true};
        REQUIRE(server.port() != 0);
        auto forward = glove::net::make_tls_forwarder({
            .allowed_upstreams = {{"localhost", server.port()}},
        });
        auto result = forward(request_for("localhost", server.port()), {}, soon(5000));
        REQUIRE(!result);
        if (result.error().find("handshake") == std::string::npos) {
            std::fprintf(stderr, "unexpected error: %s\n", result.error().c_str());
        }
        REQUIRE(result.error().find("handshake") != std::string::npos);
        REQUIRE(result.error().find(secret) == std::string::npos);
        REQUIRE(server.accepted() >= 1);
    }
    // A peer that accepts but never speaks TLS is bounded by the deadline.
    {
        loopback_server server{false};
        REQUIRE(server.port() != 0);
        auto forward = glove::net::make_tls_forwarder({
            .allowed_upstreams = {{"localhost", server.port()}},
        });
        const auto started = std::chrono::steady_clock::now();
        auto result = forward(request_for("localhost", server.port()), {}, soon(300));
        REQUIRE(!result);
        REQUIRE(result.error().find("deadline") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds{3});
    }
    // And by the stop token.
    {
        loopback_server server{false};
        REQUIRE(server.port() != 0);
        auto forward = glove::net::make_tls_forwarder({
            .allowed_upstreams = {{"localhost", server.port()}},
        });
        std::stop_source source;
        std::jthread stopper{[&source] {
            std::this_thread::sleep_for(std::chrono::milliseconds{150});
            source.request_stop();
        }};
        const auto started = std::chrono::steady_clock::now();
        auto result =
            forward(request_for("localhost", server.port()), source.get_token(), soon(30000));
        REQUIRE(!result);
        REQUIRE(result.error().find("cancelled") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds{5});
    }
    return 0;
}

// A request whose caller is already cancelled, or already out of time, must
// not dial at all: nothing reaches the network, so the credential cannot
// either.
auto pre_cancelled_cases() -> int {
    loopback_server server{false};
    REQUIRE(server.port() != 0);
    auto forward = glove::net::make_tls_forwarder({
        .allowed_upstreams = {{"localhost", server.port()}},
    });
    std::stop_source source;
    source.request_stop();
    auto cancelled =
        forward(request_for("localhost", server.port()), source.get_token(), soon(5000));
    REQUIRE(!cancelled);
    REQUIRE(cancelled.error().find("cancelled") != std::string::npos);
    auto expired =
        forward(request_for("localhost", server.port()), {}, std::chrono::steady_clock::now());
    REQUIRE(!expired);
    REQUIRE(expired.error().find("deadline") != std::string::npos);
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    REQUIRE(server.accepted() == 0);
    return 0;
}

auto send_and_receive(std::uint16_t port, std::string_view request) -> std::string {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {};
    }
    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::write(fd, request.data(), request.size()) < 0) {
        ::close(fd);
        return {};
    }
    std::string response;
    std::array<char, 1024> buffer{};
    while (true) {
        const auto got = ::read(fd, buffer.data(), buffer.size());
        if (got <= 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(got));
    }
    ::close(fd);
    return response;
}

// With the production transport installed, the endpoint attempts the exchange
// and reports a failed upstream as 502, not the 501 it returns with no transport.
auto endpoint_case() -> int {
    loopback_server upstream{true};
    REQUIRE(upstream.port() != 0);
    glove::net::credentialed_endpoint_options options;
    options.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "localhost",
        .upstream_port = upstream.port(),
        .secret_token = std::string{secret},
        .session_nonce = "glove-session-forwarder-test",
        .allowed_methods = {"POST"},
        .allowed_paths = {"/v1/messages"},
    });
    options.forward = glove::net::make_tls_forwarder({
        .allowed_upstreams = {{"localhost", upstream.port()}},
    });
    options.upstream_deadline_ms = 5000;
    auto endpoint = glove::net::start_credentialed_endpoint(std::move(options));
    REQUIRE(endpoint);
    const auto response = send_and_receive(
        (*endpoint)->port(),
        "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "x-api-key: glove-session-forwarder-test\r\nContent-Length: 2\r\n\r\n{}"
    );
    REQUIRE(response.starts_with("HTTP/1.1 502"));
    REQUIRE(response.find(secret) == std::string::npos);
    REQUIRE(upstream.accepted() >= 1);
    return 0;
}

// Opt-in: a real handshake with the provider, presenting a credential the
// provider will reject. A 401 from upstream proves trust store, SNI, hostname
// verification, and HTTP framing end to end without a real secret.
auto live_case() -> int {
    const char* enabled = std::getenv("GLOVE_LIVE_TLS");
    if (enabled == nullptr || std::string_view{enabled} != "1") {
        std::puts("tls_forwarder: live check skipped (set GLOVE_LIVE_TLS=1)");
        return 0;
    }
    auto forward = glove::net::make_tls_forwarder({
        .allowed_upstreams = {{"api.anthropic.com", 443}},
    });
    auto request = request_for("api.anthropic.com", 443);
    request.headers.emplace_back("anthropic-version", "2023-06-01");
    request.body = R"({"model":"claude-haiku-4-5","max_tokens":1,"messages":[]})";
    auto result = forward(request, {}, soon(20000));
    if (!result) {
        std::fprintf(stderr, "live error: %s\n", result.error().c_str());
    }
    REQUIRE(result);
    REQUIRE(result->status_code == 401);
    REQUIRE(!result->body.empty());
    std::puts("tls_forwarder: live check passed (upstream 401 as expected)");
    return 0;
}

auto run() -> int {
    if (const int failed = allowlist_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = fail_closed_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = pre_cancelled_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = endpoint_case(); failed != 0) {
        return failed;
    }
    return live_case();
}

} // namespace

auto main() -> int {
    const int result = run();
    if (result == 0) {
        std::puts("tls_forwarder: all checks passed");
    }
    return result;
}
