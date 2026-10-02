#include "glove/net/credentialed_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto send_and_receive(std::uint16_t port, std::string_view request) -> std::string {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {};
    }
    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (::connect(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return {};
    }

    const auto written = ::write(fd, request.data(), request.size());
    if (written < 0 || static_cast<std::size_t>(written) != request.size()) {
        ::close(fd);
        return {};
    }

    std::string response;
    std::array<char, 1024> buffer{};
    while (true) {
        const auto n = ::read(fd, buffer.data(), buffer.size());
        if (n <= 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(n));
    }
    ::close(fd);
    return response;
}

auto run() -> int {
    std::vector<glove::net::endpoint_event> recorded_events;

    glove::net::credentialed_endpoint_options options;
    options.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "mock:api.anthropic.com",
        .upstream_port = 443,
        .secret_token = "sk-ant-real-super-secret-token",
        .session_nonce = "glove-nonce-abc123xyz",
        .allowed_methods = {"POST"},
        .allowed_paths = {"/v1/messages"},
    });
    options.on_event =
        [&](const glove::net::endpoint_event& ev) -> std::expected<void, std::string> {
        recorded_events.push_back(ev);
        return {};
    };

    auto endpoint = glove::net::start_credentialed_endpoint(std::move(options));
    REQUIRE(endpoint.has_value());
    const auto port = (*endpoint)->port();
    REQUIRE(port > 0);

    auto base_url = (*endpoint)->base_url(glove::net::endpoint_provider::anthropic);
    REQUIRE(base_url.has_value());
    REQUIRE(base_url->find(std::to_string(port)) != std::string::npos);
    REQUIRE(base_url->ends_with("/anthropic"));

    auto nonce = (*endpoint)->session_nonce(glove::net::endpoint_provider::anthropic);
    REQUIRE(nonce.has_value());
    REQUIRE(*nonce == "glove-nonce-abc123xyz");

    // Case 1: Valid session nonce -> success (200 OK)
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 200 OK"));
        REQUIRE(resp.find("mock response") != std::string::npos);
    }

    // Case 2: Invalid session nonce -> 401 Unauthorized
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: wrong-nonce\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 401 Unauthorized"));
        REQUIRE(resp.find("invalid_session_nonce") != std::string::npos);
    }

    // Case 3: Missing session nonce -> 401 Unauthorized
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    // Case 4: Disallowed HTTP method -> 405 Method Not Allowed
    {
        const auto resp = send_and_receive(
            port,
            "GET /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 405 Method Not Allowed"));
    }

    // Case 5: Disallowed path -> 403 Forbidden
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/forbidden/path HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 403 Forbidden"));
    }

    // Case 6: Unknown endpoint prefix -> 404 Not Found
    {
        const auto resp = send_and_receive(
            port,
            "POST /unknown/service HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 404 Not Found"));
    }

    // Malformed framing and smuggling shapes must be rejected before any
    // routing or credential decision. Each returns 400 Bad Request. Every
    // request carries a valid Host and nonce unless the case under test is the
    // Host requirement itself, so the 400 is attributable to the named defect.
    const std::vector<std::pair<const char*, std::string>> malformed = {
        {"bare LF in request line",
         "POST /anthropic/v1/messages HTTP/1.1\nHost: 127.0.0.1\r\n\r\n"},
        {"bare LF in header line",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"bare CR in header value",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-\rnonce\r\n\r\n"},
        {"header name with a space",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nBad Name: x\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"empty header name",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n: x\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"header without a colon",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nnot-a-header\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"duplicate content-length",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n"
         "Content-Length: 0\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"non-numeric content-length",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1a2\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"oversized content-length",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "Content-Length: 99999999999999999999\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"transfer-encoding",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "Transfer-Encoding: chunked\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"absolute-form target",
         "POST http://evil.example/anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"unsupported HTTP version",
         "POST /anthropic/v1/messages HTTP/2.0\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"invalid method token",
         "P(ST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"tab in request target",
         "POST /anthropic/v1/mess\tages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"dot-segment traversal",
         "POST /anthropic/v1/../messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"percent-encoded traversal",
         "POST /anthropic/v1/%2e%2e/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"duplicate x-api-key",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"both credential headers",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n"
         "Authorization: Bearer glove-nonce-abc123xyz\r\n\r\n"},
        {"missing host on HTTP/1.1",
         "POST /anthropic/v1/messages HTTP/1.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
        {"duplicate host",
         "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: 127.0.0.1\r\n"
         "x-api-key: glove-nonce-abc123xyz\r\n\r\n"},
    };
    for (const auto& [label, request] : malformed) {
        const auto resp = send_and_receive(port, request);
        if (!resp.starts_with("HTTP/1.1 400 Bad Request")) {
            std::fprintf(
                stderr, "REQUIRE failed: %s should be 400, got: %.40s\n", label, resp.c_str()
            );
            return 1;
        }
    }

    // A query string must reach the same path rule as the bare path: the
    // allowed path with a query is served, and a disallowed path with a query
    // that contains the allowed path is still refused. Without splitting the
    // target, the second case would be the one that accidentally passed.
    {
        const auto allowed_with_query = send_and_receive(
            port,
            "POST /anthropic/v1/messages?beta=true HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(allowed_with_query.starts_with("HTTP/1.1 200 OK"));
    }
    {
        const auto disallowed_with_query = send_and_receive(
            port,
            "POST /anthropic/v1/forbidden?x=/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(disallowed_with_query.starts_with("HTTP/1.1 403 Forbidden"));
    }

    REQUIRE(!recorded_events.empty());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
