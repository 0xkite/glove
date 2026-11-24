#include "glove/net/credentialed_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

// Send `request` and read the response without closing the write side, so a
// server waiting for a declared body must time out rather than observe EOF.
auto send_partial_and_receive(std::uint16_t port, std::string_view request, int wait_ms)
    -> std::string {
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
    if (::write(fd, request.data(), request.size()) < 0) {
        ::close(fd);
        return {};
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{wait_ms};
    std::string response;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()
        );
        ::pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, static_cast<int>(std::max<long long>(left.count(), 1))) <= 0) {
            continue;
        }
        std::array<char, 1024> buffer{};
        const auto got = ::read(fd, buffer.data(), buffer.size());
        if (got <= 0) {
            break;
        }
        response.append(buffer.data(), static_cast<std::size_t>(got));
    }
    ::close(fd);
    return response;
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

// A forwarded request produces two events: the decision before the exchange,
// and the outcome after it with the exchange's duration, sizes and status. A
// failed exchange reports its duration too. An outcome that cannot be recorded
// is not delivered to the client.
auto outcome_events() -> int {
    using namespace std::chrono_literals;
    // The endpoint's worker writes these; the test reads them between requests.
    std::mutex mutex;
    std::vector<glove::net::endpoint_event> seen;
    std::atomic<bool> refuse_outcome{false};
    std::atomic<bool> fail_upstream{false};
    const auto take = [&] {
        const std::lock_guard lock{mutex};
        return std::exchange(seen, {});
    };

    glove::net::credentialed_endpoint_options options;
    options.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "api.anthropic.com",
        .upstream_port = 443,
        .secret_token = "host-only-token",
        .session_nonce = "outcome-nonce",
        .allowed_methods = {"POST"},
        .allowed_paths = {"/v1/messages"},
    });
    options.on_event =
        [&](const glove::net::endpoint_event& event) -> std::expected<void, std::string> {
        if (refuse_outcome && event.detail == "completed") {
            return std::unexpected(std::string{"audit sink full"});
        }
        const std::lock_guard lock{mutex};
        seen.push_back(event);
        return {};
    };
    options.forward = [&](
                          const glove::net::upstream_request&,
                          std::stop_token,
                          std::chrono::steady_clock::time_point
                      ) -> std::expected<glove::net::upstream_response, std::string> {
        std::this_thread::sleep_for(30ms);
        if (fail_upstream) {
            return std::unexpected(std::string{"connection reset"});
        }
        glove::net::upstream_response response;
        response.status_code = 429;
        response.body = "slow down";
        return response;
    };
    auto endpoint = glove::net::start_credentialed_endpoint(std::move(options));
    REQUIRE(endpoint.has_value());
    const auto port = (*endpoint)->port();
    const std::string request = "POST /anthropic/v1/messages HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "x-api-key: outcome-nonce\r\n"
                                "Content-Length: 5\r\n\r\nhello";

    auto response = send_and_receive(port, request);
    REQUIRE(response.starts_with("HTTP/1.1 429"));
    auto events = take();
    REQUIRE(events.size() == 2);
    REQUIRE(events[0].detail == "allowed");
    REQUIRE(events[0].upstream_duration == 0ns && events[0].upstream_status == 0);
    REQUIRE(events[1].detail == "completed" && events[1].allowed);
    REQUIRE(events[1].upstream_status == 429);
    REQUIRE(events[1].request_bytes == 5 && events[1].response_bytes == 9);
    REQUIRE(events[1].upstream_duration >= 30ms && events[1].upstream_duration < 5s);
    REQUIRE(events[1].method == "POST" && events[1].path == events[0].path);

    fail_upstream = true;
    response = send_and_receive(port, request);
    REQUIRE(response.starts_with("HTTP/1.1 502"));
    events = take();
    REQUIRE(events.size() == 2);
    REQUIRE(events[1].detail == "upstream_error");
    REQUIRE(events[1].upstream_status == 0 && events[1].response_bytes == 0);
    REQUIRE(events[1].request_bytes == 5);
    REQUIRE(events[1].upstream_duration >= 30ms);

    fail_upstream = false;
    refuse_outcome = true;
    response = send_and_receive(port, request);
    REQUIRE(response.starts_with("HTTP/1.1 503"));
    REQUIRE(!response.contains("slow down"));
    events = take();
    REQUIRE(events.size() == 1 && events[0].detail == "allowed");
    return 0;
}

// Request, per-minute and token budgets refuse with 429 before forwarding,
// and record the reason. Token counts come from the provider's response.
auto limits() -> int {
    std::mutex mutex;
    std::vector<glove::net::endpoint_event> seen;
    std::atomic<int> forwarded{0};
    const auto take = [&] {
        const std::lock_guard lock{mutex};
        return std::exchange(seen, {});
    };
    const auto start = [&](glove::net::endpoint_limits budget) {
        glove::net::credentialed_endpoint_options options;
        options.endpoints.push_back({
            .provider = glove::net::endpoint_provider::openai,
            .path_prefix = "/openai",
            .upstream_host = "api.openai.com",
            .upstream_port = 443,
            .secret_token = "host-only-token",
            .session_nonce = "limit-nonce",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/chat/completions"},
        });
        options.limits = budget;
        options.on_event =
            [&](const glove::net::endpoint_event& event) -> std::expected<void, std::string> {
            const std::lock_guard lock{mutex};
            seen.push_back(event);
            return {};
        };
        options.forward = [&](
                              const glove::net::upstream_request&,
                              std::stop_token,
                              std::chrono::steady_clock::time_point
                          ) -> std::expected<glove::net::upstream_response, std::string> {
            ++forwarded;
            glove::net::upstream_response response;
            response.status_code = 200;
            response.body = R"({"usage":{"prompt_tokens":40,"completion_tokens":10}})";
            return response;
        };
        return glove::net::start_credentialed_endpoint(std::move(options));
    };
    const std::string request = "POST /openai/v1/chat/completions HTTP/1.1\r\n"
                                "Host: 127.0.0.1\r\n"
                                "Authorization: Bearer limit-nonce\r\n"
                                "Content-Length: 0\r\n\r\n";
    const auto refused_with = [&](std::uint16_t port, std::string_view reason) -> bool {
        const auto response = send_and_receive(port, request);
        const auto events = take();
        return response.starts_with("HTTP/1.1 429") && response.contains(reason) &&
               events.size() == 1 && !events[0].allowed && events[0].detail == reason;
    };

    // Two requests, then the third is refused.
    {
        auto endpoint = start({.max_requests = 2});
        REQUIRE(endpoint.has_value());
        const auto port = (*endpoint)->port();
        for (int index = 0; index != 2; ++index) {
            REQUIRE(send_and_receive(port, request).starts_with("HTTP/1.1 200"));
            const auto events = take();
            REQUIRE(events.size() == 2 && events[1].detail == "completed");
            REQUIRE(
                events[1].tokens_reported && events[1].input_tokens == 40 &&
                events[1].output_tokens == 10
            );
        }
        REQUIRE(refused_with(port, "request_limit"));
        REQUIRE(forwarded == 2);
    }
    // One per minute.
    {
        forwarded = 0;
        auto endpoint = start({.max_requests_per_minute = 1});
        REQUIRE(endpoint.has_value());
        const auto port = (*endpoint)->port();
        REQUIRE(send_and_receive(port, request).starts_with("HTTP/1.1 200"));
        static_cast<void>(take());
        REQUIRE(refused_with(port, "rate_limit"));
        REQUIRE(forwarded == 1);
    }
    // 50 tokens per exchange against a budget of 100: two pass, the third is
    // refused.
    {
        forwarded = 0;
        auto endpoint = start({.max_tokens = 100});
        REQUIRE(endpoint.has_value());
        const auto port = (*endpoint)->port();
        for (int index = 0; index != 2; ++index) {
            REQUIRE(send_and_receive(port, request).starts_with("HTTP/1.1 200"));
            static_cast<void>(take());
        }
        REQUIRE(refused_with(port, "token_limit"));
        REQUIRE(forwarded == 2);
    }
    return 0;
}

auto run() -> int {
    std::vector<glove::net::endpoint_event> recorded_events;

    glove::net::credentialed_endpoint_options options;
    options.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "api.anthropic.com",
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

    // The provider transport is injected, so the production path holds no
    // test-only behaviour. This stub records what the endpoint handed over so
    // the tests can assert what would reach a real provider.
    std::vector<glove::net::upstream_request> forwarded_requests;
    options.forward = [&](
                          const glove::net::upstream_request& request,
                          std::stop_token,
                          std::chrono::steady_clock::time_point
                      ) -> std::expected<glove::net::upstream_response, std::string> {
        forwarded_requests.push_back(request);
        glove::net::upstream_response response;
        response.status_code = 200;
        response.headers.emplace_back("Content-Type", "application/json");
        response.body = "{\"id\":\"msg_mock\",\"type\":\"message\",\"role\":\"assistant\","
                        "\"content\":[{\"type\":\"text\",\"text\":\"mock response\"}]}";
        return response;
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

    // The transport saw exactly one request, with the real credential, the
    // rewritten target, and none of the agent-supplied credential or routing
    // fields that the endpoint strips before forwarding.
    REQUIRE(forwarded_requests.size() == 1);
    {
        const auto& request = forwarded_requests.front();
        REQUIRE(request.upstream_host == "api.anthropic.com");
        REQUIRE(request.upstream_port == 443);
        REQUIRE(request.method == "POST");
        REQUIRE(request.target == "/v1/messages");
        REQUIRE(request.secret_token == "sk-ant-real-super-secret-token");
        for (const auto& [name, value] : request.headers) {
            REQUIRE(name != "x-api-key");
            REQUIRE(name != "authorization");
            REQUIRE(name != "host");
            REQUIRE(name != "content-length");
            REQUIRE(name != "connection");
        }
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
        // The query string is preserved on the forwarded target.
        REQUIRE(!forwarded_requests.empty());
        REQUIRE(forwarded_requests.back().target == "/v1/messages?beta=true");
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

    // With no provider transport configured, an otherwise-valid request must be
    // refused with 501 rather than silently stubbed: the production default has
    // no test-only shortcut.
    {
        glove::net::credentialed_endpoint_options no_transport;
        no_transport.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-real-super-secret-token",
            .session_nonce = "glove-nonce-abc123xyz",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/messages"},
        });
        auto bare = glove::net::start_credentialed_endpoint(std::move(no_transport));
        REQUIRE(bare.has_value());
        const auto resp = send_and_receive(
            (*bare)->port(),
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 501 Not Implemented"));
    }

    // Trust-boundary limits: the header count accepts exactly the cap and
    // rejects the next one, so an off-by-one cannot silently widen the bound.
    {
        const auto build = [](std::size_t filler) {
            std::string request = "POST /anthropic/v1/messages HTTP/1.1\r\n"
                                  "Host: 127.0.0.1\r\n"
                                  "x-api-key: glove-nonce-abc123xyz\r\n"
                                  "Content-Length: 0\r\n";
            for (std::size_t index = 0; index < filler; ++index) {
                request += "X-Fill-" + std::to_string(index) + ": v\r\n";
            }
            request += "\r\n";
            return request;
        };
        // 3 fixed headers plus 97 filler is exactly the cap of 100.
        REQUIRE(send_and_receive(port, build(97)).starts_with("HTTP/1.1 200 OK"));
        // The 101st header is over it.
        REQUIRE(send_and_receive(port, build(98)).starts_with("HTTP/1.1 400 Bad Request"));
    }

    // A control character inside a header value must be rejected by the
    // field-value check. The CR/LF cases above reach the framing check instead.
    {
        std::string request = "POST /anthropic/v1/messages HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\n"
                              "x-api-key: glove-nonce-abc123xyz\r\n"
                              "X-Ctl: a\x01"
                              "b\r\n"
                              "Content-Length: 0\r\n\r\n";
        REQUIRE(send_and_receive(port, request).starts_with("HTTP/1.1 400 Bad Request"));
    }

    // Content-Length cap boundary: the exact cap is accepted and the next value
    // is rejected. GET keeps the request off the body-reading path, so the
    // accepted case is decided by the parser rather than by the body.
    {
        const auto with_length = [](std::string_view length) {
            return "GET /anthropic/v1/messages HTTP/1.1\r\n"
                   "Host: 127.0.0.1\r\n"
                   "x-api-key: glove-nonce-abc123xyz\r\n"
                   "Content-Length: " +
                   std::string{length} + "\r\n\r\n";
        };
        REQUIRE(send_and_receive(port, with_length("8388608")).starts_with("HTTP/1.1 405 "));
        REQUIRE(send_and_receive(port, with_length("8388609")).starts_with("HTTP/1.1 400 "));
    }

    // A client that declares a body and never sends it must not stall the
    // worker or block shutdown: the body read is bounded, the request is
    // refused, and the transport is never invoked with a partial body.
    {
        bool stalled_transport_called = false;
        glove::net::credentialed_endpoint_options stalled;
        stalled.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-real-super-secret-token",
            .session_nonce = "glove-nonce-abc123xyz",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/messages"},
        });
        stalled.body_deadline_ms = 300;
        stalled.forward = [&](
                              const glove::net::upstream_request&,
                              std::stop_token,
                              std::chrono::steady_clock::time_point
                          ) -> std::expected<glove::net::upstream_response, std::string> {
            stalled_transport_called = true;
            glove::net::upstream_response response;
            response.status_code = 200;
            return response;
        };
        auto bounded = glove::net::start_credentialed_endpoint(std::move(stalled));
        REQUIRE(bounded.has_value());
        const auto resp = send_partial_and_receive(
            (*bounded)->port(),
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 10\r\n\r\n",
            5000
        );
        REQUIRE(resp.starts_with("HTTP/1.1 400 Bad Request"));
        REQUIRE(!stalled_transport_called);
    }

    // A transport response whose field value carries CRLF must not be copied
    // into the head we emit: the endpoint fails closed and injects nothing.
    {
        glove::net::credentialed_endpoint_options bad_upstream;
        bad_upstream.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-real-super-secret-token",
            .session_nonce = "glove-nonce-abc123xyz",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/messages"},
        });
        bad_upstream.forward = [](
                                   const glove::net::upstream_request&,
                                   std::stop_token,
                                   std::chrono::steady_clock::time_point
                               ) -> std::expected<glove::net::upstream_response, std::string> {
            glove::net::upstream_response response;
            response.status_code = 200;
            response.headers.emplace_back("X-Bad", "v\r\nContent-Length: 99");
            response.body = "x";
            return response;
        };
        auto guarded = glove::net::start_credentialed_endpoint(std::move(bad_upstream));
        REQUIRE(guarded.has_value());
        const auto resp = send_and_receive(
            (*guarded)->port(),
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 502 Bad Gateway"));
        REQUIRE(!resp.contains("Content-Length: 99"));
    }

    // A transport response with a mixed-case Connection field must still have
    // the named hop-by-hop field removed: HTTP field names are case-insensitive.
    {
        glove::net::credentialed_endpoint_options mixed;
        mixed.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-real-super-secret-token",
            .session_nonce = "glove-nonce-abc123xyz",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/messages"},
        });
        mixed.forward = [](
                            const glove::net::upstream_request&,
                            std::stop_token,
                            std::chrono::steady_clock::time_point
                        ) -> std::expected<glove::net::upstream_response, std::string> {
            glove::net::upstream_response response;
            response.status_code = 200;
            response.headers.emplace_back("Connection", "X-Hop");
            response.headers.emplace_back("X-Hop", "must-not-be-forwarded");
            response.body = "ok";
            return response;
        };
        auto case_insensitive = glove::net::start_credentialed_endpoint(std::move(mixed));
        REQUIRE(case_insensitive.has_value());
        const auto resp = send_and_receive(
            (*case_insensitive)->port(),
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 200 OK"));
        REQUIRE(!resp.contains("must-not-be-forwarded"));
    }

    // A status that cannot be a final response must be refused, not serialized.
    {
        glove::net::credentialed_endpoint_options bad_status;
        bad_status.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-real-super-secret-token",
            .session_nonce = "glove-nonce-abc123xyz",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/messages"},
        });
        bad_status.forward = [](
                                 const glove::net::upstream_request&,
                                 std::stop_token,
                                 std::chrono::steady_clock::time_point
                             ) -> std::expected<glove::net::upstream_response, std::string> {
            glove::net::upstream_response response;
            response.status_code = 100;
            return response;
        };
        auto refused = glove::net::start_credentialed_endpoint(std::move(bad_status));
        REQUIRE(refused.has_value());
        const auto resp = send_and_receive(
            (*refused)->port(),
            "POST /anthropic/v1/messages HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-abc123xyz\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 502 Bad Gateway"));
    }

    REQUIRE(!recorded_events.empty());

    // A client-placed rule forwards the secret in the field where the client
    // presented the nonce, for each supported credential header.
    {
        glove::net::credentialed_endpoint_options placed;
        placed.endpoints.push_back({
            .provider = glove::net::endpoint_provider::client_placed,
            .path_prefix = "/p/google",
            .upstream_host = "generativelanguage.googleapis.com",
            .upstream_port = 443,
            .secret_token = "google-host-secret",
            .session_nonce = "glove-nonce-placed",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1beta/models/*"},
        });
        std::vector<glove::net::upstream_request> seen;
        placed.forward = [&](
                             const glove::net::upstream_request& request,
                             std::stop_token,
                             std::chrono::steady_clock::time_point
                         ) -> std::expected<glove::net::upstream_response, std::string> {
            seen.push_back(request);
            glove::net::upstream_response response;
            response.status_code = 200;
            response.body = "{}";
            return response;
        };
        auto placed_endpoint = glove::net::start_credentialed_endpoint(std::move(placed));
        REQUIRE(placed_endpoint.has_value());
        const auto placed_port = (*placed_endpoint)->port();
        const std::string target =
            "POST /p/google/v1beta/models/m:streamGenerateContent?alt=sse HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n";
        for (const auto& [field, line] : std::vector<std::pair<std::string, std::string>>{
                 {"x-goog-api-key", "x-goog-api-key: glove-nonce-placed\r\n"},
                 {"x-api-key", "x-api-key: glove-nonce-placed\r\n"},
                 {"authorization", "Authorization: Bearer glove-nonce-placed\r\n"},
             }) {
            const auto resp =
                send_and_receive(placed_port, target + line + "Content-Length: 0\r\n\r\n");
            REQUIRE(resp.starts_with("HTTP/1.1 200 OK"));
            REQUIRE(!seen.empty());
            REQUIRE(seen.back().credential_field == field);
            REQUIRE(seen.back().secret_token == "google-host-secret");
            REQUIRE(seen.back().target == "/v1beta/models/m:streamGenerateContent?alt=sse");
            for (const auto& [name, value] : seen.back().headers) {
                REQUIRE(name != "x-goog-api-key");
                REQUIRE(value.find("glove-nonce-placed") == std::string::npos);
            }
        }
        const auto before = seen.size();
        const auto wrong = send_and_receive(
            placed_port, target + "x-goog-api-key: other\r\nContent-Length: 0\r\n\r\n"
        );
        REQUIRE(wrong.starts_with("HTTP/1.1 401 Unauthorized"));
        const auto both = send_and_receive(
            placed_port,
            target + "x-goog-api-key: glove-nonce-placed\r\nx-api-key: glove-nonce-placed\r\n"
                     "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(!both.starts_with("HTTP/1.1 200 OK"));
        REQUIRE(seen.size() == before);
    }

    // `stem/*:suffix` admits one non-empty segment that ends in the suffix.
    {
        glove::net::credentialed_endpoint_options methods;
        methods.endpoints.push_back({
            .provider = glove::net::endpoint_provider::client_placed,
            .path_prefix = "/p/google",
            .upstream_host = "generativelanguage.googleapis.com",
            .upstream_port = 443,
            .secret_token = "google-host-secret",
            .session_nonce = "glove-nonce-methods",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1beta/models/*:generateContent"},
        });
        std::size_t forwarded = 0;
        methods.forward = [&](
                              const glove::net::upstream_request&,
                              std::stop_token,
                              std::chrono::steady_clock::time_point
                          ) -> std::expected<glove::net::upstream_response, std::string> {
            ++forwarded;
            glove::net::upstream_response response;
            response.status_code = 200;
            response.body = "{}";
            return response;
        };
        auto methods_endpoint = glove::net::start_credentialed_endpoint(std::move(methods));
        REQUIRE(methods_endpoint.has_value());
        const auto methods_port = (*methods_endpoint)->port();
        const auto post = [&](const std::string& path) {
            return send_and_receive(
                methods_port,
                "POST /p/google" + path +
                    " HTTP/1.1\r\nHost: 127.0.0.1\r\nx-goog-api-key: glove-nonce-methods\r\n"
                    "Content-Length: 0\r\n\r\n"
            );
        };
        REQUIRE(
            post("/v1beta/models/gemini-2.5-flash:generateContent").starts_with("HTTP/1.1 200")
        );
        for (const std::string path : {
                 "/v1beta/models/m:predict",
                 "/v1beta/models/a/b:generateContent",
                 "/v1beta/models/:generateContent",
                 "/v1beta/models/m:generateContentX",
                 "/v1beta/models/m",
             }) {
            REQUIRE(!post(path).starts_with("HTTP/1.1 200"));
        }
        REQUIRE(forwarded == 1);
    }
    return 0;
}

auto canary_exfiltration() -> int {
    // Reject invalid/too-short canary tokens fail-closed at startup.
    {
        glove::net::credentialed_endpoint_options bad;
        bad.canary_tokens = {"short"};
        auto res = glove::net::start_credentialed_endpoint(std::move(bad));
        REQUIRE(!res.has_value());
        REQUIRE(res.error().find("shorter than minimum") != std::string::npos);
    }

    std::vector<glove::net::endpoint_event> events;
    std::size_t forwarded = 0;

    glove::net::credentialed_endpoint_options opts;
    opts.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "api.anthropic.com",
        .upstream_port = 443,
        .secret_token = "sk-ant-host-secret-99887766",
        .session_nonce = "glove-nonce-canary",
        .allowed_methods = {"POST"},
        .allowed_paths = {"/v1/*"},
    });
    opts.canary_tokens = {"CANARY-DECOY-ALPHA-1234", "CANARY-DECOY-BETA-5678"};
    opts.on_event = [&](const glove::net::endpoint_event& ev) -> std::expected<void, std::string> {
        events.push_back(ev);
        return {};
    };
    opts.forward = [&](
                       const glove::net::upstream_request&,
                       std::stop_token,
                       std::chrono::steady_clock::time_point
                   ) -> std::expected<glove::net::upstream_response, std::string> {
        ++forwarded;
        glove::net::upstream_response response;
        response.status_code = 200;
        response.body = R"({"ok":true})";
        return response;
    };

    auto ep = glove::net::start_credentialed_endpoint(std::move(opts));
    REQUIRE(ep.has_value());
    const auto port = (*ep)->port();

    // 1. Benign request passes through.
    {
        const std::string body = R"({"prompt":"summarize README.md"})";
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-canary\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\n\r\n" + body
        );
        REQUIRE(resp.starts_with("HTTP/1.1 200"));
        REQUIRE(forwarded == 1);
    }

    // 2. Planted canary in request body is blocked with 403 and never forwarded.
    {
        const std::string body = R"({"prompt":"here is CANARY-DECOY-ALPHA-1234"})";
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-canary\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\n\r\n" + body
        );
        REQUIRE(resp.starts_with("HTTP/1.1 403 Forbidden"));
        REQUIRE(forwarded == 1);
        REQUIRE(
            !events.empty() && !events.back().allowed &&
            events.back().detail == "canary_exfiltration"
        );
    }

    // 3. Planted canary in custom header is blocked with 403.
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "x-api-key: glove-nonce-canary\r\nX-Exfil: CANARY-DECOY-BETA-5678\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 403 Forbidden"));
        REQUIRE(forwarded == 1);
        REQUIRE(events.back().detail == "canary_exfiltration");
    }

    // 4. Host rule secret_token smuggled in query string is also blocked.
    {
        const auto resp = send_and_receive(
            port,
            "POST /anthropic/v1/messages?q=sk-ant-host-secret-99887766 HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\nx-api-key: glove-nonce-canary\r\nContent-Length: 0\r\n\r\n"
        );
        REQUIRE(resp.starts_with("HTTP/1.1 403 Forbidden"));
        REQUIRE(forwarded == 1);
        REQUIRE(events.back().detail == "canary_exfiltration");
    }

    // 5. Single-pattern fast path (only rule secret_token, no extra canaries).
    {
        std::size_t single_forwarded = 0;
        glove::net::credentialed_endpoint_options single_opts;
        single_opts.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-single-only-123456",
            .session_nonce = "glove-nonce-single",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/*"},
        });
        single_opts.forward = [&](
                                  const glove::net::upstream_request&,
                                  std::stop_token,
                                  std::chrono::steady_clock::time_point
                              ) -> std::expected<glove::net::upstream_response, std::string> {
            ++single_forwarded;
            return glove::net::upstream_response{
                .status_code = 200, .body = R"({"ok":true})", .headers = {}
            };
        };
        auto single_ep = glove::net::start_credentialed_endpoint(std::move(single_opts));
        REQUIRE(single_ep.has_value());
        const auto sp = (*single_ep)->port();

        const std::string ok_body = R"({"prompt":"clean text"})";
        REQUIRE(send_and_receive(
                    sp,
                    "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "x-api-key: glove-nonce-single\r\nContent-Length: " +
                        std::to_string(ok_body.size()) + "\r\n\r\n" + ok_body
        )
                    .starts_with("HTTP/1.1 200"));
        REQUIRE(single_forwarded == 1);

        const std::string leak_body = R"({"prompt":"leak sk-ant-single-only-123456 here"})";
        REQUIRE(send_and_receive(
                    sp,
                    "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "x-api-key: glove-nonce-single\r\nContent-Length: " +
                        std::to_string(leak_body.size()) + "\r\n\r\n" + leak_body
        )
                    .starts_with("HTTP/1.1 403 Forbidden"));
        REQUIRE(single_forwarded == 1);
    }

    // 6. Common-first-byte multi-pattern path with partial-prefix restart.
    {
        std::size_t common_forwarded = 0;
        glove::net::credentialed_endpoint_options common_opts;
        common_opts.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-unused",
            .session_nonce = "glove-nonce-common",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/*"},
        });
        common_opts.scan_rule_secrets = false;
        common_opts.canary_tokens = {"CANARY-ALPHA-1234", "CANARY-BETA-5678"};
        common_opts.forward = [&](
                                  const glove::net::upstream_request&,
                                  std::stop_token,
                                  std::chrono::steady_clock::time_point
                              ) -> std::expected<glove::net::upstream_response, std::string> {
            ++common_forwarded;
            return glove::net::upstream_response{
                .status_code = 200, .body = R"({"ok":true})", .headers = {}
            };
        };
        auto common_ep = glove::net::start_credentialed_endpoint(std::move(common_opts));
        REQUIRE(common_ep.has_value());
        const auto cp = (*common_ep)->port();

        const std::string restart_body = R"({"prompt":"CANARY-ACANARY-BETA-5678"})";
        REQUIRE(send_and_receive(
                    cp,
                    "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "x-api-key: glove-nonce-common\r\nContent-Length: " +
                        std::to_string(restart_body.size()) + "\r\n\r\n" + restart_body
        )
                    .starts_with("HTTP/1.1 403 Forbidden"));
        REQUIRE(common_forwarded == 0);
    }

    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = outcome_events(); failed != 0) {
        return failed;
    }
    if (const int failed = limits(); failed != 0) {
        return failed;
    }
    if (const int failed = canary_exfiltration(); failed != 0) {
        return failed;
    }
    return run();
}
