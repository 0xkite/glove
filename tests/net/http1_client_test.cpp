#include "src/net/http1_client.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::net::byte_stream;
using glove::net::upstream_request;
using glove::net::upstream_response;
using glove::net::http::credential_scheme;
using glove::net::http::read_response;
using glove::net::http::serialize_request;

// Replays a scripted response in fixed-size pieces, so every parser boundary
// (status line, field, chunk header, CRLF) is crossed mid-read.
class scripted_stream final : public byte_stream {
public:
    scripted_stream(std::string script, std::size_t piece)
        : script_{std::move(script)}, piece_{piece} {}

    auto write_all(std::string_view data, std::stop_token /*stop*/, deadline /*until*/)
        -> std::expected<void, std::string> override {
        written_ += data;
        return {};
    }

    auto read_some(std::span<char> into, std::stop_token /*stop*/, deadline /*until*/)
        -> std::expected<std::size_t, std::string> override {
        const auto count = std::min({into.size(), piece_, script_.size() - offset_});
        std::memcpy(into.data(), script_.data() + offset_, count);
        offset_ += count;
        return count;
    }

private:
    std::string script_;
    std::size_t piece_;
    std::size_t offset_ = 0;
    std::string written_;
};

// A plain socket under the real poll-based deadline, for the timing cases.
class socket_stream final : public byte_stream {
public:
    explicit socket_stream(int fd) : fd_{fd} {}

    socket_stream(const socket_stream&) = delete;
    socket_stream& operator=(const socket_stream&) = delete;
    socket_stream(socket_stream&&) = delete;
    socket_stream& operator=(socket_stream&&) = delete;

    ~socket_stream() override { ::close(fd_); }

    auto write_all(std::string_view /*data*/, std::stop_token /*stop*/, deadline /*until*/)
        -> std::expected<void, std::string> override {
        return {};
    }

    auto read_some(std::span<char> into, std::stop_token stop, deadline until)
        -> std::expected<std::size_t, std::string> override {
        while (!stop.stop_requested()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= until) {
                return std::unexpected(std::string{"read: deadline exceeded"});
            }
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 20) > 0) {
                const auto got = ::read(fd_, into.data(), into.size());
                if (got < 0) {
                    return std::unexpected(std::string{"read failed"});
                }
                return static_cast<std::size_t>(got);
            }
        }
        return std::unexpected(std::string{"read: cancelled"});
    }

private:
    int fd_;
};

auto parse(std::string script, std::string_view method = "POST", std::size_t piece = 1)
    -> std::expected<upstream_response, std::string> {
    scripted_stream stream{std::move(script), piece};
    return read_response(
        stream,
        method,
        std::stop_token{},
        std::chrono::steady_clock::now() + std::chrono::seconds{5}
    );
}

auto header(const upstream_response& response, std::string_view name) -> std::string {
    for (const auto& [field, value] : response.headers) {
        if (field == name) {
            return value;
        }
    }
    return {};
}

auto framing_cases() -> int {
    // Content-Length, read one byte at a time.
    {
        auto response = parse(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
            "{\"ok\":true}"
        );
        REQUIRE(response);
        REQUIRE(response->status_code == 200);
        REQUIRE(response->body == "{\"ok\":true}");
        REQUIRE(header(*response, "Content-Type") == "application/json");
    }
    // Chunked with an extension and trailers; trailers are dropped.
    {
        auto response = parse(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5;name=value\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\nX-Trailer: dropped\r\n\r\n",
            "POST",
            3
        );
        REQUIRE(response);
        REQUIRE(response->body == "hello world");
        REQUIRE(header(*response, "X-Trailer").empty());
    }
    // Interim responses are skipped.
    {
        auto response = parse(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
            "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
        );
        REQUIRE(response);
        REQUIRE(response->status_code == 201);
        REQUIRE(response->body == "ok");
    }
    // No body for 204, 304, or HEAD even if a length is declared.
    {
        auto no_content = parse("HTTP/1.1 204 No Content\r\n\r\n");
        REQUIRE(no_content);
        REQUIRE(no_content->body.empty());
        auto head = parse("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", "HEAD");
        REQUIRE(head);
        REQUIRE(head->body.empty());
    }
    // An empty reason phrase is valid as long as the separator is present.
    {
        auto response = parse("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n");
        REQUIRE(response);
        REQUIRE(response->status_code == 200);
    }
    // Exactly the interim budget is accepted; one more is refused below.
    {
        std::string interim;
        for (int index = 0; index < 8; ++index) {
            interim += "HTTP/1.1 100 Continue\r\n\r\n";
        }
        auto response =
            parse(interim + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "POST", 4096);
        REQUIRE(response);
    }
    // Redirects are returned, not followed.
    {
        auto response = parse(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://evil.test/\r\n"
            "Content-Length: 0\r\n\r\n"
        );
        REQUIRE(response);
        REQUIRE(response->status_code == 307);
    }
    return 0;
}

auto rejection_cases() -> int {
    // Framing ambiguities.
    REQUIRE(!parse(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
        "0\r\n\r\n"
    ));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nx"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"));
    // Malformed chunks.
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhi\r\n0\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXX0\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n"));
    // An unframed body could be a truncated one, so it is refused.
    REQUIRE(!parse("HTTP/1.1 200 OK\r\n\r\nuntil close", "POST", 4));
    // Truncation is an error, not a short body.
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"));
    // Head syntax.
    REQUIRE(!parse("HTTP/2 200 OK\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 20 OK\r\n\r\n"));
    // The SP after the status code is mandatory.
    REQUIRE(!parse("HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nX-Smuggle: a\nb\r\n\r\n"));
    REQUIRE(!parse("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"));
    // Size caps.
    REQUIRE(!parse("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n"));
    REQUIRE(!parse(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\n", "POST", 64
    ));
    REQUIRE(
        !parse("HTTP/1.1 200 OK\r\nX-Big: " + std::string(20000, 'a') + "\r\n\r\n", "POST", 4096)
    );
    {
        std::string many = "HTTP/1.1 200 OK\r\n";
        for (int index = 0; index < 101; ++index) {
            many += "X-" + std::to_string(index) + ": v\r\n";
        }
        REQUIRE(!parse(many + "Content-Length: 0\r\n\r\n", "POST", 4096));
    }
    {
        std::string interim;
        for (int index = 0; index < 9; ++index) {
            interim += "HTTP/1.1 100 Continue\r\n\r\n";
        }
        REQUIRE(!parse(interim + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "POST", 4096));
    }
    return 0;
}

auto timing_cases() -> int {
    // A peer that never answers is bounded by the deadline.
    {
        std::array<int, 2> fds{};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
        socket_stream stream{fds[0]};
        const auto started = std::chrono::steady_clock::now();
        auto response = read_response(
            stream, "POST", std::stop_token{}, started + std::chrono::milliseconds{200}
        );
        REQUIRE(!response);
        REQUIRE(response.error().find("deadline") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds{2});
        ::close(fds[1]);
    }
    // A stop request ends the wait well before the deadline.
    {
        std::array<int, 2> fds{};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0);
        socket_stream stream{fds[0]};
        std::stop_source source;
        std::jthread stopper{[&source] {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            source.request_stop();
        }};
        const auto started = std::chrono::steady_clock::now();
        auto response =
            read_response(stream, "POST", source.get_token(), started + std::chrono::seconds{30});
        REQUIRE(!response);
        REQUIRE(response.error().find("cancelled") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds{5});
        ::close(fds[1]);
    }
    return 0;
}

auto serialization_cases() -> int {
    upstream_request request;
    request.provider = glove::net::endpoint_provider::anthropic;
    request.upstream_host = "api.anthropic.com";
    request.upstream_port = 443;
    request.method = "POST";
    request.target = "/v1/messages?beta=true";
    request.headers = {{"content-type", "application/json"}, {"anthropic-version", "2023-06-01"}};
    request.body = R"({"model":"x"})";
    request.secret_token = "sk-ant-secret";

    auto wire = serialize_request(request, credential_scheme::x_api_key);
    REQUIRE(wire);
    REQUIRE(
        wire->starts_with("POST /v1/messages?beta=true HTTP/1.1\r\nHost: api.anthropic.com\r\n")
    );
    REQUIRE(wire->find("x-api-key: sk-ant-secret\r\n") != std::string::npos);
    REQUIRE(wire->find("Content-Length: 13\r\n") != std::string::npos);
    REQUIRE(wire->find("Connection: close\r\n\r\n{\"model\":\"x\"}") != std::string::npos);
    REQUIRE(wire->find("Expect") == std::string::npos);
    REQUIRE(wire->find("Authorization") == std::string::npos);

    auto bearer = serialize_request(request, credential_scheme::bearer);
    REQUIRE(bearer);
    REQUIRE(bearer->find("Authorization: Bearer sk-ant-secret\r\n") != std::string::npos);
    REQUIRE(bearer->find("x-api-key") == std::string::npos);

    request.upstream_port = 8443;
    auto ported = serialize_request(request, credential_scheme::x_api_key);
    REQUIRE(ported);
    REQUIRE(ported->find("Host: api.anthropic.com:8443\r\n") != std::string::npos);
    request.upstream_port = 443;

    // Anything that could frame an extra line is refused, and the secret is
    // never echoed back in the error.
    auto bad_secret = request;
    bad_secret.secret_token = "sk-ant-secret\r\nX-Injected: 1";
    auto refused = serialize_request(bad_secret, credential_scheme::x_api_key);
    REQUIRE(!refused);
    REQUIRE(refused.error().find("sk-ant") == std::string::npos);

    auto bad_header = request;
    bad_header.headers.emplace_back("x-ok", "a\r\nHost: evil.test");
    REQUIRE(!serialize_request(bad_header, credential_scheme::x_api_key));

    auto bad_target = request;
    bad_target.target = "/v1/messages HTTP/1.1\r\nHost: evil";
    REQUIRE(!serialize_request(bad_target, credential_scheme::x_api_key));

    auto tab_target = request;
    tab_target.target = "/v1/messages\tHTTP/1.1";
    REQUIRE(!serialize_request(tab_target, credential_scheme::x_api_key));
    auto high_target = request;
    high_target.target = "/v1/\xc3\xa9";
    REQUIRE(!serialize_request(high_target, credential_scheme::x_api_key));

    // Fields the transport owns are refused, never emitted twice.
    for (const char* owned :
         {"Host",
          "content-length",
          "Transfer-Encoding",
          "connection",
          "x-api-key",
          "Authorization",
          "expect"}) {
        auto duplicate = request;
        duplicate.headers.emplace_back(owned, "1");
        REQUIRE(!serialize_request(duplicate, credential_scheme::x_api_key));
    }

    auto bad_method = request;
    bad_method.method = "PO ST";
    REQUIRE(!serialize_request(bad_method, credential_scheme::x_api_key));

    auto empty_secret = request;
    empty_secret.secret_token.clear();
    REQUIRE(!serialize_request(empty_secret, credential_scheme::x_api_key));
    return 0;
}

auto run() -> int {
    if (const int failed = framing_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = rejection_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = timing_cases(); failed != 0) {
        return failed;
    }
    return serialization_cases();
}

} // namespace

auto main() -> int {
    const int result = run();
    if (result == 0) {
        std::puts("http1_client: all checks passed");
    }
    return result;
}
