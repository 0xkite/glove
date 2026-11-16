#include "glove/container/profile.hpp"

#include "src/net/egress_connect_parser.hpp"
#include "src/net/http_syntax.hpp"

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kSamples = 10;
constexpr std::size_t kIterations = 2000;
constexpr std::size_t kWarmup = 200;

template<typename Fn> void run_bench(std::string_view name, Fn&& fn) {
    std::uint64_t checksum = 0;
    for (std::size_t i = 0; i < kWarmup; ++i) {
        checksum += fn();
    }
    std::vector<double> samples_ns;
    samples_ns.reserve(kSamples);
    for (std::size_t s = 0; s < kSamples; ++s) {
        const auto t0 = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < kIterations; ++i) {
            checksum += fn();
        }
        const auto dt = std::chrono::steady_clock::now() - t0;
        const double ns = std::chrono::duration<double, std::nano>{dt}.count();
        samples_ns.push_back(ns / static_cast<double>(kIterations));
    }
    const double mean =
        std::accumulate(samples_ns.begin(), samples_ns.end(), 0.0) / static_cast<double>(kSamples);
    double sq = 0.0;
    for (double x : samples_ns) {
        sq += (x - mean) * (x - mean);
    }
    const double stddev = std::sqrt(sq / static_cast<double>(kSamples - 1U));
    const double margin = 1.959963984540054 * (stddev / std::sqrt(static_cast<double>(kSamples)));
    std::printf(
        "{\"benchmark\":\"%.*s\",\"latency_ns_mean\":%.2f,\"latency_ns_stddev\":%.2f,"
        "\"ci95\":[%.2f,%.2f],\"ops_per_sec\":%.1f,\"checksum\":%llu}\n",
        static_cast<int>(name.size()),
        name.data(),
        mean,
        stddev,
        mean - margin,
        mean + margin,
        1e9 / mean,
        static_cast<unsigned long long>(checksum)
    );
}

} // namespace

auto main() -> int {
    const std::string connect_req =
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n"
        "User-Agent: glove-test\r\nProxy-Authorization: Basic dGVzdDp0b2tlbg==\r\n\r\n";

    run_bench("net.egress_connect.parse_and_auth", [&]() -> std::uint64_t {
        std::string host;
        std::uint16_t port = 0;
        const bool ok = glove::net::detail::parse_connect(connect_req, host, port);
        const bool auth = glove::net::detail::authenticated(connect_req, "Basic dGVzdDp0b2tlbg==");
        return (ok && auth) ? port : 0U;
    });

    run_bench("net.http_syntax.header_validate", [&]() -> std::uint64_t {
        const bool t = glove::net::http::is_token("x-anthropic-version");
        const bool v = glove::net::http::is_valid_field_value("2023-06-01");
        const auto len = glove::net::http::parse_content_length("4096", 8U * 1024U * 1024U);
        return (t && v && len) ? *len : 0U;
    });

    glove::container::profile sample_profile;
    sample_profile.filesystem = {
        {.path = "/tmp/bench-ws", .writable = true},
        {.path = "/usr/local/share/tool-a", .writable = false},
        {.path = "/usr/local/share/tool-b", .writable = false},
        {.path = "/usr/local/share/tool-c", .writable = false},
        {.path = "/usr/local/share/tool-d", .writable = false},
    };
    sample_profile.runtime_filesystem = {
        {.path = "/opt/runtime/a", .writable = false},
        {.path = "/opt/runtime/b", .writable = false},
    };
    sample_profile.environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"};
    sample_profile.home_dir = "/tmp/bench-ws";
    sample_profile.work_dir = "/tmp/bench-ws";

    run_bench("container.profile.validate", [&]() -> std::uint64_t {
        auto out = glove::container::validate(sample_profile);
        return out ? out->filesystem.size() : 0U;
    });
    return 0;
}
