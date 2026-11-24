#include "glove/container/denial_decision.hpp"
#include "glove/container/profile.hpp"
#include "glove/net/credentialed_endpoint.hpp"

#include "src/net/canary_scanner.hpp"
#include "src/net/egress_connect_parser.hpp"
#include "src/net/http_syntax.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

    const std::vector<std::string> single_canary = {"sk-ant-api03-canary-secret-token-0001"};
    std::vector<std::string> sixty_four_canaries;
    std::vector<std::string> diverse_canaries;
    sixty_four_canaries.reserve(64);
    diverse_canaries.reserve(64);
    constexpr std::string_view prefix_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (std::size_t i = 0; i < 64; ++i) {
        sixty_four_canaries.push_back("CANARY-TOKEN-PROJECT-SECRET-" + std::to_string(100000 + i));
        std::string tok(1, prefix_chars[i % prefix_chars.size()]);
        tok += "-CANARY-SECRET-" + std::to_string(100000 + i);
        diverse_canaries.push_back(std::move(tok));
    }

    auto single_scanner = glove::net::detail::canary_scanner::build(single_canary);
    auto multi_scanner = glove::net::detail::canary_scanner::build(sixty_four_canaries);
    auto diverse_scanner = glove::net::detail::canary_scanner::build(diverse_canaries);

    const std::string payload_1k(1024, 'a');
    std::string payload_64k(64U * 1024U, 'b');
    for (std::size_t i = 0; i < payload_64k.size(); i += 97) {
        payload_64k[i] = 'C';
    }
    std::string payload_1m(1024U * 1024U, 'x');
    for (std::size_t i = 0; i < payload_1m.size(); i += 131) {
        payload_1m[i] = 's';
    }

    run_bench("net.canary_scanner.build_64_tokens", [&]() -> std::uint64_t {
        auto s = glove::net::detail::canary_scanner::build(sixty_four_canaries);
        return (s && !s->empty()) ? 1U : 0U;
    });

    run_bench("net.canary_scanner.scan_1kb_1tok", [&]() -> std::uint64_t {
        return single_scanner->contains_any(payload_1k) ? 1U : 0U;
    });

    run_bench("net.canary_scanner.scan_64kb_1tok", [&]() -> std::uint64_t {
        return single_scanner->contains_any(payload_64k) ? 1U : 0U;
    });

    run_bench("net.canary_scanner.scan_1kb_64tok", [&]() -> std::uint64_t {
        return multi_scanner->contains_any(payload_1k) ? 1U : 0U;
    });

    run_bench("net.canary_scanner.scan_64kb_64tok", [&]() -> std::uint64_t {
        return multi_scanner->contains_any(payload_64k) ? 1U : 0U;
    });

    run_bench("net.canary_scanner.scan_64kb_64tok_diverse", [&]() -> std::uint64_t {
        return diverse_scanner->contains_any(payload_64k) ? 1U : 0U;
    });

    // Realistic mixed-provider 16-token set (diverse first bytes, e.g. sk-, ghp_, AKIA, AIza,
    // xoxb).
    const std::vector<std::string> mixed_provider_canaries = {
        "sk-ant-api03-canary-0001",
        "sk-proj-canary-secret-02",
        "ghp_canaryTokenGitHub03",
        "gho_canaryTokenOAuth004",
        "AKIAIOSFODNN7CANARY005",
        "AIzaSyCanaryGoogleKey06",
        "xoxb-canary-slack-bot-7",
        "xoxp-canary-slack-usr-8",
        "glpat-canaryGitLabTok09",
        "npm_canaryNpmToken00010",
        "pypi-canaryPyPiToken011",
        "hf_canaryHuggingFace012",
        "r8_canaryReplicateTok13",
        "pk_live_canaryStripe014",
        "whsec_canaryWebhook0015",
        "CANARY-DECOY-HOST-00016",
    };
    auto mixed_scanner = glove::net::detail::canary_scanner::build(mixed_provider_canaries);

    run_bench("net.canary_scanner.scan_64kb_16tok_mixed", [&]() -> std::uint64_t {
        return mixed_scanner->contains_any(payload_64k) ? 1U : 0U;
    });

    // Denial feature builder + heuristic decider benchmark (Target 3 baseline).
    const std::vector<std::string> denial_roots{"/tmp/bench-ws"};
    const std::vector<std::string> denial_decoys{"/Users/bench/.ssh/decoy_id"};
    const auto denial_ctx =
        glove::container::make_denial_context(denial_roots, "/Users/bench", denial_decoys);
    const glove::container::sandbox_denial sample_denial{
        .kind = "file_read",
        .operation = "file-read-data",
        .target = "/Users/bench/.ssh/id_ed25519",
        .target_truncated = false,
        .comm = "python3",
        .pid = 4242,
        .duplicate_reports = 0,
        .readings = 1,
    };
    auto decider = glove::container::make_heuristic_denial_decider();
    glove::container::denial_feature_builder builder{denial_ctx};
    for (int i = 0; i < 32; ++i) {
        builder.observe(sample_denial, std::chrono::milliseconds{i * 100});
    }

    run_bench("container.denial_decision.observe_and_score", [&]() -> std::uint64_t {
        glove::container::denial_feature_builder local_builder{denial_ctx};
        local_builder.observe(sample_denial, std::chrono::milliseconds{100});
        const auto feats = local_builder.features(std::chrono::milliseconds{200});
        const auto decision = decider->decide(feats);
        return static_cast<std::uint64_t>(decision.verdict);
    });

    run_bench("container.denial_decision.features_and_decide", [&]() -> std::uint64_t {
        const auto feats = builder.features(std::chrono::milliseconds{4000});
        const auto decision = decider->decide(feats);
        return static_cast<std::uint64_t>(decision.verdict);
    });

    // End-to-end credentialed_endpoint loopback HTTP/1.1 round-trip with stub forwarder
    // (1 KB body, canary scanner enabled).
    {
        glove::net::credentialed_endpoint_options ep_opts;
        ep_opts.endpoints.push_back({
            .provider = glove::net::endpoint_provider::anthropic,
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .upstream_port = 443,
            .secret_token = "sk-ant-bench-host-secret-99887766",
            .session_nonce = "glove-bench-nonce-0001",
            .allowed_methods = {"POST"},
            .allowed_paths = {"/v1/*"},
        });
        ep_opts.canary_tokens = mixed_provider_canaries;
        ep_opts.forward = [](
                              const glove::net::upstream_request&,
                              std::stop_token,
                              std::chrono::steady_clock::time_point
                          ) -> std::expected<glove::net::upstream_response, std::string> {
            return glove::net::upstream_response{
                .status_code = 200,
                .body = R"({"ok":true,"usage":{"input_tokens":10,"output_tokens":5}})",
                .headers = {{"Content-Type", "application/json"}},
            };
        };
        auto ep = glove::net::start_credentialed_endpoint(std::move(ep_opts));
        if (ep) {
            const std::uint16_t port = (*ep)->port();
            const std::string req = "POST /anthropic/v1/messages HTTP/1.1\r\n"
                                    "Host: 127.0.0.1\r\n"
                                    "x-api-key: glove-bench-nonce-0001\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: " +
                                    std::to_string(payload_1k.size()) + "\r\n\r\n" + payload_1k;

            auto do_http = [&]() -> std::uint64_t {
                const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) {
                    return 0U;
                }
                ::sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                if (::connect(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0) {
                    ::close(fd);
                    return 0U;
                }
                std::size_t sent = 0;
                while (sent < req.size()) {
                    const auto n = ::send(fd, req.data() + sent, req.size() - sent, 0);
                    if (n <= 0) {
                        break;
                    }
                    sent += static_cast<std::size_t>(n);
                }
                char buf[512];
                std::size_t total = 0;
                for (;;) {
                    const auto n = ::recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        break;
                    }
                    total += static_cast<std::size_t>(n);
                }
                ::close(fd);
                return total;
            };

            constexpr std::size_t kHttpIters = 50;
            for (std::size_t w = 0; w < 10; ++w) {
                (void)do_http();
            }
            std::vector<double> samples_ns;
            samples_ns.reserve(kSamples);
            std::uint64_t checksum = 0;
            for (std::size_t s = 0; s < kSamples; ++s) {
                const auto t0 = std::chrono::steady_clock::now();
                for (std::size_t i = 0; i < kHttpIters; ++i) {
                    checksum += do_http();
                }
                const auto dt = std::chrono::steady_clock::now() - t0;
                samples_ns.push_back(
                    std::chrono::duration<double, std::nano>{dt}.count() /
                    static_cast<double>(kHttpIters)
                );
            }
            const double mean = std::accumulate(samples_ns.begin(), samples_ns.end(), 0.0) /
                                static_cast<double>(kSamples);
            std::printf(
                "{\"benchmark\":\"net.credentialed_endpoint.roundtrip_1kb\",\"latency_ns_mean\":%."
                "2f,"
                "\"ops_per_sec\":%.1f,\"checksum\":%llu}\n",
                mean,
                1e9 / mean,
                static_cast<unsigned long long>(checksum)
            );
        }
    }

    // 1 MB scan: use fewer inner iterations to keep total runtime fast.
    {
        constexpr std::size_t kLargeIters = 100;
        std::vector<double> samples_ns;
        samples_ns.reserve(kSamples);
        std::uint64_t checksum = 0;
        for (std::size_t s = 0; s < kSamples; ++s) {
            const auto t0 = std::chrono::steady_clock::now();
            for (std::size_t i = 0; i < kLargeIters; ++i) {
                checksum += multi_scanner->contains_any(payload_1m) ? 1U : 0U;
            }
            const auto dt = std::chrono::steady_clock::now() - t0;
            samples_ns.push_back(
                std::chrono::duration<double, std::nano>{dt}.count() /
                static_cast<double>(kLargeIters)
            );
        }
        const double mean = std::accumulate(samples_ns.begin(), samples_ns.end(), 0.0) /
                            static_cast<double>(kSamples);
        std::printf(
            "{\"benchmark\":\"net.canary_scanner.scan_1mb_64tok\",\"latency_ns_mean\":%.2f,"
            "\"throughput_mb_s\":%.1f,\"checksum\":%llu}\n",
            mean,
            (1.0 / (mean * 1e-9)),
            static_cast<unsigned long long>(checksum)
        );
    }
    return 0;
}
