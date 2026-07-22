#include "glove/mcp/client.hpp"
#include "glove/mcp/transport.hpp"

#include "src/mcp/codec.hpp"

#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t default_samples = 20;
constexpr std::size_t default_iterations = 1'000;
constexpr std::size_t warmup_iterations = 100;
constexpr std::size_t minimum_samples = 2;
constexpr std::size_t maximum_samples = 1'000;
constexpr std::size_t maximum_iterations = 10'000'000;
constexpr double nanoseconds_per_second = 1'000'000'000.0;
constexpr double normal_95_percentile = 1.959963984540054;

struct options {
    std::size_t samples = default_samples;
    std::size_t iterations = default_iterations;
};

struct measurement {
    double mean_nanoseconds = 0.0;
    double standard_deviation_nanoseconds = 0.0;
    double ci95_lower_nanoseconds = 0.0;
    double ci95_upper_nanoseconds = 0.0;
    std::uint64_t checksum = 0;
};

auto parse_count(std::string_view value, std::size_t minimum, std::size_t maximum)
    -> std::expected<std::size_t, std::string> {
    std::size_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed < minimum ||
        parsed > maximum) {
        return std::unexpected(std::string{"benchmark count is outside its allowed range"});
    }
    return parsed;
}

auto parse_options(int argc, char** argv) -> std::expected<options, std::string> {
    options parsed;
    for (int index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) {
            return std::unexpected(std::string{"benchmark options require a value"});
        }
        const std::string_view option{argv[index]};
        const std::string_view value{argv[index + 1]};
        if (option == "--samples") {
            auto count = parse_count(value, minimum_samples, maximum_samples);
            if (!count) {
                return std::unexpected(count.error());
            }
            parsed.samples = *count;
        } else if (option == "--iterations") {
            auto count = parse_count(value, 1, maximum_iterations);
            if (!count) {
                return std::unexpected(count.error());
            }
            parsed.iterations = *count;
        } else {
            return std::unexpected(std::string{"unknown benchmark option"});
        }
    }
    return parsed;
}

template<typename Operation>
auto measure(const options& configured, Operation&& operation)
    -> std::expected<measurement, std::string> {
    std::uint64_t checksum = 0;
    for (std::size_t iteration = 0; iteration < warmup_iterations; ++iteration) {
        auto result = operation();
        if (!result) {
            return std::unexpected(result.error());
        }
        checksum += *result;
    }

    std::vector<double> sample_nanoseconds;
    sample_nanoseconds.reserve(configured.samples);
    for (std::size_t sample = 0; sample < configured.samples; ++sample) {
        const auto started = std::chrono::steady_clock::now();
        for (std::size_t iteration = 0; iteration < configured.iterations; ++iteration) {
            auto result = operation();
            if (!result) {
                return std::unexpected(result.error());
            }
            checksum += *result;
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        const auto elapsed_nanoseconds = std::chrono::duration<double, std::nano>{elapsed}.count();
        sample_nanoseconds.push_back(
            elapsed_nanoseconds / static_cast<double>(configured.iterations)
        );
    }

    const double mean = std::accumulate(sample_nanoseconds.begin(), sample_nanoseconds.end(), 0.0) /
                        static_cast<double>(sample_nanoseconds.size());
    double squared_deviation_sum = 0.0;
    for (const double sample : sample_nanoseconds) {
        const double deviation = sample - mean;
        squared_deviation_sum += deviation * deviation;
    }
    const double standard_deviation =
        std::sqrt(squared_deviation_sum / static_cast<double>(sample_nanoseconds.size() - 1));
    const double margin = normal_95_percentile * standard_deviation /
                          std::sqrt(static_cast<double>(sample_nanoseconds.size()));
    return measurement{
        .mean_nanoseconds = mean,
        .standard_deviation_nanoseconds = standard_deviation,
        .ci95_lower_nanoseconds = mean - margin,
        .ci95_upper_nanoseconds = mean + margin,
        .checksum = checksum,
    };
}

void write_result(std::string_view name, const options& configured, const measurement& measured) {
    std::cout << std::setprecision(17) << "{\"schema_version\":1,\"benchmark\":\"" << name
              << "\",\"samples\":" << configured.samples
              << ",\"iterations_per_sample\":" << configured.iterations
              << ",\"warmup_iterations\":" << warmup_iterations
              << ",\"latency_ns_mean\":" << measured.mean_nanoseconds
              << ",\"latency_ns_stddev\":" << measured.standard_deviation_nanoseconds
              << ",\"latency_ns_ci95_normal_lower\":" << measured.ci95_lower_nanoseconds
              << ",\"latency_ns_ci95_normal_upper\":" << measured.ci95_upper_nanoseconds
              << ",\"throughput_ops_per_second\":"
              << nanoseconds_per_second / measured.mean_nanoseconds
              << ",\"checksum\":" << measured.checksum << "}\n";
}

auto codec_operation() -> std::expected<std::size_t, std::string> {
    constexpr std::string_view frame =
        R"({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"echoes its input","inputSchema":{"type":"object"}},{"name":"add","description":"adds two numbers","inputSchema":{"type":"object"}}]}})";
    auto envelope = glove::mcp::codec::decode_response(frame);
    if (!envelope) {
        return std::unexpected(envelope.error());
    }
    auto tools = glove::mcp::codec::parse_tools_list_result(*envelope);
    if (!tools) {
        return std::unexpected(tools.error());
    }
    return tools->size();
}

auto make_round_trip_client() -> std::unique_ptr<glove::mcp::client> {
    auto handler = [](std::string_view frame) -> std::optional<std::string> {
        auto request = glove::mcp::codec::decode_request(frame);
        if (!request || !request->id || request->method != "tools/list") {
            return R"({"jsonrpc":"2.0","id":0,"error":{"code":-32600,"message":"invalid benchmark request"}})";
        }
        auto response = glove::mcp::codec::encode_response_with_result(
            *request->id,
            R"({"tools":[{"name":"echo","description":"echoes its input","inputSchema":{"type":"object"}}]})"
        );
        if (!response) {
            return R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"benchmark encoding failed"}})";
        }
        return std::move(*response);
    };
    return glove::mcp::make_client(glove::mcp::make_in_memory_transport(std::move(handler)));
}

auto run(const options& configured) -> std::expected<void, std::string> {
    auto codec = measure(configured, codec_operation);
    if (!codec) {
        return std::unexpected(codec.error());
    }
    write_result("mcp.codec.tools_list_decode", configured, *codec);

    auto client = make_round_trip_client();
    auto round_trip = measure(configured, [&client]() -> std::expected<std::size_t, std::string> {
        auto tools = client->list_tools();
        if (!tools) {
            return std::unexpected(tools.error());
        }
        return tools->size();
    });
    if (!round_trip) {
        return std::unexpected(round_trip.error());
    }
    write_result("mcp.client.in_memory_tools_list_round_trip", configured, *round_trip);
    return {};
}

} // namespace

auto main(int argc, char** argv) -> int {
    auto configured = parse_options(argc, argv);
    if (!configured) {
        std::fprintf(stderr, "glove_mcp_benchmark: %s\n", configured.error().c_str());
        return 2;
    }
    auto result = run(*configured);
    if (!result) {
        std::fprintf(stderr, "glove_mcp_benchmark: %s\n", result.error().c_str());
        return 1;
    }
    return 0;
}
