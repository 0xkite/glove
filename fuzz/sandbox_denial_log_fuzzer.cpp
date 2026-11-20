#include "sandbox_denial_log.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace {

using glove::container::detail::classify_denial_operation;
using glove::container::detail::denial_event;
using glove::container::detail::denial_parse_error;
using glove::container::detail::max_denial_comm_bytes;
using glove::container::detail::max_denial_line_bytes;
using glove::container::detail::max_denial_operation_bytes;
using glove::container::detail::max_denial_readings;
using glove::container::detail::max_denial_target_bytes;

auto operation_bytes_valid(std::string_view operation) -> bool {
    return std::ranges::all_of(operation, [](char byte) {
        const auto value = static_cast<unsigned char>(byte);
        return value >= 0x21U && value <= 0x7EU;
    });
}

// The parser's size bound and per-reading bounds, for either entry point.
void check_bounds(
    std::string_view raw, const std::expected<denial_event, denial_parse_error>& parsed
) {
    if (raw.size() > max_denial_line_bytes &&
        (parsed || parsed.error() != denial_parse_error::oversized)) {
        __builtin_trap();
    }
    if (!parsed) {
        return;
    }
    if (parsed->readings.empty() || parsed->readings.size() > max_denial_readings) {
        __builtin_trap();
    }
    for (const auto& reading : parsed->readings) {
        if (reading.pid < 1 || reading.untrusted_comm.empty() ||
            reading.untrusted_comm.size() > max_denial_comm_bytes || reading.operation.empty() ||
            reading.operation.size() > max_denial_operation_bytes ||
            !operation_bytes_valid(reading.operation) ||
            reading.target.size() > max_denial_target_bytes ||
            (reading.target_truncated && reading.target.size() != max_denial_target_bytes) ||
            reading.kind != classify_denial_operation(reading.operation)) {
            __builtin_trap();
        }
    }
}

} // namespace

// Input is not pre-filtered by size: the parser's own bound is under test.
extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view raw{reinterpret_cast<const char*>(data), size};
    (void)classify_denial_operation(raw);

    check_bounds(raw, glove::container::detail::parse_denial_line(raw));
    check_bounds(
        raw,
        glove::container::detail::parse_tagged_denial_line(raw, "00112233445566778899aabbccddeeff")
    );
    return 0;
}
