#pragma once

// Parser for one `log stream --style ndjson` line carrying a macOS sandbox
// denial. Pure and bounded: no process, no attribution, no I/O.
//
// Nothing here is an identity. The pid is what the log line says; it names a
// process only after the caller ties it to a process Glove pins itself.
// untrusted_comm and target are bytes chosen by the contained agent: they may
// hold newlines, control bytes, quotes and text that imitates another denial,
// and must be escaped before display. A process name can embed a second
// "(<pid>) deny(<n>)" sequence, so the parser keeps every reading of the
// message; an ambiguous event must never be attributed to one process on its
// text alone.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container::detail {

constexpr std::size_t max_denial_line_bytes = 16384;
constexpr std::size_t max_denial_target_bytes = 4096;
constexpr std::size_t max_denial_comm_bytes = 32;
constexpr std::size_t max_denial_operation_bytes = 64;
constexpr std::size_t max_denial_readings = 4;

enum class denial_class : std::uint8_t {
    file_read,
    file_write,
    file_other,
    network,
    mach,
    ipc,
    process_info,
    process,
    signal,
    sysctl,
    system_info,
    iokit,
    syscall,
    other,
};

enum class denial_parse_error : std::uint8_t {
    oversized,
    not_json,
    wrong_provenance,
    not_a_denial,
    bad_timestamp,
};

struct denial_reading {
    std::int32_t pid = 0;
    std::uint32_t code = 0;
    std::string untrusted_comm;
    std::string operation;
    denial_class kind = denial_class::other;
    std::string target;
    bool target_truncated = false;
};

struct denial_event {
    std::vector<denial_reading> readings;
    std::uint32_t duplicate_reports = 0;
    std::int64_t unix_micros = 0;
    std::uint64_t mach_timestamp = 0;

    [[nodiscard]] auto ambiguous() const noexcept -> bool { return readings.size() > 1; }
};

[[nodiscard]] auto classify_denial_operation(std::string_view operation) noexcept -> denial_class;

// Rejects a line that is oversized, not one JSON object with the required
// members, not emitted by the kernel's Sandbox extension, not a denial
// message, or not carrying a well-formed timestamp, in that order.
[[nodiscard]] auto parse_denial_line(std::string_view line)
    -> std::expected<denial_event, denial_parse_error>;

} // namespace glove::container::detail
