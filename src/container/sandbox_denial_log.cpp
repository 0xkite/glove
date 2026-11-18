#include "sandbox_denial_log.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace glove::container::detail {

namespace {

// Only the members the parser trusts; every other ndjson member is skipped.
struct denial_log_record {
    std::string event_message;
    std::int64_t process_id = -1;
    std::string process_image_path;
    std::string sender_image_path;
    std::string timestamp;
    std::uint64_t mach_timestamp = 0;

    struct glaze {
        using T = denial_log_record;
        static constexpr auto value = glz::object(
            "eventMessage",
            &T::event_message,
            "processID",
            &T::process_id,
            "processImagePath",
            &T::process_image_path,
            "senderImagePath",
            &T::sender_image_path,
            "timestamp",
            &T::timestamp,
            "machTimestamp",
            &T::mach_timestamp
        );
    };
};

// The line is a view into a caller's buffer with no terminator past its end;
// Glaze must not read beyond line.size().
constexpr glz::opts record_options{
    .null_terminated = false, .error_on_unknown_keys = false, .error_on_missing_keys = true
};

// Kernel provenance: userland (logger, os_log) can write the same message text
// but cannot claim pid 0, the kernel image, and the Sandbox extension sender.
constexpr std::string_view kernel_image_path = "/kernel";
constexpr std::string_view sandbox_sender_path =
    "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox";

constexpr std::string_view sandbox_prefix = "Sandbox: ";
constexpr std::string_view deny_infix = ") deny(";
constexpr std::size_t max_number_digits = 9;
constexpr std::size_t timestamp_bytes = 31;

constexpr auto is_digit(char byte) noexcept -> bool {
    return byte >= '0' && byte <= '9';
}

constexpr auto is_operation_byte(char byte) noexcept -> bool {
    const auto value = static_cast<unsigned char>(byte);
    return value >= 0x21U && value <= 0x7EU;
}

// Consumes 1..9 ASCII digits at text[pos]; nine digits always fit in uint32.
auto take_number(std::string_view text, std::size_t& pos) noexcept -> std::optional<std::uint32_t> {
    std::uint32_t value = 0;
    std::size_t digits = 0;
    while (pos < text.size() && is_digit(text[pos])) {
        if (digits == max_number_digits) {
            return std::nullopt;
        }
        value = (value * 10U) + static_cast<std::uint32_t>(text[pos] - '0');
        ++digits;
        ++pos;
    }
    if (digits == 0) {
        return std::nullopt;
    }
    return value;
}

auto take_literal(std::string_view text, std::size_t& pos, std::string_view literal) noexcept
    -> bool {
    // Bounds are checked before comparing so this cannot throw out_of_range.
    if (pos > text.size() || text.size() - pos < literal.size() ||
        !std::equal(
            literal.begin(), literal.end(), text.begin() + static_cast<std::ptrdiff_t>(pos)
        )) {
        return false;
    }
    pos += literal.size();
    return true;
}

// "<N> duplicate report[s] for " in front of the denial; absent means 0.
auto take_duplicate_prefix(std::string_view message, std::size_t& pos) noexcept -> std::uint32_t {
    std::size_t cursor = 0;
    const auto count = take_number(message, cursor);
    if (!count || !take_literal(message, cursor, " duplicate report")) {
        return 0;
    }
    (void)take_literal(message, cursor, "s");
    if (!take_literal(message, cursor, " for ")) {
        return 0;
    }
    pos = cursor;
    return *count;
}

// One reading if BODY from split reads "(<pid>) deny(<code>) <op>[ <target>]".
auto reading_at(std::string_view body, std::size_t split) -> std::optional<denial_reading> {
    std::size_t pos = split;
    if (!take_literal(body, pos, "(")) {
        return std::nullopt;
    }
    const auto pid = take_number(body, pos);
    if (!pid || *pid == 0 || !take_literal(body, pos, deny_infix)) {
        return std::nullopt;
    }
    const auto code = take_number(body, pos);
    if (!code || !take_literal(body, pos, ") ")) {
        return std::nullopt;
    }
    const std::size_t operation_start = pos;
    while (pos < body.size() && body[pos] != ' ') {
        if (!is_operation_byte(body[pos]) || pos - operation_start == max_denial_operation_bytes) {
            return std::nullopt;
        }
        ++pos;
    }
    const auto operation = body.substr(operation_start, pos - operation_start);
    if (operation.empty()) {
        return std::nullopt;
    }
    // The target is opaque agent-chosen bytes, newlines included.
    const auto target = pos < body.size() ? body.substr(pos + 1) : std::string_view{};
    const bool truncated = target.size() > max_denial_target_bytes;
    return denial_reading{
        .pid = static_cast<std::int32_t>(*pid),
        .code = *code,
        .untrusted_comm = std::string{body.substr(0, split)},
        .operation = std::string{operation},
        .kind = classify_denial_operation(operation),
        .target = std::string{target.substr(0, max_denial_target_bytes)},
        .target_truncated = truncated,
    };
}

auto two_digits(std::string_view text, std::size_t pos) noexcept -> std::optional<int> {
    if (!is_digit(text[pos]) || !is_digit(text[pos + 1])) {
        return std::nullopt;
    }
    return ((text[pos] - '0') * 10) + (text[pos + 1] - '0');
}

// "YYYY-MM-DD HH:MM:SS.ffffff+HHMM" (or "-HHMM") to UTC microseconds.
auto parse_timestamp(std::string_view text) noexcept -> std::optional<std::int64_t> {
    if (text.size() != timestamp_bytes || text[4] != '-' || text[7] != '-' || text[10] != ' ' ||
        text[13] != ':' || text[16] != ':' || text[19] != '.' ||
        (text[26] != '+' && text[26] != '-')) {
        return std::nullopt;
    }
    const auto century = two_digits(text, 0);
    const auto year_low = two_digits(text, 2);
    const auto month = two_digits(text, 5);
    const auto day = two_digits(text, 8);
    const auto hour = two_digits(text, 11);
    const auto minute = two_digits(text, 14);
    const auto second = two_digits(text, 17);
    const auto offset_hour = two_digits(text, 27);
    const auto offset_minute = two_digits(text, 29);
    if (!century || !year_low || !month || !day || !hour || !minute || !second || !offset_hour ||
        !offset_minute) {
        return std::nullopt;
    }
    std::int64_t fraction = 0;
    for (std::size_t pos = 20; pos != 26; ++pos) {
        if (!is_digit(text[pos])) {
            return std::nullopt;
        }
        fraction = (fraction * 10) + (text[pos] - '0');
    }
    const int year = (*century * 100) + *year_low;
    if (year < 1970 || *hour > 23 || *minute > 59 || *second > 59 || *offset_hour > 23 ||
        *offset_minute > 59) {
        return std::nullopt;
    }
    const std::chrono::year_month_day date{
        std::chrono::year{year},
        std::chrono::month{static_cast<unsigned>(*month)},
        std::chrono::day{static_cast<unsigned>(*day)},
    };
    if (!date.ok()) {
        return std::nullopt;
    }
    using std::chrono::hours;
    using std::chrono::microseconds;
    using std::chrono::minutes;
    using std::chrono::seconds;
    const auto local = std::chrono::sys_days{date}.time_since_epoch() + hours{*hour} +
                       minutes{*minute} + seconds{*second} + microseconds{fraction};
    const auto offset = hours{*offset_hour} + minutes{*offset_minute};
    const auto utc = text[26] == '+' ? local - offset : local + offset;
    return std::chrono::duration_cast<microseconds>(utc).count();
}

} // namespace

auto classify_denial_operation(std::string_view operation) noexcept -> denial_class {
    if (operation.starts_with("file-read")) {
        return denial_class::file_read;
    }
    if (operation.starts_with("file-write")) {
        return denial_class::file_write;
    }
    if (operation.starts_with("file-")) {
        return denial_class::file_other;
    }
    if (operation.starts_with("network")) {
        return denial_class::network;
    }
    if (operation.starts_with("mach-")) {
        return denial_class::mach;
    }
    if (operation.starts_with("ipc-")) {
        return denial_class::ipc;
    }
    if (operation.starts_with("process-info")) {
        return denial_class::process_info;
    }
    if (operation.starts_with("process-")) {
        return denial_class::process;
    }
    if (operation == "signal") {
        return denial_class::signal;
    }
    if (operation.starts_with("sysctl")) {
        return denial_class::sysctl;
    }
    if (operation == "system-info") {
        return denial_class::system_info;
    }
    if (operation.starts_with("iokit-")) {
        return denial_class::iokit;
    }
    if (operation.starts_with("syscall-")) {
        return denial_class::syscall;
    }
    return denial_class::other;
}

auto parse_denial_line(std::string_view line) -> std::expected<denial_event, denial_parse_error> {
    if (line.size() > max_denial_line_bytes) {
        return std::unexpected(denial_parse_error::oversized);
    }
    denial_log_record record;
    if (const auto error = glz::read<record_options>(record, line); error) {
        return std::unexpected(denial_parse_error::not_json);
    }
    if (record.process_id != 0 || record.process_image_path != kernel_image_path ||
        record.sender_image_path != sandbox_sender_path) {
        return std::unexpected(denial_parse_error::wrong_provenance);
    }

    const std::string_view message{record.event_message};
    std::size_t pos = 0;
    denial_event event;
    event.duplicate_reports = take_duplicate_prefix(message, pos);
    if (!take_literal(message, pos, sandbox_prefix)) {
        return std::unexpected(denial_parse_error::not_a_denial);
    }
    const auto body = message.substr(pos);
    // Every split is kept: the comm is agent-chosen and can contain a forged
    // "(<pid>) deny(" of its own, so no single reading is privileged.
    for (std::size_t split = 1; split <= max_denial_comm_bytes && split < body.size(); ++split) {
        auto reading = reading_at(body, split);
        if (!reading) {
            continue;
        }
        if (event.readings.size() == max_denial_readings) {
            return std::unexpected(denial_parse_error::not_a_denial);
        }
        event.readings.push_back(std::move(*reading));
    }
    if (event.readings.empty()) {
        return std::unexpected(denial_parse_error::not_a_denial);
    }

    const auto micros = parse_timestamp(record.timestamp);
    if (!micros) {
        return std::unexpected(denial_parse_error::bad_timestamp);
    }
    event.unix_micros = *micros;
    event.mach_timestamp = record.mach_timestamp;
    return event;
}

} // namespace glove::container::detail
