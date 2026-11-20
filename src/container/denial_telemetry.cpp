#include "glove/container/denial_telemetry.hpp"

#include "denial_telemetry_detail.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace glove::container {

namespace {

constexpr std::size_t escape_bytes = 3;

constexpr auto is_plain(unsigned char byte) noexcept -> bool {
    return byte >= 0x20U && byte <= 0x7EU && byte != '"' && byte != '\\' && byte != '%';
}

} // namespace

auto encode_untrusted(std::string_view bytes, std::size_t max_bytes) -> encoded_text {
    constexpr std::string_view hex = "0123456789ABCDEF";
    encoded_text out;
    out.text.reserve(std::min(max_bytes, bytes.size() * escape_bytes));
    for (std::size_t index = 0; index != bytes.size(); ++index) {
        const auto byte = static_cast<unsigned char>(bytes[index]);
        const std::size_t needed = is_plain(byte) ? 1 : escape_bytes;
        if (out.text.size() + needed > max_bytes) {
            out.truncated = true;
            break;
        }
        if (needed == 1) {
            out.text.push_back(static_cast<char>(byte));
        } else {
            out.text.push_back('%');
            out.text.push_back(hex.at(byte >> 4U));
            out.text.push_back(hex.at(byte & 0x0FU));
        }
    }
    return out;
}

auto is_encoded_text(std::string_view text) noexcept -> bool {
    return std::ranges::all_of(text, [](char value) {
        const auto byte = static_cast<unsigned char>(value);
        return byte >= 0x20U && byte <= 0x7EU && byte != '"' && byte != '\\';
    });
}

} // namespace glove::container

namespace glove::container::detail {

auto denial_kind_name(denial_class kind) noexcept -> std::string_view {
    switch (kind) {
    case denial_class::file_read:
        return "file_read";
    case denial_class::file_write:
        return "file_write";
    case denial_class::file_other:
        return "file_other";
    case denial_class::network:
        return "network";
    case denial_class::mach:
        return "mach";
    case denial_class::ipc:
        return "ipc";
    case denial_class::process_info:
        return "process_info";
    case denial_class::process:
        return "process";
    case denial_class::signal:
        return "signal";
    case denial_class::sysctl:
        return "sysctl";
    case denial_class::system_info:
        return "system_info";
    case denial_class::iokit:
        return "iokit";
    case denial_class::syscall:
        return "syscall";
    case denial_class::other:
        return "other";
    }
    return "other";
}

auto to_sandbox_denial(const denial_event& event) -> glove::container::sandbox_denial {
    glove::container::sandbox_denial out;
    out.duplicate_reports = event.duplicate_reports;
    if (event.readings.size() != 1) {
        // An ambiguous line names no single process; keep no agent text.
        out.kind = "ambiguous";
        out.readings = static_cast<std::uint32_t>(event.readings.size());
        return out;
    }
    const auto& reading = event.readings.front();
    out.kind = std::string{denial_kind_name(reading.kind)};
    out.operation = encode_untrusted(reading.operation, max_denial_operation_text_bytes).text;
    auto target = encode_untrusted(reading.target, max_denial_target_text_bytes);
    out.target = std::move(target.text);
    out.target_truncated = target.truncated || reading.target_truncated;
    out.comm = encode_untrusted(reading.untrusted_comm, max_denial_comm_text_bytes).text;
    out.pid = reading.pid;
    out.readings = 1;
    return out;
}

} // namespace glove::container::detail
