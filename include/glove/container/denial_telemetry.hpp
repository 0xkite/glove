#pragma once

// Sandbox denial telemetry for one launch, in a form safe to record.
//
// This is telemetry, not enforcement: the sandbox profile is the control, and
// nothing may wait on, gate on, or react to a denial record or its absence.
// Records are a lower bound; the log drops some denials and the monitor
// bounds what it keeps. Every text field is bytes chosen by the contained
// process, rendered by encode_untrusted into printable ASCII. The pid is what
// the log line says; it is not an identity and must never choose a signal
// target. A session whose telemetry is unavailable or degraded is still
// sandboxed.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

constexpr std::size_t max_denial_target_text_bytes = 512;
constexpr std::size_t max_denial_operation_text_bytes = 192;
constexpr std::size_t max_denial_comm_text_bytes = 96;
constexpr std::size_t max_denial_reason_text_bytes = 256;

struct encoded_text {
    std::string text;
    bool truncated = false;
};

// Copies bytes 0x20..0x7E except '"', '\' and '%'; every other byte becomes
// '%' and two uppercase hex digits. Never emits part of an escape and never
// exceeds max_bytes; truncated is true when any input byte was not rendered.
[[nodiscard]] auto encode_untrusted(std::string_view bytes, std::size_t max_bytes) -> encoded_text;

// True when every byte is in 0x20..0x7E and is neither '"' nor '\'.
[[nodiscard]] auto is_encoded_text(std::string_view text) noexcept -> bool;

struct sandbox_denial {
    std::string kind;      // fixed vocabulary, or "ambiguous"
    std::string operation; // encoded; empty when ambiguous
    std::string target;    // encoded; empty when ambiguous
    bool target_truncated = false;
    std::string comm;     // encoded; empty when ambiguous
    std::int32_t pid = 0; // what the log line says; not an identity; 0 when ambiguous
    std::uint32_t duplicate_reports = 0;
    std::uint32_t readings = 1;
};

enum class denial_telemetry_state : std::uint8_t { unavailable, live, degraded };

struct denial_observer {
    std::function<void(const sandbox_denial&)> on_denial;     // telemetry thread
    std::function<void(std::string_view reason)> on_degraded; // telemetry thread, at most once
};

struct denial_monitor_report {
    denial_telemetry_state state = denial_telemetry_state::unavailable;
    std::string reason; // Glove's own text, encoded; empty when live
    std::uint64_t stream_events = 0;
    std::uint64_t stream_rejected = 0;
    bool end_proof = false;
};

constexpr int denial_monitor_start_timeout_ms = 2000;
constexpr int denial_monitor_finish_timeout_ms = 1000;

// One launch's denial telemetry. start() waits at most
// denial_monitor_start_timeout_ms and finish() at most
// denial_monitor_finish_timeout_ms. Defined on macOS only.
class denial_monitor final {
public:
    denial_monitor(const denial_monitor&) = delete;
    auto operator=(const denial_monitor&) -> denial_monitor& = delete;
    denial_monitor(denial_monitor&&) = delete;
    auto operator=(denial_monitor&&) -> denial_monitor& = delete;
    // Disarms and stops the stream without a closing proof.
    ~denial_monitor();

    // Never null; an unavailable monitor reports why.
    static auto start(denial_observer observer) -> std::unique_ptr<denial_monitor>;
    static auto start_for_test(denial_observer observer, std::vector<std::string> stream_argv)
        -> std::unique_ptr<denial_monitor>;

    [[nodiscard]] auto state() const noexcept -> denial_telemetry_state;
    [[nodiscard]] auto reason() const -> std::string;
    // The tag every deny rule of the launch must carry; empty when unavailable.
    [[nodiscard]] auto tag() const noexcept -> const std::string&;
    // Idempotent; after it returns no observer callback runs.
    auto finish() -> denial_monitor_report;
    [[nodiscard]] auto stream_pid_for_test() const noexcept -> int;

private:
    struct implementation;

    explicit denial_monitor(std::unique_ptr<implementation> impl) noexcept;

    std::unique_ptr<implementation> impl_;
};

} // namespace glove::container
