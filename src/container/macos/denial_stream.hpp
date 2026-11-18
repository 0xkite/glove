#pragma once

// Supervised `log stream` child delivering parsed kernel sandbox denials.
//
// Telemetry only. No containment decision may wait on this class: when the
// log ends, floods, or emits garbage, the stream degrades to "no telemetry"
// and the sandbox is unchanged. "live" means a canary denial from a process
// this object holds unreaped was observed, not merely that the child runs.
// Events are passed on unchanged; their names and targets are agent-chosen
// bytes (possibly not UTF-8) and their pid is not an identity.

#include "sandbox_denial_log.hpp"

#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container::macos_detail {

constexpr std::size_t denial_stream_read_chunk_bytes = 4096;
constexpr int denial_stream_poll_ms = 100;
constexpr int denial_stream_stop_grace_ms = 2000;
constexpr int denial_canary_interval_ms = 250;

enum class denial_stream_state : std::uint8_t { starting, live, degraded, stopped };

struct denial_stream_counters {
    std::uint64_t lines = 0;
    std::uint64_t events = 0;
    std::uint64_t oversized_lines = 0;
    std::uint64_t rejected_not_json = 0;
    std::uint64_t rejected_provenance = 0;
    std::uint64_t rejected_not_a_denial = 0;
    std::uint64_t rejected_timestamp = 0;
};

struct denial_stream_options {
    // Empty selects `log stream --style ndjson` with the kernel-provenance
    // predicate. argv[0] must be an absolute path.
    std::vector<std::string> argv;
    // Both run on the reader thread. An exception from on_event degrades the
    // stream; on_degraded is called at most once.
    std::function<void(const detail::denial_event&)> on_event;
    std::function<void(std::string_view reason)> on_degraded;
};

class denial_stream final {
public:
    denial_stream(const denial_stream&) = delete;
    auto operator=(const denial_stream&) -> denial_stream& = delete;
    denial_stream(denial_stream&&) = delete;
    auto operator=(denial_stream&&) -> denial_stream& = delete;
    // Stops the child within denial_stream_stop_grace_ms plus a bounded
    // drain, signalling it only while it is unreaped, and joins the reader.
    // A callback that never returns blocks this destructor, and the object
    // must not be destroyed from inside a callback.
    ~denial_stream();

    static auto start(denial_stream_options options)
        -> std::expected<std::unique_ptr<denial_stream>, std::string>;

    [[nodiscard]] auto state() const noexcept -> denial_stream_state;
    [[nodiscard]] auto counters() const noexcept -> denial_stream_counters;

    // Spawns sandboxed canaries until one's denial is observed or timeout
    // passes. Canaries stay unreaped until return, so a pid match is an
    // identity match. Success sets the state to live. prove_live must not be
    // called from two threads at once.
    auto prove_live(std::chrono::milliseconds timeout) -> std::expected<void, std::string>;

    [[nodiscard]] auto child_pid_for_test() const noexcept -> ::pid_t;

private:
    struct implementation;

    explicit denial_stream(std::unique_ptr<implementation> impl) noexcept;

    std::unique_ptr<implementation> impl_;
};

} // namespace glove::container::macos_detail
