#pragma once

// A denial trace: one launch's raw denial telemetry as JSON lines, recorded
// for training and evaluating denial deciders offline. Traces hold events,
// not features, so a feature schema change does not invalidate a corpus.
//
// Line 1 is the header (classification context); then one line per denial in
// arrival order; then, when the launch ended cleanly, one end line. Text
// fields are encode_untrusted output and stay bounded. A trace is untrusted
// input when read back: the agent chose its targets and process names, and
// anyone with write access to the file chose everything else.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_telemetry.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

// Version 2 added the header's decoys. Version 1 traces still load, with no
// decoys, so an older corpus stays usable.
constexpr std::uint32_t denial_trace_version = 2;
constexpr std::size_t max_denial_trace_events = 16384;
constexpr std::size_t max_denial_trace_bytes = std::size_t{32} << 20U;
constexpr std::size_t max_denial_trace_line_bytes = std::size_t{64} << 10U;

struct denial_trace_event {
    std::chrono::milliseconds at{0}; // since the launch began
    sandbox_denial denial;
};

struct denial_trace_end {
    std::chrono::milliseconds at{0};
    denial_telemetry_state state = denial_telemetry_state::unavailable;
    std::string reason; // encoded
    bool end_proof = false;
    std::uint64_t stream_events = 0;
    std::uint64_t stream_rejected = 0;
    std::uint64_t dropped = 0; // denials past max_denial_trace_events
};

struct denial_trace {
    denial_context context;
    std::vector<denial_trace_event> events;
    std::optional<denial_trace_end> end; // absent when the launch did not end cleanly
    bool truncated = false;              // the file ended inside a line
};

// Each returns one line ending in '\n'. An event or context whose text fields
// are not encoded text, or are over their bounds, is refused.
[[nodiscard]] auto denial_trace_header_line(const denial_context& context)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto denial_trace_event_line(const denial_trace_event& event)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto denial_trace_end_line(const denial_trace_end& end)
    -> std::expected<std::string, std::string>;

// Refuses anything but the documented shape: a header first, events with
// non-decreasing times and bounded encoded fields, at most one end line and
// nothing after it. A final line without '\n' is dropped and marks the trace
// truncated.
[[nodiscard]] auto parse_denial_trace(std::string_view text)
    -> std::expected<denial_trace, std::string>;

} // namespace glove::container
