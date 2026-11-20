// A denial trace is untrusted text. The reader must never crash, hang or
// over-read; whatever it accepts must serialize again and parse back to the
// same trace, and must replay into finite features.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_trace.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    namespace container = glove::container;
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    const auto trace = container::parse_denial_trace(text);
    if (!trace) {
        return 0;
    }
    auto header = container::denial_trace_header_line(trace->context);
    if (!header) {
        __builtin_trap();
    }
    std::string again = *header;
    container::denial_feature_builder builder{trace->context};
    for (const auto& event : trace->events) {
        auto line = container::denial_trace_event_line(event);
        if (!line) {
            __builtin_trap();
        }
        again += *line;
        builder.observe(event.denial, event.at);
    }
    if (trace->end) {
        auto line = container::denial_trace_end_line(*trace->end);
        if (!line) {
            __builtin_trap();
        }
        again += *line;
    }
    const auto reparsed = container::parse_denial_trace(again);
    if (!reparsed || reparsed->events.size() != trace->events.size() ||
        reparsed->context.workspace_roots != trace->context.workspace_roots ||
        reparsed->context.home != trace->context.home ||
        reparsed->end.has_value() != trace->end.has_value()) {
        __builtin_trap();
    }
    const auto at = trace->events.empty() ? std::chrono::milliseconds{0} : trace->events.back().at;
    for (const float value : builder.features(at)) {
        if (!std::isfinite(value) || value < 0.0F) {
            __builtin_trap();
        }
    }
    return 0;
}
