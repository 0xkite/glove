#pragma once

#include "glove/audit/event.hpp"

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace glove::audit {

// Append-only event sink. Implementations must be safe for concurrent record()
// calls — multiple decorators may share one sink across agent threads.
class sink {
public:
    sink() = default;
    sink(const sink&) = delete;
    sink& operator=(const sink&) = delete;
    sink(sink&&) = delete;
    sink& operator=(sink&&) = delete;
    virtual ~sink() = default;

    virtual auto record(const event& e) -> std::expected<void, std::string> = 0;
};

// In-memory sink. Records are buffered and exposed via take(); useful for
// tests and short-lived inspection windows.
class memory_sink : public sink {
public:
    auto take() -> std::vector<event>;
};

auto make_memory_sink() -> std::shared_ptr<memory_sink>;

// JSON-lines sink. One event per line; failures during write are surfaced as
// `std::unexpected`. The file is opened append-binary; concurrent processes
// targeting the same file are not supported.
//
// Bounded growth policy: `jsonl_sink_limits::max_file_bytes` of 0 keeps the
// sink unbounded. When a positive cap is configured, the cap is hard: the
// journal is bounded to the cap at construction (a pre-existing oversized
// file is truncated with a bounded read), each write first truncates the
// oldest complete records so the file never exceeds the cap, and the file
// never contains blank or partial lines — every retained line is a complete
// record. A single event whose encoded form cannot fit under the cap is
// dropped with a structured operator log note rather than written. Failures
// during truncation are surfaced as `std::unexpected` like any other write
// failure.
struct jsonl_sink_limits {
    std::uint64_t max_file_bytes = 0;
};

auto make_jsonl_sink(const std::filesystem::path& path, jsonl_sink_limits limits = {})
    -> std::expected<std::shared_ptr<sink>, std::string>;

} // namespace glove::audit
