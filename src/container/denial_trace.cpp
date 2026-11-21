#include "glove/container/denial_trace.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

// Glaze reflects these, so they need linkage.
namespace denial_trace_detail {

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct header_record {
    std::string type = "header";
    std::string format = "glove-denial-trace";
    std::uint32_t version = denial_trace_version;
    std::string home;
    std::vector<std::string> workspace_roots;
    std::vector<std::string> decoys;
};

// The version 1 header, which had no decoys.
// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct header_record_v1 {
    std::string type = "header";
    std::string format = "glove-denial-trace";
    std::uint32_t version = 1;
    std::string home;
    std::vector<std::string> workspace_roots;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct event_record {
    std::string type = "event";
    std::int64_t t_ms = 0;
    std::string kind;
    std::string operation;
    std::string target;
    bool target_truncated = false;
    std::string comm;
    std::int32_t pid = 0;
    std::uint32_t duplicate_reports = 0;
    std::uint32_t readings = 1;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct end_record {
    std::string type = "end";
    std::int64_t t_ms = 0;
    std::string state;
    std::string reason;
    bool end_proof = false;
    std::uint64_t stream_events = 0;
    std::uint64_t stream_rejected = 0;
    std::uint64_t dropped = 0;
};

} // namespace denial_trace_detail

namespace {

using denial_trace_detail::end_record;
using denial_trace_detail::event_record;
using denial_trace_detail::header_record;
using denial_trace_detail::header_record_v1;

struct trace_opts : glz::opts {
    bool validate_trailing_whitespace = true;
};

constexpr trace_opts trace_read_options{
    {.null_terminated = false, .error_on_unknown_keys = true, .error_on_missing_keys = true},
};

constexpr std::size_t max_kind_bytes = 32;
// sandbox_denial::readings counts the parser's readings of one line.
constexpr std::uint32_t max_readings = 4;
// Thirty days: a bound on a launch, and far from overflow.
constexpr std::int64_t max_trace_ms = std::int64_t{30} * 24 * 60 * 60 * 1000;

constexpr std::string_view header_prefix = R"({"type":"header",)";
constexpr std::string_view event_prefix = R"({"type":"event",)";
constexpr std::string_view end_prefix = R"({"type":"end",)";

auto bounded(std::string_view text, std::size_t max_bytes) -> bool {
    return text.size() <= max_bytes && is_encoded_text(text);
}

// The form make_denial_context produces for one directory.
auto valid_root(std::string_view root) -> bool {
    return root.size() > 1 && root.starts_with('/') && !root.ends_with('/') &&
           bounded(root, max_denial_target_text_bytes);
}

auto valid_context(const denial_context& context) -> bool {
    return (context.home.empty() || valid_root(context.home)) &&
           context.workspace_roots.size() <= max_denial_context_roots &&
           std::ranges::all_of(context.workspace_roots, valid_root) &&
           context.decoys.size() <= max_denial_context_decoys &&
           std::ranges::all_of(context.decoys, valid_root);
}

auto valid_kind(std::string_view kind) -> bool {
    return !kind.empty() && kind.size() <= max_kind_bytes &&
           std::ranges::all_of(kind, [](char byte) {
               return (byte >= 'a' && byte <= 'z') || byte == '_';
           });
}

auto valid_event(const denial_trace_event& event) -> bool {
    const auto& denial = event.denial;
    if (event.at.count() < 0 || event.at.count() > max_trace_ms || !valid_kind(denial.kind) ||
        denial.pid < 0 || denial.readings == 0 || denial.readings > max_readings) {
        return false;
    }
    if (denial.kind == "ambiguous") {
        return denial.operation.empty() && denial.target.empty() && denial.comm.empty() &&
               denial.pid == 0 && !denial.target_truncated;
    }
    return bounded(denial.operation, max_denial_operation_text_bytes) &&
           bounded(denial.target, max_denial_target_text_bytes) &&
           bounded(denial.comm, max_denial_comm_text_bytes);
}

auto state_name(denial_telemetry_state state) -> std::string_view {
    switch (state) {
    case denial_telemetry_state::live:
        return "live";
    case denial_telemetry_state::degraded:
        return "degraded";
    case denial_telemetry_state::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

auto state_from(std::string_view name) -> std::optional<denial_telemetry_state> {
    for (const auto state : {
             denial_telemetry_state::live,
             denial_telemetry_state::degraded,
             denial_telemetry_state::unavailable,
         }) {
        if (state_name(state) == name) {
            return state;
        }
    }
    return std::nullopt;
}

template<typename Record>
auto line_of(const Record& record) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(record);
    if (!encoded) {
        return std::unexpected(std::string{"encode denial trace line"});
    }
    encoded->push_back('\n');
    return std::move(*encoded);
}

template<typename Record> auto read_line(std::string_view line, Record& record) -> bool {
    return !glz::read<trace_read_options>(record, line);
}

auto to_event(const event_record& record) -> denial_trace_event {
    return {
        .at = std::chrono::milliseconds{record.t_ms},
        .denial = {
            .kind = record.kind,
            .operation = record.operation,
            .target = record.target,
            .target_truncated = record.target_truncated,
            .comm = record.comm,
            .pid = record.pid,
            .duplicate_reports = record.duplicate_reports,
            .readings = record.readings,
        },
    };
}

auto refuse(std::string_view why) -> std::unexpected<std::string> {
    return std::unexpected(std::string{"denial trace: "} + std::string{why});
}

struct trace_reader {
    denial_trace trace;
    bool header_seen = false;
    std::int64_t last_ms = 0;

    auto line(std::string_view text) -> std::expected<void, std::string> {
        if (text.size() > max_denial_trace_line_bytes) {
            return refuse("line is too long");
        }
        if (trace.end) {
            return refuse("line after the end record");
        }
        if (!header_seen) {
            return header(text);
        }
        if (text.starts_with(event_prefix)) {
            return event(text);
        }
        if (text.starts_with(end_prefix)) {
            return end(text);
        }
        return refuse("unknown line type");
    }

    auto header(std::string_view text) -> std::expected<void, std::string> {
        if (!text.starts_with(header_prefix)) {
            return refuse("first line is not a header");
        }
        header_record record;
        if (header_record_v1 old; read_line(text, old)) {
            record = {
                .type = std::move(old.type),
                .format = std::move(old.format),
                .version = old.version == 1 ? denial_trace_version : 0,
                .home = std::move(old.home),
                .workspace_roots = std::move(old.workspace_roots),
                .decoys = {},
            };
        } else if (!read_line(text, record)) {
            return refuse("first line is not a header");
        }
        if (record.type != "header" || record.format != "glove-denial-trace" ||
            record.version != denial_trace_version) {
            return refuse("first line is not a version 1 or 2 header");
        }
        trace.context = {
            .workspace_roots = std::move(record.workspace_roots),
            .home = std::move(record.home),
            .decoys = std::move(record.decoys),
        };
        if (!valid_context(trace.context)) {
            return refuse("header context is not encoded directories");
        }
        header_seen = true;
        return {};
    }

    auto event(std::string_view text) -> std::expected<void, std::string> {
        event_record record;
        if (!read_line(text, record) || record.type != "event") {
            return refuse("malformed event line");
        }
        auto parsed = to_event(record);
        if (!valid_event(parsed) || record.t_ms < last_ms) {
            return refuse("event is out of bounds or out of order");
        }
        if (trace.events.size() == max_denial_trace_events) {
            return refuse("too many events");
        }
        last_ms = record.t_ms;
        trace.events.push_back(std::move(parsed));
        return {};
    }

    auto end(std::string_view text) -> std::expected<void, std::string> {
        end_record record;
        if (!read_line(text, record) || record.type != "end") {
            return refuse("malformed end line");
        }
        const auto state = state_from(record.state);
        if (!state || record.t_ms < last_ms || record.t_ms > max_trace_ms ||
            !bounded(record.reason, max_denial_reason_text_bytes)) {
            return refuse("end record is out of bounds");
        }
        trace.end = denial_trace_end{
            .at = std::chrono::milliseconds{record.t_ms},
            .state = *state,
            .reason = std::move(record.reason),
            .end_proof = record.end_proof,
            .stream_events = record.stream_events,
            .stream_rejected = record.stream_rejected,
            .dropped = record.dropped,
        };
        return {};
    }
};

} // namespace

auto denial_trace_header_line(const denial_context& context)
    -> std::expected<std::string, std::string> {
    if (!valid_context(context)) {
        return std::unexpected(std::string{"denial trace context is not encoded directories"});
    }
    header_record record;
    record.home = context.home;
    record.workspace_roots = context.workspace_roots;
    record.decoys = context.decoys;
    return line_of(record);
}

auto denial_trace_event_line(const denial_trace_event& event)
    -> std::expected<std::string, std::string> {
    if (!valid_event(event)) {
        return std::unexpected(std::string{"denial trace event is out of bounds"});
    }
    const auto& denial = event.denial;
    event_record record;
    record.t_ms = event.at.count();
    record.kind = denial.kind;
    record.operation = denial.operation;
    record.target = denial.target;
    record.target_truncated = denial.target_truncated;
    record.comm = denial.comm;
    record.pid = denial.pid;
    record.duplicate_reports = denial.duplicate_reports;
    record.readings = denial.readings;
    return line_of(record);
}

auto denial_trace_end_line(const denial_trace_end& end) -> std::expected<std::string, std::string> {
    if (end.at.count() < 0 || end.at.count() > max_trace_ms ||
        !bounded(end.reason, max_denial_reason_text_bytes)) {
        return std::unexpected(std::string{"denial trace end is out of bounds"});
    }
    end_record record;
    record.t_ms = end.at.count();
    record.state = std::string{state_name(end.state)};
    record.reason = end.reason;
    record.end_proof = end.end_proof;
    record.stream_events = end.stream_events;
    record.stream_rejected = end.stream_rejected;
    record.dropped = end.dropped;
    return line_of(record);
}

auto parse_denial_trace(std::string_view text) -> std::expected<denial_trace, std::string> {
    if (text.size() > max_denial_trace_bytes) {
        return refuse("file is too large");
    }
    trace_reader reader;
    while (!text.empty()) {
        const auto newline = text.find('\n');
        if (newline == std::string_view::npos) {
            reader.trace.truncated = true;
            break;
        }
        if (auto read = reader.line(text.substr(0, newline)); !read) {
            return std::unexpected(std::move(read.error()));
        }
        text.remove_prefix(newline + 1);
    }
    if (!reader.header_seen) {
        return refuse("no header");
    }
    return std::move(reader.trace);
}

} // namespace glove::container
