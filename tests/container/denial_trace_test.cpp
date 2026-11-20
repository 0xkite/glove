// Denial trace format: what the writer emits parses back to the same events,
// and the reader refuses every line that is out of shape, order or bounds.

#include "glove/container/denial_trace.hpp"

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::denial_context;
using glove::container::denial_telemetry_state;
using glove::container::denial_trace_end;
using glove::container::denial_trace_end_line;
using glove::container::denial_trace_event;
using glove::container::denial_trace_event_line;
using glove::container::denial_trace_header_line;
using glove::container::parse_denial_trace;
using glove::container::sandbox_denial;
using std::chrono::milliseconds;

auto context() -> denial_context {
    return {.workspace_roots = {"/Users/u/proj", "/private/tmp/a%25b"}, .home = "/Users/u"};
}

auto event(long long at, std::string kind, std::string target) -> denial_trace_event {
    return {
        .at = milliseconds{at},
        .denial = {
            .kind = std::move(kind),
            .operation = "file-write-create",
            .target = std::move(target),
            .target_truncated = false,
            .comm = "touch",
            .pid = 42,
            .duplicate_reports = 1,
            .readings = 1
        },
    };
}

auto header() -> std::string {
    return *denial_trace_header_line(context());
}

auto line(const denial_trace_event& item) -> std::string {
    return *denial_trace_event_line(item);
}

auto end_line() -> std::string {
    return *denial_trace_end_line(
        {.at = milliseconds{900},
         .state = denial_telemetry_state::degraded,
         .reason = "denial stream stalled",
         .end_proof = false,
         .stream_events = 3,
         .stream_rejected = 1,
         .dropped = 2}
    );
}

auto round_trip() -> int {
    sandbox_denial ambiguous;
    ambiguous.kind = "ambiguous";
    ambiguous.readings = 2;
    const std::string text = header() + line(event(5, "file_write", "/Users/u/.zshrc")) +
                             line({.at = milliseconds{5}, .denial = ambiguous}) +
                             line(event(700, "network", "")) + end_line();
    const auto trace = parse_denial_trace(text);
    REQUIRE(trace.has_value());
    REQUIRE(trace->context.home == "/Users/u");
    REQUIRE(trace->context.workspace_roots == context().workspace_roots);
    REQUIRE(trace->events.size() == 3);
    const auto& first = trace->events.front();
    REQUIRE(first.at == milliseconds{5});
    REQUIRE(first.denial.kind == "file_write" && first.denial.target == "/Users/u/.zshrc");
    REQUIRE(first.denial.comm == "touch" && first.denial.pid == 42);
    REQUIRE(first.denial.duplicate_reports == 1 && first.denial.readings == 1);
    REQUIRE(trace->events.at(1).denial.kind == "ambiguous");
    REQUIRE(trace->events.at(1).denial.readings == 2);
    REQUIRE(trace->end.has_value());
    REQUIRE(trace->end->state == denial_telemetry_state::degraded);
    REQUIRE(trace->end->reason == "denial stream stalled" && trace->end->dropped == 2);
    REQUIRE(trace->end->stream_events == 3 && trace->end->stream_rejected == 1);
    REQUIRE(!trace->truncated);

    // A launch that did not end cleanly: no end line, a cut last line.
    const auto cut = header() + line(event(5, "file_read", "/x"));
    const auto partial = parse_denial_trace(cut + cut.substr(header().size(), 20));
    REQUIRE(partial.has_value() && partial->truncated && !partial->end);
    REQUIRE(partial->events.size() == 1);
    REQUIRE(parse_denial_trace(header()).has_value());
    return 0;
}

auto writer_refuses() -> int {
    REQUIRE(!denial_trace_event_line(event(1, "file_read", "/a\"b")).has_value());
    REQUIRE(!denial_trace_event_line(event(1, "file_read", std::string(513, 'a'))).has_value());
    REQUIRE(!denial_trace_event_line(event(-1, "file_read", "/a")).has_value());
    REQUIRE(!denial_trace_event_line(event(1, "File", "/a")).has_value());
    auto ambiguous_with_text = event(1, "ambiguous", "/a");
    REQUIRE(!denial_trace_event_line(ambiguous_with_text).has_value());
    REQUIRE(!denial_trace_header_line({.workspace_roots = {"relative"}, .home = ""}).has_value());
    REQUIRE(!denial_trace_header_line({.workspace_roots = {"/a/"}, .home = ""}).has_value());
    REQUIRE(!denial_trace_header_line({.workspace_roots = {}, .home = "/"}).has_value());
    REQUIRE(!denial_trace_header_line({.workspace_roots = {"/a b\\c"}, .home = ""}).has_value());
    REQUIRE(denial_trace_header_line({.workspace_roots = {}, .home = ""}).has_value());
    REQUIRE(!denial_trace_end_line({.at = milliseconds{1}, .reason = "a\nb"}).has_value());
    return 0;
}

auto refused(const std::string& text) -> bool {
    return !parse_denial_trace(text).has_value();
}

auto reader_refuses() -> int {
    const auto ok_event = line(event(10, "file_read", "/x"));
    REQUIRE(!refused(header() + ok_event));
    REQUIRE(refused(""));
    REQUIRE(refused(ok_event));
    REQUIRE(refused(header() + header()));
    REQUIRE(refused(header() + "\n"));
    REQUIRE(refused(header() + R"({"type":"other"})" + "\n"));
    REQUIRE(refused(header() + end_line() + ok_event));
    REQUIRE(refused(header() + end_line() + end_line()));
    REQUIRE(refused(header() + ok_event + line(event(9, "file_read", "/x"))));
    REQUIRE(refused(header() + line(event(1000, "file_read", "/x")) + end_line()));
    // Shape: unknown and missing keys, trailing bytes, wrong types.
    auto with = [&](std::string_view from, std::string_view to) {
        auto text = header() + ok_event;
        const auto at = text.rfind(from);
        text.replace(at, from.size(), to);
        return text;
    };
    REQUIRE(refused(with(R"("readings":1})", R"("readings":1,"x":1})")));
    REQUIRE(refused(with(R"(,"readings":1})", "}")));
    REQUIRE(refused(with(R"("readings":1})", R"("readings":1}})")));
    REQUIRE(refused(with(R"("readings":1})", R"("readings":0})")));
    REQUIRE(refused(with(R"("readings":1})", R"("readings":5})")));
    REQUIRE(refused(with(R"("pid":42)", R"("pid":-1)")));
    REQUIRE(refused(with(R"("target":"/x")", R"("target":"/\"x")")));
    REQUIRE(refused(with(R"("target":"/x")", R"("target":"/\u0001")")));
    REQUIRE(refused(with(R"("t_ms":10)", R"("t_ms":"10")")));
    REQUIRE(refused(with(R"("t_ms":10)", R"("t_ms":99999999999999)")));
    REQUIRE(refused(with(R"("type":"event")", R"("type":"end")")));
    auto bad_header = header();
    bad_header.replace(bad_header.find(R"("version":1)"), 11, R"("version":2)");
    REQUIRE(refused(bad_header));
    auto bad_root = header();
    bad_root.replace(bad_root.find("/Users/u/proj"), 13, "Users/u/proj");
    REQUIRE(refused(bad_root));
    auto bad_state = end_line();
    bad_state.replace(bad_state.find("degraded"), 8, "unknown!");
    REQUIRE(refused(header() + bad_state));
    REQUIRE(refused(header() + std::string(70000, 'x') + "\n"));
    REQUIRE(refused(std::string((std::size_t{32} << 20U) + 1, '\n')));
    return 0;
}

} // namespace

int main() {
    for (auto* step : {round_trip, writer_refuses, reader_refuses}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    std::printf("denial trace ok\n");
    return 0;
}
