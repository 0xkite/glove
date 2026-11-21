// Bounded denial telemetry records: exact shapes, the per-second and
// per-session caps, unsafe-field replacement, sink failure, and the stderr
// notice lines.

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/container/denial_telemetry.hpp"

#include "denial_audit.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <memory>
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

using glove::audit::action;
using glove::container::denial_monitor_report;
using glove::container::denial_telemetry_state;
using glove::container::sandbox_denial;
using glove::mcp::tool_call_status;
using glove::run::detail::denial_audit_writer;
using glove::run::detail::denial_notice;
using glove::run::detail::denial_notice_line;
using time_point = std::chrono::steady_clock::time_point;

struct fake_clock {
    time_point now{};

    auto function() -> denial_audit_writer::clock {
        return [this] { return now; };
    }

    void advance_ms(int milliseconds) { now += std::chrono::milliseconds{milliseconds}; }
};

class failing_after_sink final : public glove::audit::sink {
public:
    explicit failing_after_sink(int good) : good_{good} {}

    auto record(const glove::audit::event& /*event*/) -> std::expected<void, std::string> override {
        ++calls;
        if (calls > good_) {
            return std::unexpected(std::string{"disk full"});
        }
        return {};
    }

    int calls = 0;

private:
    int good_;
};

auto sample_denial() -> sandbox_denial {
    return {
        .kind = "file_write",
        .operation = "file-write-create",
        .target = "/tmp/x%0Ay",
        .target_truncated = false,
        .comm = "touch",
        .pid = 42,
        .duplicate_reports = 2,
        .readings = 1,
    };
}

auto live_report() -> denial_monitor_report {
    return {
        .state = denial_telemetry_state::live,
        .reason = "",
        .stream_events = 5,
        .stream_rejected = 1,
        .end_proof = true,
    };
}

// The value of "name":<number> in a summary's arguments_json, or -1.
auto field(const std::string& json, std::string_view name) -> long long {
    const std::string key = "\"" + std::string{name} + "\":";
    const auto at = json.find(key);
    if (at == std::string::npos) {
        return -1;
    }
    return std::stoll(json.substr(at + key.size()));
}

auto clean_json(std::string_view text) -> bool {
    std::string stripped;
    for (const char byte : text) {
        if (byte != '{' && byte != '}' && byte != '"' && byte != ':' && byte != ',') {
            stripped.push_back(byte);
        }
    }
    return glove::container::is_encoded_text(stripped);
}

auto all_clean(const std::vector<glove::audit::event>& events) -> bool {
    for (const auto& event : events) {
        if (!clean_json(event.arguments_json) ||
            !glove::container::is_encoded_text(event.error_message)) {
            return false;
        }
    }
    return true;
}

// A denial whose target is a decoy also gets a "decoy" record with its own
// cap, even when the ordinary rate window is already full, and the summary
// counts every hit.
auto decoys() -> int {
    auto sink = glove::audit::make_memory_sink();
    fake_clock clock;
    denial_audit_writer writer{sink, clock.function()};
    const std::vector<std::filesystem::path> planted{"/Users/u/vault/glove_ab12", "/tmp/x\ny"};
    writer.watch_decoys(planted);
    writer.record_start(denial_telemetry_state::live, "");
    for (int index = 0; index != 16; ++index) {
        writer.on_denial(sample_denial()); // "/tmp/x%0Ay" is the encoded second decoy
    }
    auto read_decoy = sample_denial();
    read_decoy.kind = "file_read";
    read_decoy.operation = "file-read-data";
    read_decoy.target = "/Users/u/vault/glove_ab12";
    for (int index = 0; index != 40; ++index) {
        writer.on_denial(read_decoy);
    }
    auto other = sample_denial();
    other.target = "/Users/u/vault/glove_ab12.pub";
    writer.on_denial(other);
    REQUIRE(writer.finish(live_report()).has_value());
    const auto events = sink->take();
    std::size_t decoy_records = 0;
    for (const auto& event : events) {
        if (event.tool_name == "decoy") {
            ++decoy_records;
            REQUIRE(event.status != tool_call_status::ok);
            REQUIRE(
                event.arguments_json.contains("glove_ab12") ||
                event.arguments_json.contains("/tmp/x%0Ay")
            );
            REQUIRE(!event.arguments_json.contains(".pub"));
        }
    }
    REQUIRE(decoy_records == glove::run::detail::decoy_audit_per_session);
    REQUIRE(events.back().tool_name == "summary");
    REQUIRE(field(events.back().arguments_json, "decoys") == 2);
    REQUIRE(field(events.back().arguments_json, "decoy_hits") == 56);
    REQUIRE(all_clean(events));
    return 0;
}

// A shadow decider's verdict is recorded once per escalation, whatever the
// ordinary rate window holds, and the summary carries the highest verdict.
// Nothing here can act on a verdict: the writer only appends records.
auto shadow() -> int {
    auto sink = glove::audit::make_memory_sink();
    fake_clock clock;
    denial_audit_writer writer{sink, clock.function()};
    const glove::container::denial_context context{
        .workspace_roots = {"/Users/u/proj"},
        .home = "/Users/u",
        .decoys = {"/Users/u/vault/token"},
    };
    writer.attach_decider(glove::container::make_heuristic_denial_decider(), context);
    writer.record_start(denial_telemetry_state::live, "");
    auto calm = sample_denial();
    calm.target = "/Users/u/proj/x";
    for (int index = 0; index != 20; ++index) {
        writer.on_denial(calm); // fills the one-second audit window
    }
    auto reach = sample_denial();
    reach.kind = "file_read";
    reach.target = "/Users/u/vault/token";
    clock.advance_ms(250);
    writer.on_denial(reach);
    writer.on_denial(reach);
    clock.advance_ms(250);
    writer.on_denial(reach);
    writer.on_denial(reach);
    REQUIRE(writer.finish(live_report()).has_value());
    writer.on_denial(reach);
    const auto events = sink->take();
    std::vector<glove::audit::event> verdicts;
    for (const auto& event : events) {
        if (event.tool_name == "verdict") {
            verdicts.push_back(event);
        }
    }
    REQUIRE(verdicts.size() == 2);
    REQUIRE(verdicts.at(0).arguments_json.contains(R"("mode":"shadow","arm":"heuristic")"));
    REQUIRE(verdicts.at(0).arguments_json.contains(R"("verdict":"flag")"));
    REQUIRE(field(verdicts.at(0).arguments_json, "denials") == 21);
    REQUIRE(field(verdicts.at(0).arguments_json, "t_ms") == 250);
    REQUIRE(verdicts.at(1).arguments_json.contains(R"("verdict":"terminate")"));
    REQUIRE(field(verdicts.at(1).arguments_json, "denials") == 23);
    REQUIRE(field(verdicts.at(1).arguments_json, "t_ms") == 500);
    for (const auto& verdict : verdicts) {
        REQUIRE(verdict.status != tool_call_status::ok);
        REQUIRE(verdict.error_message == "shadow verdict; no action was taken");
    }
    REQUIRE(events.back().tool_name == "summary");
    REQUIRE(
        events.back().arguments_json.contains(R"("decider":"heuristic","verdict":"terminate")")
    );
    REQUIRE(all_clean(events));

    // Without a decider the summary says nothing about one, and a decider
    // attached after the start is ignored.
    auto plain_sink = glove::audit::make_memory_sink();
    denial_audit_writer plain{plain_sink, clock.function()};
    plain.record_start(denial_telemetry_state::live, "");
    plain.attach_decider(glove::container::make_heuristic_denial_decider(), context);
    plain.on_denial(reach);
    REQUIRE(plain.finish(live_report()).has_value());
    for (const auto& event : plain_sink->take()) {
        REQUIRE(event.tool_name != "verdict");
        REQUIRE(!event.arguments_json.contains("decider"));
    }

    // A decider the operator asked for but glove could not use is recorded
    // once, with its reason, and the launch's telemetry is otherwise as usual.
    auto missing_sink = glove::audit::make_memory_sink();
    denial_audit_writer missing{missing_sink, clock.function()};
    missing.record_decider_unavailable("denial model: no such file");
    missing.record_decider_unavailable("again");
    missing.record_start(denial_telemetry_state::live, "");
    REQUIRE(missing.finish(live_report()).has_value());
    const auto missing_events = missing_sink->take();
    REQUIRE(missing_events.front().tool_name == "decider");
    REQUIRE(missing_events.front().status != tool_call_status::ok);
    REQUIRE(missing_events.front().error_message == "denial model: no such file");
    REQUIRE(std::ranges::count_if(missing_events, [](const auto& event) {
                return event.tool_name == "decider";
            }) == 1);
    return 0;
}

auto shapes() -> int {
    auto sink = glove::audit::make_memory_sink();
    fake_clock clock;
    denial_audit_writer writer{sink, clock.function()};
    writer.record_start(denial_telemetry_state::live, "");
    writer.on_denial(sample_denial());
    REQUIRE(writer.finish(live_report()).has_value());
    const auto events = sink->take();
    REQUIRE(events.size() == 3);
    for (const auto& event : events) {
        REQUIRE(event.what == action::sandbox_denial);
    }
    REQUIRE(events[0].tool_name == "telemetry");
    REQUIRE(events[0].arguments_json == R"({"state":"live"})");
    REQUIRE(events[0].status == tool_call_status::ok);
    REQUIRE(events[1].tool_name == "file_write");
    REQUIRE(
        events[1].arguments_json ==
        R"({"operation":"file-write-create","target":"/tmp/x%0Ay","target_truncated":false,"comm":"touch","pid":42,"duplicates":2,"readings":1})"
    );
    REQUIRE(events[2].tool_name == "summary");
    REQUIRE(
        events[2].arguments_json ==
        R"({"state":"live","recorded":1,"suppressed_rate":0,"suppressed_cap":0,"suppressed_error":0,"unsafe_fields":0,"duplicates":2,"stream_events":5,"stream_rejected":1,"end_proof":true})"
    );
    REQUIRE(events[2].status == tool_call_status::ok);
    REQUIRE(all_clean(events));
    return 0;
}

auto rate() -> int {
    auto sink = glove::audit::make_memory_sink();
    fake_clock clock;
    denial_audit_writer writer{sink, clock.function()};
    writer.record_start(denial_telemetry_state::live, "");
    for (int index = 0; index != 40; ++index) {
        writer.on_denial(sample_denial());
    }
    clock.advance_ms(1000);
    for (int index = 0; index != 40; ++index) {
        writer.on_denial(sample_denial());
    }
    REQUIRE(writer.finish(live_report()).has_value());
    const auto events = sink->take();
    REQUIRE(events.size() == 1 + 32 + 1);
    REQUIRE(field(events.back().arguments_json, "recorded") == 32);
    REQUIRE(field(events.back().arguments_json, "suppressed_rate") == 48);
    REQUIRE(all_clean(events));
    return 0;
}

auto cap() -> int {
    auto sink = glove::audit::make_memory_sink();
    fake_clock clock;
    denial_audit_writer writer{sink, clock.function()};
    writer.record_start(denial_telemetry_state::live, "");
    for (int windows = 0; windows != 20; ++windows) {
        for (int index = 0; index != 16; ++index) {
            writer.on_denial(sample_denial());
        }
        clock.advance_ms(1000);
    }
    REQUIRE(writer.finish(live_report()).has_value());
    const auto events = sink->take();
    REQUIRE(field(events.back().arguments_json, "recorded") == 256);
    REQUIRE(field(events.back().arguments_json, "suppressed_cap") == 64);
    REQUIRE(field(events.back().arguments_json, "suppressed_rate") == 0);
    return 0;
}

auto unsafe() -> int {
    const auto one = [](sandbox_denial denial) -> std::vector<glove::audit::event> {
        auto sink = glove::audit::make_memory_sink();
        denial_audit_writer writer{sink};
        writer.record_start(denial_telemetry_state::live, "");
        writer.on_denial(denial);
        (void)writer.finish(live_report());
        return sink->take();
    };
    auto quoted = sample_denial();
    quoted.target = "a\"b";
    auto events = one(quoted);
    REQUIRE(events.size() == 3);
    REQUIRE(events[1].arguments_json.contains(R"("target":"")"));
    REQUIRE(field(events[2].arguments_json, "unsafe_fields") == 1);

    auto long_target = sample_denial();
    long_target.target = std::string(513, 'a');
    events = one(long_target);
    REQUIRE(events[1].arguments_json.contains(R"("target":"")"));
    REQUIRE(field(events[2].arguments_json, "unsafe_fields") == 1);

    auto bad_kind = sample_denial();
    bad_kind.kind = "x y\n";
    events = one(bad_kind);
    REQUIRE(events[1].tool_name.empty());
    REQUIRE(field(events[2].arguments_json, "unsafe_fields") == 1);
    return 0;
}

auto unavailable() -> int {
    auto sink = glove::audit::make_memory_sink();
    denial_audit_writer writer{sink};
    writer.record_start(denial_telemetry_state::unavailable, "log%20missing");
    REQUIRE(writer.finish({}).has_value());
    const auto events = sink->take();
    REQUIRE(events.size() == 1);
    REQUIRE(events[0].arguments_json == R"({"state":"unavailable"})");
    REQUIRE(events[0].status == tool_call_status::transport_error);
    REQUIRE(events[0].error_message == "log%20missing");
    return 0;
}

// A degradation reported before the start record (the stream died between
// its start proof and arming) is written after it, never before.
auto early_degraded() -> int {
    {
        auto sink = glove::audit::make_memory_sink();
        denial_audit_writer writer{sink};
        writer.on_degraded("early");
        writer.record_start(denial_telemetry_state::live, "");
        const auto events = sink->take();
        REQUIRE(events.size() == 2);
        REQUIRE(events[0].arguments_json == R"({"state":"live"})");
        REQUIRE(events[1].arguments_json == R"({"state":"degraded"})");
        REQUIRE(events[1].error_message == "early");
    }
    {
        auto sink = glove::audit::make_memory_sink();
        denial_audit_writer writer{sink};
        writer.record_start(denial_telemetry_state::degraded, "lost");
        writer.on_degraded("again");
        const auto events = sink->take();
        REQUIRE(events.size() == 2);
        REQUIRE(events[0].arguments_json == R"({"state":"live"})");
        REQUIRE(events[1].arguments_json == R"({"state":"degraded"})");
        REQUIRE(events[1].error_message == "lost");
    }
    {
        auto sink = glove::audit::make_memory_sink();
        denial_audit_writer writer{sink};
        writer.on_degraded("early");
        writer.record_start(denial_telemetry_state::unavailable, "none");
        const auto events = sink->take();
        REQUIRE(events.size() == 1);
        REQUIRE(events[0].arguments_json == R"({"state":"unavailable"})");
    }
    return 0;
}

auto degraded() -> int {
    auto sink = glove::audit::make_memory_sink();
    denial_audit_writer writer{sink};
    writer.record_start(denial_telemetry_state::live, "");
    writer.on_degraded("log%20stream%20ended");
    writer.on_degraded("again");
    REQUIRE(writer
                .finish({
                    .state = denial_telemetry_state::degraded,
                    .reason = "log%20stream%20ended",
                    .stream_events = 0,
                    .stream_rejected = 0,
                    .end_proof = false,
                })
                .has_value());
    const auto events = sink->take();
    REQUIRE(events.size() == 3);
    REQUIRE(events[1].arguments_json == R"({"state":"degraded"})");
    REQUIRE(events[1].status == tool_call_status::transport_error);
    REQUIRE(events[2].arguments_json.contains(R"("state":"degraded")"));
    REQUIRE(events[2].status == tool_call_status::transport_error);
    REQUIRE(events[2].error_message == "log%20stream%20ended");
    REQUIRE(all_clean(events));
    return 0;
}

auto sink_failure() -> int {
    auto sink = std::make_shared<failing_after_sink>(2);
    denial_audit_writer writer{sink};
    writer.record_start(denial_telemetry_state::live, "");
    writer.on_denial(sample_denial());
    writer.on_denial(sample_denial()); // third record() fails
    REQUIRE(sink->calls == 3);
    writer.on_denial(sample_denial());
    writer.on_denial(sample_denial());
    REQUIRE(sink->calls == 3);
    const auto finished = writer.finish(live_report());
    REQUIRE(sink->calls == 4);
    REQUIRE(!finished);
    REQUIRE(finished.error().starts_with("audit denial telemetry: "));

    // The summary counts the suppressed denials.
    auto memory = glove::audit::make_memory_sink();
    auto failing = std::make_shared<failing_after_sink>(1);

    struct tee final : glove::audit::sink {
        std::shared_ptr<glove::audit::sink> first;
        std::shared_ptr<glove::audit::sink> second;

        auto record(const glove::audit::event& event) -> std::expected<void, std::string> override {
            (void)first->record(event);
            return second->record(event);
        }
    };

    auto both = std::make_shared<tee>();
    both->first = memory;
    both->second = failing;
    denial_audit_writer counted{both};
    counted.record_start(denial_telemetry_state::live, "");
    counted.on_denial(sample_denial()); // fails
    counted.on_denial(sample_denial()); // suppressed
    (void)counted.finish(live_report());
    const auto events = memory->take();
    REQUIRE(field(events.back().arguments_json, "suppressed_error") == 1);
    return 0;
}

auto notices() -> int {
    REQUIRE(
        denial_notice_line(denial_notice::starting, "") ==
        "glove: starting sandbox denial telemetry (up to 2 s)\n"
    );
    REQUIRE(
        denial_notice_line(denial_notice::live, "") == "glove: sandbox denial telemetry is live\n"
    );
    REQUIRE(
        denial_notice_line(denial_notice::unavailable, "log%20missing") ==
        "glove: sandbox denial telemetry unavailable (log%20missing); the agent still runs "
        "sandboxed\n"
    );
    REQUIRE(
        denial_notice_line(denial_notice::stopping, "") ==
        "glove: stopping sandbox denial telemetry (up to 1 s)\n"
    );
    REQUIRE(
        denial_notice_line(denial_notice::degraded, "log%20missing") ==
        "glove: sandbox denial telemetry was incomplete this session (log%20missing); the agent "
        "ran sandboxed\n"
    );
    for (const std::string& bad : {std::string{"a\"b"}, std::string(257, 'a')}) {
        REQUIRE(denial_notice_line(denial_notice::unavailable, bad).contains("(unknown)"));
        REQUIRE(denial_notice_line(denial_notice::degraded, bad).contains("(unknown)"));
    }
    for (const auto what :
         {denial_notice::starting,
          denial_notice::live,
          denial_notice::unavailable,
          denial_notice::stopping,
          denial_notice::degraded}) {
        for (const char byte : denial_notice_line(what, "a%0Ab")) {
            const auto value = static_cast<unsigned char>(byte);
            REQUIRE(value == 0x0AU || (value >= 0x20U && value <= 0x7EU));
        }
    }
    return 0;
}

} // namespace

int main() {
    for (auto* step :
         {shapes,
          rate,
          cap,
          unsafe,
          unavailable,
          early_degraded,
          degraded,
          sink_failure,
          notices,
          decoys,
          shadow}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    std::printf("denial audit ok\n");
    return 0;
}
