// JSONL sink: writes one well-formed JSON object per event; the bounded
// policy enforces the cap exactly and never retains blank or partial lines.

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include <glaze/glaze.hpp>
#include <sys/stat.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

// Wire-shape mirror of the sink's serialized event: every retained line must
// parse as exactly this strict object.
struct wire_event {
    std::string action;
    std::string tool;
    std::string arguments;
    std::string status;
    std::string error;
    std::int64_t timestamp_ns = 0;
    std::int64_t latency_ns = 0;
};

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream in{path};
    if (!in) {
        std::fprintf(stderr, "REQUIRE failed: open %s\n", path.c_str());
        std::exit(1);
    }
    std::stringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

// Strict complete-records contract: the file ends with exactly one newline,
// contains no blank lines, and every line parses as a valid audit event.
auto require_complete_jsonl_records(const std::string& contents) -> int {
    if (contents.empty() || contents.back() != '\n' || contents.front() != '{' ||
        contents.find("\n\n") != std::string::npos) {
        std::fprintf(stderr, "REQUIRE failed: journal is not complete newline-delimited JSON\n");
        return 1;
    }
    std::size_t begin = 0;
    while (begin < contents.size()) {
        const auto end = contents.find('\n', begin);
        if (end == std::string::npos) {
            std::fprintf(stderr, "REQUIRE failed: unterminated final line\n");
            return 1;
        }
        const std::string line = contents.substr(begin, end - begin);
        wire_event parsed;
        constexpr glz::opts strict{.error_on_unknown_keys = true};
        if (line.empty() || glz::read<strict>(parsed, line) || parsed.action.empty()) {
            std::fprintf(stderr, "REQUIRE failed: retained line is not a valid JSON record\n");
            return 1;
        }
        begin = end + 1U;
    }
    return 0;
}

auto make_event(std::string tool, std::string arguments) -> glove::audit::event {
    return glove::audit::event{
        .what = glove::audit::action::call_tool,
        .tool_name = std::move(tool),
        .arguments_json = std::move(arguments),
        .status = glove::mcp::tool_call_status::ok,
        .error_message = "",
        .at = std::chrono::system_clock::now(),
        .latency = std::chrono::nanoseconds{1},
    };
}

auto run() -> int {
    auto path = std::filesystem::temp_directory_path() / "glove_jsonl_sink_test.jsonl";
    std::filesystem::remove(path);

    auto sink_or = glove::audit::make_jsonl_sink(path);
    REQUIRE(sink_or.has_value());
    auto sink = *sink_or;

    glove::audit::event a{
        .what = glove::audit::action::call_tool,
        .tool_name = "echo",
        .arguments_json = R"({"text":"hi"})",
        .status = glove::mcp::tool_call_status::ok,
        .error_message = "",
        .at = std::chrono::system_clock::now(),
        .latency = std::chrono::nanoseconds{1234},
    };
    REQUIRE(sink->record(a).has_value());

    glove::audit::event b{
        .what = glove::audit::action::call_tool,
        .tool_name = "rm",
        .arguments_json = "{}",
        .status = glove::mcp::tool_call_status::invalid_arguments,
        .error_message = "policy denied",
        .at = std::chrono::system_clock::now(),
        .latency = std::chrono::nanoseconds{42},
    };
    REQUIRE(sink->record(b).has_value());

    glove::audit::event local_service{
        .what = glove::audit::action::local_service,
        .tool_name = "session-1:sage-observe",
        .arguments_json = {},
        .status = glove::mcp::tool_call_status::transport_error,
        .error_message = "closed",
        .at = std::chrono::system_clock::now(),
        .latency = std::chrono::nanoseconds{7},
    };
    REQUIRE(sink->record(local_service).has_value());

    std::ifstream in{path};
    REQUIRE(in);
    std::stringstream buf;
    buf << in.rdbuf();
    auto contents = buf.str();

    REQUIRE(contents.find("\"action\":\"call_tool\"") != std::string::npos);
    REQUIRE(contents.find("\"tool\":\"echo\"") != std::string::npos);
    REQUIRE(contents.find("\"status\":\"ok\"") != std::string::npos);
    REQUIRE(contents.find("\"tool\":\"rm\"") != std::string::npos);
    REQUIRE(contents.find("\"status\":\"invalid_arguments\"") != std::string::npos);
    REQUIRE(contents.find("policy denied") != std::string::npos);
    REQUIRE(contents.find("\"action\":\"local_service\"") != std::string::npos);
    REQUIRE(contents.find("session-1:sage-observe") != std::string::npos);

    // Three lines, three newlines.
    int newlines = 0;
    for (char c : contents) {
        if (c == '\n') {
            ++newlines;
        }
    }
    REQUIRE(newlines == 3);

    std::filesystem::remove(path);

    // Bounded policy: with a positive max_file_bytes cap, the sink truncates
    // the oldest records to make room for the newest one, the physical file
    // size never exceeds the cap across repeated truncation cycles, and
    // every retained line stays a complete, parseable JSON record.
    const auto bounded_path =
        std::filesystem::temp_directory_path() / "glove_jsonl_sink_bounded_test.jsonl";
    std::filesystem::remove(bounded_path);
    constexpr std::uint64_t cap = 512;
    auto bounded_or = glove::audit::make_jsonl_sink(bounded_path, {.max_file_bytes = cap});
    REQUIRE(bounded_or.has_value());
    auto bounded = *bounded_or;

    for (int index = 0; index < 200; ++index) {
        glove::audit::event fill = make_event(
            "fill-" + std::to_string(index),
            R"({"padding":"0123456789012345678901234567890123456789"})"
        );
        REQUIRE(bounded->record(fill).has_value());
        // The cap is enforced exactly after every record, not just at the
        // end: byte accounting must track the physical file through
        // repeated truncation cycles.
        REQUIRE(std::filesystem::file_size(bounded_path) <= cap);
    }

    auto bounded_size = std::filesystem::file_size(bounded_path);
    REQUIRE(bounded_size <= cap);
    REQUIRE(bounded_size > 0);

    // The newest record must be present after truncation; the oldest are
    // gone. Reopening the sink must not change the physical size.
    const auto bounded_contents = read_file(bounded_path);
    REQUIRE(bounded_contents.find("fill-199") != std::string::npos);
    REQUIRE(bounded_contents.find("fill-0\"") == std::string::npos);
    REQUIRE(require_complete_jsonl_records(bounded_contents) == 0);
    REQUIRE(bounded_contents.size() == bounded_size);

    // Release the first sink (it holds the exclusive journal lock).
    bounded.reset();
    bounded_or->reset();
    auto reopened_or = glove::audit::make_jsonl_sink(bounded_path, {.max_file_bytes = cap});
    REQUIRE(reopened_or.has_value());
    auto reopened = *reopened_or;
    REQUIRE(std::filesystem::file_size(bounded_path) == bounded_size);
    for (int index = 0; index < 50; ++index) {
        glove::audit::event fill = make_event(
            "reopen-" + std::to_string(index),
            R"({"padding":"0123456789012345678901234567890123456789"})"
        );
        REQUIRE(reopened->record(fill).has_value());
        REQUIRE(std::filesystem::file_size(bounded_path) <= cap);
    }
    REQUIRE(require_complete_jsonl_records(read_file(bounded_path)) == 0);
    REQUIRE(read_file(bounded_path).find("reopen-49") != std::string::npos);

    std::filesystem::remove(bounded_path);

    // Hard cap, oversized single event: an event whose encoded form cannot
    // fit under the cap is dropped — never written, never partially
    // written — and the journal keeps its exact previous size.
    const auto oversized_path =
        std::filesystem::temp_directory_path() / "glove_jsonl_sink_oversized_test.jsonl";
    std::filesystem::remove(oversized_path);
    auto oversized_or = glove::audit::make_jsonl_sink(oversized_path, {.max_file_bytes = 256});
    REQUIRE(oversized_or.has_value());
    auto oversized = *oversized_or;
    glove::audit::event normal = make_event("fits", R"({"padding":"pad"})");
    REQUIRE(oversized->record(normal).has_value());
    const auto before_oversized = std::filesystem::file_size(oversized_path);
    glove::audit::event too_big =
        make_event("too-big", R"({"padding":")" + std::string(512, 'x') + R"("})");
    REQUIRE(too_big.tool_name == "too-big");
    REQUIRE(oversized->record(too_big).has_value());
    REQUIRE(std::filesystem::file_size(oversized_path) == before_oversized);
    REQUIRE(require_complete_jsonl_records(read_file(oversized_path)) == 0);
    REQUIRE(read_file(oversized_path).find("too-big") == std::string::npos);
    REQUIRE(read_file(oversized_path).find("\"tool\":\"fits\"") != std::string::npos);
    std::filesystem::remove(oversized_path);

    // Pre-existing oversized journal: the sink bounds the file to the cap at
    // construction with a bounded read, and the retained suffix is a run of
    // complete parseable records.
    const auto preexisting_path =
        std::filesystem::temp_directory_path() / "glove_jsonl_sink_preexisting_test.jsonl";
    std::filesystem::remove(preexisting_path);
    {
        std::ofstream seed{preexisting_path, std::ios::binary};
        REQUIRE(seed.good());
        for (int index = 0; index < 100; ++index) {
            seed << R"({"action":"call_tool","tool":"seed-)" << index
                 << R"(","arguments":"{}","status":"ok","error":"","timestamp_ns":0,)"
                    R"("latency_ns":1})"
                 << '\n';
        }
        seed.flush();
        REQUIRE(seed.good());
    }
    REQUIRE(std::filesystem::file_size(preexisting_path) > 512);
    // The journal must be an owner-only file for make_jsonl_sink to accept it.
    REQUIRE(::chmod(preexisting_path.c_str(), 0600) == 0);
    auto preexisting_or = glove::audit::make_jsonl_sink(preexisting_path, {.max_file_bytes = 512});
    REQUIRE(preexisting_or.has_value());
    // Already bounded immediately after construction, before any record().
    REQUIRE(std::filesystem::file_size(preexisting_path) <= 512);
    REQUIRE(require_complete_jsonl_records(read_file(preexisting_path)) == 0);
    for (int index = 0; index < 20; ++index) {
        glove::audit::event fill = make_event(
            "post-" + std::to_string(index),
            R"({"padding":"0123456789012345678901234567890123456789"})"
        );
        REQUIRE(preexisting_or.value()->record(fill).has_value());
        REQUIRE(std::filesystem::file_size(preexisting_path) <= 512);
    }
    REQUIRE(require_complete_jsonl_records(read_file(preexisting_path)) == 0);
    REQUIRE(read_file(preexisting_path).find("post-19") != std::string::npos);

    std::filesystem::remove(preexisting_path);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
