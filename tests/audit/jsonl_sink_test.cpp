// JSONL sink: writes one well-formed JSON object per event.

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

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
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
