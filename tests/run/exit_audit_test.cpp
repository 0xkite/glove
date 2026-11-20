// The agent's exit record survives a failed group cleanup: the known exit
// code is recorded first, then a separate agent_cleanup_failed record.

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include "exit_audit.hpp"

#include <cstdio>
#include <expected>
#include <memory>
#include <optional>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::audit::action;
using glove::mcp::tool_call_status;
using glove::run::detail::record_agent_exit;

class failing_sink final : public glove::audit::sink {
public:
    auto record(const glove::audit::event& /*event*/) -> std::expected<void, std::string> override {
        ++calls;
        return std::unexpected(std::string{"full"});
    }

    int calls = 0;
};

auto memory_cases() -> int {
    {
        auto sink = glove::audit::make_memory_sink();
        const auto result = record_agent_exit(sink, 0, std::nullopt);
        REQUIRE(result && *result == 0);
        const auto events = sink->take();
        REQUIRE(events.size() == 1);
        REQUIRE(events[0].what == action::agent_exit && events[0].tool_name == "0");
        REQUIRE(events[0].status == tool_call_status::ok);
    }
    {
        auto sink = glove::audit::make_memory_sink();
        const auto result = record_agent_exit(sink, 3, 3);
        REQUIRE(result && *result == 3);
        const auto events = sink->take();
        REQUIRE(events.size() == 1);
        REQUIRE(events[0].status == tool_call_status::execution_error);
    }
    {
        auto sink = glove::audit::make_memory_sink();
        const std::expected<int, std::string> waited =
            std::unexpected(std::string{"agent group drain: x"});
        const auto result = record_agent_exit(sink, waited, 9);
        REQUIRE(!result && result.error() == "wait: agent group drain: x");
        const auto events = sink->take();
        REQUIRE(events.size() == 2);
        REQUIRE(events[0].what == action::agent_exit && events[0].tool_name == "9");
        REQUIRE(events[0].status == tool_call_status::execution_error);
        REQUIRE(events[1].what == action::control);
        REQUIRE(events[1].tool_name == "agent_cleanup_failed");
        REQUIRE(events[1].status == tool_call_status::execution_error);
        REQUIRE(events[1].error_message == "agent group drain: x");
    }
    {
        auto sink = glove::audit::make_memory_sink();
        const std::expected<int, std::string> waited = std::unexpected(std::string{"y"});
        const auto result = record_agent_exit(sink, waited, std::nullopt);
        REQUIRE(!result && result.error() == "wait: y");
        REQUIRE(sink->take().empty());
    }
    return 0;
}

auto failing_cases() -> int {
    {
        auto sink = std::make_shared<failing_sink>();
        const auto result = record_agent_exit(sink, 0, std::nullopt);
        REQUIRE(!result && result.error() == "audit exit: full");
    }
    {
        auto sink = std::make_shared<failing_sink>();
        const std::expected<int, std::string> waited =
            std::unexpected(std::string{"agent group drain: x"});
        const auto result = record_agent_exit(sink, waited, 9);
        REQUIRE(!result);
        REQUIRE(result.error().contains("wait: "));
        REQUIRE(result.error().contains("audit exit: full"));
        REQUIRE(sink->calls == 2);
    }
    return 0;
}

} // namespace

int main() {
    if (const int failed = memory_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = failing_cases(); failed != 0) {
        return failed;
    }
    std::printf("exit audit ok\n");
    return 0;
}
