// End-to-end kernel test: drive a server reading from the kernel side of a
// mock_pair, while the test acts as the agent on the other side. Validates
// the request/response loop, policy gating, and audit recording.

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/kernel/extension.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/kernel/server.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include "tests/kernel/mock_pair.hpp"

#include <cstdio>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class echo_extension final : public glove::kernel::extension {
public:
    auto name() const -> std::string_view override { return "echo"; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return std::vector<glove::mcp::tool_descriptor>{
            {.name = "say",
             .description = "Echo the text argument back as content.",
             .input_schema_json = R"({"type":"object","properties":{"text":{"type":"string"}}})",
             .annotations = {}},
            {.name = "secret",
             .description = "Must not be advertised when policy denies it.",
             .input_schema_json = R"({"type":"object"})",
             .annotations = {}},
        };
    }

    auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        if (tool_name != "say") {
            return std::unexpected(std::string{"unknown tool"});
        }
        return glove::mcp::tool_call_result{
            .status = glove::mcp::tool_call_status::ok,
            .content = "echoed",
            .structured_json = std::string{arguments_json},
            .error_message = "",
        };
    }
};

class raw_json_extension final : public glove::kernel::extension {
public:
    auto name() const -> std::string_view override { return "raw"; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return std::vector<glove::mcp::tool_descriptor>{
            {.name = "pretty",
             .description = "Returns pretty-printed structured JSON.",
             .input_schema_json = "{\n  \"type\": \"object\"\n}",
             .annotations = {}},
            {.name = "broken",
             .description = "Returns malformed structured JSON.",
             .input_schema_json = "{}",
             .annotations = {}},
        };
    }

    auto invoke(std::string_view tool_name, std::string_view /*arguments_json*/)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        if (tool_name == "pretty") {
            return glove::mcp::tool_call_result{
                .status = glove::mcp::tool_call_status::ok,
                .content = "ok",
                .structured_json = "{\n  \"nested\": {\n    \"ok\": true,\n    \"exact\": "
                                   "9007199254740993,\n    \"msg\": \"hi\\u0001\"\n  }\n}",
                .error_message = "",
            };
        }
        return glove::mcp::tool_call_result{
            .status = glove::mcp::tool_call_status::ok,
            .content = "bad",
            .structured_json = "{not valid json",
            .error_message = "",
        };
    }
};

auto run() -> int {
    glove::testing::mock_pair pair;

    glove::kernel::registry reg;
    REQUIRE(reg.add(std::make_unique<echo_extension>()).has_value());

    // Policy operates on the qualified tool name as the agent sees it.
    auto policy_eng = glove::policy::make_allow_list_engine(
        {.allow = {"echo.say"},
         .deny = {"echo.forbidden"},
         .default_decision = glove::policy::decision::deny}
    );
    auto sink = glove::audit::make_memory_sink();

    glove::kernel::server::options opts{
        .identity = {.name = "glove-test", .version = "0.0.1"},
        .policy = std::move(policy_eng),
        .audit = sink,
    };
    glove::kernel::server srv{pair.kernel_side(), reg, std::move(opts)};

    std::thread server_thread{[&] { (void)srv.run(); }};

    auto& agent = pair.agent_side();

    // initialize
    REQUIRE(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})"
            )
            .has_value()
    );
    auto reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":1") != std::string::npos);
    REQUIRE(reply->find("\"name\":\"glove-test\"") != std::string::npos);
    REQUIRE(reply->find("2025-06-18") != std::string::npos);

    // tools/list
    REQUIRE(agent.send(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").has_value());
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":2") != std::string::npos);
    REQUIRE(reply->find("\"name\":\"echo.say\"") != std::string::npos);
    REQUIRE(reply->find("echo.secret") == std::string::npos);

    // tools/call allowed
    REQUIRE(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo.say","arguments":{"text":"hi"}}})"
            )
            .has_value()
    );
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":3") != std::string::npos);
    REQUIRE(reply->find("\"text\":\"hi\"") != std::string::npos);

    // tools/call denied by policy (echo.forbidden does not exist as a tool,
    // but it doesn't matter — policy denies before dispatch; we just need a
    // name that's not in the allow list).
    REQUIRE(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo.unknown_tool","arguments":{}}})"
            )
            .has_value()
    );
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":4") != std::string::npos);
    REQUIRE(reply->find("policy denied") != std::string::npos);

    // unknown method
    REQUIRE(agent.send(R"({"jsonrpc":"2.0","id":5,"method":"resources/list"})").has_value());
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":5") != std::string::npos);
    REQUIRE(reply->find("-32601") != std::string::npos);

    // unknown method with quotes/backslashes/control escapes must still produce valid
    // single-line JSON-RPC error without dropping the session.
    REQUIRE(
        agent.send(R"({"jsonrpc":"2.0","id":6,"method":"bad\\method\"name\n\u0000"})").has_value()
    );
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":6") != std::string::npos);
    REQUIRE(reply->find("-32601") != std::string::npos);
    REQUIRE(reply->find('\n') == std::string::npos);

    // notification: no response should appear.
    REQUIRE(agent.send(R"({"jsonrpc":"2.0","method":"notifications/initialized"})").has_value());

    // Close the agent → kernel direction so the server exits.
    pair.close_agent_to_kernel();
    server_thread.join();

    auto events = sink->take();
    // Expected: initialize, tools/list, tools/call OK, tools/call DENIED.
    REQUIRE(events.size() >= 4);
    REQUIRE(events[0].what == glove::audit::action::initialize);
    REQUIRE(events[1].what == glove::audit::action::list_tools);
    REQUIRE(events[2].what == glove::audit::action::call_tool);
    REQUIRE(events[2].status == glove::mcp::tool_call_status::ok);
    REQUIRE(events[3].what == glove::audit::action::call_tool);
    REQUIRE(events[3].status == glove::mcp::tool_call_status::invalid_arguments);
    REQUIRE(events[3].error_message.find("policy denied") != std::string::npos);

    return 0;
}

auto run_raw_json_normalization() -> int {
    glove::testing::mock_pair pair;
    glove::kernel::registry reg;
    REQUIRE(reg.add(std::make_unique<raw_json_extension>()).has_value());

    glove::kernel::server::options opts{
        .identity = {.name = "glove-test", .version = "0.0.1"},
        .policy = nullptr,
        .audit = nullptr,
    };
    glove::kernel::server srv{pair.kernel_side(), reg, std::move(opts)};
    std::thread server_thread{[&] { (void)srv.run(); }};

    auto& agent = pair.agent_side();
    REQUIRE(agent.send(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").has_value());
    auto reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find('\n') == std::string::npos);
    REQUIRE(reply->find(R"("inputSchema":{"type":"object"})") != std::string::npos);

    REQUIRE(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"raw.pretty","arguments":{}}})"
            )
            .has_value()
    );
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find('\n') == std::string::npos);
    REQUIRE(reply->find(R"("exact":9007199254740993)") != std::string::npos);
    REQUIRE(reply->find(R"("nested":{"ok":true)") != std::string::npos);

    REQUIRE(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"raw.broken","arguments":{}}})"
            )
            .has_value()
    );
    reply = agent.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":3") != std::string::npos);
    REQUIRE(reply->find("-32603") != std::string::npos);

    pair.close_agent_to_kernel();
    server_thread.join();
    return 0;
}

} // namespace

auto main() -> int {
    if (run() != 0) {
        return 1;
    }
    return run_raw_json_normalization();
}
