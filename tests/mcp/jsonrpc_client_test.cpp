// End-to-end test for the real client: in_memory_transport + a fake JSON-RPC
// server that switches on the method name and returns canned responses.

#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"

#include "src/mcp/codec.hpp"

#include <array>
#include <cstdio>
#include <memory>
#include <optional>
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

auto fake_server(std::string_view request_frame) -> std::optional<std::string> {
    // Decoding the request would pull glaze into the test. Instead we sniff
    // the method name out of the frame; brittle but adequate for a fixed
    // protocol.
    if (request_frame.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return R"({"jsonrpc":"2.0","id":1,"result":{"tools":[)"
               R"({"name":"echo","description":"echoes its input","inputSchema":{"type":"object"}},)"
               R"({"name":"add","description":"adds two numbers","inputSchema":{"type":"object"}}]}})";
    }
    if (request_frame.find("\"method\":\"tools/call\"") != std::string_view::npos) {
        if (request_frame.find("\"name\":\"echo\"") != std::string_view::npos) {
            return R"({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"echoed!"}],"isError":false}})";
        }
        if (request_frame.find("\"name\":\"broken\"") != std::string_view::npos) {
            return R"({"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"oops"}],"isError":true}})";
        }
        if (request_frame.find("\"name\":\"missing\"") != std::string_view::npos) {
            return R"({"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"tool not found"}})";
        }
    }
    return R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"unhandled by fake server"}})";
}

auto mismatched_id_server(std::string_view request_frame) -> std::optional<std::string> {
    if (request_frame.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return R"({"jsonrpc":"2.0","id":99,"result":{"tools":[]}})";
    }
    return std::nullopt;
}

auto duplicate_id_server(std::string_view request_frame) -> std::optional<std::string> {
    if (request_frame.find("\"method\":\"tools/list\"") != std::string_view::npos) {
        return R"({"jsonrpc":"2.0","id":1,"result":{"tools":[]}})";
    }
    if (request_frame.find("\"method\":\"tools/call\"") != std::string_view::npos) {
        return R"({"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}})";
    }
    return std::nullopt;
}

auto correlated_server(std::string_view request_frame) -> std::optional<std::string> {
    auto request = glove::mcp::codec::decode_request(request_frame);
    if (!request || !request->id) {
        return R"({"jsonrpc":"2.0","id":0,"error":{"code":-32600,"message":"invalid request"}})";
    }
    auto response = glove::mcp::codec::encode_response_with_result(
        *request->id, R"({"content":[{"type":"text","text":"ok"}],"isError":false})"
    );
    if (!response) {
        return R"({"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"encoding failed"}})";
    }
    return std::move(*response);
}

auto run() -> int {
    auto transport = glove::mcp::make_in_memory_transport(fake_server);
    auto client = glove::mcp::make_client(std::move(transport));

    {
        auto tools = client->list_tools();
        REQUIRE(tools.has_value());
        REQUIRE(tools->size() == 2);
        REQUIRE((*tools)[0].name == "echo");
        REQUIRE((*tools)[1].name == "add");
    }

    {
        glove::mcp::tool_call_request req{.name = "echo", .arguments_json = R"({"msg":"hi"})"};
        auto result = client->call_tool(req);
        REQUIRE(result.has_value());
        REQUIRE(result->status == glove::mcp::tool_call_status::ok);
        REQUIRE(result->content == "echoed!");
    }

    {
        glove::mcp::tool_call_request req{.name = "broken", .arguments_json = "{}"};
        auto result = client->call_tool(req);
        REQUIRE(result.has_value());
        REQUIRE(result->status == glove::mcp::tool_call_status::execution_error);
    }

    {
        glove::mcp::tool_call_request req{.name = "missing", .arguments_json = "{}"};
        auto result = client->call_tool(req);
        REQUIRE(result.has_value());
        REQUIRE(result->status == glove::mcp::tool_call_status::execution_error);
        REQUIRE(result->error_message.find("tool not found") != std::string::npos);
    }

    {
        auto mismatched =
            glove::mcp::make_client(glove::mcp::make_in_memory_transport(mismatched_id_server));
        auto tools = mismatched->list_tools();
        REQUIRE(!tools.has_value());
        REQUIRE(tools.error().find("response id") != std::string::npos);
    }

    {
        auto duplicate =
            glove::mcp::make_client(glove::mcp::make_in_memory_transport(duplicate_id_server));
        REQUIRE(duplicate->list_tools().has_value());
        auto result = duplicate->call_tool({.name = "echo", .arguments_json = "{}"});
        REQUIRE(!result.has_value());
        REQUIRE(result.error().find("response id") != std::string::npos);
    }

    {
        auto concurrent =
            glove::mcp::make_client(glove::mcp::make_in_memory_transport(correlated_server));
        std::array<bool, 8> succeeded{};
        {
            std::vector<std::jthread> workers;
            workers.reserve(succeeded.size());
            for (std::size_t index = 0; index < succeeded.size(); ++index) {
                workers.emplace_back([&concurrent, &succeeded, index] {
                    auto result = concurrent->call_tool({.name = "echo", .arguments_json = "{}"});
                    succeeded[index] = result.has_value() && result->content == "ok";
                });
            }
        }
        for (const bool result : succeeded) {
            REQUIRE(result);
        }
    }

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
