// Pure codec round-trip and error-path tests. No transport, no client.

#include "glove/mcp/messages.hpp"

#include "src/mcp/codec.hpp"
#include "src/mcp/jsonrpc.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto test_request_is_single_line() -> int {
    auto req = glove::mcp::codec::build_tools_list_request(7);
    REQUIRE(req.has_value());
    REQUIRE(req->find('\n') == std::string::npos);
    REQUIRE(req->find("\"method\":\"tools/list\"") != std::string::npos);
    REQUIRE(req->find("\"id\":7") != std::string::npos);
    return 0;
}

auto test_decode_valid_response() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"e","inputSchema":{"type":"object"}}]}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    REQUIRE(env->id == 1);
    REQUIRE(env->result.has_value());
    REQUIRE(!env->error.has_value());

    auto tools = glove::mcp::codec::parse_tools_list_result(*env);
    REQUIRE(tools.has_value());
    REQUIRE(tools->size() == 1);
    REQUIRE((*tools)[0].name == "echo");
    REQUIRE((*tools)[0].description == "e");
    REQUIRE((*tools)[0].input_schema_json.find("\"type\"") != std::string::npos);
    return 0;
}

auto test_decode_error_envelope() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"method not found"}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    REQUIRE(env->error.has_value());
    REQUIRE(env->error->code == -32601);

    auto tools = glove::mcp::codec::parse_tools_list_result(*env);
    REQUIRE(!tools.has_value());
    REQUIRE(tools.error().find("method not found") != std::string::npos);
    return 0;
}

auto test_decode_rejects_both_result_and_error() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":3,"result":{"x":1},"error":{"code":1,"message":"both"}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(!env.has_value());
    return 0;
}

auto test_decode_rejects_neither_result_nor_error() -> int {
    std::string frame = R"({"jsonrpc":"2.0","id":4})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(!env.has_value());
    return 0;
}

auto test_decode_rejects_missing_jsonrpc_field() -> int {
    std::string frame = R"({"id":5,"result":{}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(!env.has_value());
    return 0;
}

auto test_decode_rejects_malformed_json() -> int {
    std::string frame = "{not json";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(!env.has_value());
    return 0;
}

auto test_decode_request_handles_unterminated_malformed_input() -> int {
    // A libFuzzer finding. Copy into a fixed-size array so this deliberately
    // lacks the sentinel byte that std::string storage normally provides.
    constexpr std::string_view malformed_request =
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{},\"error\":{\"code\":-32603,"
        "\"message\":\"conflicting {\"json"
        "\x9A"
        "pc\"env"
        "\x9B\x93\x90\x98"
        "e\":\"2.0\",\"id\":{\"jsonr3,pc\"\"r\":\"2.0}\",\"sid}";
    std::array<char, malformed_request.size()> frame{};
    std::ranges::copy(malformed_request, frame.begin());

    auto request = glove::mcp::codec::decode_request(std::string_view{frame.data(), frame.size()});
    REQUIRE(!request.has_value());
    return 0;
}

auto test_call_request_round_trip() -> int {
    glove::mcp::tool_call_request req{
        .name = "do_thing",
        .arguments_json = R"({"answer":42})",
    };
    auto frame = glove::mcp::codec::build_tools_call_request(11, req);
    REQUIRE(frame.has_value());
    REQUIRE(frame->find('\n') == std::string::npos);
    REQUIRE(frame->find("\"method\":\"tools/call\"") != std::string::npos);
    REQUIRE(frame->find("\"name\":\"do_thing\"") != std::string::npos);
    REQUIRE(frame->find("\"answer\":42") != std::string::npos);
    return 0;
}

auto test_parse_call_result_success() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":"hello"}],"isError":false}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto result = glove::mcp::codec::parse_tools_call_result(*env);
    REQUIRE(result.has_value());
    REQUIRE(result->status == glove::mcp::tool_call_status::ok);
    REQUIRE(result->content == "hello");
    return 0;
}

auto test_parse_call_result_is_error_flag() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":13,"result":{"content":[{"type":"text","text":"bad"}],"isError":true}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto result = glove::mcp::codec::parse_tools_call_result(*env);
    REQUIRE(result.has_value());
    REQUIRE(result->status == glove::mcp::tool_call_status::execution_error);
    REQUIRE(result->content == "bad");
    REQUIRE(result->structured_json.empty());
    return 0;
}

auto test_parse_resources_list() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":20,"result":{"resources":[)"
        R"({"uri":"file:///a","name":"A","description":"first","mimeType":"text/plain"},)"
        R"({"uri":"file:///b","name":"B"}]}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto out = glove::mcp::codec::parse_resources_list_result(*env);
    REQUIRE(out.has_value());
    REQUIRE(out->size() == 2);
    REQUIRE((*out)[0].uri == "file:///a");
    REQUIRE((*out)[0].mime_type == "text/plain");
    REQUIRE((*out)[1].uri == "file:///b");
    REQUIRE((*out)[1].description.empty());
    REQUIRE((*out)[1].mime_type.empty());
    return 0;
}

auto test_parse_prompts_list() -> int {
    std::string frame =
        R"({"jsonrpc":"2.0","id":21,"result":{"prompts":[)"
        R"({"name":"summarize","description":"d","arguments":[{"name":"text","required":true}]},)"
        R"({"name":"trivial"}]}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto out = glove::mcp::codec::parse_prompts_list_result(*env);
    REQUIRE(out.has_value());
    REQUIRE(out->size() == 2);
    REQUIRE((*out)[0].name == "summarize");
    REQUIRE((*out)[0].arguments_json.find("\"required\":true") != std::string::npos);
    REQUIRE((*out)[1].name == "trivial");
    REQUIRE((*out)[1].description.empty());
    REQUIRE((*out)[1].arguments_json.empty());
    return 0;
}

auto test_parse_call_result_structured_content() -> int {
    std::string frame = R"({"jsonrpc":"2.0","id":14,"result":{)"
                        R"("content":[{"type":"text","text":"summary"}],)"
                        R"("isError":false,)"
                        R"("structuredContent":{"answer":42,"items":["a","b"]}}})";
    auto env = glove::mcp::codec::decode_response(frame);
    REQUIRE(env.has_value());
    auto result = glove::mcp::codec::parse_tools_call_result(*env);
    REQUIRE(result.has_value());
    REQUIRE(result->status == glove::mcp::tool_call_status::ok);
    REQUIRE(result->content == "summary");
    REQUIRE(result->structured_json.find("\"answer\":42") != std::string::npos);
    REQUIRE(result->structured_json.find("\"items\":[\"a\",\"b\"]") != std::string::npos);
    return 0;
}

} // namespace

auto main() -> int {
    if (test_request_is_single_line() != 0) {
        return 1;
    }
    if (test_decode_valid_response() != 0) {
        return 1;
    }
    if (test_decode_error_envelope() != 0) {
        return 1;
    }
    if (test_decode_rejects_both_result_and_error() != 0) {
        return 1;
    }
    if (test_decode_rejects_neither_result_nor_error() != 0) {
        return 1;
    }
    if (test_decode_rejects_missing_jsonrpc_field() != 0) {
        return 1;
    }
    if (test_decode_rejects_malformed_json() != 0) {
        return 1;
    }
    if (test_decode_request_handles_unterminated_malformed_input() != 0) {
        return 1;
    }
    if (test_call_request_round_trip() != 0) {
        return 1;
    }
    if (test_parse_call_result_success() != 0) {
        return 1;
    }
    if (test_parse_call_result_is_error_flag() != 0) {
        return 1;
    }
    if (test_parse_call_result_structured_content() != 0) {
        return 1;
    }
    if (test_parse_resources_list() != 0) {
        return 1;
    }
    if (test_parse_prompts_list() != 0) {
        return 1;
    }
    return 0;
}
