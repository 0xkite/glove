#include "src/mcp/codec.hpp"

#include "glove/mcp/messages.hpp"

#include "src/mcp/jsonrpc.hpp"
#include "src/mcp/mcp_messages.hpp"

#include <glaze/glaze.hpp>

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::mcp::codec {

namespace {

// MCP servers freely add fields beyond the spec (e.g. yams emits a top-level
// `_meta`). Read with `error_on_unknown_keys=false` so forward-compatible
// extensions don't break parsing.
constexpr glz::opts lenient_read_opts{.error_on_unknown_keys = false};

template<class T> auto read_lenient(std::string_view buffer) -> std::expected<T, std::string> {
    // The public codec boundary accepts any byte span. Glaze enables its padded
    // fast path only for a mutable, resizable buffer; parsing an arbitrary
    // string_view directly would leave that boundary to the caller.
    std::string parse_buffer{buffer};
    T value{};
    auto ec = glz::read<lenient_read_opts>(value, parse_buffer);
    if (ec) {
        return std::unexpected(glz::format_error(ec, parse_buffer));
    }
    return value;
}

auto write_json_string(auto&& value) -> std::expected<std::string, std::string> {
    auto got = glz::write_json(std::forward<decltype(value)>(value));
    if (!got) {
        return std::unexpected(
            std::string{"glaze write_json: "} + glz::format_error(got.error(), std::string{})
        );
    }
    return std::move(*got);
}

} // namespace

auto encode_request(std::int64_t id, std::string_view method, std::string_view params_json)
    -> std::expected<std::string, std::string> {
    jsonrpc_request_envelope env{
        .jsonrpc = "2.0",
        .id = id,
        .method = std::string{method},
        .params = glz::raw_json{params_json.empty() ? std::string{"{}"} : std::string{params_json}},
    };
    return write_json_string(env);
}

auto decode_response(std::string_view frame)
    -> std::expected<jsonrpc_response_envelope, std::string> {
    auto env = read_lenient<jsonrpc_response_envelope>(frame);
    if (!env) {
        return std::unexpected(env.error());
    }
    if (env->jsonrpc != "2.0") {
        return std::unexpected(std::string{"jsonrpc field missing or != \"2.0\""});
    }
    if (env->result.has_value() == env->error.has_value()) {
        return std::unexpected(
            std::string{"jsonrpc response must have exactly one of result or error"}
        );
    }
    return env;
}

auto build_initialize_request(
    std::int64_t id, std::string_view client_name, std::string_view client_version
) -> std::expected<std::string, std::string> {
    mcp_initialize_params params{
        .protocolVersion = std::string{client_protocol_version},
        .capabilities = glz::raw_json{"{}"},
        .clientInfo = mcp_client_info{
            .name = std::string{client_name},
            .version = std::string{client_version},
        },
    };
    auto params_json = write_json_string(params);
    if (!params_json) {
        return std::unexpected(params_json.error());
    }
    return encode_request(id, "initialize", *params_json);
}

auto parse_initialize_result(const jsonrpc_response_envelope& env)
    -> std::expected<server_info, std::string> {
    if (env.error) {
        return std::unexpected(std::string{"server error: "} + env.error->message);
    }
    if (!env.result) {
        return std::unexpected(std::string{"missing result"});
    }
    auto value = read_lenient<mcp_initialize_result>(env.result->str);
    if (!value) {
        return std::unexpected(value.error());
    }

    bool negotiated_known = false;
    for (auto v : supported_protocol_versions) {
        if (v == value->protocolVersion) {
            negotiated_known = true;
            break;
        }
    }
    if (!negotiated_known) {
        return std::unexpected(
            std::string{"server returned unsupported protocolVersion: "} + value->protocolVersion
        );
    }

    return server_info{
        .name = std::move(value->serverInfo.name),
        .version = std::move(value->serverInfo.version),
        .protocol_version = std::move(value->protocolVersion),
    };
}

auto build_initialized_notification() -> std::expected<std::string, std::string> {
    // Notification: no id, no params required by spec.
    return std::string{R"({"jsonrpc":"2.0","method":"notifications/initialized"})"};
}

auto build_tools_list_request(std::int64_t id) -> std::expected<std::string, std::string> {
    return encode_request(id, "tools/list", "{}");
}

auto parse_tools_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<tool_descriptor>, std::string> {
    if (env.error) {
        return std::unexpected(std::string{"server error: "} + env.error->message);
    }
    if (!env.result) {
        return std::unexpected(std::string{"missing result"});
    }
    auto value = read_lenient<mcp_tools_list_result>(env.result->str);
    if (!value) {
        return std::unexpected(value.error());
    }

    std::vector<tool_descriptor> out;
    out.reserve(value->tools.size());
    for (auto& t : value->tools) {
        tool_annotations ann;
        if (t.annotations) {
            ann.has_annotations = true;
            ann.read_only_hint = t.annotations->readOnlyHint.value_or(false);
            ann.destructive_hint = t.annotations->destructiveHint.value_or(false);
            ann.idempotent_hint = t.annotations->idempotentHint.value_or(false);
            ann.open_world_hint = t.annotations->openWorldHint.value_or(false);
        }
        out.push_back(
            tool_descriptor{
                .name = std::move(t.name),
                .description = std::move(t.description),
                .input_schema_json = std::move(t.inputSchema.str),
                .annotations = ann,
            }
        );
    }
    return out;
}

auto build_tools_call_request(std::int64_t id, const tool_call_request& req)
    -> std::expected<std::string, std::string> {
    mcp_tools_call_params params{
        .name = req.name,
        .arguments =
            glz::raw_json{req.arguments_json.empty() ? std::string{"{}"} : req.arguments_json},
    };
    auto params_json = write_json_string(params);
    if (!params_json) {
        return std::unexpected(params_json.error());
    }
    return encode_request(id, "tools/call", *params_json);
}

auto parse_tools_call_result(const jsonrpc_response_envelope& env)
    -> std::expected<tool_call_result, std::string> {
    if (env.error) {
        return tool_call_result{
            .status = tool_call_status::execution_error,
            .content = {},
            .structured_json = {},
            .error_message = env.error->message,
        };
    }
    if (!env.result) {
        return std::unexpected(std::string{"missing result"});
    }
    auto value = read_lenient<mcp_tools_call_result>(env.result->str);
    if (!value) {
        return std::unexpected(value.error());
    }

    std::string flattened;
    for (const auto& block : value->content) {
        if (!flattened.empty()) {
            flattened.push_back('\n');
        }
        flattened.append(block.text);
    }
    return tool_call_result{
        .status = value->isError ? tool_call_status::execution_error : tool_call_status::ok,
        .content = std::move(flattened),
        .structured_json =
            value->structuredContent ? std::move(value->structuredContent->str) : std::string{},
        .error_message =
            value->isError ? std::string{"server reported isError=true"} : std::string{},
    };
}

auto build_resources_list_request(std::int64_t id) -> std::expected<std::string, std::string> {
    return encode_request(id, "resources/list", "{}");
}

auto parse_resources_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<resource_descriptor>, std::string> {
    if (env.error) {
        return std::unexpected(std::string{"server error: "} + env.error->message);
    }
    if (!env.result) {
        return std::unexpected(std::string{"missing result"});
    }
    auto value = read_lenient<mcp_resources_list_result>(env.result->str);
    if (!value) {
        return std::unexpected(value.error());
    }
    std::vector<resource_descriptor> out;
    out.reserve(value->resources.size());
    for (auto& r : value->resources) {
        out.push_back(
            resource_descriptor{
                .uri = std::move(r.uri),
                .name = std::move(r.name),
                .description = r.description ? std::move(*r.description) : std::string{},
                .mime_type = r.mimeType ? std::move(*r.mimeType) : std::string{},
            }
        );
    }
    return out;
}

auto build_prompts_list_request(std::int64_t id) -> std::expected<std::string, std::string> {
    return encode_request(id, "prompts/list", "{}");
}

auto parse_prompts_list_result(const jsonrpc_response_envelope& env)
    -> std::expected<std::vector<prompt_descriptor>, std::string> {
    if (env.error) {
        return std::unexpected(std::string{"server error: "} + env.error->message);
    }
    if (!env.result) {
        return std::unexpected(std::string{"missing result"});
    }
    auto value = read_lenient<mcp_prompts_list_result>(env.result->str);
    if (!value) {
        return std::unexpected(value.error());
    }
    std::vector<prompt_descriptor> out;
    out.reserve(value->prompts.size());
    for (auto& p : value->prompts) {
        out.push_back(
            prompt_descriptor{
                .name = std::move(p.name),
                .description = p.description ? std::move(*p.description) : std::string{},
                .arguments_json = p.arguments ? std::move(p.arguments->str) : std::string{},
            }
        );
    }
    return out;
}

auto decode_request(std::string_view frame)
    -> std::expected<jsonrpc_incoming_request, std::string> {
    auto req = read_lenient<jsonrpc_incoming_request>(frame);
    if (!req) {
        return std::unexpected(req.error());
    }
    if (req->jsonrpc != "2.0") {
        return std::unexpected(std::string{"jsonrpc field missing or != \"2.0\""});
    }
    if (req->method.empty()) {
        return std::unexpected(std::string{"jsonrpc request missing method"});
    }
    return req;
}

namespace {

// Per-call envelope writers — small, no struct round-trip. Direct construction
// avoids paying glaze's reflection cost for the response hot path.
void append_id(std::string& out, std::int64_t id) {
    out.append("\"id\":");
    out.append(std::to_string(id));
}

} // namespace

auto encode_response_with_result(std::int64_t id, std::string_view result_json)
    -> std::expected<std::string, std::string> {
    if (result_json.find('\n') != std::string_view::npos) {
        return std::unexpected(std::string{"result_json must not contain newline"});
    }
    std::string out;
    out.reserve(result_json.size() + 48);
    out.append(R"({"jsonrpc":"2.0",)");
    append_id(out, id);
    out.append(",\"result\":");
    out.append(result_json);
    out.push_back('}');
    return out;
}

auto encode_response_with_error(std::int64_t id, std::int64_t code, std::string_view message)
    -> std::expected<std::string, std::string> {
    if (message.find('\n') != std::string_view::npos ||
        message.find('"') != std::string_view::npos) {
        return std::unexpected(std::string{"error message contains illegal characters"});
    }
    std::string out;
    out.reserve(message.size() + 64);
    out.append(R"({"jsonrpc":"2.0",)");
    append_id(out, id);
    out.append(R"(,"error":{"code":)");
    out.append(std::to_string(code));
    out.append(R"(,"message":")");
    out.append(message);
    out.append(R"("}})");
    return out;
}

} // namespace glove::mcp::codec
