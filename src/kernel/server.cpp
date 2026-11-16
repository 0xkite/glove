#include "glove/kernel/server.hpp"

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include "src/mcp/codec.hpp"
#include "src/mcp/jsonrpc.hpp"
#include "src/mcp/mcp_messages.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::kernel {

namespace {

// Standard JSON-RPC error codes per the spec.
constexpr std::int64_t err_method_not_found = -32601;
constexpr std::int64_t err_invalid_params = -32602;
constexpr std::int64_t err_internal_error = -32603;

struct safe_write_opts_t : glz::opts {
    bool escape_control_characters = true;
};

constexpr safe_write_opts_t safe_write_opts{};

auto write_json_safe(const auto& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write<safe_write_opts>(value);
    if (!encoded) {
        return std::unexpected(
            std::string{"glaze write_json: "} + glz::format_error(encoded.error(), std::string{})
        );
    }
    return std::move(*encoded);
}

auto normalize_raw_json(std::string_view raw) -> std::expected<glz::raw_json, std::string> {
    std::string buf{raw};
    if (auto ec = glz::validate_json(buf); ec) {
        return std::unexpected(
            std::string{"invalid raw JSON fragment: "} + glz::format_error(ec, buf)
        );
    }
    auto compact = glz::minify_json(buf);
    if (std::any_of(compact.begin(), compact.end(), [](unsigned char ch) { return ch < 0x20U; })) {
        return std::unexpected(
            std::string{"invalid raw JSON fragment: unescaped control character"}
        );
    }
    return glz::raw_json{std::move(compact)};
}

auto encode_initialize_response(std::int64_t id, const server_identity& self)
    -> std::expected<std::string, std::string> {
    glove::mcp::mcp_initialize_result result;
    result.protocolVersion = "2025-06-18";
    result.serverInfo.name = self.name;
    result.serverInfo.version = self.version;
    result.capabilities = glz::raw_json{R"({"tools":{}})"};

    auto encoded = write_json_safe(result);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return glove::mcp::codec::encode_response_with_result(id, *encoded);
}

auto encode_tools_list_response(
    std::int64_t id, const std::vector<glove::mcp::tool_descriptor>& tools
) -> std::expected<std::string, std::string> {
    glove::mcp::mcp_tools_list_result wire;
    wire.tools.reserve(tools.size());
    for (const auto& t : tools) {
        glove::mcp::mcp_tool_def def;
        def.name = t.name;
        def.description = t.description;
        if (t.input_schema_json.empty()) {
            def.inputSchema = glz::raw_json{std::string{"{}"}};
        } else {
            auto normalized = normalize_raw_json(t.input_schema_json);
            if (!normalized) {
                return glove::mcp::codec::encode_response_with_error(
                    id, err_internal_error, normalized.error()
                );
            }
            def.inputSchema = std::move(*normalized);
        }
        if (t.annotations.has_annotations) {
            glove::mcp::mcp_tool_annotations ann;
            ann.readOnlyHint = t.annotations.read_only_hint;
            ann.destructiveHint = t.annotations.destructive_hint;
            ann.idempotentHint = t.annotations.idempotent_hint;
            ann.openWorldHint = t.annotations.open_world_hint;
            def.annotations = std::move(ann);
        }
        wire.tools.push_back(std::move(def));
    }
    auto encoded = write_json_safe(wire);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return glove::mcp::codec::encode_response_with_result(id, *encoded);
}

auto encode_tools_call_response(std::int64_t id, const glove::mcp::tool_call_result& result)
    -> std::expected<std::string, std::string> {
    glove::mcp::mcp_tools_call_result wire;
    wire.isError = result.status != glove::mcp::tool_call_status::ok;
    glove::mcp::mcp_content_block block;
    block.type = "text";
    block.text =
        wire.isError && !result.error_message.empty() ? result.error_message : result.content;
    wire.content.push_back(std::move(block));
    if (!result.structured_json.empty()) {
        auto normalized = normalize_raw_json(result.structured_json);
        if (!normalized) {
            return glove::mcp::codec::encode_response_with_error(
                id, err_internal_error, normalized.error()
            );
        }
        wire.structuredContent = std::move(*normalized);
    }
    auto encoded = write_json_safe(wire);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return glove::mcp::codec::encode_response_with_result(id, *encoded);
}

auto record(
    const std::shared_ptr<glove::audit::sink>& sink,
    glove::audit::action what,
    std::string_view tool_name,
    std::string_view arguments,
    glove::mcp::tool_call_status status,
    std::string error_message,
    std::chrono::steady_clock::time_point start
) -> std::expected<void, std::string> {
    if (!sink) {
        return {};
    }
    glove::audit::event ev{
        .what = what,
        .tool_name = std::string{tool_name},
        .arguments_json = std::string{arguments},
        .status = status,
        .error_message = std::move(error_message),
        .at = std::chrono::system_clock::now(),
        .latency = std::chrono::steady_clock::now() - start,
    };
    return sink->record(ev);
}

auto extract_call_args(const glove::mcp::jsonrpc_incoming_request& req)
    -> std::expected<glove::mcp::mcp_tools_call_params, std::string> {
    if (!req.params) {
        return std::unexpected(std::string{"tools/call: missing params"});
    }
    glove::mcp::mcp_tools_call_params parsed;
    auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(parsed, req.params->str);
    if (ec) {
        return std::unexpected(glz::format_error(ec, req.params->str));
    }
    return parsed;
}

} // namespace

server::server(glove::mcp::transport& t, registry& r, options opts)
    : transport_{&t}, registry_{&r}, opts_{std::move(opts)} {}

auto server::run() -> std::expected<void, std::string> {
    for (;;) {
        auto frame = transport_->recv();
        if (!frame) {
            // EOF or transport-level error → clean exit. Leave it to the
            // caller (the host process) to decide whether to retry.
            return {};
        }

        auto req = glove::mcp::codec::decode_request(*frame);
        if (!req) {
            // Frame parse failure: respond with a parse-error if we can find
            // an id, otherwise drop. Don't kill the loop on bad input.
            continue;
        }

        // Notification path — no response is sent.
        if (!req->id) {
            // We don't currently subscribe to any notifications beyond
            // initialized; ignored ones are silent.
            continue;
        }

        const std::int64_t id = *req->id;
        const auto start = std::chrono::steady_clock::now();
        std::expected<std::string, std::string> reply = std::unexpected(std::string{"unhandled"});

        if (req->method == "initialize") {
            reply = encode_initialize_response(id, opts_.identity);
            if (auto audited = record(
                    opts_.audit,
                    glove::audit::action::initialize,
                    "",
                    "",
                    glove::mcp::tool_call_status::ok,
                    "",
                    start
                );
                !audited) {
                return std::unexpected(std::string{"audit: "} + audited.error());
            }
        } else if (req->method == "tools/list") {
            auto tools = registry_->list_tools();
            if (!tools) {
                reply = glove::mcp::codec::encode_response_with_error(
                    id, err_internal_error, tools.error()
                );
                if (auto audited = record(
                        opts_.audit,
                        glove::audit::action::list_tools,
                        "",
                        "",
                        glove::mcp::tool_call_status::execution_error,
                        tools.error(),
                        start
                    );
                    !audited) {
                    return std::unexpected(std::string{"audit: "} + audited.error());
                }
            } else {
                if (opts_.policy) {
                    std::erase_if(*tools, [this](const glove::mcp::tool_descriptor& tool) {
                        return !opts_.policy->visible(tool.name);
                    });
                }
                reply = encode_tools_list_response(id, *tools);
                if (auto audited = record(
                        opts_.audit,
                        glove::audit::action::list_tools,
                        "",
                        "",
                        glove::mcp::tool_call_status::ok,
                        "",
                        start
                    );
                    !audited) {
                    return std::unexpected(std::string{"audit: "} + audited.error());
                }
            }
        } else if (req->method == "tools/call") {
            auto args = extract_call_args(*req);
            if (!args) {
                reply = glove::mcp::codec::encode_response_with_error(
                    id, err_invalid_params, args.error()
                );
                if (auto audited = record(
                        opts_.audit,
                        glove::audit::action::call_tool,
                        "",
                        "",
                        glove::mcp::tool_call_status::invalid_arguments,
                        args.error(),
                        start
                    );
                    !audited) {
                    return std::unexpected(std::string{"audit: "} + audited.error());
                }
            } else {
                std::string args_json = std::move(args->arguments.str);
                if (args_json.empty()) {
                    args_json = "{}";
                }

                if (opts_.policy) {
                    auto verdict = opts_.policy->check(args->name, args_json);
                    if (verdict.verdict == glove::policy::decision::deny) {
                        glove::mcp::tool_call_result denied{
                            .status = glove::mcp::tool_call_status::invalid_arguments,
                            .content = {},
                            .structured_json = {},
                            .error_message = std::string{"policy denied: "} + verdict.reason,
                        };
                        reply = encode_tools_call_response(id, denied);
                        if (auto audited = record(
                                opts_.audit,
                                glove::audit::action::call_tool,
                                args->name,
                                args_json,
                                denied.status,
                                denied.error_message,
                                start
                            );
                            !audited) {
                            return std::unexpected(std::string{"audit: "} + audited.error());
                        }
                        // Send below.
                        if (auto sent = transport_->send(*reply); !sent) {
                            return std::unexpected(sent.error());
                        }
                        continue;
                    }
                }

                auto result = registry_->invoke(args->name, args_json);
                if (!result) {
                    reply = glove::mcp::codec::encode_response_with_error(
                        id, err_internal_error, result.error()
                    );
                    if (auto audited = record(
                            opts_.audit,
                            glove::audit::action::call_tool,
                            args->name,
                            args_json,
                            glove::mcp::tool_call_status::execution_error,
                            result.error(),
                            start
                        );
                        !audited) {
                        return std::unexpected(std::string{"audit: "} + audited.error());
                    }
                } else {
                    reply = encode_tools_call_response(id, *result);
                    if (auto audited = record(
                            opts_.audit,
                            glove::audit::action::call_tool,
                            args->name,
                            args_json,
                            result->status,
                            result->error_message,
                            start
                        );
                        !audited) {
                        return std::unexpected(std::string{"audit: "} + audited.error());
                    }
                }
            }
        } else {
            reply = glove::mcp::codec::encode_response_with_error(
                id, err_method_not_found, std::string{"method not found: "} + req->method
            );
        }

        if (!reply) {
            return std::unexpected(reply.error());
        }
        if (auto sent = transport_->send(*reply); !sent) {
            return std::unexpected(sent.error());
        }
    }
}

} // namespace glove::kernel
