#pragma once

// Reflection-driven `glove::kernel::extension` adapter.
//
// Bridges C++26 P2996-annotated argument structs (`glove::reflect::descriptor_of<ArgsT>()`)
// directly to `glove::kernel::registry` and MCP `tools/list` / `tools/call` without
// hand-written JSON-Schema strings or manual argument deserialization.

#if defined(GLOVE_HAS_REFLECTION)

#    include "glove/kernel/extension.hpp"
#    include "glove/mcp/messages.hpp"
#    include "glove/reflect/codegen.hpp"

#    include <glaze/glaze.hpp>

#    include <expected>
#    include <functional>
#    include <string>
#    include <string_view>
#    include <unordered_map>
#    include <utility>
#    include <vector>

namespace glove::reflect {

class reflected_extension final : public glove::kernel::extension {
public:
    explicit reflected_extension(std::string name) : name_{std::move(name)} {}

    template<class ArgsT, class HandlerFn> void add_tool(HandlerFn&& handler) {
        auto descriptor = descriptor_of<ArgsT>();
        const std::string tool_name = descriptor.name;
        descriptors_.push_back(std::move(descriptor));
        handlers_.emplace(
            tool_name,
            [fn = std::forward<HandlerFn>(handler)](std::string_view arguments_json)
                -> std::expected<glove::mcp::tool_call_result, std::string> {
                ArgsT parsed{};
                if (!arguments_json.empty()) {
                    if (const auto err = glz::read_json(parsed, arguments_json); err) {
                        return glove::mcp::tool_call_result{
                            .status = glove::mcp::tool_call_status::invalid_arguments,
                            .content = {},
                            .structured_json = {},
                            .error_message = glz::format_error(err, arguments_json),
                        };
                    }
                }
                return fn(parsed);
            }
        );
    }

    auto name() const -> std::string_view override { return name_; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return descriptors_;
    }

    auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        const auto it = handlers_.find(std::string{tool_name});
        if (it == handlers_.end()) {
            return glove::mcp::tool_call_result{
                .status = glove::mcp::tool_call_status::tool_not_found,
                .content = {},
                .structured_json = {},
                .error_message = "unknown tool: " + std::string{tool_name},
            };
        }
        return it->second(arguments_json);
    }

private:
    using handler_t =
        std::function<std::expected<glove::mcp::tool_call_result, std::string>(std::string_view)>;

    std::string name_;
    std::vector<glove::mcp::tool_descriptor> descriptors_;
    std::unordered_map<std::string, handler_t> handlers_;
};

} // namespace glove::reflect

#endif // GLOVE_HAS_REFLECTION
