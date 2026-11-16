#pragma once

// Reflection-driven `glove::kernel::extension` adapter.
//
// Bridges C++26 P2996-annotated argument structs (`glove::reflect::descriptor_of<ArgsT>()`)
// directly to `glove::kernel::registry` and MCP `tools/list` / `tools/call` without
// hand-written JSON-Schema strings or manual argument deserialization.

#include "glove/kernel/extension.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/reflect/codegen.hpp"
#include "glove/reflect/json_codec.hpp"

#include <concepts>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace glove::reflect {

#if defined(GLOVE_HAS_REFLECTION)
namespace detail {

template<class TargetT>
[[nodiscard]] inline auto
assign_json_value(TargetT& target, const json_value& value, std::string_view field_name)
    -> std::expected<void, std::string> {
    using base_t = std::remove_cvref_t<typename unwrap_optional<TargetT>::type>;
    if constexpr (is_optional<std::remove_cvref_t<TargetT>>::value) {
        if (std::holds_alternative<std::monostate>(value)) {
            target.reset();
            return {};
        }
        base_t inner{};
        if (auto res = assign_json_value(inner, value, field_name); !res) {
            return res;
        }
        target = std::move(inner);
        return {};
    } else if constexpr (std::same_as<base_t, bool>) {
        if (const auto* b = std::get_if<bool>(&value)) {
            target = *b;
            return {};
        }
        return std::unexpected("expected boolean for field '" + std::string{field_name} + "'");
    } else if constexpr (std::integral<base_t>) {
        if (const auto* n = std::get_if<std::int64_t>(&value)) {
            if constexpr (std::signed_integral<base_t>) {
                if (*n < static_cast<std::int64_t>(std::numeric_limits<base_t>::min()) ||
                    *n > static_cast<std::int64_t>(std::numeric_limits<base_t>::max())) {
                    return std::unexpected(
                        "integer out of range for field '" + std::string{field_name} + "'"
                    );
                }
                target = static_cast<base_t>(*n);
            } else {
                if (*n < 0 || static_cast<std::uint64_t>(*n) >
                                  static_cast<std::uint64_t>(std::numeric_limits<base_t>::max())) {
                    return std::unexpected(
                        "integer out of range for field '" + std::string{field_name} + "'"
                    );
                }
                target = static_cast<base_t>(*n);
            }
            return {};
        }
        return std::unexpected("expected integer for field '" + std::string{field_name} + "'");
    } else if constexpr (std::floating_point<base_t>) {
        if (const auto* d = std::get_if<double>(&value)) {
            target = static_cast<base_t>(*d);
            return {};
        }
        if (const auto* n = std::get_if<std::int64_t>(&value)) {
            target = static_cast<base_t>(*n);
            return {};
        }
        return std::unexpected("expected number for field '" + std::string{field_name} + "'");
    } else if constexpr (std::same_as<base_t, std::string>) {
        if (const auto* s = std::get_if<std::string>(&value)) {
            target = *s;
            return {};
        }
        return std::unexpected("expected string for field '" + std::string{field_name} + "'");
    } else if constexpr (std::same_as<base_t, std::vector<std::string>>) {
        if (const auto* arr = std::get_if<std::vector<std::string>>(&value)) {
            target = *arr;
            return {};
        }
        return std::unexpected("expected string array for field '" + std::string{field_name} + "'");
    } else {
        return std::unexpected(
            "unsupported reflected argument type for field '" + std::string{field_name} + "'"
        );
    }
}

template<class ArgsT>
[[nodiscard]] inline auto decode_reflected_args(std::string_view arguments_json)
    -> std::expected<ArgsT, std::string> {
    auto obj = parse_json_object(arguments_json);
    if (!obj) {
        return std::unexpected(obj.error());
    }

    ArgsT parsed{};
    std::string decode_error;
    static constexpr auto members = std::define_static_array(
        std::meta::nonstatic_data_members_of(^^ArgsT, std::meta::access_context::current())
    );
    template for (constexpr auto member : members) {
        if (decode_error.empty()) {
            using field_t = [:std::meta::type_of(member):];
            std::string field_name{std::meta::identifier_of(member)};
            bool is_required = !is_optional<std::remove_cvref_t<field_t>>::value;
            visit_template_annotations<member, ^^param_meta>([&](const auto& meta) {
                if (!meta.label.view().empty()) {
                    field_name.assign(meta.label.view());
                }
                if (!meta.required) {
                    is_required = false;
                }
            });

            const auto it = obj->find(field_name);
            if (it == obj->end()) {
                if (is_required) {
                    decode_error = "missing required argument: " + field_name;
                }
            } else if (
                auto assigned = assign_json_value(parsed.[:member:], it->second, field_name);
                !assigned
            ) {
                decode_error = assigned.error();
            }
        }
    }
    if (!decode_error.empty()) {
        return std::unexpected(std::move(decode_error));
    }
    return parsed;
}

} // namespace detail
#endif // GLOVE_HAS_REFLECTION

class reflected_extension final : public glove::kernel::extension {
public:
    using handler_t =
        std::function<std::expected<glove::mcp::tool_call_result, std::string>(std::string_view)>;

    explicit reflected_extension(std::string name) : name_{std::move(name)} {}

    auto add_descriptor_tool(glove::mcp::tool_descriptor descriptor, handler_t handler)
        -> std::expected<void, std::string> {
        const std::string tool_name = descriptor.name;
        if (handlers_.contains(tool_name)) {
            return std::unexpected("duplicate reflected tool: " + tool_name);
        }
        descriptors_.push_back(std::move(descriptor));
        handlers_.emplace(tool_name, std::move(handler));
        return {};
    }

#if defined(GLOVE_HAS_REFLECTION)
    template<class ArgsT, class HandlerFn>
    auto add_tool(HandlerFn&& handler) -> std::expected<void, std::string> {
        auto descriptor = descriptor_of<ArgsT>();
        return add_descriptor_tool(
            std::move(descriptor),
            [fn = std::forward<HandlerFn>(handler)](std::string_view arguments_json)
                -> std::expected<glove::mcp::tool_call_result, std::string> {
                auto parsed = detail::decode_reflected_args<ArgsT>(arguments_json);
                if (!parsed) {
                    return glove::mcp::tool_call_result{
                        .status = glove::mcp::tool_call_status::invalid_arguments,
                        .content = {},
                        .structured_json = {},
                        .error_message = parsed.error(),
                    };
                }
                return fn(*parsed);
            }
        );
    }
#endif

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
    std::string name_;
    std::vector<glove::mcp::tool_descriptor> descriptors_;
    std::unordered_map<std::string, handler_t> handlers_;
};

} // namespace glove::reflect
