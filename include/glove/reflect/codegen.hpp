#pragma once

// Reflection-driven MCP tool codec and schema generator (C++26 P2996 + P3394).
//
// When GLOVE_REFLECTION=ON (GCC 16+ `-std=c++26 -freflection` or a P2996-capable
// clang), `input_schema_of<T>()` and `descriptor_of<T>()` inspect structural
// `[[=tool_meta{...}]]` / `[[=param_meta{...}]]` annotations and data members
// of `T` via `<meta>` to synthesize MCP `tool_descriptor`s without manual
// schema boilerplate.

#if defined(GLOVE_HAS_REFLECTION)

#    include "glove/mcp/messages.hpp"

#    include <algorithm>
#    include <concepts>
#    include <cstddef>
#    if __has_include(<meta>)
#        include <meta>
#    else
#        include <experimental/meta>
#    endif
#    include <optional>
#    include <string>
#    include <string_view>
#    include <type_traits>
#    include <vector>

namespace glove::reflect {

inline constexpr bool reflection_available = true;

// Structural fixed-length string so annotation structs satisfy C++26 P3394
// structural-type requirements (std::string_view has private members in
// libstdc++ and cannot appear in `[[=...]]` annotations).
template<std::size_t N> struct fixed_string {
    char data[N]{};

    consteval fixed_string(const char (&str)[N]) { std::copy_n(str, N, data); }

    constexpr auto view() const noexcept -> std::string_view { return {data, N > 0 ? N - 1U : 0U}; }
};

template<std::size_t NameN, std::size_t DescN> struct tool_meta {
    fixed_string<NameN> name;
    fixed_string<DescN> description;
};

template<std::size_t NameN, std::size_t DescN>
tool_meta(const char (&)[NameN], const char (&)[DescN]) -> tool_meta<NameN, DescN>;

template<std::size_t LabelN, std::size_t DescN> struct param_meta {
    fixed_string<LabelN> label;
    fixed_string<DescN> description;
    bool required = true;
};

template<std::size_t LabelN, std::size_t DescN>
param_meta(const char (&)[LabelN], const char (&)[DescN], bool = true) -> param_meta<LabelN, DescN>;

namespace detail {

template<class T> struct is_optional : std::false_type {};

template<class T> struct is_optional<std::optional<T>> : std::true_type {};

template<class T> struct is_vector : std::false_type {};

template<class T, class Alloc> struct is_vector<std::vector<T, Alloc>> : std::true_type {};

template<class T> struct unwrap_optional {
    using type = T;
};

template<class T> struct unwrap_optional<std::optional<T>> {
    using type = T;
};

inline void append_json_escaped(std::string& out, std::string_view text) {
    out.push_back('"');
    for (const char ch : text) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    out.push_back('"');
}

template<class FieldT> inline void append_json_schema_for_type(std::string& out) {
    using base_t = std::remove_cvref_t<typename unwrap_optional<FieldT>::type>;
    if constexpr (std::same_as<base_t, bool>) {
        out += R"({"type":"boolean"})";
    } else if constexpr (std::integral<base_t>) {
        out += R"({"type":"integer"})";
    } else if constexpr (std::floating_point<base_t>) {
        out += R"({"type":"number"})";
    } else if constexpr (
        std::same_as<base_t, std::string> || std::same_as<base_t, std::string_view>
    ) {
        out += R"({"type":"string"})";
    } else if constexpr (is_vector<base_t>::value) {
        out += R"({"type":"array","items":)";
        append_json_schema_for_type<typename base_t::value_type>(out);
        out.push_back('}');
    } else {
        out += R"({"type":"object"})";
    }
}

template<std::meta::info Target, std::meta::info TemplateRef, class Fn>
constexpr void visit_template_annotations(Fn&& fn) {
    template for (constexpr auto ann :
                  std::define_static_array(std::meta::annotations_of(Target))) {
        constexpr auto ann_type = std::meta::type_of(ann);
        if constexpr (
            std::meta::has_template_arguments(ann_type) &&
            std::meta::template_of(ann_type) == TemplateRef
        ) {
            fn(std::meta::extract<typename[:ann_type:]>(ann));
        }
    }
}

} // namespace detail

template<class T> auto input_schema_of() -> std::string {
    std::string out = R"({"type":"object","properties":{)";
    std::vector<std::string> required_fields;
    bool first_prop = true;

    constexpr auto ctx = std::meta::access_context::current();
    template for (constexpr auto member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, ctx))) {
        using member_t = typename[:std::meta::type_of(member):];
        std::string prop_name{std::meta::identifier_of(member)};
        std::string description;
        bool required = !detail::is_optional<std::remove_cvref_t<member_t>>::value;

        detail::visit_template_annotations<member, ^^param_meta>([&](const auto& meta) {
            if (!meta.label.view().empty()) {
                prop_name.assign(meta.label.view());
            }
            description.assign(meta.description.view());
            if (!meta.required) {
                required = false;
            }
        });

        if (!first_prop) {
            out.push_back(',');
        }
        first_prop = false;

        detail::append_json_escaped(out, prop_name);
        out.push_back(':');

        if (description.empty()) {
            detail::append_json_schema_for_type<member_t>(out);
        } else {
            std::string type_schema;
            detail::append_json_schema_for_type<member_t>(type_schema);
            // Insert `"description":"..."` before the closing `}` of the property schema.
            if (!type_schema.empty() && type_schema.back() == '}') {
                type_schema.pop_back();
                type_schema += R"(,"description":)";
                detail::append_json_escaped(type_schema, description);
                type_schema.push_back('}');
            }
            out += type_schema;
        }

        if (required) {
            required_fields.push_back(prop_name);
        }
    }

    out += R"(},"required":[)";
    for (std::size_t i = 0; i < required_fields.size(); ++i) {
        if (i > 0) {
            out.push_back(',');
        }
        detail::append_json_escaped(out, required_fields[i]);
    }
    out += "]}";
    return out;
}

template<class T> auto descriptor_of() -> glove::mcp::tool_descriptor {
    glove::mcp::tool_descriptor desc{};
    desc.name = std::string{std::meta::identifier_of(^^T)};
    detail::visit_template_annotations<^^T, ^^tool_meta>([&](const auto& meta) {
        if (!meta.name.view().empty()) {
            desc.name.assign(meta.name.view());
        }
        desc.description.assign(meta.description.view());
    });
    desc.input_schema_json = input_schema_of<T>();
    return desc;
}

} // namespace glove::reflect

#else

namespace glove::reflect {

// When GLOVE_REFLECTION is off, including this header on a non-reflection
// build is allowed so consumers can gate reflection via `reflection_available`.
inline constexpr bool reflection_available = false;

} // namespace glove::reflect

#endif // GLOVE_HAS_REFLECTION
