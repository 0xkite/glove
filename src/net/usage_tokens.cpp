#include "usage_tokens.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <string>

namespace glove::net::detail {

namespace {

constexpr std::size_t max_depth = 32;
constexpr std::size_t max_documents = 4096;
constexpr std::array<std::string_view, 3> input_fields{
    "prompt_tokens", "input_tokens", "promptTokenCount"
};
constexpr std::array<std::string_view, 3> output_fields{
    "completion_tokens", "output_tokens", "candidatesTokenCount"
};

auto count(const glz::generic& value) -> std::uint64_t {
    if (!value.is_number()) {
        return 0;
    }
    const double number = value.get_number();
    if (!std::isfinite(number) || number < 0 || number > 1e15) {
        return 0;
    }
    return static_cast<std::uint64_t>(number);
}

void take_usage(const glz::generic::object_t& usage, usage_tokens& out) {
    for (const auto& [name, value] : usage) {
        if (std::ranges::find(input_fields, name) != input_fields.end()) {
            out.input = std::max(out.input, count(value));
            out.reported = true;
        } else if (std::ranges::find(output_fields, name) != output_fields.end()) {
            out.output = std::max(out.output, count(value));
            out.reported = true;
        }
    }
}

void visit(const glz::generic& value, usage_tokens& out, std::size_t depth) {
    if (depth > max_depth) {
        return;
    }
    if (value.is_object()) {
        for (const auto& [name, child] : value.get_object()) {
            if ((name == "usage" || name == "usageMetadata") && child.is_object()) {
                take_usage(child.get_object(), out);
            }
            visit(child, out, depth + 1);
        }
    } else if (value.is_array()) {
        for (const auto& child : value.get_array()) {
            visit(child, out, depth + 1);
        }
    }
}

void read_document(std::string_view text, usage_tokens& out) {
    if (text.empty() || (text.front() != '{' && text.front() != '[')) {
        return;
    }
    glz::generic parsed;
    if (glz::read_json(parsed, std::string{text})) {
        return;
    }
    visit(parsed, out, 0);
}

auto trim(std::string_view text) -> std::string_view {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == '\r' || text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

} // namespace

auto read_usage_tokens(std::string_view body) noexcept -> usage_tokens {
    usage_tokens out;
    try {
        const auto whole = trim(body);
        if (!whole.empty() && whole.front() == '{') {
            read_document(whole, out);
            return out;
        }
        std::size_t documents = 0;
        while (!body.empty() && documents < max_documents) {
            const auto end = body.find('\n');
            const auto line = trim(body.substr(0, end));
            body = end == std::string_view::npos ? std::string_view{} : body.substr(end + 1);
            if (line.starts_with("data:")) {
                ++documents;
                read_document(trim(line.substr(5)), out);
            }
        }
    } catch (...) {
        return {};
    }
    return out;
}

} // namespace glove::net::detail
