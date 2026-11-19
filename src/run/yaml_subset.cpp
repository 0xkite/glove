#include "yaml_subset.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <ranges>
#include <tuple>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace {

using result = std::expected<void, std::string>;

auto at_line(std::size_t line, std::string_view what) -> std::string {
    return "line " + std::to_string(line) + ": " + std::string{what};
}

auto is_key_char(char ch) -> bool {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
           ch == '_' || ch == '-' || ch == '.';
}

auto is_indicator(char ch) -> bool {
    return std::string_view{"&*!|>%@`?"}.contains(ch);
}

auto is_dash_item(std::string_view text) -> bool {
    return !text.empty() && text.front() == '-' && (text.size() == 1 || text[1] == ' ');
}

auto trim_right(std::string_view text) -> std::string_view {
    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }
    return text;
}

auto skip_spaces(std::string_view text, std::size_t at) -> std::size_t {
    while (at < text.size() && text[at] == ' ') {
        ++at;
    }
    return at;
}

// One UTF-8 sequence at TEXT[AT]: its code point and length, or nullopt for
// malformed, overlong, surrogate, or out-of-range input.
auto decode_utf8(std::string_view text, std::size_t at)
    -> std::optional<std::pair<std::uint32_t, std::size_t>> {
    const auto lead = static_cast<unsigned char>(text[at]);
    std::size_t length = 0;
    std::uint32_t code = 0;
    if ((lead & 0xE0U) == 0xC0U) {
        length = 2;
        code = lead & 0x1FU;
    } else if ((lead & 0xF0U) == 0xE0U) {
        length = 3;
        code = lead & 0x0FU;
    } else if ((lead & 0xF8U) == 0xF0U) {
        length = 4;
        code = lead & 0x07U;
    } else {
        return std::nullopt;
    }
    if (at + length > text.size()) {
        return std::nullopt;
    }
    for (std::size_t k = 1; k < length; ++k) {
        const auto next = static_cast<unsigned char>(text[at + k]);
        if ((next & 0xC0U) != 0x80U) {
            return std::nullopt;
        }
        code = (code << 6U) | (next & 0x3FU);
    }
    constexpr std::array<std::uint32_t, 5> minimum{0, 0, 0x80U, 0x800U, 0x10000U};
    if (code < minimum.at(length) || code > 0x10FFFFU || (code >= 0xD800U && code <= 0xDFFFU)) {
        return std::nullopt;
    }
    return std::pair{code, length};
}

// C0/C1 controls, DEL, the byte-order mark, and the Unicode line and
// paragraph separators: some readers treat them as breaks or hide them.
auto forbidden_code(std::uint32_t code) -> bool {
    return code < 0x20U || (code >= 0x7FU && code <= 0x9FU) || code == 0xFEFFU || code == 0x2028U ||
           code == 0x2029U;
}

auto check_bytes(std::string_view text) -> result {
    std::size_t line = 1;
    for (std::size_t i = 0; i < text.size();) {
        const auto byte = static_cast<unsigned char>(text[i]);
        if (byte == '\n') {
            ++line;
            ++i;
            continue;
        }
        if (byte == '\t') {
            return std::unexpected(at_line(line, "tabs are not allowed; indent with spaces"));
        }
        if (byte == '\r') {
            return std::unexpected(at_line(line, "carriage returns are not allowed; use LF"));
        }
        std::uint32_t code = byte;
        std::size_t length = 1;
        if (byte >= 0x80U) {
            const auto decoded = decode_utf8(text, i);
            if (!decoded) {
                return std::unexpected(at_line(line, "text is not valid UTF-8"));
            }
            std::tie(code, length) = *decoded;
        }
        if (forbidden_code(code)) {
            return std::unexpected(
                at_line(line, "control or invisible characters are not allowed")
            );
        }
        i += length;
    }
    return {};
}

// Where a quoted scalar starting at TEXT[AT] ends (one past the closing
// quote), or nullopt when it does not close on this line.
auto quoted_end(std::string_view text, std::size_t at) -> std::optional<std::size_t> {
    const char quote = text[at];
    for (std::size_t j = at + 1; j < text.size(); ++j) {
        if (quote == '"' && text[j] == '\\') {
            ++j;
        } else if (text[j] == quote) {
            if (quote == '\'' && j + 1 < text.size() && text[j + 1] == '\'') {
                ++j;
            } else {
                return j + 1;
            }
        }
    }
    return std::nullopt;
}

// Whether TEXT[I] begins a node, so that a quote there opens a quoted
// scalar ("it's" stays plain).
auto opens_node(std::string_view text, std::size_t i) -> bool {
    std::size_t k = i;
    while (k > 0 && text[k - 1] == ' ') {
        --k;
    }
    if (k == 0) {
        return true;
    }
    const char before = text[k - 1];
    return before == '[' || before == '{' || before == ',' || (before == ':' && k < i) ||
           (before == '-' && k == 1 && k < i);
}

// TEXT without a trailing comment; refuses quotes that do not close.
auto strip_comment(std::string_view text, std::size_t line)
    -> std::expected<std::string_view, std::string> {
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char ch = text[i];
        if ((ch == '"' || ch == '\'') && opens_node(text, i)) {
            const auto end = quoted_end(text, i);
            if (!end) {
                return std::unexpected(at_line(line, "quoted values must close on the same line"));
            }
            i = *end - 1;
        } else if (ch == '#' && (i == 0 || text[i - 1] == ' ')) {
            return trim_right(text.substr(0, i));
        }
    }
    return trim_right(text);
}

auto append_utf8(std::string& out, std::uint32_t code) {
    if (code < 0x80U) {
        out.push_back(static_cast<char>(code));
    } else if (code < 0x800U) {
        out.push_back(static_cast<char>(0xC0U | (code >> 6U)));
        out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
    } else {
        out.push_back(static_cast<char>(0xE0U | (code >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
    }
}

auto append_json_string(std::string& out, std::string_view text) {
    out.push_back('"');
    for (const char ch : text) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
}

// A plain scalar that is an unsigned decimal integer JSON can carry as-is.
auto json_integer(std::string_view text) -> bool {
    return !text.empty() && text.size() <= 10U && (text.size() == 1 || text.front() != '0') &&
           std::ranges::all_of(text, [](char ch) { return ch >= '0' && ch <= '9'; });
}

struct source_line {
    std::size_t indent;
    std::string_view content;
    std::size_t number;
};

class translator {
public:
    translator(std::vector<source_line> lines, const yaml_subset_limits& limits)
        : lines_{std::move(lines)}, limits_{limits} {}

    auto document() -> std::expected<std::string, std::string> {
        if (lines_.empty()) {
            return std::unexpected(std::string{"document has no content"});
        }
        const auto& first = lines_.front();
        if (first.indent != 0 || is_dash_item(first.content)) {
            return fail(first, "the document must be a mapping starting in column 1");
        }
        if (auto ok = mapping(0, 0); !ok) {
            return std::unexpected(ok.error());
        }
        if (next_ < lines_.size()) {
            return fail(lines_[next_], "unexpected indentation");
        }
        return std::move(out_);
    }

private:
    static auto fail(const source_line& line, std::string_view what)
        -> std::unexpected<std::string> {
        return std::unexpected(at_line(line.number, what));
    }

    static auto key_split(std::string_view text)
        -> std::optional<std::pair<std::string_view, std::string_view>> {
        std::size_t k = 0;
        while (k < text.size() && is_key_char(text[k])) {
            ++k;
        }
        if (k == 0 || k >= text.size() || text[k] != ':' ||
            (k + 1 < text.size() && text[k + 1] != ' ')) {
            return std::nullopt;
        }
        return std::pair{text.substr(0, k), text.substr(skip_spaces(text, k + 1))};
    }

    [[nodiscard]] auto deeper(std::size_t depth, const source_line& line) const -> result {
        if (depth >= limits_.max_depth) {
            return fail(line, "values are nested too deeply");
        }
        return {};
    }

    auto block(std::size_t indent, std::size_t depth) -> result {
        const auto& line = lines_[next_];
        if (auto ok = deeper(depth, line); !ok) {
            return ok;
        }
        if (is_dash_item(line.content)) {
            return sequence(indent, depth);
        }
        if (key_split(line.content)) {
            return mapping(indent, depth);
        }
        return fail(line, "expected 'key: value' or '- item'");
    }

    auto mapping_value(
        const source_line& line, std::string_view rest, std::size_t indent, std::size_t depth
    ) -> result {
        if (!rest.empty()) {
            return inline_value(line, rest, depth + 1);
        }
        if (next_ < lines_.size() &&
            (lines_[next_].indent > indent ||
             (lines_[next_].indent == indent && is_dash_item(lines_[next_].content)))) {
            return block(lines_[next_].indent, depth + 1);
        }
        return fail(line, "a key has no value; write [] or {} for an empty one");
    }

    auto mapping(std::size_t indent, std::size_t depth) -> result {
        out_.push_back('{');
        std::vector<std::string_view> keys;
        while (next_ < lines_.size() && lines_[next_].indent == indent) {
            const auto line = lines_[next_];
            const auto split = key_split(line.content);
            if (!split) {
                return fail(
                    line,
                    is_dash_item(line.content)
                        ? "a sequence item cannot follow a key at the same indentation"
                        : "expected 'key: value' with a plain key (letters, digits, _ - .)"
                );
            }
            if (std::ranges::find(keys, split->first) != keys.end()) {
                return fail(line, "duplicate key '" + std::string{split->first} + "'");
            }
            if (keys.size() >= limits_.max_entries) {
                return fail(line, "too many keys in one mapping");
            }
            keys.push_back(split->first);
            out_ += keys.size() == 1 ? "" : ",";
            append_json_string(out_, split->first);
            out_.push_back(':');
            ++next_;
            if (auto ok = mapping_value(line, split->second, indent, depth); !ok) {
                return ok;
            }
        }
        if (next_ < lines_.size() && lines_[next_].indent > indent) {
            return fail(lines_[next_], "unexpected indentation");
        }
        out_.push_back('}');
        return {};
    }

    auto sequence(std::size_t indent, std::size_t depth) -> result {
        out_.push_back('[');
        std::size_t count = 0;
        while (next_ < lines_.size() && lines_[next_].indent == indent &&
               is_dash_item(lines_[next_].content)) {
            const auto line = lines_[next_];
            const std::size_t at = skip_spaces(line.content, 1);
            const auto item = line.content.substr(at);
            if (item.empty()) {
                return fail(line, "a sequence item must hold a value on the same line");
            }
            if (is_dash_item(item)) {
                return fail(line, "nested block sequences are not allowed; use [a, b]");
            }
            if (++count > limits_.max_entries) {
                return fail(line, "too many items in one sequence");
            }
            out_ += count == 1 ? "" : ",";
            if (key_split(item)) {
                // A mapping whose first key shares the dash's line: read it
                // as a mapping indented to that key.
                lines_[next_] = {.indent = indent + at, .content = item, .number = line.number};
                if (auto ok = deeper(depth + 1, line); !ok) {
                    return ok;
                }
                if (auto ok = mapping(indent + at, depth + 1); !ok) {
                    return ok;
                }
                continue;
            }
            ++next_;
            if (auto ok = inline_value(line, item, depth + 1); !ok) {
                return ok;
            }
        }
        if (next_ < lines_.size() && lines_[next_].indent > indent) {
            return fail(lines_[next_], "unexpected indentation");
        }
        out_.push_back(']');
        return {};
    }

    auto inline_value(const source_line& line, std::string_view text, std::size_t depth) -> result {
        std::size_t at = 0;
        if (auto ok = node(line, text, at, depth, false); !ok) {
            return ok;
        }
        if (skip_spaces(text, at) != text.size()) {
            return fail(line, "unexpected text after a value");
        }
        return {};
    }

    auto node(
        const source_line& line,
        std::string_view text,
        std::size_t& at,
        std::size_t depth,
        bool in_flow
    ) -> result {
        at = skip_spaces(text, at);
        if (at >= text.size()) {
            return fail(line, "missing value");
        }
        const char first = text[at];
        if (first == '{' || first == '[') {
            if (auto ok = deeper(depth, line); !ok) {
                return ok;
            }
            return flow(line, text, at, depth);
        }
        if (first == '"') {
            return double_quoted(line, text, at);
        }
        if (first == '\'') {
            return single_quoted(line, text, at);
        }
        return plain(line, text, at, in_flow);
    }

    auto plain(const source_line& line, std::string_view text, std::size_t& at, bool in_flow)
        -> result {
        const char first = text[at];
        if (is_indicator(first)) {
            return fail(
                line,
                std::string{"'"} + first +
                    "' cannot start a value (anchors, aliases, tags, block scalars, and "
                    "directives are not allowed); quote the value"
            );
        }
        if (first == '-' && (at + 1 == text.size() || text[at + 1] == ' ')) {
            return fail(line, "a lone '-' is not a value");
        }
        const std::size_t start = at;
        for (; at < text.size(); ++at) {
            const char ch = text[at];
            const bool next_ends = at + 1 == text.size() || text[at + 1] == ' ' ||
                                   (in_flow && std::string_view{",]}"}.contains(text[at + 1]));
            if (ch == ':' && next_ends) {
                return fail(line, "a plain value cannot contain ': '; quote the value");
            }
            if (in_flow && std::string_view{",[]{}"}.contains(ch)) {
                break;
            }
            if (!in_flow && std::string_view{"[]{}"}.contains(ch)) {
                return fail(line, "a plain value cannot contain brackets or braces; quote it");
            }
        }
        const auto value = trim_right(text.substr(start, at - start));
        if (value == "~" || value == "null" || value == "Null" || value == "NULL") {
            return fail(line, "null is not allowed; quote the value, or write ~/path for home");
        }
        if (json_integer(value)) {
            out_ += value;
        } else {
            append_json_string(out_, value);
        }
        return {};
    }

    // Four hex digits as a code point, or nullopt.
    static auto hex_code(std::string_view digits) -> std::optional<std::uint32_t> {
        std::uint32_t code = 0;
        for (const char hex : digits) {
            std::uint32_t digit = 0;
            if (hex >= '0' && hex <= '9') {
                digit = static_cast<std::uint32_t>(hex - '0');
            } else if (hex >= 'a' && hex <= 'f') {
                digit = static_cast<std::uint32_t>(hex - 'a') + 10U;
            } else if (hex >= 'A' && hex <= 'F') {
                digit = static_cast<std::uint32_t>(hex - 'A') + 10U;
            } else {
                return std::nullopt;
            }
            code = (code << 4U) | digit;
        }
        return code;
    }

    // The escape whose backslash is at TEXT[AT]; leaves AT on its last byte.
    static auto
    escape(const source_line& line, std::string_view text, std::size_t& at, std::string& value)
        -> result {
        if (++at >= text.size()) {
            return fail(line, "quoted values must close on the same line");
        }
        const char kind = text[at];
        if (kind == '"' || kind == '\\' || kind == '/') {
            value.push_back(kind);
            return {};
        }
        if (kind != 'u' || at + 4 >= text.size()) {
            return fail(line, R"(unsupported escape; use \", \\, \/, or \uXXXX)");
        }
        const auto code = hex_code(text.substr(at + 1, 4));
        if (!code) {
            return fail(line, R"(\u needs four hex digits)");
        }
        if (forbidden_code(*code) || (*code >= 0xD800U && *code <= 0xDFFFU)) {
            return fail(
                line, "escaped control, invisible, or surrogate characters are not allowed"
            );
        }
        append_utf8(value, *code);
        at += 4;
        return {};
    }

    auto double_quoted(const source_line& line, std::string_view text, std::size_t& at) -> result {
        std::string value;
        for (++at; at < text.size(); ++at) {
            const char ch = text[at];
            if (ch == '"') {
                ++at;
                append_json_string(out_, value);
                return {};
            }
            if (ch != '\\') {
                value.push_back(ch);
            } else if (auto ok = escape(line, text, at, value); !ok) {
                return ok;
            }
        }
        return fail(line, "quoted values must close on the same line");
    }

    auto single_quoted(const source_line& line, std::string_view text, std::size_t& at) -> result {
        std::string value;
        for (++at; at < text.size(); ++at) {
            if (text[at] != '\'') {
                value.push_back(text[at]);
            } else if (at + 1 < text.size() && text[at + 1] == '\'') {
                value.push_back('\'');
                ++at;
            } else {
                ++at;
                append_json_string(out_, value);
                return {};
            }
        }
        return fail(line, "quoted values must close on the same line");
    }

    auto flow_key(
        const source_line& line,
        std::string_view text,
        std::size_t& at,
        std::vector<std::string_view>& keys
    ) -> result {
        const std::size_t start = at;
        while (at < text.size() && is_key_char(text[at])) {
            ++at;
        }
        if (at == start || at + 1 >= text.size() || text[at] != ':' || text[at + 1] != ' ') {
            return fail(line, "flow mapping entries must be 'key: value' with a plain key");
        }
        const auto key = text.substr(start, at - start);
        if (std::ranges::find(keys, key) != keys.end()) {
            return fail(line, "duplicate key '" + std::string{key} + "'");
        }
        keys.push_back(key);
        append_json_string(out_, key);
        out_.push_back(':');
        ++at;
        return {};
    }

    auto flow(const source_line& line, std::string_view text, std::size_t& at, std::size_t depth)
        -> result {
        const bool is_map = text[at] == '{';
        const char close = is_map ? '}' : ']';
        out_.push_back(text[at]);
        std::vector<std::string_view> keys;
        std::size_t count = 0;
        at = skip_spaces(text, at + 1);
        if (at < text.size() && text[at] == close) {
            ++at;
            out_.push_back(close);
            return {};
        }
        for (;;) {
            if (++count > limits_.max_entries) {
                return fail(line, "too many entries in one flow collection");
            }
            out_ += count == 1 ? "" : ",";
            at = skip_spaces(text, at);
            if (is_map) {
                if (auto ok = flow_key(line, text, at, keys); !ok) {
                    return ok;
                }
            }
            if (auto ok = node(line, text, at, depth + 1, true); !ok) {
                return ok;
            }
            at = skip_spaces(text, at);
            if (at >= text.size()) {
                return fail(line, "flow collections must close on the same line");
            }
            if (text[at] == close) {
                ++at;
                out_.push_back(close);
                return {};
            }
            if (text[at] != ',') {
                return fail(line, "expected ',' or a closing bracket");
            }
            at = skip_spaces(text, at + 1);
            if (at < text.size() && text[at] == close) {
                return fail(line, "trailing commas are not allowed");
            }
        }
    }

    std::vector<source_line> lines_;
    yaml_subset_limits limits_;
    std::size_t next_ = 0;
    std::string out_;
};

} // namespace

auto yaml_subset_to_json(std::string_view text, const yaml_subset_limits& limits)
    -> std::expected<std::string, std::string> {
    if (text.empty()) {
        return std::unexpected(std::string{"document is empty"});
    }
    if (text.size() > limits.max_bytes) {
        return std::unexpected(
            "document is larger than " + std::to_string(limits.max_bytes) + " bytes"
        );
    }
    if (auto ok = check_bytes(text); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<source_line> lines;
    std::size_t number = 0;
    for (const auto raw : std::views::split(text, '\n')) {
        const std::string_view whole{raw.begin(), raw.end()};
        if (++number > limits.max_lines) {
            return std::unexpected(std::string{"document has too many lines"});
        }
        const std::size_t indent = skip_spaces(whole, 0);
        const auto rest = whole.substr(indent);
        if (indent == 0 && (rest.starts_with("---") || rest.starts_with("..."))) {
            return std::unexpected(at_line(number, "document markers are not allowed"));
        }
        auto content = strip_comment(rest, number);
        if (!content) {
            return std::unexpected(content.error());
        }
        if (!content->empty()) {
            lines.push_back({.indent = indent, .content = *content, .number = number});
        }
    }
    return translator{std::move(lines), limits}.document();
}

} // namespace glove::run::detail
