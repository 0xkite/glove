#include "wallet_status_json.hpp"

#include "wallet_status_bridge.hpp"

#include <glaze/glaze.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace glove::control {
namespace {

constexpr std::size_t max_json_nesting = 64U;

[[nodiscard]] auto utf8_byte(std::string_view value, std::size_t position) -> unsigned char {
    return static_cast<unsigned char>(value.at(position));
}

[[nodiscard]] auto is_utf8_continuation(unsigned char byte) -> bool {
    return byte >= 0x80U && byte <= 0xBFU;
}

[[nodiscard]] auto valid_utf8_three(std::string_view value, std::size_t position) -> bool {
    if (position + 2U >= value.size()) {
        return false;
    }
    const auto lead = utf8_byte(value, position);
    const auto second = utf8_byte(value, position + 1U);
    const auto accepts_any_continuation =
        (lead >= 0xE1U && lead <= 0xECU) || (lead >= 0xEEU && lead <= 0xEFU);
    const auto valid_second = (lead == 0xE0U && second >= 0xA0U && second <= 0xBFU) ||
                              (lead == 0xEDU && second >= 0x80U && second <= 0x9FU) ||
                              (accepts_any_continuation && is_utf8_continuation(second));
    return valid_second && is_utf8_continuation(utf8_byte(value, position + 2U));
}

[[nodiscard]] auto valid_utf8_four(std::string_view value, std::size_t position) -> bool {
    if (position + 3U >= value.size()) {
        return false;
    }
    const auto lead = utf8_byte(value, position);
    const auto second = utf8_byte(value, position + 1U);
    const auto valid_second = (lead == 0xF0U && second >= 0x90U && second <= 0xBFU) ||
                              (lead == 0xF4U && second >= 0x80U && second <= 0x8FU) ||
                              (lead >= 0xF1U && lead <= 0xF3U && is_utf8_continuation(second));
    return valid_second && is_utf8_continuation(utf8_byte(value, position + 2U)) &&
           is_utf8_continuation(utf8_byte(value, position + 3U));
}

[[nodiscard]] auto utf8_sequence_width(std::string_view value, std::size_t position)
    -> std::size_t {
    const auto lead = utf8_byte(value, position);
    if (lead <= 0x7FU) {
        return 1U;
    }
    if (lead >= 0xC2U && lead <= 0xDFU) {
        const auto valid =
            position + 1U < value.size() && is_utf8_continuation(utf8_byte(value, position + 1U));
        return valid ? 2U : 0U;
    }
    if (lead >= 0xE0U && lead <= 0xEFU) {
        return valid_utf8_three(value, position) ? 3U : 0U;
    }
    if (lead >= 0xF0U && lead <= 0xF4U) {
        return valid_utf8_four(value, position) ? 4U : 0U;
    }
    return 0U;
}

[[nodiscard]] auto valid_utf8(std::string_view value) -> bool {
    std::size_t position = 0;
    while (position < value.size()) {
        const auto width = utf8_sequence_width(value, position);
        if (width == 0U) {
            return false;
        }
        position += width;
    }
    return true;
}

class strict_json_parser {
public:
    explicit strict_json_parser(std::string_view input) : input_(input) {}

    [[nodiscard]] auto parse() -> bool {
        skip_whitespace();
        if (!parse_value(0U)) {
            return false;
        }
        skip_whitespace();
        return position_ == input_.size();
    }

private:
    auto skip_whitespace() -> void {
        while (position_ < input_.size()) {
            const auto byte = input_.at(position_);
            if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r') {
                return;
            }
            ++position_;
        }
    }

    [[nodiscard]] auto consume(char expected) -> bool {
        const auto matches = position_ < input_.size() && input_.at(position_) == expected;
        if (matches) {
            ++position_;
        }
        return matches;
    }

    [[nodiscard]] auto consume_literal(std::string_view literal) -> bool {
        const auto matches = input_.substr(position_, literal.size()) == literal;
        if (matches) {
            position_ += literal.size();
        }
        return matches;
    }

    [[nodiscard]] auto parse_string() -> std::optional<std::string> {
        if (position_ >= input_.size() || input_.at(position_) != '"') {
            return std::nullopt;
        }
        const auto start = position_++;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_.at(position_++));
            if (byte == static_cast<unsigned char>('"')) {
                const auto raw = input_.substr(start, position_ - start);
                auto decoded = glz::read_json<std::string>(raw);
                if (!decoded || !valid_utf8(*decoded)) {
                    return std::nullopt;
                }
                return std::move(*decoded);
            }
            if (byte < 0x20U) {
                return std::nullopt;
            }
            if (byte == static_cast<unsigned char>('\\')) {
                if (position_ >= input_.size()) {
                    return std::nullopt;
                }
                ++position_;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto is_digit(char byte) -> bool { return byte >= '0' && byte <= '9'; }

    [[nodiscard]] auto consume_digits() -> bool {
        const auto start = position_;
        while (position_ < input_.size() && is_digit(input_.at(position_))) {
            ++position_;
        }
        return position_ != start;
    }

    [[nodiscard]] auto parse_integer_part() -> bool {
        if (position_ >= input_.size()) {
            return false;
        }
        if (input_.at(position_) == '0') {
            ++position_;
            return position_ >= input_.size() || !is_digit(input_.at(position_));
        }
        const auto first = input_.at(position_);
        return first >= '1' && first <= '9' && consume_digits();
    }

    [[nodiscard]] auto parse_fraction() -> bool {
        if (position_ >= input_.size() || input_.at(position_) != '.') {
            return true;
        }
        ++position_;
        return consume_digits();
    }

    [[nodiscard]] auto parse_exponent() -> bool {
        if (position_ >= input_.size()) {
            return true;
        }
        const auto marker = input_.at(position_);
        if (marker != 'e' && marker != 'E') {
            return true;
        }
        ++position_;
        if (position_ < input_.size()) {
            const auto sign = input_.at(position_);
            if (sign == '+' || sign == '-') {
                ++position_;
            }
        }
        return consume_digits();
    }

    [[nodiscard]] auto parse_number() -> bool {
        if (position_ < input_.size() && input_.at(position_) == '-') {
            ++position_;
        }
        return parse_integer_part() && parse_fraction() && parse_exponent();
    }

    [[nodiscard]] auto parse_object(std::size_t depth) -> bool {
        if (depth >= max_json_nesting || !consume('{')) {
            return false;
        }
        skip_whitespace();
        if (consume('}')) {
            return true;
        }

        std::set<std::string, std::less<>> keys;
        while (true) {
            auto key = parse_string();
            if (!key || !keys.emplace(std::move(*key)).second) {
                return false;
            }
            skip_whitespace();
            if (!consume(':')) {
                return false;
            }
            skip_whitespace();
            if (!parse_value(depth + 1U)) {
                return false;
            }
            skip_whitespace();
            if (consume('}')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }
    }

    [[nodiscard]] auto parse_array(std::size_t depth) -> bool {
        if (depth >= max_json_nesting || !consume('[')) {
            return false;
        }
        skip_whitespace();
        if (consume(']')) {
            return true;
        }
        while (true) {
            if (!parse_value(depth + 1U)) {
                return false;
            }
            skip_whitespace();
            if (consume(']')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }
    }

    [[nodiscard]] auto parse_value(std::size_t depth) -> bool {
        if (position_ >= input_.size()) {
            return false;
        }
        switch (input_.at(position_)) {
        case '{':
            return parse_object(depth);
        case '[':
            return parse_array(depth);
        case '"':
            return parse_string().has_value();
        case 't':
            return consume_literal("true");
        case 'f':
            return consume_literal("false");
        case 'n':
            return consume_literal("null");
        default:
            return parse_number();
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
};

} // namespace

auto valid_wallet_status_json(std::string_view frame) noexcept -> bool {
    if (frame.empty() || frame.size() > max_wallet_status_frame_bytes) {
        return false;
    }
    try {
        return strict_json_parser{frame}.parse();
    } catch (...) {
        return false;
    }
}

} // namespace glove::control
