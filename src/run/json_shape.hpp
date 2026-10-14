#pragma once

#include <cstddef>
#include <set>
#include <string>
#include <string_view>

namespace glove::run::detail {

// Structural admission of one JSON object: bounded depth, no duplicate keys
// per object, no trailing bytes, no control characters inside strings. It is
// not a typed decoder; callers decode admitted bytes separately.
class json_shape_guard {
public:
    json_shape_guard(std::string_view input, std::size_t max_depth)
        : input_{input}, max_depth_{max_depth} {}

    // The object must span the whole input: no leading or trailing bytes, so a
    // frame with a trailing newline or padding is not the same body.
    [[nodiscard]] auto object_only() -> bool {
        if (position_ >= input_.size() || input_[position_] != '{') {
            return false;
        }
        return value(0) && position_ == input_.size();
    }

private:
    void skip_space() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\n' || input_[position_] == '\r')) {
            ++position_;
        }
    }

    [[nodiscard]] auto string_value(std::string* out) -> bool {
        if (position_ >= input_.size() || input_[position_] != '"') {
            return false;
        }
        ++position_;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_[position_++]);
            if (byte == static_cast<unsigned char>('"')) {
                return true;
            }
            if (byte < 0x20U) {
                return false;
            }
            if (out != nullptr) {
                out->push_back(static_cast<char>(byte));
            }
            if (byte == static_cast<unsigned char>('\\')) {
                if (position_ >= input_.size()) {
                    return false;
                }
                if (out != nullptr) {
                    out->push_back(input_[position_]);
                }
                ++position_;
            }
        }
        return false;
    }

    [[nodiscard]] auto literal(std::string_view text) -> bool {
        if (input_.substr(position_, text.size()) != text) {
            return false;
        }
        position_ += text.size();
        return true;
    }

    [[nodiscard]] auto digits() -> bool {
        const auto start = position_;
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
            ++position_;
        }
        return position_ != start;
    }

    [[nodiscard]] auto number() -> bool {
        if (position_ < input_.size() && input_[position_] == '-') {
            ++position_;
        }
        if (position_ < input_.size() && input_[position_] == '0') {
            ++position_;
        } else if (!digits()) {
            return false;
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            if (!digits()) {
                return false;
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            if (!digits()) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto object(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        std::set<std::string> keys;
        if (position_ < input_.size() && input_[position_] == '}') {
            ++position_;
            return true;
        }
        for (;;) {
            std::string key;
            // Raw (escaped) key bytes: an escaped alias of an existing key is a
            // different raw spelling; typed decoders reject it separately.
            if (!string_value(&key) || !keys.insert(std::move(key)).second) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size() || input_[position_++] != ':') {
                return false;
            }
            skip_space();
            if (!value(depth + 1)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == '}') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto array(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        if (position_ < input_.size() && input_[position_] == ']') {
            ++position_;
            return true;
        }
        for (;;) {
            if (!value(depth + 1)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == ']') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto value(std::size_t depth) -> bool {
        if (depth > max_depth_ || position_ >= input_.size()) {
            return false;
        }
        switch (input_[position_]) {
        case '{':
            return object(depth);
        case '[':
            return array(depth);
        case '"':
            return string_value(nullptr);
        case 't':
            return literal("true");
        case 'f':
            return literal("false");
        case 'n':
            return literal("null");
        default:
            return number();
        }
    }

    std::string_view input_;
    std::size_t max_depth_;
    std::size_t position_ = 0;
};

[[nodiscard]] inline auto bounded_json_object(std::string_view input, std::size_t max_depth)
    -> bool {
    return json_shape_guard{input, max_depth}.object_only();
}

} // namespace glove::run::detail
