#include "glove/reflect/json_codec.hpp"

#include <glaze/glaze.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace glove::reflect::detail {

auto parse_json_object(std::string_view json) -> std::expected<json_object, std::string> {
    json_object result;
    if (json.empty()) {
        return result;
    }

    glz::json_t root{};
    if (const auto err = glz::read_json(root, json); err) {
        return std::unexpected(glz::format_error(err, json));
    }
    if (!root.is_object()) {
        return std::unexpected("expected JSON object for tool arguments");
    }

    for (const auto& [key, val] : root.get_object()) {
        if (val.is_null()) {
            result.emplace(key, std::monostate{});
        } else if (val.is_boolean()) {
            result.emplace(key, val.get_boolean());
        } else if (val.is_number()) {
            const double num = val.get_number();
            double intpart = 0.0;
            if (std::isfinite(num) && std::modf(num, &intpart) == 0.0 &&
                intpart >= static_cast<double>(std::numeric_limits<std::int64_t>::min()) &&
                intpart <= static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
                result.emplace(key, static_cast<std::int64_t>(intpart));
            } else {
                result.emplace(key, num);
            }
        } else if (val.is_string()) {
            result.emplace(key, val.get_string());
        } else if (val.is_array()) {
            std::vector<std::string> items;
            const auto& arr = val.get_array();
            items.reserve(arr.size());
            for (const auto& item : arr) {
                if (!item.is_string()) {
                    return std::unexpected(
                        "expected string element in array field '" + key + "'"
                    );
                }
                items.push_back(item.get_string());
            }
            result.emplace(key, std::move(items));
        } else {
            return std::unexpected("unsupported nested JSON value for field '" + key + "'");
        }
    }

    return result;
}

} // namespace glove::reflect::detail
