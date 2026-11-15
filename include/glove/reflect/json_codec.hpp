#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace glove::reflect::detail {

using json_value = std::variant<
    std::monostate,
    bool,
    std::int64_t,
    double,
    std::string,
    std::vector<std::string>>;
using json_object = std::unordered_map<std::string, json_value>;

[[nodiscard]] auto parse_json_object(std::string_view json)
    -> std::expected<json_object, std::string>;

} // namespace glove::reflect::detail
