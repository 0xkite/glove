#pragma once

// A strict YAML subset for operator-authored configuration, translated to
// canonical JSON so that one mature strict decoder applies the schema.
//
// Accepted: block mappings and sequences indented with spaces; sequence
// items that hold a scalar, a one-line flow collection, or a mapping whose
// first key shares the dash's line; one-line flow mappings and sequences;
// plain, "double-quoted" (escapes \" \\ \/ \uXXXX), and 'single-quoted'
// scalars; '#' comments.
//
// Refused, with the line number: duplicate keys, anchors, aliases, tags,
// block scalars (| >), directives, document markers, multi-line scalars,
// tabs, carriage returns, control and invisible characters, invalid UTF-8,
// empty values, and plain null (~, null). Plain unsigned integers without a
// leading zero become JSON numbers; every other scalar becomes a string.

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

namespace glove::run::detail {

struct yaml_subset_limits {
    std::size_t max_bytes = 0;
    std::size_t max_lines = 0;
    std::size_t max_entries = 0; // per mapping or sequence
    std::size_t max_depth = 8;
};

// A JSON object for a document whose root is a mapping, or an error naming
// the line.
[[nodiscard]] auto yaml_subset_to_json(std::string_view text, const yaml_subset_limits& limits)
    -> std::expected<std::string, std::string>;

} // namespace glove::run::detail
