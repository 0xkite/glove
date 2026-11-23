#pragma once

#include <cstdint>
#include <string_view>

namespace glove::net::detail {

struct usage_tokens {
    std::uint64_t input = 0;
    std::uint64_t output = 0;
    bool reported = false;
};

// Token counts a provider reported in a response body: one JSON object, or a
// server-sent event stream whose `data:` lines are JSON objects. Every object
// named `usage` or `usageMetadata` at any depth is read, and the largest value
// of each count across the body wins, because streams repeat or accumulate
// them. Read by field name, not by provider: input is `prompt_tokens`,
// `input_tokens` or `promptTokenCount`; output is `completion_tokens`,
// `output_tokens` or `candidatesTokenCount`. An unreadable body, or one
// without these fields, reports nothing. The body is untrusted.
[[nodiscard]] auto read_usage_tokens(std::string_view body) noexcept -> usage_tokens;

} // namespace glove::net::detail
