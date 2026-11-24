// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::net::detail {

constexpr std::size_t max_canary_tokens = 64;
constexpr std::size_t min_canary_token_bytes = 8;
constexpr std::size_t max_canary_token_bytes = 256;
constexpr std::size_t max_canary_trie_nodes = 16384;

// Bounded Aho-Corasick multi-pattern matcher for host-side exfiltration checks.
// Once constructed, `contains_any` scans in linear time with zero allocations.
class canary_scanner final {
public:
    canary_scanner() = default;

    [[nodiscard]] static auto build(std::span<const std::string> patterns)
        -> std::expected<canary_scanner, std::string>;

    [[nodiscard]] auto empty() const noexcept -> bool {
        return single_pattern_.empty() && nodes_.size() <= 1U;
    }

    [[nodiscard]] auto contains_any(std::string_view haystack) const noexcept -> bool;

private:
    static constexpr std::uint16_t match_bit = 0x8000U;
    static_assert(max_canary_trie_nodes <= 0x7FFFU, "trie node indices must fit in 15 bits");

    // 512 bytes (8 cache lines) per state; bit 15 of each transition encodes
    // whether the destination state is a match so contains_any() performs one
    // memory load per input byte instead of two.
    struct state_row final {
        std::array<std::uint16_t, 256> next{};
    };

    std::string single_pattern_;
    int common_first_byte_ = -1;
    std::size_t min_pattern_len_ = 0;
    // 65,536-bit (8 KiB, L1-resident) filter of 2-byte pattern prefixes used
    // when patterns have diverse first bytes to skip non-matching windows in
    // state 0 without touching the 512 B/node DFA table.
    std::vector<std::uint64_t> pair_bits_;
    std::vector<state_row> nodes_;
};

} // namespace glove::net::detail
