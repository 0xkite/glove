// SPDX-License-Identifier: GPL-3.0-only
#include "canary_scanner.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::net::detail {

auto canary_scanner::build(std::span<const std::string> patterns)
    -> std::expected<canary_scanner, std::string> {
    if (patterns.size() > max_canary_tokens) {
        return std::unexpected(
            "canary_tokens exceeds max count (" + std::to_string(max_canary_tokens) + ")"
        );
    }

    canary_scanner scanner;
    if (patterns.empty()) {
        return scanner;
    }

    std::size_t total_bytes = 0;
    std::size_t min_len = max_canary_token_bytes;
    for (const auto& pattern : patterns) {
        if (pattern.size() < min_canary_token_bytes) {
            return std::unexpected(
                "canary token shorter than minimum (" + std::to_string(min_canary_token_bytes) +
                " bytes)"
            );
        }
        if (pattern.size() > max_canary_token_bytes) {
            return std::unexpected(
                "canary token exceeds maximum (" + std::to_string(max_canary_token_bytes) +
                " bytes)"
            );
        }
        total_bytes += pattern.size();
        min_len = std::min(min_len, pattern.size());
    }
    scanner.min_pattern_len_ = min_len;

    if (patterns.size() == 1U) {
        scanner.single_pattern_ = patterns.front();
        return scanner;
    }

    const std::size_t reserve_nodes = std::min(total_bytes + 1U, max_canary_trie_nodes);
    scanner.nodes_.reserve(reserve_nodes);
    scanner.nodes_.emplace_back(); // root node 0

    std::vector<bool> is_match;
    is_match.reserve(reserve_nodes);
    is_match.push_back(false);

    int common_first = static_cast<unsigned char>(patterns.front().front());
    for (const auto& pattern : patterns) {
        if (static_cast<unsigned char>(pattern.front()) != common_first) {
            common_first = -1;
        }
        std::uint16_t state = 0;
        for (const char ch : pattern) {
            const auto byte = static_cast<unsigned char>(ch);
            if (scanner.nodes_[state].next[byte] == 0U) {
                if (scanner.nodes_.size() >= max_canary_trie_nodes) {
                    return std::unexpected(
                        "canary scanner trie exceeds node limit (" +
                        std::to_string(max_canary_trie_nodes) + ")"
                    );
                }
                const auto next_state = static_cast<std::uint16_t>(scanner.nodes_.size());
                scanner.nodes_.emplace_back();
                is_match.push_back(false);
                scanner.nodes_[state].next[byte] = next_state;
            }
            state = scanner.nodes_[state].next[byte];
        }
        is_match[state] = true;
    }
    scanner.common_first_byte_ = common_first;
    if (common_first < 0) {
        scanner.pair_bits_.assign(1024U, 0U);
        for (const auto& pattern : patterns) {
            const auto pair =
                static_cast<std::uint32_t>(static_cast<unsigned char>(pattern[0])) |
                (static_cast<std::uint32_t>(static_cast<unsigned char>(pattern[1])) << 8U);
            scanner.pair_bits_[pair >> 6U] |= (std::uint64_t{1} << (pair & 63U));
        }
    }

    std::vector<std::uint16_t> fail(scanner.nodes_.size(), 0U);
    std::vector<std::uint16_t> queue;
    queue.reserve(scanner.nodes_.size());

    for (std::size_t byte = 0; byte < 256U; ++byte) {
        const std::uint16_t child = scanner.nodes_[0].next[byte];
        if (child != 0U) {
            fail[child] = 0U;
            queue.push_back(child);
        }
    }

    for (std::size_t head = 0; head < queue.size(); ++head) {
        const std::uint16_t current = queue[head];
        const std::uint16_t fail_state = fail[current];
        if (is_match[fail_state]) {
            is_match[current] = true;
        }
        auto& current_next = scanner.nodes_[current].next;
        const auto& fail_next = scanner.nodes_[fail_state].next;
        for (std::size_t byte = 0; byte < 256U; ++byte) {
            const std::uint16_t child = current_next[byte];
            if (child != 0U) {
                fail[child] = fail_next[byte];
                queue.push_back(child);
            } else {
                current_next[byte] = fail_next[byte];
            }
        }
    }

    // Encode match_bit directly into destination transitions so the hot scan
    // loop does not need a second memory load per byte.
    for (auto& row : scanner.nodes_) {
        for (std::uint16_t& target : row.next) {
            if (is_match[target]) {
                target = static_cast<std::uint16_t>(target | match_bit);
            }
        }
    }

    return scanner;
}

auto canary_scanner::contains_any(std::string_view haystack) const noexcept -> bool {
    if (empty() || haystack.size() < min_pattern_len_) {
        return false;
    }
    if (!single_pattern_.empty()) {
        return haystack.find(single_pattern_) != std::string_view::npos;
    }

    const state_row* const table = nodes_.data();
    const auto* cursor = reinterpret_cast<const unsigned char*>(haystack.data());
    const auto* const end = cursor + haystack.size();
    const auto* const last_start = end - min_pattern_len_;
    std::uint16_t state = 0;

    if (common_first_byte_ >= 0) {
        const int first_byte = common_first_byte_;
        while (cursor < end) {
            if (state == 0U) {
                if (cursor > last_start) {
                    return false;
                }
                const void* found = std::memchr(
                    cursor, first_byte, static_cast<std::size_t>(last_start - cursor) + 1U
                );
                if (found == nullptr) {
                    return false;
                }
                cursor = static_cast<const unsigned char*>(found);
            }
            state = table[state].next[*cursor++];
            if ((state & match_bit) != 0U) {
                return true;
            }
        }
        return false;
    }

    const std::uint64_t* const bits = pair_bits_.data();
    while (cursor < end) {
        if (state == 0U) {
            while (cursor <= last_start) {
                const auto pair = static_cast<std::uint32_t>(cursor[0]) |
                                  (static_cast<std::uint32_t>(cursor[1]) << 8U);
                if ((bits[pair >> 6U] & (std::uint64_t{1} << (pair & 63U))) != 0U) {
                    break;
                }
                ++cursor;
            }
            if (cursor > last_start) {
                return false;
            }
        }
        state = table[state].next[*cursor++];
        if ((state & match_bit) != 0U) {
            return true;
        }
    }
    return false;
}

} // namespace glove::net::detail
