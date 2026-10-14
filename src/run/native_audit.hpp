#pragma once

#include "glove/audit/sink.hpp"

#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

namespace glove::run::detail {

inline constexpr std::size_t native_audit_max_events = 1024U;
inline constexpr std::size_t native_audit_max_bytes = 1024U * 1024U;

// Failure stays a failed expected; never allocate another diagnostic under OOM.
inline auto native_audit_allocation_error() noexcept -> std::unexpected<std::string> {
    static_assert(std::is_nothrow_default_constructible_v<std::string>);
    static_assert(std::is_nothrow_move_constructible_v<std::string>);
    return std::unexpected(std::string{});
}

// Host-only bounded retention, not a capacity override, allocator or RSS quota.
// The label is borrowed synchronously by the factory and copied by the sink.
auto make_native_audit_sink(
    std::size_t max_events = native_audit_max_events,
    std::size_t max_bytes = native_audit_max_bytes,
    std::string_view label = "native"
) -> std::expected<std::shared_ptr<audit::sink>, std::string>;

} // namespace glove::run::detail
