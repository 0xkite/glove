#pragma once

#include "glove/audit/sink.hpp"

#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <type_traits>

namespace glove::run::detail {

// Private production policy, not a guest/operator capacity override. Retention
// is per launch; exhaustion refuses further audited operations without eviction.
// Bytes charge retained events and string lengths, not allocator overhead/RSS.
inline constexpr std::size_t pi_audit_max_events = 1024U;
inline constexpr std::size_t pi_audit_max_bytes = 1024U * 1024U;

// A failed expected with an empty diagnostic is the allocation-pressure
// fallback. Never build another owning message while handling bad_alloc.
inline auto pi_audit_allocation_error() noexcept -> std::unexpected<std::string> {
    static_assert(std::is_nothrow_default_constructible_v<std::string>);
    static_assert(std::is_nothrow_move_constructible_v<std::string>);
    return std::unexpected(std::string{});
}

auto make_pi_audit_sink(
    std::size_t max_events = pi_audit_max_events, std::size_t max_bytes = pi_audit_max_bytes
) -> std::expected<std::shared_ptr<audit::sink>, std::string>;

} // namespace glove::run::detail
