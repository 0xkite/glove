#pragma once

#include "glove/supervisor/library_bundle.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace glove::supervisor {

inline constexpr std::string_view sage_guest_runtime_id = "sage-guest";
inline constexpr std::string_view sage_bundle_projection_schema = "sage_bundle_v1";
inline constexpr std::string_view sage_bundle_projection_mount = "sage-bundles";
inline constexpr std::uint64_t max_sage_bundle_projection_bytes = std::uint64_t{64} * 1024U * 1024U;

[[nodiscard]] auto
sage_bundle_projection_digest(std::span<const resolved_library_projection> projections)
    -> std::expected<std::string, std::string>;

// Copies exact descriptor-pinned canonical bundles into a new owner-controlled
// lease directory. The caller mounts that directory read-only into the guest.
[[nodiscard]] auto materialize_sage_bundle_projection(
    int directory_fd, std::span<const resolved_library_projection> projections
) -> std::expected<void, std::string>;

} // namespace glove::supervisor
