#pragma once

#include "glove/host/runtime_policy.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>

namespace glove::run::detail {

// Leaves room beside <=128-KiB argv and the bounded private environment under
// the executor's independent combined192-KiB admission. Logical bytes, not RSS.
inline constexpr std::size_t native_library_max_bytes = 32U * 1024U;

// Native macOS closed projection only: zero entries, or exactly one
// DYLD_LIBRARY_PATH equal to ordered, existing sealed payload/root-N/lib dirs.
// Admitted internal aliases are resolved through bounded no-follow descriptors;
// no external alias, arbitrary variable/value override, host root or ambient search.
// Host snapshot admission remains mandatory; this is not an atomic namespace
// snapshot or a replacement for source exclusions/content/version validation.
[[nodiscard]] auto validate_native_library_environment(
    const host::staged_runtime_harness& runtime, std::span<const std::string> environment
) -> std::expected<void, std::string>;

} // namespace glove::run::detail
