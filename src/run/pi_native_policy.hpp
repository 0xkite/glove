#pragma once

#include "native_harness_adapter.hpp"

namespace glove::run::detail {

// Trusted host composition selects this closed policy independently of the
// encoder. Neither CLI/project configuration nor encoder output can replace it.
[[nodiscard]] auto pi_native_startup_policy() -> native_startup_policy;

} // namespace glove::run::detail
