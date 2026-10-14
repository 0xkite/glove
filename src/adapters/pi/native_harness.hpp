#pragma once

#include "../../run/native_harness_adapter.hpp"

namespace glove::run::adapters {

// Compiled host-only startup encoding. There is no managed session-runtime or
// observation-schema capability implied by implementing this small interface.
class pi_harness_adapter final : public detail::native_harness_adapter {
public:
    [[nodiscard]] auto encode_startup(const detail::native_startup_input& input) const
        -> std::expected<detail::native_startup_recipe, std::string> override;
};

} // namespace glove::run::adapters
