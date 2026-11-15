#pragma once

#include "../../run/native_harness_adapter.hpp"

namespace glove::run::adapters {

// Compiled host-only Claude Code startup encoding for the native core. It
// returns bounded typed requirements only: no spawn, cleanup, credential,
// endpoint, history or capability authority. The core selects the policy,
// admits every slot, and materializes endpoint/nonce values itself.
class claude_harness_adapter final : public detail::native_harness_adapter {
public:
    [[nodiscard]] auto encode_startup(const detail::native_startup_input& input) const
        -> std::expected<detail::native_startup_recipe, std::string> override;
};

} // namespace glove::run::adapters
