#pragma once

#include "glove/audit/sink.hpp"

#include <expected>
#include <memory>
#include <optional>
#include <string>

namespace glove::run::detail {

// Records the agent's exit. When wait() failed after the leader was reaped
// (its group could not be proven empty), the known exit code is still
// recorded, followed by a separate control/agent_cleanup_failed record, and
// the wait error is returned. A null sink records nothing.
[[nodiscard]] auto record_agent_exit(
    const std::shared_ptr<glove::audit::sink>& sink,
    const std::expected<int, std::string>& waited,
    std::optional<int> reaped_code
) -> std::expected<int, std::string>;

} // namespace glove::run::detail
