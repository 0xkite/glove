#pragma once

// Loads the operator's denial model for shadow decisions (see
// glove/container/denial_decision.hpp). A model that cannot be loaded never
// stops a launch: the caller records why and runs without a decider.

#include "glove/container/denial_decision.hpp"

#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>

namespace glove::run::detail {

// Reads PATH and builds its decider. The file decides how this launch's
// denials are judged, so it is refused when another local user could have
// written it (not owned by this user or root, or group/other-writable), when
// it is not one regular file, and when any of EXPOSED (the launch's grant
// paths) contains it, because the agent could then read its thresholds or
// rewrite them. Every error is fixed ASCII text.
[[nodiscard]] auto
load_shadow_decider(const std::filesystem::path& path, std::span<const std::string> exposed)
    -> std::expected<std::shared_ptr<const glove::container::denial_decider>, std::string>;

} // namespace glove::run::detail
