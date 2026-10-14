#pragma once

#include "glove/container/profile.hpp"

#include <expected>
#include <string>
#include <vector>

namespace glove::container::macos_detail {

// Metadata-only admission for canonical, structurally validated runtime roots.
// This is a prelaunch check, not protection against subsequent host mutation.
auto validate_runtime_filesystem(const std::vector<fs_rule>& roots)
    -> std::expected<void, std::string>;

// Metadata-only admission for structurally validated immutable files and
// reserved child names. No payload reads, chmod or subtree enumeration.
// Descriptor/name rechecks do not prevent subsequent host mutation.
auto validate_launch_constraints(const profile& p) -> std::expected<void, std::string>;

} // namespace glove::container::macos_detail
