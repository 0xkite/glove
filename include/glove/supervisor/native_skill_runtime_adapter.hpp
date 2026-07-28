#pragma once

#include "glove/supervisor/library_bundle.hpp"

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

// Built-in harness metadata for runtimes that consume the Agent Skills
// standard. The table is intentionally closed: a root-owned policy can choose
// a command and trusted discovery directory, but cannot define a new adapter
// or redirect Glove-managed state to an arbitrary location.
struct native_skill_runtime_adapter {
    std::string runtime_id;
    std::string executable_name;
    std::string home_mount_alias;
    std::vector<std::string> skill_root_components;
    std::vector<std::string> managed_environment;

    auto operator==(const native_skill_runtime_adapter&) const -> bool = default;
};

[[nodiscard]] auto native_skill_runtime_adapter_for(std::string_view runtime_id)
    -> std::optional<native_skill_runtime_adapter>;

struct native_skill_projection {
    std::string projection_id;
    std::string bundle_content_digest;
    std::string key;
    std::string content_digest;
    std::string content;

    auto operator==(const native_skill_projection&) const -> bool = default;
};

struct native_skill_runtime_projection {
    std::vector<native_skill_projection> skills;

    auto operator==(const native_skill_runtime_projection&) const -> bool = default;
};

// Decode identity-pinned Sage bundles into the shared Agent Skills format.
// Every supported harness uses a private native location for these exact
// SKILL.md bytes; unsupported entry kinds fail closed.
[[nodiscard]] auto resolve_native_skill_runtime_projection(
    const native_skill_runtime_adapter& adapter,
    const std::vector<resolved_library_projection>& bundles
) -> std::expected<native_skill_runtime_projection, std::string>;

// Commitment includes the adapter ID as well as every projected skill, so a
// valid context for one harness cannot be rebound as another harness's home.
[[nodiscard]] auto native_skill_runtime_projection_digest(
    const native_skill_runtime_adapter& adapter,
    const native_skill_runtime_projection& projection
) -> std::expected<std::string, std::string>;

// Materialize under a descriptor-owned empty /home/agent. `skill_root_components`
// are adapter-owned constants (for example .claude/skills), never plan data.
[[nodiscard]] auto materialize_native_skill_runtime_projection(
    int private_home_fd,
    const native_skill_runtime_adapter& adapter,
    const native_skill_runtime_projection& projection
) -> std::expected<void, std::string>;

} // namespace glove::supervisor
