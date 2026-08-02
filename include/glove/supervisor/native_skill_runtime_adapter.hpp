#pragma once

#include "glove/supervisor/harness_adoption.hpp"
#include "glove/supervisor/library_bundle.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

struct native_harness_adoption_manifest {
    // Logical selectors only: host paths and host configuration bytes never
    // enter the manifest or its digest. A selected executable is discovery
    // input; launch authority is the Glove-owned snapshot when required.
    std::uint32_t schema_version = 1;
    std::vector<std::string> source_artifact_ids;
    std::vector<std::string> excluded_host_state_ids;
    bool require_snapshot = false;

    auto operator==(const native_harness_adoption_manifest&) const -> bool = default;
};

struct native_skill_runtime_configuration {
    // Materialized beneath an adapter-owned private-home directory, never
    // below a projected project. Components are compile-time adapter data;
    // future adoption manifests may supply only typed contents, never paths.
    std::vector<std::string> directory_components;
    std::string filename;
    std::string contents;

    auto operator==(const native_skill_runtime_configuration&) const -> bool = default;
};

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
    // Harness-owned arguments appended after the operator-pinned launch
    // arguments. These encode how a client must run inside Glove's already
    // enforced outer sandbox; policy cannot remove or replace them.
    std::vector<std::string> managed_arguments;
    std::optional<native_harness_adoption_manifest> adoption_manifest;
    std::optional<native_skill_runtime_configuration> managed_configuration;

    auto operator==(const native_skill_runtime_adapter&) const -> bool = default;
};

[[nodiscard]] auto native_skill_runtime_adapter_for(std::string_view runtime_id)
    -> std::optional<native_skill_runtime_adapter>;

// Canonical built-in adapter catalog used by owner-local discovery and policy
// tooling. Callers must still resolve executables through an explicit,
// digest-bound search path.
[[nodiscard]] auto native_skill_runtime_adapters() -> std::vector<native_skill_runtime_adapter>;

[[nodiscard]] auto
native_harness_adoption_manifest_digest(const native_skill_runtime_adapter& adapter)
    -> std::expected<std::string, std::string>;

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
    const native_skill_runtime_projection& projection,
    const native_harness_adoption_identity* adoption = nullptr
) -> std::expected<std::string, std::string>;

// Materialize under a descriptor-owned empty /home/agent. `skill_root_components`
// are adapter-owned constants (for example .claude/skills), never plan data.
// An optional adoption is already descriptor-verified and may only be consumed
// by the adapter's closed private-home projector.
[[nodiscard]] auto materialize_native_skill_runtime_projection(
    int private_home_fd,
    const native_skill_runtime_adapter& adapter,
    const native_skill_runtime_projection& projection,
    const resolved_native_harness_adoption* adoption = nullptr
) -> std::expected<void, std::string>;

} // namespace glove::supervisor
