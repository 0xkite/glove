#pragma once

#include "glove/supervisor/library_bundle.hpp"

#include <cstddef>
#include <expected>
#include <string>
#include <vector>

namespace glove::supervisor {

// A derived, bounded Codex-native view of Sage's already identity-pinned
// library bundles. This type intentionally contains no host path, executable,
// environment authority, or secret material. The session preparer must write
// these exact bytes below the private CODEX_HOME and commit them to the launch
// binding before advertising adapter capability v1.
struct codex_skill_projection {
    std::string projection_id;
    std::string bundle_content_digest;
    std::string key;
    std::string content_digest;
    std::string content;

    auto operator==(const codex_skill_projection&) const -> bool = default;
};

struct codex_unmaterialized_entry_projection {
    std::string projection_id;
    std::string bundle_content_digest;
    std::string key;
    std::string kind;
    std::string content_digest;
    std::size_t content_size = 0;

    auto operator==(const codex_unmaterialized_entry_projection&) const -> bool = default;
};

struct codex_runtime_projection {
    std::vector<codex_skill_projection> skills;
    // These validated entries remain available in the raw bundle but have no
    // Codex-native materialization. Their metadata is part of projection identity.
    std::vector<codex_unmaterialized_entry_projection> unmaterialized_entries;

    auto operator==(const codex_runtime_projection&) const -> bool = default;
};

// Strictly decodes each verified Sage session-library bundle. Only `skill`
// entries materialize into the Codex private home. Known non-skill kinds
// (`behavior`, `prompt`, `template`, `workflow`) remain explicitly represented
// in projection identity. Unknown kinds fail closed.
[[nodiscard]] auto
resolve_codex_runtime_projection(const std::vector<resolved_library_projection>& bundles)
    -> std::expected<codex_runtime_projection, std::string>;

// Canonical, versioned commitment for the exact native projection. This
// deliberately commits every source bundle identity, skill byte digest, and
// unmaterialized known-entry metadata without exposing contents in a receipt or
// controller-visible launch record.
[[nodiscard]] auto codex_runtime_projection_digest(const codex_runtime_projection& projection)
    -> std::expected<std::string, std::string>;

// Materializes a projection into an empty, descriptor-owned private home as
// `$CODEX_HOME/skills/<projection>-<skill>/SKILL.md`. Callers must mount that
// home and commit the resulting mount/environment to the managed launch
// binding; this helper never accepts a pathname from a controller request.
[[nodiscard]] auto materialize_codex_runtime_projection(
    int private_home_fd, const codex_runtime_projection& projection
) -> std::expected<void, std::string>;

} // namespace glove::supervisor
