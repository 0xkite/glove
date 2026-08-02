#pragma once

#include "glove/container/refinement_protocol.hpp"
#include "glove/supervisor/harness_adoption.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/path_exposure.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

enum class sandbox_backend : std::uint8_t {
    linux_production,
    apple_container,
    // Decode-only compatibility for policies emitted before Apple Container
    // became the default macOS shipping backend.
    macos_experimental,
};

struct resource_limits {
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t memory_bytes = 0;
    std::uint32_t pids = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t terminal_output_bytes = 0;

    auto operator==(const resource_limits&) const -> bool = default;
};

// Exact executor-owned process template. Remote plans select only its bounded
// template identifier and independently derived digest; they never carry these
// launch fields.
struct runtime_launch_template {
    // Empty for an explicitly pinned executable. A supported native adapter
    // delegates executable discovery to the local Glove supervisor using only
    // the policy-owned search paths below; it is never selected or influenced
    // by a session request.
    std::string runtime_discovery;
    std::string executable_path;
    std::vector<std::string> executable_search_paths;
    std::vector<std::string> arguments;
    std::vector<std::string> environment;
    // Immutable operator-installed harness files required in addition to the
    // selected executable. These remain local policy, are mounted read-only,
    // and are never accepted from a Sage session request.
    std::vector<std::string> read_only_paths;

    auto operator==(const runtime_launch_template&) const -> bool = default;
};

// Validate only the bounded, canonical launch-template fields. This is shared
// by policy tooling and the session-policy loader so operator diagnostics use
// the exact enforcement rules rather than a second approximation.
[[nodiscard]] auto validate_runtime_launch_template(const runtime_launch_template& launch)
    -> result<void>;

// Canonical SHA-256 commitment for the complete host launch template.
[[nodiscard]] auto runtime_launch_template_digest(const runtime_launch_template& launch)
    -> result<std::string>;

// Resolve an explicit executable or search the template's ordered,
// digest-bound roots for its built-in adapter executable. Inherited PATH is
// never consulted.
[[nodiscard]] auto resolve_runtime_executable(const runtime_launch_template& launch)
    -> result<std::string>;

struct runtime_template_policy {
    std::string runtime_template_id;
    std::string runtime_id;
    std::string adapter_command_digest;
    sandbox_backend backend = sandbox_backend::apple_container;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
    // Absent policies remain eligible for plan-only validation, never launch
    // resolution. A present template must match adapter_command_digest.
    std::optional<runtime_launch_template> launch;
    // Owner-local adoption authority. The protected root never crosses the
    // controller boundary; launch projections retain only the redacted pair
    // of content digests.
    std::optional<native_harness_adoption_policy> adoption;
};

// Host-owned sandbox destination for exact Sage bundle objects. The alias may
// cross the plan boundary; the absolute sandbox target never does.
struct library_projection_destination_policy {
    std::string alias;
    std::string target_path;

    auto operator==(const library_projection_destination_policy&) const -> bool = default;
};

struct egress_target_policy {
    std::string host;
    std::uint16_t port = 443;
    bool allow_private = false;

    auto operator==(const egress_target_policy&) const -> bool = default;
};

struct egress_policy {
    std::string policy_id;
    std::vector<egress_target_policy> targets;

    auto operator==(const egress_policy&) const -> bool = default;
};

// An identifier selected by the plan resolves only through this local policy.
// The source never crosses the control or P2P wire. At preparation it is
// identity-pinned and mounted read-only at the exact managed-home target.
struct secret_mount_policy {
    std::string handle;
    std::string runtime_id;
    std::string source_path;
    std::string target_path;

    auto operator==(const secret_mount_policy&) const -> bool = default;
};

// Protected, host-owned policy. Its exact revision must match every accepted
// controller plan. Numeric limits are admitted only as exact configured
// profiles, preventing a remote caller from selecting arbitrary quotas.
struct session_plan_policy {
    std::uint64_t revision = 0;
    std::uint64_t max_plan_ttl_ms = 0;
    std::vector<runtime_template_policy> runtime_templates;
    std::vector<library_projection_destination_policy> library_projection_destinations;
    std::vector<resource_limits> resource_profiles;
    std::vector<std::string> egress_policy_ids;
    std::vector<std::string> tool_policy_ids;
    std::vector<std::string> secret_handles;
    std::vector<egress_policy> egress_policies;
    std::vector<secret_mount_policy> secret_mounts;
};

struct session_plan_validation {
    std::uint8_t schema_version = 1;
    std::uint64_t policy_revision = 0;

    auto operator==(const session_plan_validation&) const -> bool = default;
};

// Host-authored launch projection selected by an identifier-only validated
// plan. This returns no path descriptor and performs no filesystem or process
// side effect; start must still resolve grants and enforce every other gate.
struct runtime_launch_projection {
    session_plan_validation validation;
    std::string runtime_id;
    std::string runtime_template_id;
    std::string adapter_command_digest;
    sandbox_backend backend = sandbox_backend::apple_container;
    std::vector<std::string> argv;
    std::vector<std::string> environment;
    std::vector<std::string> read_only_paths;
    resource_limits limits;
    std::uint64_t expires_at_ms = 0;
    bool requires_direct_write_approval = false;
    std::string egress_policy_id;
    std::vector<egress_target_policy> egress_targets;
    std::vector<secret_mount_policy> secret_mounts;
    // Present only when the local runtime template has bound a verified
    // adoption manifest. No protected root, host path, or selector reaches
    // this session-visible projection.
    std::optional<native_harness_adoption_identity> adoption;
    std::optional<container::refinement_execution_binding> refinement;

    auto operator==(const runtime_launch_projection&) const -> bool = default;
};

struct validated_session_plan_document {
    session_plan_validation validation;
    std::uint64_t expires_at_ms = 0;
    std::string canonical_json;
};

// Canonical identifier-only request to resolve one Sage-staged bundle. The
// digest names exact bytes in the protected local bundle store; the destination
// remains a host-policy alias rather than a sandbox path.
struct library_bundle_projection {
    std::string projection_id;
    std::string content_digest;
    std::string destination_alias;

    auto operator==(const library_bundle_projection&) const -> bool = default;
};

struct resolved_library_projection_target {
    library_bundle_projection projection;
    std::string target_path;

    auto operator==(const resolved_library_projection_target&) const -> bool = default;
};

// Strict decoder and independent host-policy validator for Sage's canonical,
// identifier-only GloveSessionPlan JSON. Validation has no durable or launch
// side effects and does not return path descriptors.
class session_plan_validator {
public:
    // Load strict host policy from an owner-only, single-link regular file.
    // The file is read through a stable descriptor and rechecked afterward;
    // raw host paths are confined to this local configuration surface.
    [[nodiscard]] static auto load(
        const std::filesystem::path& policy_path,
        std::shared_ptr<const path_exposure_registry> exposures = {}
    ) -> result<session_plan_validator>;

    [[nodiscard]] static auto build(
        session_plan_policy policy,
        path_alias_registry paths,
        std::shared_ptr<const path_exposure_registry> exposures = {}
    ) -> result<session_plan_validator>;

    [[nodiscard]] auto validate_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<session_plan_validation>;

    // Re-encode an accepted plan in the exact field order owned by this
    // decoder. The returned identifier-only JSON is safe to persist, but it is
    // not launch authority and must be revalidated before a future start.
    [[nodiscard]] auto canonicalize_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<validated_session_plan_document>;

    // Resolve only protected process fields after repeating complete plan
    // validation. Policies without a digest-bound launch template fail closed.
    [[nodiscard]] auto
    resolve_runtime_launch_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<runtime_launch_projection>;

    // Resolve the descriptor-owned adoption state selected solely by the
    // owner-local runtime template. Remote plans do not name it.
    [[nodiscard]] auto
    resolve_native_harness_adoption_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<std::optional<resolved_native_harness_adoption>>;

    // Resolve host-owned aliases to identity-pinned descriptors after complete
    // plan validation. Callers must first establish their own durable start
    // authorization. Direct-write remains unavailable through this generic
    // path; partial failure closes all previously resolved descriptors.
    [[nodiscard]] auto
    resolve_path_grants_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<std::vector<resolved_path_grant>>;

    // Extract exact library bundle commitments only after repeating complete
    // canonical plan validation. This performs no bundle lookup or filesystem
    // operation and returns no host destination path.
    [[nodiscard]] auto
    resolve_library_projections_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<std::vector<library_bundle_projection>>;

    // Resolve destination aliases only to protected sandbox targets. Bundle
    // bytes remain unopened until the launch preparation boundary.
    [[nodiscard]] auto
    resolve_library_projection_targets_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<std::vector<resolved_library_projection_target>>;

    // Derive the host-validated half of the matched refinement context. The
    // supplied matched-context field is intentionally not an input to this
    // digest, allowing a controller to construct the fixture and then submit
    // the final exact digest.
    [[nodiscard]] auto
    refinement_plan_context_digest_json(std::string_view plan_json, std::uint64_t now_ms) const
        -> result<std::string>;

private:
    session_plan_policy policy_;
    path_alias_registry paths_;
    std::shared_ptr<const path_exposure_registry> exposures_;
};

} // namespace glove::supervisor
