#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {

inline constexpr std::uint64_t default_session_registry_bytes = std::uint64_t{64} * 1024U * 1024U;

enum class session_state : std::uint8_t {
    created,
    preparing,
    starting,
    running,
    stopping,
    exited,
    failed,
};

struct session_record {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    session_state state = session_state::created;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;

    auto operator==(const session_record&) const -> bool = default;
};

// Sage-issued, local-channel start authorization. This contains no opaque
// operator proof. Direct-write plans therefore remain structurally ineligible
// until Glove has a separately authenticated local-consent verifier.
struct session_start_authorization {
    std::uint8_t schema_version = 1;
    std::string authorization_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::uint64_t approved_at_ms = 0;
    std::uint64_t expires_at_ms = 0;

    auto operator==(const session_start_authorization&) const -> bool = default;
};

struct session_start_reservation {
    session_record session;
    supervisor::runtime_launch_projection launch;
    std::string authorization_id;
    std::uint64_t authorization_expires_at_ms = 0;

    auto operator==(const session_start_reservation&) const -> bool = default;
};

struct session_start_inputs {
    session_record session;
    supervisor::runtime_launch_projection launch;
    std::vector<supervisor::resolved_path_grant> path_grants;
    std::vector<supervisor::resolved_library_projection> library_projections;
    // Descriptor-pinned adoption state is local launch material, not remote
    // plan content. It must exactly match launch.adoption when present.
    std::optional<supervisor::resolved_native_harness_adoption> adoption;
    std::string authorization_id;
    std::uint64_t authorization_expires_at_ms = 0;
};

struct linux_cgroup_recovery_identity {
    std::uint8_t schema_version = 1;
    std::uint64_t device = 0;
    std::uint64_t inode = 0;

    auto operator==(const linux_cgroup_recovery_identity&) const -> bool = default;
};

struct linux_filesystem_quota_partition {
    std::string alias;
    std::uint64_t quota_bytes = 0;

    auto operator==(const linux_filesystem_quota_partition&) const -> bool = default;
};

// Bounded cleanup authority for deterministic owner-only materializations. It
// contains no host path; the daemon supplies its configured materialization
// root and Glove verifies every present tmpfs quota before cleanup begins.
struct linux_filesystem_recovery_identity {
    std::uint8_t schema_version = 1;
    std::uint64_t disk_limit_bytes = 0;
    std::vector<linux_filesystem_quota_partition> partitions;

    auto operator==(const linux_filesystem_recovery_identity&) const -> bool = default;
};

// Immutable execution commitment produced only after reversible Linux
// preparation has resolved and bound every launch input. This is not remote
// authority; the registry independently checks it against the current durable
// reservation before committing the launch-adjacent transition.
struct session_execution_binding {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::string profile_digest;
    linux_cgroup_recovery_identity cgroup_identity;
    linux_filesystem_recovery_identity filesystem_identity;

    auto operator==(const session_execution_binding&) const -> bool = default;
};

struct session_starting_record {
    session_record session;
    std::string authorization_id;
    std::uint64_t authorization_expires_at_ms = 0;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    linux_cgroup_recovery_identity cgroup_identity;
    linux_filesystem_recovery_identity filesystem_identity;

    auto operator==(const session_starting_record&) const -> bool = default;
};

// Opaque host-owned commitment to one Linux process instance and its cgroup.
// The raw cgroup path is deliberately excluded. PID is only one component and
// must never be treated as sufficient recovery authority by itself.
struct linux_process_identity {
    std::uint8_t schema_version = 1;
    std::uint32_t pid = 0;
    std::string boot_id;
    std::uint64_t start_time_ticks = 0;
    std::uint64_t cgroup_device = 0;
    std::uint64_t cgroup_inode = 0;
    std::string cgroup_path_digest;

    auto operator==(const linux_process_identity&) const -> bool = default;
};

struct session_running_commitment {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::string profile_digest;
    linux_process_identity process_identity;
    linux_filesystem_recovery_identity filesystem_identity;

    auto operator==(const session_running_commitment&) const -> bool = default;
};

struct session_running_record {
    session_record session;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    linux_process_identity process_identity;
    linux_filesystem_recovery_identity filesystem_identity;

    auto operator==(const session_running_record&) const -> bool = default;
};

// Durable stop intent for the exact process/resource identity previously
// admitted by mark_running. Stop remains locally available after launch
// authorization expires; this record grants no new execution authority.
struct session_stopping_record {
    session_record session;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    linux_process_identity process_identity;
    linux_filesystem_recovery_identity filesystem_identity;

    auto operator==(const session_stopping_record&) const -> bool = default;
};

// Durable cross-journal terminal projection. The receipt references identify
// the exact authenticated envelope retained by the Glove receipt journal;
// mark_exited accepts them only after exact producer-side membership proof.
struct session_exited_record {
    session_record session;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    linux_process_identity process_identity;
    linux_filesystem_recovery_identity filesystem_identity;
    std::uint64_t finished_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_hmac;
    container::resource_termination_cause termination_cause =
        container::resource_termination_cause::supervisor_error;
    std::optional<int> exit_code;
    bool refinement_receipt = false;

    auto operator==(const session_exited_record&) const -> bool = default;
};

enum class session_failure_code : std::uint8_t {
    authorization_expired,
    launch_failed,
    supervisor_error,
    recovered_without_process,
    recovered_terminated,
};

// Bounded terminal commitment for failures that occur after the durable
// starting transition but before an authenticated terminal receipt exists.
// It deliberately carries no free-form remote-controlled detail.
struct session_failure_commitment {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::string profile_digest;
    session_failure_code code = session_failure_code::supervisor_error;

    auto operator==(const session_failure_commitment&) const -> bool = default;
};

struct session_failed_record {
    session_record session;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::optional<linux_process_identity> process_identity;
    std::optional<linux_cgroup_recovery_identity> cgroup_identity;
    std::optional<linux_filesystem_recovery_identity> filesystem_identity;
    std::uint64_t failed_at_ms = 0;
    session_failure_code code = session_failure_code::supervisor_error;

    auto operator==(const session_failed_record&) const -> bool = default;
};

// Bounded restart inventory for the only states that may have crossed the
// process-launch boundary. No canonical plan, raw path, argv, environment, or
// secret material is exposed through this projection.
struct session_recovery_record {
    session_record session;
    std::string authorization_id;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::optional<linux_process_identity> process_identity;
    std::optional<linux_cgroup_recovery_identity> cgroup_identity;
    std::optional<linux_filesystem_recovery_identity> filesystem_identity;
    bool requires_refinement_receipt = false;

    auto operator==(const session_recovery_record&) const -> bool = default;
};

// Backend-neutral, path-free recovery authority for a managed runtime whose
// lifecycle is not represented by Linux cgroup/process identities. The
// backend owns the opaque instance identity and must independently prove it
// still refers to the exact launch configuration before signaling or cleanup.
struct managed_runtime_recovery_identity {
    std::uint8_t schema_version = 1;
    std::string backend;
    std::string instance_id;
    std::string launch_identity_digest;

    auto operator==(const managed_runtime_recovery_identity&) const -> bool = default;
};

struct managed_session_execution_binding {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::string profile_digest;
    managed_runtime_recovery_identity runtime_identity;

    auto operator==(const managed_session_execution_binding&) const -> bool = default;
};

struct managed_session_running_commitment {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::string profile_digest;
    managed_runtime_recovery_identity runtime_identity;

    auto operator==(const managed_session_running_commitment&) const -> bool = default;
};

struct managed_session_lifecycle_record {
    session_record session;
    std::string authorization_id;
    std::uint64_t authorization_expires_at_ms = 0;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    managed_runtime_recovery_identity runtime_identity;

    auto operator==(const managed_session_lifecycle_record&) const -> bool = default;
};

struct managed_session_exited_record {
    managed_session_lifecycle_record lifecycle;
    std::uint64_t finished_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_hmac;
    container::resource_termination_cause termination_cause =
        container::resource_termination_cause::supervisor_error;
    std::optional<int> exit_code;

    auto operator==(const managed_session_exited_record&) const -> bool = default;
};

struct managed_session_failed_record {
    managed_session_lifecycle_record lifecycle;
    std::uint64_t failed_at_ms = 0;
    session_failure_code code = session_failure_code::supervisor_error;

    auto operator==(const managed_session_failed_record&) const -> bool = default;
};

enum class session_registry_error_code : std::uint8_t {
    invalid_request,
    invalid_plan,
    invalid_authorization,
    invalid_state,
    idempotency_conflict,
    session_conflict,
    not_found,
    capacity,
    storage,
};

struct session_registry_error {
    session_registry_error_code code = session_registry_error_code::storage;
    std::string message;

    auto operator==(const session_registry_error&) const -> bool = default;
};

template<typename Value>
using session_registry_result = std::expected<Value, session_registry_error>;

// Exclusive owner of a bounded append-only session registry. A create record
// persists the exact independently validated canonical plan before success.
// A later reservation may persist preparing authority, but the registry
// deliberately has no path resolution or process-spawn operation.
class session_registry final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class session_registry;
    };

    session_registry(construction_token token, std::unique_ptr<implementation> state);
    session_registry(const session_registry&) = delete;
    auto operator=(const session_registry&) -> session_registry& = delete;
    session_registry(session_registry&&) = delete;
    auto operator=(session_registry&&) -> session_registry& = delete;
    ~session_registry();

    [[nodiscard]] static auto open_or_create(
        const std::filesystem::path& path,
        std::shared_ptr<const supervisor::session_plan_validator> validator,
        std::shared_ptr<const supervisor::library_bundle_store> library_bundles = nullptr,
        std::uint64_t max_bytes = default_session_registry_bytes
    ) -> session_registry_result<std::unique_ptr<session_registry>>;

    [[nodiscard]] auto create(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        std::string_view plan_json,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_record>;

    [[nodiscard]] auto status(std::string_view session_id) const
        -> session_registry_result<session_record>;
    // Durably reserve a validated, non-direct-write session for start. The
    // operation repeats plan/runtime validation and binds an expiring approval
    // to both controller and local content digests. It performs no path
    // resolution and starts no process.
    [[nodiscard]] auto reserve_start(
        const session_start_authorization& authorization,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_start_reservation>;
    // Resolve descriptor-owned launch inputs only for a current durable
    // reservation. This is a reversible preparation step and does not
    // materialize filesystems or start a process.
    [[nodiscard]] auto resolve_start_inputs(
        std::string_view session_id, std::string_view authorization_id, std::uint64_t now_ms
    ) -> session_registry_result<session_start_inputs>;
    // Persist the exact prepared profile commitment before any process may be
    // cloned. Callers must reserve authenticated terminal-receipt capacity
    // before invoking this transition. This method itself does not launch.
    [[nodiscard]] auto mark_starting(
        const session_execution_binding& binding,
        const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_starting_record>;
    // Restart-safe recovery of the exact immutable execution commitment.
    [[nodiscard]] auto starting_status(std::string_view session_id) const
        -> session_registry_result<session_starting_record>;
    // Called from the managed-session child-release gate. The child must remain
    // blocked until this synchronized transition succeeds.
    [[nodiscard]] auto mark_running(
        const session_running_commitment& running,
        const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_running_record>;
    [[nodiscard]] auto running_status(std::string_view session_id) const
        -> session_registry_result<session_running_record>;
    // Persist local stop intent for exactly the process/resource identity
    // admitted by mark_running. This transition is idempotent and deliberately
    // does not require the historical launch authorization to remain current.
    [[nodiscard]] auto mark_stopping(
        const session_running_commitment& running,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_stopping_record>;
    [[nodiscard]] auto stopping_status(std::string_view session_id) const
        -> session_registry_result<session_stopping_record>;
    // Close a running or stopping session only after the producer proves that the exact
    // authenticated terminal envelope is already durable in its journal.
    [[nodiscard]] auto mark_exited(
        const container::authenticated_resource_enforcement_receipt& terminal,
        const container::receipt_audit_producer& receipt_producer,
        std::string_view idempotency_key
    ) -> session_registry_result<session_exited_record>;
    [[nodiscard]] auto mark_refinement_exited(
        const container::authenticated_refinement_evaluation_receipt& terminal,
        const container::receipt_audit_producer& receipt_producer,
        std::string_view idempotency_key
    ) -> session_registry_result<session_exited_record>;
    [[nodiscard]] auto exited_status(std::string_view session_id) const
        -> session_registry_result<session_exited_record>;
    // Close a launch attempt without a resource receipt. Expired approval does
    // not block cleanup, but every immutable session/profile field must still
    // match the durable starting record.
    [[nodiscard]] auto mark_failed(
        const session_failure_commitment& failure,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<session_failed_record>;
    [[nodiscard]] auto failed_status(std::string_view session_id) const
        -> session_registry_result<session_failed_record>;
    [[nodiscard]] auto mark_managed_starting(
        const managed_session_execution_binding& binding,
        const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<managed_session_lifecycle_record>;
    [[nodiscard]] auto mark_managed_running(
        const managed_session_running_commitment& running,
        const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<managed_session_lifecycle_record>;
    [[nodiscard]] auto mark_managed_stopping(
        const managed_session_running_commitment& running,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<managed_session_lifecycle_record>;
    [[nodiscard]] auto mark_managed_exited(
        const container::authenticated_resource_enforcement_receipt& terminal,
        const container::receipt_audit_producer& receipt_producer,
        std::string_view idempotency_key
    ) -> session_registry_result<managed_session_exited_record>;
    [[nodiscard]] auto mark_managed_failed(
        const session_failure_commitment& failure,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> session_registry_result<managed_session_failed_record>;
    [[nodiscard]] auto managed_lifecycle_status(std::string_view session_id) const
        -> session_registry_result<managed_session_lifecycle_record>;
    [[nodiscard]] auto managed_recovery_candidates() const
        -> session_registry_result<std::vector<managed_session_lifecycle_record>>;
    // Returns every current starting/running/stopping session in deterministic session-
    // ID order. The registry has a fixed 10,000-record ceiling, so this startup
    // snapshot is bounded independently of caller input.
    [[nodiscard]] auto recovery_candidates() const
        -> session_registry_result<std::vector<session_recovery_record>>;
    [[nodiscard]] auto canonical_plan(std::string_view session_id) const
        -> session_registry_result<std::string>;
    [[nodiscard]] auto record_count() const -> std::uint64_t;
    [[nodiscard]] auto library_projections_available() const noexcept -> bool;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
