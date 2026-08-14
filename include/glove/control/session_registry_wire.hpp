#pragma once

#include "glove/control/session_registry.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <glaze/glaze.hpp>

namespace glove::control::wire {

inline constexpr std::uint64_t max_record_payload_bytes = std::uint64_t{1024} * 1024U;
inline constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

// Wire representation of a persisted session registry record. This must stay
// byte-for-byte stable with the on-disk registry format.
struct persisted_session {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string operation;
    std::string idempotency_key;
    std::string session_id;
    std::string controller_plan_digest;
    std::string request_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::string authorization_id;
    std::uint64_t authorized_at_ms = 0;
    std::uint64_t authorization_expires_at_ms = 0;
    std::string launch_profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::uint8_t process_identity_schema_version = 0;
    std::uint32_t process_pid = 0;
    std::string process_boot_id;
    std::uint64_t process_start_time_ticks = 0;
    std::uint64_t process_cgroup_device = 0;
    std::uint64_t process_cgroup_inode = 0;
    std::string process_cgroup_path_digest;
    std::optional<linux_cgroup_recovery_identity> cgroup_identity;
    std::optional<linux_filesystem_recovery_identity> filesystem_identity;
    std::optional<managed_runtime_recovery_identity> managed_runtime_identity;
    std::string failure_code;
    std::uint64_t finished_at_ms = 0;
    std::uint64_t receipt_started_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_previous_hmac;
    std::string receipt_hmac;
    std::string termination_cause;
    std::optional<int> exit_code;
    std::string canonical_plan_json;
    std::string previous_hash;
    std::string this_hash;
};

struct plan_runtime_header {
    std::string runtime_template_id;
};

// Low-level wire codec primitives.
auto append_u32(std::vector<unsigned char>& output, std::uint32_t value) -> void;
auto append_u64(std::vector<unsigned char>& output, std::uint64_t value) -> void;
auto append_string(std::vector<unsigned char>& output, std::string_view value) -> bool;
auto append_filesystem_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_filesystem_recovery_identity>& identity
) -> std::expected<void, std::string>;
auto append_cgroup_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_cgroup_recovery_identity>& identity
) -> void;
auto append_managed_runtime_identity(
    std::vector<unsigned char>& output,
    const std::optional<managed_runtime_recovery_identity>& identity
) -> std::expected<void, std::string>;
auto decode_u32(std::span<const unsigned char, 4> input) noexcept -> std::uint32_t;

// Terminal receipt reference used by hash_terminal_reference/envelope.
struct terminal_reference {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string_view key_id;
    std::string_view session_id;
    std::string_view controller_plan_digest;
    std::string_view profile_digest;
    std::string_view receipt_digest;
    std::string_view previous_hmac;
    std::string_view this_hmac;
    container::resource_termination_cause termination_cause =
        container::resource_termination_cause::supervisor_error;
    std::uint64_t started_at_ms = 0;
    std::uint64_t finished_at_ms = 0;
    std::optional<int> exit_code;
};

// Record materialization + hashing.
auto record_material(const persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string>;
auto hash_record(const persisted_session& record) -> std::expected<std::string, std::string>;
auto hash_plan(std::string_view plan) -> std::expected<std::string, std::string>;
auto hash_start_authorization(const session_start_authorization& authorization)
    -> std::expected<std::string, std::string>;
auto hash_execution_binding(const session_execution_binding& binding)
    -> std::expected<std::string, std::string>;
auto hash_running_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string>;
auto hash_stopping_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string>;
auto hash_managed_execution_binding(const managed_session_execution_binding& binding)
    -> std::expected<std::string, std::string>;
auto hash_managed_running_commitment(
    const managed_session_running_commitment& running, std::string_view domain
) -> std::expected<std::string, std::string>;
auto termination_cause_name(container::resource_termination_cause cause) -> std::string_view;
auto termination_cause_from_wire(std::string_view value)
    -> std::optional<container::resource_termination_cause>;
auto hash_terminal_reference(const terminal_reference& terminal)
    -> std::expected<std::string, std::string>;
auto hash_terminal_envelope(const container::authenticated_resource_enforcement_receipt& terminal)
    -> std::expected<std::string, std::string>;
auto hash_terminal_envelope(const container::authenticated_refinement_evaluation_receipt& terminal)
    -> std::expected<std::string, std::string>;
auto failure_code_name(session_failure_code code) -> std::string_view;
auto failure_code_from_wire(std::string_view value) -> std::optional<session_failure_code>;
auto hash_failure_commitment(const session_failure_commitment& failure)
    -> std::expected<std::string, std::string>;
auto state_from_wire(std::string_view state) -> std::optional<session_state>;

auto encode_record(const persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string>;
auto decode_record(std::string_view payload)
    -> std::expected<persisted_session, std::string>;

} // namespace glove::control::wire
