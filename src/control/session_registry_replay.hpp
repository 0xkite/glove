#pragma once

#include "session_registry_recovery.hpp"

#include <string_view>

namespace glove::control {

// Idempotent replay lookups reconstruct the exact historical response for a
// repeated operation. `found = false` means "no prior record; proceed fresh".

auto start_reservation_from_record(
    session_registry::implementation& state, const wire::persisted_session& record
) -> session_registry_result<session_start_reservation>;

auto starting_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_starting_record>;

auto running_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_running_record>;

auto stopping_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_stopping_record>;

auto exited_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_exited_record>;

auto failed_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_failed_record>;

auto managed_lifecycle_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_lifecycle_record>;

auto managed_exited_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_exited_record>;

auto managed_failed_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_failed_record>;

auto find_create_replay_locked(
    session_registry::implementation& state, std::string_view session_id,
    std::string_view controller_plan_digest, std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<replay_lookup>;

auto find_start_replay_locked(
    session_registry::implementation& state, const session_start_authorization& authorization,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<start_replay_lookup>;

auto find_starting_replay_locked(
    session_registry::implementation& state, const session_execution_binding& binding,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<starting_replay_lookup>;

auto find_running_replay_locked(
    session_registry::implementation& state, const session_running_commitment& running_commitment,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<running_replay_lookup>;

auto find_stopping_replay_locked(
    session_registry::implementation& state, const session_running_commitment& running_commitment,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<stopping_replay_lookup>;

auto find_failure_replay_locked(
    session_registry::implementation& state, const session_failure_commitment& failure_commitment,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<failure_replay_lookup>;

auto find_exited_replay_locked(
    session_registry::implementation& state,
    const container::authenticated_resource_enforcement_receipt& terminal,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<exited_replay_lookup>;

auto find_exited_replay_locked(
    session_registry::implementation& state,
    const container::authenticated_refinement_evaluation_receipt& terminal,
    std::string_view request_digest, std::string_view idempotency_key
) -> session_registry_result<exited_replay_lookup>;

auto append_record_locked(session_registry::implementation& state, wire::persisted_session record)
    -> session_registry_result<session_record>;

} // namespace glove::control
