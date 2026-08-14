#include "session_registry_replay.hpp"

namespace glove::control {

auto start_reservation_from_record(
    session_registry::implementation& state, const wire::persisted_session& record
) -> session_registry_result<session_start_reservation> {
    // This reconstructs the exact historical idempotent response, not current
    // launch authority. Callers must still enforce authorization_expires_at_ms
    // before the later process-start transition.
    auto launch = state.validator->resolve_runtime_launch_json(
        record.canonical_plan_json, record.authorized_at_ms
    );
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves to a runtime launch: " + launch.error()
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }
    return session_start_reservation{
        .session = public_record(record),
        .launch = std::move(*launch),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
    };
}

auto starting_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_starting_record> {
    if (record.state != "starting" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || !record.cgroup_identity ||
        !valid_cgroup_identity(*record.cgroup_identity) || !record.filesystem_identity ||
        !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable starting commitment"
        ));
    }
    return session_starting_record{
        .session = public_record(record),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .cgroup_identity = *record.cgroup_identity,
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto running_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_running_record> {
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "running" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        !process_identity || !record.cgroup_identity ||
        !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable running commitment"
        ));
    }
    return session_running_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto stopping_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_stopping_record> {
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "stopping" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        record.stopping_at_ms < record.running_at_ms || !process_identity ||
        !record.cgroup_identity || !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable stopping commitment"
        ));
    }
    return session_stopping_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto exited_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_exited_record> {
    const auto termination = termination_cause_from_wire(record.termination_cause);
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "exited" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        !process_identity ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0 ? record.running_at_ms : record.stopping_at_ms) ||
        !record.cgroup_identity || !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity) ||
        !valid_digest(record.receipt_key_id) || record.receipt_sequence == 0 ||
        !valid_digest(record.receipt_digest) || !valid_digest(record.receipt_hmac) ||
        !termination) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable terminal receipt"
        ));
    }
    return session_exited_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
        .finished_at_ms = record.finished_at_ms,
        .receipt_key_id = record.receipt_key_id,
        .receipt_sequence = record.receipt_sequence,
        .receipt_digest = record.receipt_digest,
        .receipt_hmac = record.receipt_hmac,
        .termination_cause = *termination,
        .exit_code = record.exit_code,
        .refinement_receipt = record.operation == "mark_refinement_exited",
    };
}

auto failed_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_failed_record> {
    const auto code = failure_code_from_wire(record.failure_code);
    auto process_identity = process_identity_from_wire(record);
    const bool prepared_resources =
        record.cgroup_identity && valid_cgroup_identity(*record.cgroup_identity) &&
        record.filesystem_identity && valid_filesystem_identity(*record.filesystem_identity);
    const bool process_matches_cgroup =
        process_identity && prepared_resources &&
        process_identity->cgroup_device == record.cgroup_identity->device &&
        process_identity->cgroup_inode == record.cgroup_identity->inode;
    if (record.state != "failed" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0
                 ? (record.running_at_ms == 0 ? record.starting_at_ms : record.running_at_ms)
                 : record.stopping_at_ms) ||
        !code ||
        (record.running_at_ms == 0 && (!no_process_identity(record) || !prepared_resources)) ||
        (record.running_at_ms != 0 && !process_matches_cgroup)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable failure commitment"
        ));
    }
    return session_failed_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(process_identity),
        .cgroup_identity = record.cgroup_identity,
        .filesystem_identity = record.filesystem_identity,
        .failed_at_ms = record.finished_at_ms,
        .code = *code,
    };
}

auto managed_lifecycle_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_lifecycle_record> {
    if ((record.state != "starting" && record.state != "running" && record.state != "stopping" &&
         record.state != "exited" && record.state != "failed") ||
        !valid_digest(record.launch_profile_digest) || record.starting_at_ms == 0 ||
        (record.running_at_ms != 0 && record.running_at_ms < record.starting_at_ms) ||
        (record.stopping_at_ms != 0 && record.stopping_at_ms < record.running_at_ms) ||
        !no_process_identity(record) || record.cgroup_identity || record.filesystem_identity ||
        !record.managed_runtime_identity ||
        !valid_managed_runtime_identity(*record.managed_runtime_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed runtime commitment"
        ));
    }
    return managed_session_lifecycle_record{
        .session = public_record(record),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .runtime_identity = *record.managed_runtime_identity,
    };
}

auto managed_exited_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_exited_record> {
    auto lifecycle = managed_lifecycle_from_wire(record);
    const auto termination = termination_cause_from_wire(record.termination_cause);
    if (!lifecycle || record.state != "exited" || record.running_at_ms == 0 ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0 ? record.running_at_ms : record.stopping_at_ms) ||
        !valid_digest(record.receipt_key_id) || record.receipt_sequence == 0 ||
        !valid_digest(record.receipt_digest) || !valid_digest(record.receipt_hmac) ||
        !termination) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed terminal receipt"
        ));
    }
    return managed_session_exited_record{
        .lifecycle = std::move(*lifecycle),
        .finished_at_ms = record.finished_at_ms,
        .receipt_key_id = record.receipt_key_id,
        .receipt_sequence = record.receipt_sequence,
        .receipt_digest = record.receipt_digest,
        .receipt_hmac = record.receipt_hmac,
        .termination_cause = *termination,
        .exit_code = record.exit_code,
    };
}

auto managed_failed_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_failed_record> {
    auto lifecycle = managed_lifecycle_from_wire(record);
    const auto code = failure_code_from_wire(record.failure_code);
    if (!lifecycle || record.state != "failed" || !code ||
        record.finished_at_ms <
            (record.stopping_at_ms != 0
                 ? record.stopping_at_ms
                 : (record.running_at_ms != 0 ? record.running_at_ms : record.starting_at_ms))) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed failure commitment"
        ));
    }
    return managed_session_failed_record{
        .lifecycle = std::move(*lifecycle),
        .failed_at_ms = record.finished_at_ms,
        .code = *code,
    };
}

auto find_create_replay_locked(
    session_registry::implementation& state,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "create" || record.session_id != session_id ||
        record.controller_plan_digest != controller_plan_digest ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session create idempotency payload changed"
        ));
    }
    return replay_lookup{.found = true, .record = public_record(record)};
}

auto find_start_replay_locked(
    session_registry::implementation& state,
    const session_start_authorization& authorization,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<start_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return start_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "reserve_start" || record.session_id != authorization.session_id ||
        record.controller_plan_digest != authorization.controller_plan_digest ||
        record.plan_content_digest != authorization.plan_content_digest ||
        record.authorization_id != authorization.authorization_id ||
        record.authorized_at_ms != authorization.approved_at_ms ||
        record.authorization_expires_at_ms != authorization.expires_at_ms ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session start idempotency payload changed"
        ));
    }
    auto reservation = start_reservation_from_record(state, record);
    if (!reservation) {
        return std::unexpected(reservation.error());
    }
    return start_replay_lookup{.found = true, .reservation = std::move(*reservation)};
}

auto find_starting_replay_locked(
    session_registry::implementation& state,
    const session_execution_binding& binding,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<starting_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return starting_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_starting" || record.session_id != binding.session_id ||
        record.controller_plan_digest != binding.controller_plan_digest ||
        record.plan_content_digest != binding.plan_content_digest ||
        record.authorization_id != binding.authorization_id ||
        record.launch_profile_digest != binding.profile_digest ||
        record.cgroup_identity != binding.cgroup_identity ||
        record.filesystem_identity != binding.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session starting idempotency payload changed"
        ));
    }
    auto starting = starting_record_from_wire(record);
    if (!starting) {
        return std::unexpected(starting.error());
    }
    return starting_replay_lookup{.found = true, .record = std::move(*starting)};
}

auto find_running_replay_locked(
    session_registry::implementation& state,
    const session_running_commitment& running_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<running_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return running_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_running" || record.session_id != running_commitment.session_id ||
        record.controller_plan_digest != running_commitment.controller_plan_digest ||
        record.plan_content_digest != running_commitment.plan_content_digest ||
        record.authorization_id != running_commitment.authorization_id ||
        record.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(record, running_commitment.process_identity) ||
        record.filesystem_identity != running_commitment.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session running idempotency payload changed"
        ));
    }
    auto running = running_record_from_wire(record);
    if (!running) {
        return std::unexpected(running.error());
    }
    return running_replay_lookup{.found = true, .record = std::move(*running)};
}

auto find_stopping_replay_locked(
    session_registry::implementation& state,
    const session_running_commitment& running_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<stopping_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return stopping_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_stopping" || record.session_id != running_commitment.session_id ||
        record.controller_plan_digest != running_commitment.controller_plan_digest ||
        record.plan_content_digest != running_commitment.plan_content_digest ||
        record.authorization_id != running_commitment.authorization_id ||
        record.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(record, running_commitment.process_identity) ||
        record.filesystem_identity != running_commitment.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session stopping idempotency payload changed"
        ));
    }
    auto stopping = stopping_record_from_wire(record);
    if (!stopping) {
        return std::unexpected(stopping.error());
    }
    return stopping_replay_lookup{.found = true, .record = std::move(*stopping)};
}

auto find_failure_replay_locked(
    session_registry::implementation& state,
    const session_failure_commitment& failure_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<failure_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return failure_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_failed" || record.session_id != failure_commitment.session_id ||
        record.controller_plan_digest != failure_commitment.controller_plan_digest ||
        record.plan_content_digest != failure_commitment.plan_content_digest ||
        record.authorization_id != failure_commitment.authorization_id ||
        record.launch_profile_digest != failure_commitment.profile_digest ||
        record.failure_code != failure_code_name(failure_commitment.code) ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session failure idempotency payload changed"
        ));
    }
    auto failed = failed_record_from_wire(record);
    if (!failed) {
        return std::unexpected(failed.error());
    }
    return failure_replay_lookup{.found = true, .record = std::move(*failed)};
}

auto find_exited_replay_locked(
    session_registry::implementation& state,
    const container::authenticated_resource_enforcement_receipt& terminal,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<exited_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }

    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return exited_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_exited" || record.session_id != terminal.session_id ||
        record.controller_plan_digest != terminal.controller_plan_digest ||
        record.launch_profile_digest != terminal.receipt.profile_digest ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session terminal idempotency payload changed"
        ));
    }
    auto exited = exited_record_from_wire(record);
    if (!exited) {
        return std::unexpected(exited.error());
    }
    return exited_replay_lookup{.found = true, .record = std::move(*exited)};
}

auto find_exited_replay_locked(
    session_registry::implementation& state,
    const container::authenticated_refinement_evaluation_receipt& terminal,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<exited_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return exited_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_refinement_exited" || record.session_id != terminal.session_id ||
        record.controller_plan_digest != terminal.controller_plan_digest ||
        record.launch_profile_digest != terminal.receipt.resource_receipt.profile_digest ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "refinement session terminal idempotency payload changed"
        ));
    }
    auto exited = exited_record_from_wire(record);
    if (!exited) {
        return std::unexpected(exited.error());
    }
    return exited_replay_lookup{.found = true, .record = std::move(*exited)};
}

auto append_record_locked(session_registry::implementation& state, wire::persisted_session record)
    -> session_registry_result<session_record> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    auto this_hash = hash_record(record);
    if (!this_hash) {
        return std::unexpected(storage_failure(this_hash.error()));
    }
    record.this_hash = std::move(*this_hash);
    auto encoded = encode_record(record);
    if (!encoded) {
        return std::unexpected(failure(session_registry_error_code::capacity, encoded.error()));
    }
    if (encoded->size() > state.max_bytes - state.durable_bytes) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry byte limit exhausted")
        );
    }
    const auto original_size = state.durable_bytes;
    if (auto written = write_at(state.opened.file.get(), *encoded, original_size); !written) {
        (void)rollback_append(state, original_size);
        return std::unexpected(storage_failure(written.error()));
    }
    if (auto synced = sync_descriptor(state.opened.file.get(), "sync session registry append");
        !synced) {
        (void)rollback_append(state, original_size);
        return std::unexpected(storage_failure(synced.error()));
    }
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != original_size + encoded->size()) {
        state.poisoned = true;
        return std::unexpected(storage_failure("session registry identity update failed"));
    }
    const auto index = state.records.size();
    state.durable_bytes += encoded->size();
    state.identity = *identity;
    state.sessions.insert_or_assign(record.session_id, index);
    state.requests.emplace(record.idempotency_key, index);
    state.records.push_back(std::move(record));
    return public_record(state.records.back());
}


} // namespace glove::control
