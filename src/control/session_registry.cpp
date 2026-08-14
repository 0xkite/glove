#include "glove/control/session_registry.hpp"

#include "glove/container/digest.hpp"
#include "glove/control/session_registry_wire.hpp"

#include "session_registry_impl.hpp"
#include "session_registry_recovery.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace glove::control {


namespace {

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

} // namespace

session_registry::session_registry(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

session_registry::~session_registry() = default;

auto session_registry::open_or_create(
    const std::filesystem::path& path,
    std::shared_ptr<const supervisor::session_plan_validator> validator,
    std::shared_ptr<const supervisor::library_bundle_store> library_bundles,
    std::uint64_t max_bytes
) -> session_registry_result<std::unique_ptr<session_registry>> {
    if (!validator || path.empty() || max_bytes < min_registry_bytes ||
        max_bytes > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session registry configuration"
        ));
    }
    auto opened = open_registry(path);
    if (!opened) {
        return std::unexpected(storage_failure(opened.error()));
    }
    auto state = std::make_unique<implementation>();
    state->opened = std::move(*opened);
    state->validator = std::move(validator);
    state->library_bundles = std::move(library_bundles);
    state->max_bytes = max_bytes;
    if (state->opened.created) {
        if (auto initialized = initialize_empty(*state); !initialized) {
            std::string error = initialized.error();
            if (::unlinkat(state->opened.parent.get(), state->opened.name.c_str(), 0) != 0) {
                error += "; " + system_error("remove incomplete session registry");
            } else if (
                auto synced =
                    sync_descriptor(state->opened.parent.get(), "sync incomplete registry cleanup");
                !synced
            ) {
                error += "; " + synced.error();
            }
            return std::unexpected(storage_failure(std::move(error)));
        }
    }
    if (auto recovered = recover(*state); !recovered) {
        return std::unexpected(storage_failure(recovered.error()));
    }
    return std::make_unique<session_registry>(construction_token{}, std::move(state));
}

auto session_registry::create(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view plan_json,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_record> {
    if (!valid_identifier(session_id) || !valid_digest(controller_plan_digest) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session create request")
        );
    }
    auto request_digest = hash_plan(plan_json);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    {
        const std::scoped_lock lock{state_->mutex};
        auto replay = find_create_replay_locked(
            *state_, session_id, controller_plan_digest, *request_digest, idempotency_key
        );
        if (!replay) {
            return std::unexpected(replay.error());
        }
        if (replay->found) {
            return replay->record;
        }
    }
    auto canonical = state_->validator->canonicalize_json(plan_json, now_ms);
    if (!canonical) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_plan, "session plan was rejected")
        );
    }
    auto content_digest = hash_plan(canonical->canonical_json);
    if (!content_digest) {
        return std::unexpected(storage_failure(content_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_create_replay_locked(
        *state_, session_id, controller_plan_digest, *request_digest, idempotency_key
    );
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return replay->record;
    }
    if (state_->sessions.contains(std::string{session_id})) {
        return std::unexpected(failure(
            session_registry_error_code::session_conflict, "session identity already exists"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "create",
        .idempotency_key = std::string{idempotency_key},
        .session_id = std::string{session_id},
        .controller_plan_digest = std::string{controller_plan_digest},
        .request_digest = std::move(*request_digest),
        .plan_content_digest = std::move(*content_digest),
        .state = "created",
        .policy_revision = canonical->validation.policy_revision,
        .expires_at_ms = canonical->expires_at_ms,
        .created_at_ms = now_ms,
        .authorization_id = {},
        .authorized_at_ms = 0,
        .authorization_expires_at_ms = 0,
        .launch_profile_digest = {},
        .starting_at_ms = 0,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = std::move(canonical->canonical_json),
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    return append_record_locked(*state_, std::move(record));
}

auto session_registry::reserve_start(
    const session_start_authorization& authorization,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_start_reservation> {
    if (authorization.schema_version != 1 || !valid_identifier(authorization.authorization_id) ||
        !valid_identifier(authorization.session_id) ||
        !valid_digest(authorization.controller_plan_digest) ||
        !valid_digest(authorization.plan_content_digest) || !valid_identifier(idempotency_key) ||
        authorization.approved_at_ms == 0 ||
        authorization.expires_at_ms <= authorization.approved_at_ms ||
        authorization.expires_at_ms - authorization.approved_at_ms >
            max_start_authorization_ttl_ms ||
        now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "invalid session start authorization"
        ));
    }
    auto request_digest = hash_start_authorization(authorization);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    {
        const std::scoped_lock lock{state_->mutex};
        auto replay =
            find_start_replay_locked(*state_, authorization, *request_digest, idempotency_key);
        if (!replay) {
            return std::unexpected(replay.error());
        }
        if (replay->found) {
            return std::move(replay->reservation);
        }
    }
    if (authorization.approved_at_ms > now_ms || authorization.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "session start authorization is not currently valid"
        ));
    }

    std::string canonical_plan;
    {
        const std::scoped_lock lock{state_->mutex};
        if (state_->poisoned || !verify_identity(*state_)) {
            return std::unexpected(storage_failure("session registry is poisoned"));
        }
        const auto existing = state_->sessions.find(authorization.session_id);
        if (existing == state_->sessions.end()) {
            return std::unexpected(
                failure(session_registry_error_code::not_found, "session was not found")
            );
        }
        const auto& record = state_->records[existing->second];
        if (record.state != "created") {
            return std::unexpected(failure(
                session_registry_error_code::invalid_state,
                "session is not eligible for start reservation"
            ));
        }
        if (record.controller_plan_digest != authorization.controller_plan_digest ||
            record.plan_content_digest != authorization.plan_content_digest ||
            authorization.approved_at_ms < record.created_at_ms ||
            authorization.expires_at_ms > record.expires_at_ms) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_authorization,
                "start authorization does not bind the stored session plan"
            ));
        }
        canonical_plan = record.canonical_plan_json;
    }

    auto launch = state_->validator->resolve_runtime_launch_json(canonical_plan, now_ms);
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

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_start_replay_locked(*state_, authorization, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->reservation);
    }
    const auto existing = state_->sessions.find(authorization.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "created" ||
        prior.controller_plan_digest != authorization.controller_plan_digest ||
        prior.plan_content_digest != authorization.plan_content_digest ||
        prior.canonical_plan_json != canonical_plan) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session changed before start reservation"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "reserve_start",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "preparing",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = authorization.authorization_id,
        .authorized_at_ms = authorization.approved_at_ms,
        .authorization_expires_at_ms = authorization.expires_at_ms,
        .launch_profile_digest = {},
        .starting_at_ms = 0,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto reserved = append_record_locked(*state_, std::move(record));
    if (!reserved) {
        return std::unexpected(reserved.error());
    }
    return session_start_reservation{
        .session = std::move(*reserved),
        .launch = std::move(*launch),
        .authorization_id = authorization.authorization_id,
        .authorization_expires_at_ms = authorization.expires_at_ms,
    };
}

auto session_registry::resolve_start_inputs(
    std::string_view session_id, std::string_view authorization_id, std::uint64_t now_ms
) -> session_registry_result<session_start_inputs> {
    if (!valid_identifier(session_id) || !valid_identifier(authorization_id) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session start-input request"
        ));
    }
    std::string canonical_plan;
    session_record prepared_session;
    std::uint64_t authorization_expires_at_ms = 0;
    {
        const std::scoped_lock lock{state_->mutex};
        if (state_->poisoned || !verify_identity(*state_)) {
            return std::unexpected(storage_failure("session registry is poisoned"));
        }
        const auto existing = state_->sessions.find(std::string{session_id});
        if (existing == state_->sessions.end()) {
            return std::unexpected(
                failure(session_registry_error_code::not_found, "session was not found")
            );
        }
        const auto& record = state_->records[existing->second];
        if (record.state != "preparing") {
            return std::unexpected(failure(
                session_registry_error_code::invalid_state,
                "session has no durable start reservation"
            ));
        }
        if (record.authorization_id != authorization_id ||
            record.authorization_expires_at_ms <= now_ms) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_authorization,
                "session start reservation is not currently authorized"
            ));
        }
        canonical_plan = record.canonical_plan_json;
        prepared_session = public_record(record);
        authorization_expires_at_ms = record.authorization_expires_at_ms;
    }

    auto launch = state_->validator->resolve_runtime_launch_json(canonical_plan, now_ms);
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
    auto adoption = state_->validator->resolve_native_harness_adoption_json(canonical_plan, now_ms);
    if (!adoption) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session adoption binding no longer resolves"
        ));
    }
    if (launch->adoption.has_value() != adoption->has_value() ||
        (launch->adoption && adoption->value().identity() != *launch->adoption)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session adoption binding differs from launch projection"
        ));
    }
    auto path_grants = state_->validator->resolve_path_grants_json(canonical_plan, now_ms);
    if (!path_grants) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session path grants no longer resolve"
        ));
    }
    auto library_projections =
        state_->validator->resolve_library_projection_targets_json(canonical_plan, now_ms);
    if (!library_projections) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session library projections no longer resolve"
        ));
    }
    std::vector<supervisor::resolved_library_projection> resolved_library_projections;
    if (!library_projections->empty()) {
        if (!state_->library_bundles) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_plan,
                "session library bundle store is unavailable"
            ));
        }
        auto resolved = state_->library_bundles->resolve_projections(*library_projections);
        if (!resolved) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_plan,
                "stored session library bundles no longer resolve"
            ));
        }
        resolved_library_projections = std::move(*resolved);
    }

    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& current = state_->records[existing->second];
    if (current.state != "preparing" || current.authorization_id != authorization_id ||
        current.authorization_expires_at_ms != authorization_expires_at_ms ||
        current.authorization_expires_at_ms <= now_ms ||
        current.canonical_plan_json != canonical_plan ||
        public_record(current) != prepared_session) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session changed while resolving start inputs"
        ));
    }
    return session_start_inputs{
        .session = std::move(prepared_session),
        .launch = std::move(*launch),
        .path_grants = std::move(*path_grants),
        .library_projections = std::move(resolved_library_projections),
        .adoption = std::move(*adoption),
        .authorization_id = std::string{authorization_id},
        .authorization_expires_at_ms = authorization_expires_at_ms,
    };
}

auto session_registry::mark_starting(
    const session_execution_binding& binding,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_starting_record> {
    if (binding.schema_version != 1 || !valid_identifier(binding.session_id) ||
        !valid_digest(binding.controller_plan_digest) ||
        !valid_digest(binding.plan_content_digest) || !valid_identifier(binding.authorization_id) ||
        !valid_digest(binding.profile_digest) || !valid_cgroup_identity(binding.cgroup_identity) ||
        !valid_filesystem_identity(binding.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session execution commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            binding.session_id, binding.controller_plan_digest, binding.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "execution commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_execution_binding(binding);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_starting_replay_locked(*state_, binding, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(binding.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "preparing") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the starting transition"
        ));
    }
    if (prior.session_id != binding.session_id ||
        prior.controller_plan_digest != binding.controller_plan_digest ||
        prior.plan_content_digest != binding.plan_content_digest ||
        prior.authorization_id != binding.authorization_id ||
        prior.authorization_expires_at_ms <= now_ms || prior.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "execution commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves before starting"
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto authorization_expires_at_ms = prior.authorization_expires_at_ms;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_starting",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "starting",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = binding.cgroup_identity,
        .filesystem_identity = binding.filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_starting_record{
        .session = std::move(*appended),
        .authorization_id = binding.authorization_id,
        .authorization_expires_at_ms = authorization_expires_at_ms,
        .profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .cgroup_identity = binding.cgroup_identity,
        .filesystem_identity = binding.filesystem_identity,
    };
}

auto session_registry::status(std::string_view session_id) const
    -> session_registry_result<session_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return public_record(state_->records[existing->second]);
}

auto session_registry::starting_status(std::string_view session_id) const
    -> session_registry_result<session_starting_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return starting_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_running(
    const session_running_commitment& running_commitment,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_running_record> {
    if (running_commitment.schema_version != 1 ||
        !valid_identifier(running_commitment.session_id) ||
        !valid_digest(running_commitment.controller_plan_digest) ||
        !valid_digest(running_commitment.plan_content_digest) ||
        !valid_identifier(running_commitment.authorization_id) ||
        !valid_digest(running_commitment.profile_digest) ||
        !valid_process_identity(running_commitment.process_identity) ||
        !valid_filesystem_identity(running_commitment.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session running commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            running_commitment.session_id,
            running_commitment.controller_plan_digest,
            running_commitment.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "running commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_running_commitment(running_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_running_replay_locked(*state_, running_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(running_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the running transition"
        ));
    }
    if (prior.session_id != running_commitment.session_id ||
        prior.controller_plan_digest != running_commitment.controller_plan_digest ||
        prior.plan_content_digest != running_commitment.plan_content_digest ||
        prior.authorization_id != running_commitment.authorization_id ||
        prior.launch_profile_digest != running_commitment.profile_digest ||
        !prior.cgroup_identity ||
        prior.cgroup_identity->device != running_commitment.process_identity.cgroup_device ||
        prior.cgroup_identity->inode != running_commitment.process_identity.cgroup_inode ||
        prior.filesystem_identity != running_commitment.filesystem_identity ||
        now_ms < prior.starting_at_ms || now_ms >= prior.authorization_expires_at_ms ||
        now_ms >= prior.expires_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "running commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible before child release"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_running",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "running",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = now_ms,
        .stopping_at_ms = 0,
        .process_identity_schema_version = running_commitment.process_identity.schema_version,
        .process_pid = running_commitment.process_identity.pid,
        .process_boot_id = running_commitment.process_identity.boot_id,
        .process_start_time_ticks = running_commitment.process_identity.start_time_ticks,
        .process_cgroup_device = running_commitment.process_identity.cgroup_device,
        .process_cgroup_inode = running_commitment.process_identity.cgroup_inode,
        .process_cgroup_path_digest = running_commitment.process_identity.cgroup_path_digest,
        .cgroup_identity = prior.cgroup_identity,
        .filesystem_identity = prior.filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_running_record{
        .session = std::move(*appended),
        .profile_digest = running_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = now_ms,
        .process_identity = running_commitment.process_identity,
        .filesystem_identity = running_commitment.filesystem_identity,
    };
}

auto session_registry::running_status(std::string_view session_id) const
    -> session_registry_result<session_running_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return running_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_stopping(
    const session_running_commitment& running_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_stopping_record> {
    if (running_commitment.schema_version != 1 ||
        !valid_identifier(running_commitment.session_id) ||
        !valid_digest(running_commitment.controller_plan_digest) ||
        !valid_digest(running_commitment.plan_content_digest) ||
        !valid_identifier(running_commitment.authorization_id) ||
        !valid_digest(running_commitment.profile_digest) ||
        !valid_process_identity(running_commitment.process_identity) ||
        !valid_filesystem_identity(running_commitment.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session stopping commitment"
        ));
    }
    auto request_digest = hash_stopping_commitment(running_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_stopping_replay_locked(*state_, running_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(running_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "running") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the stopping transition"
        ));
    }
    if (prior.session_id != running_commitment.session_id ||
        prior.controller_plan_digest != running_commitment.controller_plan_digest ||
        prior.plan_content_digest != running_commitment.plan_content_digest ||
        prior.authorization_id != running_commitment.authorization_id ||
        prior.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(prior, running_commitment.process_identity) ||
        prior.filesystem_identity != running_commitment.filesystem_identity ||
        now_ms < prior.running_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "stopping commitment does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto cgroup_identity = prior.cgroup_identity;
    const auto filesystem_identity = prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_stopping",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "stopping",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = now_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_stopping_record{
        .session = std::move(*appended),
        .profile_digest = running_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = now_ms,
        .process_identity = running_commitment.process_identity,
        .filesystem_identity = running_commitment.filesystem_identity,
    };
}

auto session_registry::stopping_status(std::string_view session_id) const
    -> session_registry_result<session_stopping_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return stopping_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_exited(
    const container::authenticated_resource_enforcement_receipt& terminal,
    const container::receipt_audit_producer& receipt_producer,
    std::string_view idempotency_key
) -> session_registry_result<session_exited_record> {
    const auto termination_name = termination_cause_name(terminal.receipt.termination_cause);
    auto receipt_digest = container::resource_enforcement_receipt_digest(terminal.receipt);
    if (terminal.schema_version != 1 || terminal.sequence == 0 || !valid_digest(terminal.key_id) ||
        !valid_identifier(terminal.session_id) || !valid_digest(terminal.controller_plan_digest) ||
        terminal.receipt.schema_version != 1 || !valid_digest(terminal.receipt.profile_digest) ||
        !valid_digest(terminal.receipt_digest) || !valid_digest(terminal.previous_hmac) ||
        !valid_digest(terminal.this_hmac) || termination_name.empty() ||
        terminal.receipt.started_at_ms == 0 ||
        terminal.receipt.finished_at_ms < terminal.receipt.started_at_ms ||
        !valid_identifier(idempotency_key) || !receipt_digest ||
        *receipt_digest != terminal.receipt_digest) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid authenticated session terminal envelope"
        ));
    }
    auto confirmed = receipt_producer.confirms_terminal(terminal);
    if (!confirmed) {
        return std::unexpected(storage_failure(confirmed.error()));
    }
    if (!*confirmed) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "terminal envelope is not durable in the receipt journal"
        ));
    }
    auto request_digest = hash_terminal_envelope(terminal);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_exited_replay_locked(*state_, terminal, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(terminal.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (refinement_plan(prior.canonical_plan_json)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "refinement sessions require a distinct refinement receipt"
        ));
    }
    if (prior.state != "running" && prior.state != "stopping") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the exited transition"
        ));
    }
    if (prior.session_id != terminal.session_id ||
        prior.controller_plan_digest != terminal.controller_plan_digest ||
        prior.launch_profile_digest != terminal.receipt.profile_digest ||
        terminal.receipt.started_at_ms > prior.running_at_ms ||
        terminal.receipt.finished_at_ms <
            (prior.state == "stopping" ? prior.stopping_at_ms : prior.running_at_ms)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "terminal envelope does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto stopping_at_ms = prior.stopping_at_ms;
    auto process_identity = process_identity_from_wire(prior);
    if (!process_identity) {
        state_->poisoned = true;
        return std::unexpected(storage_failure("session registry process identity is invalid"));
    }
    const auto cgroup_identity = *prior.cgroup_identity;
    const auto filesystem_identity = *prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_exited",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "exited",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = prior.stopping_at_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = terminal.receipt.finished_at_ms,
        .receipt_started_at_ms = terminal.receipt.started_at_ms,
        .receipt_key_id = terminal.key_id,
        .receipt_sequence = terminal.sequence,
        .receipt_digest = terminal.receipt_digest,
        .receipt_previous_hmac = terminal.previous_hmac,
        .receipt_hmac = terminal.this_hmac,
        .termination_cause = std::string{termination_name},
        .exit_code = terminal.receipt.exit_code,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_exited_record{
        .session = std::move(*appended),
        .profile_digest = terminal.receipt.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = filesystem_identity,
        .finished_at_ms = terminal.receipt.finished_at_ms,
        .receipt_key_id = terminal.key_id,
        .receipt_sequence = terminal.sequence,
        .receipt_digest = terminal.receipt_digest,
        .receipt_hmac = terminal.this_hmac,
        .termination_cause = terminal.receipt.termination_cause,
        .exit_code = terminal.receipt.exit_code,
        .refinement_receipt = false,
    };
}

auto session_registry::exited_status(std::string_view session_id) const
    -> session_registry_result<session_exited_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return exited_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_refinement_exited(
    const container::authenticated_refinement_evaluation_receipt& terminal,
    const container::receipt_audit_producer& receipt_producer,
    std::string_view idempotency_key
) -> session_registry_result<session_exited_record> {
    const auto& resource = terminal.receipt.resource_receipt;
    const auto termination_name = termination_cause_name(resource.termination_cause);
    auto receipt_digest = container::refinement_evaluation_receipt_digest(terminal.receipt);
    if (terminal.schema_version != 1 || terminal.sequence == 0 || !valid_digest(terminal.key_id) ||
        !valid_identifier(terminal.session_id) || !valid_digest(terminal.controller_plan_digest) ||
        terminal.receipt.schema_version !=
            container::refinement_evaluation_receipt_schema_version ||
        terminal.receipt.runtime_template_id != container::refinement_runtime_template_id ||
        resource.schema_version != 1 || !valid_digest(resource.profile_digest) ||
        !valid_digest(terminal.receipt_digest) || !valid_digest(terminal.previous_hmac) ||
        !valid_digest(terminal.this_hmac) || termination_name.empty() ||
        resource.started_at_ms == 0 || resource.finished_at_ms < resource.started_at_ms ||
        !valid_identifier(idempotency_key) || !receipt_digest ||
        *receipt_digest != terminal.receipt_digest) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid authenticated refinement terminal envelope"
        ));
    }
    auto confirmed = receipt_producer.confirms_terminal(terminal);
    if (!confirmed) {
        return std::unexpected(storage_failure(confirmed.error()));
    }
    if (!*confirmed) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "refinement terminal envelope is not durable in the receipt journal"
        ));
    }
    auto request_digest = hash_terminal_envelope(terminal);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_exited_replay_locked(*state_, terminal, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(terminal.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (!refinement_plan(prior.canonical_plan_json)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "non-refinement sessions cannot accept a refinement receipt"
        ));
    }
    if (prior.state != "running" && prior.state != "stopping") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the refinement exited transition"
        ));
    }
    if (prior.session_id != terminal.session_id ||
        prior.controller_plan_digest != terminal.controller_plan_digest ||
        prior.launch_profile_digest != resource.profile_digest ||
        resource.started_at_ms > prior.running_at_ms ||
        resource.finished_at_ms <
            (prior.state == "stopping" ? prior.stopping_at_ms : prior.running_at_ms)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "refinement envelope does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    auto process_identity = process_identity_from_wire(prior);
    if (!process_identity) {
        state_->poisoned = true;
        return std::unexpected(storage_failure("session registry process identity is invalid"));
    }
    const auto filesystem_identity = *prior.filesystem_identity;
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto stopping_at_ms = prior.stopping_at_ms;

    wire::persisted_session record = prior;
    record.schema_version = 1;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_refinement_exited";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "exited";
    record.failure_code.clear();
    record.finished_at_ms = resource.finished_at_ms;
    record.receipt_started_at_ms = resource.started_at_ms;
    record.receipt_key_id = terminal.key_id;
    record.receipt_sequence = terminal.sequence;
    record.receipt_digest = terminal.receipt_digest;
    record.receipt_previous_hmac = terminal.previous_hmac;
    record.receipt_hmac = terminal.this_hmac;
    record.termination_cause = std::string{termination_name};
    record.exit_code = resource.exit_code;
    record.previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                   : state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_exited_record{
        .session = std::move(*appended),
        .profile_digest = resource.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = filesystem_identity,
        .finished_at_ms = resource.finished_at_ms,
        .receipt_key_id = terminal.key_id,
        .receipt_sequence = terminal.sequence,
        .receipt_digest = terminal.receipt_digest,
        .receipt_hmac = terminal.this_hmac,
        .termination_cause = resource.termination_cause,
        .exit_code = resource.exit_code,
        .refinement_receipt = true,
    };
}

auto session_registry::mark_failed(
    const session_failure_commitment& failure_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_failed_record> {
    const auto failure_name = failure_code_name(failure_commitment.code);
    const auto parsed_failure = failure_code_from_wire(failure_name);
    if (failure_commitment.schema_version != 1 ||
        !valid_identifier(failure_commitment.session_id) ||
        !valid_digest(failure_commitment.controller_plan_digest) ||
        !valid_digest(failure_commitment.plan_content_digest) ||
        !valid_identifier(failure_commitment.authorization_id) ||
        !valid_digest(failure_commitment.profile_digest) || !valid_identifier(idempotency_key) ||
        now_ms == 0 || !parsed_failure || *parsed_failure != failure_commitment.code) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session failure commitment"
        ));
    }
    auto request_digest = hash_failure_commitment(failure_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_failure_replay_locked(*state_, failure_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(failure_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting" && prior.state != "running" && prior.state != "stopping") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the failed transition"
        ));
    }
    if (prior.session_id != failure_commitment.session_id ||
        prior.controller_plan_digest != failure_commitment.controller_plan_digest ||
        prior.plan_content_digest != failure_commitment.plan_content_digest ||
        prior.authorization_id != failure_commitment.authorization_id ||
        prior.launch_profile_digest != failure_commitment.profile_digest ||
        now_ms < (prior.state == "stopping"
                      ? prior.stopping_at_ms
                      : (prior.state == "running" ? prior.running_at_ms : prior.starting_at_ms)) ||
        ((prior.state == "running" || prior.state == "stopping") &&
         failure_commitment.code != session_failure_code::supervisor_error &&
         failure_commitment.code != session_failure_code::recovered_without_process &&
         failure_commitment.code != session_failure_code::recovered_terminated)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "failure commitment does not match the durable starting session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto stopping_at_ms = prior.stopping_at_ms;
    auto process_identity = process_identity_from_wire(prior);
    if ((prior.state == "running" || prior.state == "stopping") && !process_identity) {
        state_->poisoned = true;
        return std::unexpected(storage_failure("session registry process identity is invalid"));
    }
    const auto cgroup_identity = prior.cgroup_identity;
    const auto filesystem_identity = prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_failed",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "failed",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = prior.stopping_at_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = std::string{failure_name},
        .finished_at_ms = now_ms,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_failed_record{
        .session = std::move(*appended),
        .profile_digest = failure_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = stopping_at_ms,
        .process_identity = std::move(process_identity),
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .failed_at_ms = now_ms,
        .code = failure_commitment.code,
    };
}

auto session_registry::failed_status(std::string_view session_id) const
    -> session_registry_result<session_failed_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return failed_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_managed_starting(
    const managed_session_execution_binding& binding,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (binding.schema_version != 1 || !valid_identifier(binding.session_id) ||
        !valid_digest(binding.controller_plan_digest) ||
        !valid_digest(binding.plan_content_digest) || !valid_identifier(binding.authorization_id) ||
        !valid_digest(binding.profile_digest) ||
        !valid_managed_runtime_identity(binding.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session execution commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            binding.session_id, binding.controller_plan_digest, binding.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed execution commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_managed_execution_binding(binding);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_starting" ||
            record.session_id != binding.session_id ||
            record.controller_plan_digest != binding.controller_plan_digest ||
            record.plan_content_digest != binding.plan_content_digest ||
            record.authorization_id != binding.authorization_id ||
            record.launch_profile_digest != binding.profile_digest ||
            record.managed_runtime_identity != binding.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed starting idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(binding.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "preparing" || prior.session_id != binding.session_id ||
        prior.controller_plan_digest != binding.controller_plan_digest ||
        prior.plan_content_digest != binding.plan_content_digest ||
        prior.authorization_id != binding.authorization_id ||
        prior.authorization_expires_at_ms <= now_ms || prior.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed execution commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible for managed start"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_managed_starting",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "starting",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = binding.runtime_identity,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_running(
    const managed_session_running_commitment& running,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (running.schema_version != 1 || !valid_identifier(running.session_id) ||
        !valid_digest(running.controller_plan_digest) ||
        !valid_digest(running.plan_content_digest) || !valid_identifier(running.authorization_id) ||
        !valid_digest(running.profile_digest) ||
        !valid_managed_runtime_identity(running.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session running commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            running.session_id, running.controller_plan_digest, running.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed running commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest =
        hash_managed_running_commitment(running, "glove.managed-session-running-commitment");
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_running" || record.session_id != running.session_id ||
            record.controller_plan_digest != running.controller_plan_digest ||
            record.plan_content_digest != running.plan_content_digest ||
            record.authorization_id != running.authorization_id ||
            record.launch_profile_digest != running.profile_digest ||
            record.managed_runtime_identity != running.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed running idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(running.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting" || prior.session_id != running.session_id ||
        prior.controller_plan_digest != running.controller_plan_digest ||
        prior.plan_content_digest != running.plan_content_digest ||
        prior.authorization_id != running.authorization_id ||
        prior.launch_profile_digest != running.profile_digest ||
        prior.managed_runtime_identity != running.runtime_identity ||
        now_ms < prior.starting_at_ms || now_ms >= prior.authorization_expires_at_ms ||
        now_ms >= prior.expires_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed running commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible before managed child release"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_running";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "running";
    record.running_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_stopping(
    const managed_session_running_commitment& running,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (running.schema_version != 1 || !valid_identifier(running.session_id) ||
        !valid_digest(running.controller_plan_digest) ||
        !valid_digest(running.plan_content_digest) || !valid_identifier(running.authorization_id) ||
        !valid_digest(running.profile_digest) ||
        !valid_managed_runtime_identity(running.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session stopping commitment"
        ));
    }
    auto request_digest =
        hash_managed_running_commitment(running, "glove.managed-session-stopping-commitment");
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_stopping" ||
            record.session_id != running.session_id ||
            record.controller_plan_digest != running.controller_plan_digest ||
            record.plan_content_digest != running.plan_content_digest ||
            record.authorization_id != running.authorization_id ||
            record.launch_profile_digest != running.profile_digest ||
            record.managed_runtime_identity != running.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed stopping idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(running.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "running" || prior.session_id != running.session_id ||
        prior.controller_plan_digest != running.controller_plan_digest ||
        prior.plan_content_digest != running.plan_content_digest ||
        prior.authorization_id != running.authorization_id ||
        prior.launch_profile_digest != running.profile_digest ||
        prior.managed_runtime_identity != running.runtime_identity ||
        now_ms < prior.running_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed stopping commitment does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_stopping";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "stopping";
    record.stopping_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_exited(
    const container::authenticated_resource_enforcement_receipt& terminal,
    const container::receipt_audit_producer& receipt_producer,
    std::string_view idempotency_key
) -> session_registry_result<managed_session_exited_record> {
    const auto termination_name = termination_cause_name(terminal.receipt.termination_cause);
    auto receipt_digest = container::resource_enforcement_receipt_digest(terminal.receipt);
    if (terminal.schema_version != 1 || terminal.sequence == 0 || !valid_digest(terminal.key_id) ||
        !valid_identifier(terminal.session_id) || !valid_digest(terminal.controller_plan_digest) ||
        terminal.receipt.schema_version != 1 || !valid_digest(terminal.receipt.profile_digest) ||
        !valid_digest(terminal.receipt_digest) || !valid_digest(terminal.previous_hmac) ||
        !valid_digest(terminal.this_hmac) || termination_name.empty() ||
        terminal.receipt.started_at_ms == 0 ||
        terminal.receipt.finished_at_ms < terminal.receipt.started_at_ms ||
        !valid_identifier(idempotency_key) || !receipt_digest ||
        *receipt_digest != terminal.receipt_digest) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid authenticated managed session terminal envelope"
        ));
    }
    auto confirmed = receipt_producer.confirms_terminal(terminal);
    if (!confirmed) {
        return std::unexpected(storage_failure(confirmed.error()));
    }
    if (!*confirmed) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed terminal envelope is not durable in the receipt journal"
        ));
    }
    auto request_digest = hash_terminal_envelope(terminal);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_exited" || record.session_id != terminal.session_id ||
            record.controller_plan_digest != terminal.controller_plan_digest ||
            record.launch_profile_digest != terminal.receipt.profile_digest ||
            record.receipt_sequence != terminal.sequence ||
            record.receipt_digest != terminal.receipt_digest ||
            record.receipt_hmac != terminal.this_hmac || record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed terminal idempotency payload changed"
            ));
        }
        return managed_exited_from_wire(record);
    }
    const auto existing = state_->sessions.find(terminal.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if ((prior.state != "running" && prior.state != "stopping") ||
        !prior.managed_runtime_identity || prior.session_id != terminal.session_id ||
        prior.controller_plan_digest != terminal.controller_plan_digest ||
        prior.launch_profile_digest != terminal.receipt.profile_digest ||
        terminal.receipt.started_at_ms > prior.running_at_ms ||
        terminal.receipt.finished_at_ms <
            (prior.state == "stopping" ? prior.stopping_at_ms : prior.running_at_ms)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed terminal envelope does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_exited";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "exited";
    record.finished_at_ms = terminal.receipt.finished_at_ms;
    record.receipt_started_at_ms = terminal.receipt.started_at_ms;
    record.receipt_key_id = terminal.key_id;
    record.receipt_sequence = terminal.sequence;
    record.receipt_digest = terminal.receipt_digest;
    record.receipt_previous_hmac = terminal.previous_hmac;
    record.receipt_hmac = terminal.this_hmac;
    record.termination_cause = std::string{termination_name};
    record.exit_code = terminal.receipt.exit_code;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_exited_from_wire(state_->records.back());
}

auto session_registry::mark_managed_failed(
    const session_failure_commitment& failure_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_failed_record> {
    const auto failure_name = failure_code_name(failure_commitment.code);
    if (failure_commitment.schema_version != 1 ||
        !valid_identifier(failure_commitment.session_id) ||
        !valid_digest(failure_commitment.controller_plan_digest) ||
        !valid_digest(failure_commitment.plan_content_digest) ||
        !valid_identifier(failure_commitment.authorization_id) ||
        !valid_digest(failure_commitment.profile_digest) || !valid_identifier(idempotency_key) ||
        now_ms == 0 || !failure_code_from_wire(failure_name)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session failure commitment"
        ));
    }
    auto request_digest = hash_failure_commitment(failure_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_failed" ||
            record.session_id != failure_commitment.session_id ||
            record.controller_plan_digest != failure_commitment.controller_plan_digest ||
            record.plan_content_digest != failure_commitment.plan_content_digest ||
            record.authorization_id != failure_commitment.authorization_id ||
            record.launch_profile_digest != failure_commitment.profile_digest ||
            record.failure_code != failure_name || record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed failure idempotency payload changed"
            ));
        }
        return managed_failed_from_wire(record);
    }
    const auto existing = state_->sessions.find(failure_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if ((prior.state != "starting" && prior.state != "running" && prior.state != "stopping") ||
        !prior.managed_runtime_identity ||
        prior.controller_plan_digest != failure_commitment.controller_plan_digest ||
        prior.plan_content_digest != failure_commitment.plan_content_digest ||
        prior.authorization_id != failure_commitment.authorization_id ||
        prior.launch_profile_digest != failure_commitment.profile_digest ||
        now_ms < (prior.state == "stopping"
                      ? prior.stopping_at_ms
                      : (prior.state == "running" ? prior.running_at_ms : prior.starting_at_ms)) ||
        ((prior.state == "running" || prior.state == "stopping") &&
         failure_commitment.code != session_failure_code::supervisor_error &&
         failure_commitment.code != session_failure_code::recovered_without_process &&
         failure_commitment.code != session_failure_code::recovered_terminated)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed failure commitment does not match the durable session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_failed";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "failed";
    record.failure_code = std::string{failure_name};
    record.finished_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_failed_from_wire(state_->records.back());
}

auto session_registry::managed_lifecycle_status(std::string_view session_id) const
    -> session_registry_result<managed_session_lifecycle_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return managed_lifecycle_from_wire(state_->records[existing->second]);
}

auto session_registry::managed_recovery_candidates() const
    -> session_registry_result<std::vector<managed_session_lifecycle_record>> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    std::vector<managed_session_lifecycle_record> candidates;
    candidates.reserve(state_->sessions.size());
    for (const auto& [session_id, index] : state_->sessions) {
        const auto& record = state_->records[index];
        if ((record.state != "starting" && record.state != "running" &&
             record.state != "stopping") ||
            !record.managed_runtime_identity) {
            continue;
        }
        auto candidate = managed_lifecycle_from_wire(record);
        if (!candidate) {
            return std::unexpected(candidate.error());
        }
        candidates.push_back(std::move(*candidate));
    }
    std::ranges::sort(candidates, {}, [](const auto& candidate) -> std::string_view {
        return candidate.session.session_id;
    });
    return candidates;
}

auto session_registry::recovery_candidates() const
    -> session_registry_result<std::vector<session_recovery_record>> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    std::vector<session_recovery_record> candidates;
    candidates.reserve(state_->sessions.size());
    for (const auto& [session_id, index] : state_->sessions) {
        const auto& record = state_->records[index];
        if (record.state != "starting" && record.state != "running" && record.state != "stopping") {
            continue;
        }
        if (record.managed_runtime_identity) {
            continue;
        }
        candidates.push_back({
            .session = public_record(record),
            .authorization_id = record.authorization_id,
            .profile_digest = record.launch_profile_digest,
            .starting_at_ms = record.starting_at_ms,
            .running_at_ms = record.running_at_ms,
            .stopping_at_ms = record.stopping_at_ms,
            .process_identity = process_identity_from_wire(record),
            .cgroup_identity = record.cgroup_identity,
            .filesystem_identity = record.filesystem_identity,
            .requires_refinement_receipt = refinement_plan(record.canonical_plan_json),
        });
    }
    std::ranges::sort(candidates, {}, [](const auto& candidate) -> std::string_view {
        return candidate.session.session_id;
    });
    return candidates;
}

auto session_registry::canonical_plan(std::string_view session_id) const
    -> session_registry_result<std::string> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return state_->records[existing->second].canonical_plan_json;
}

auto session_registry::record_count() const -> std::uint64_t {
    const std::scoped_lock lock{state_->mutex};
    return static_cast<std::uint64_t>(state_->records.size());
}

auto session_registry::library_projections_available() const noexcept -> bool {
    return state_ && state_->library_bundles != nullptr;
}

} // namespace glove::control
