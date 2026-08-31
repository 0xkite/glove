#include "session_registry_recovery.hpp"

namespace glove::control {

// Recovery compares a frozen intent/disposition record against the session
// record it was bound to. Lifecycle progression mutates `state` and
// `running_at_ms`, and policy revisions may advance without changing the
// session's durable identity, so those three fields are neutralized before
// the comparison. Everything else must still match exactly: any other
// mismatch is a genuine binding crossing, not lifecycle progression.
auto same_session_snapshot(wire::persisted_session left, wire::persisted_session right) -> bool {
    left.sequence = right.sequence = 0;
    left.operation = right.operation = {};
    left.idempotency_key = right.idempotency_key = {};
    left.request_digest = right.request_digest = {};
    left.previous_hash = right.previous_hash = {};
    left.this_hash = right.this_hash = {};
    left.state = right.state = {};
    left.running_at_ms = right.running_at_ms = 0;
    left.policy_revision = right.policy_revision = 0;
    left.observation_intent = right.observation_intent = std::nullopt;
    return left == right;
}

namespace {

auto same_observation_intent_binding(
    wire::persisted_observation_intent left, wire::persisted_observation_intent right
) -> bool {
    left.disposition = right.disposition = {};
    left.decided_at_ms = right.decided_at_ms = 0;
    return left == right;
}

} // namespace

auto initialize_empty(session_registry::implementation& state) -> std::expected<void, std::string> {
    auto written = write_at(state.opened.file.get(), registry_magic, 0);
    if (!written) {
        return written;
    }
    if (auto synced = sync_descriptor(state.opened.file.get(), "sync session registry"); !synced) {
        return synced;
    }
    return sync_descriptor(state.opened.parent.get(), "sync session registry directory");
}

auto read_persisted_record(int descriptor, std::uint64_t file_size, std::uint64_t offset)
    -> std::expected<decoded_persisted_record, std::string> {
    if (file_size - offset < 8U) {
        return std::unexpected(std::string{"session registry record boundary is invalid"});
    }
    std::array<unsigned char, 4> prefix{};
    if (auto read = read_at(descriptor, std::span{prefix}, offset); !read) {
        return std::unexpected(read.error());
    }
    const auto payload_size = static_cast<std::uint64_t>(decode_u32(prefix));
    if (payload_size == 0 || payload_size > max_record_payload_bytes ||
        payload_size > file_size - offset - 8U) {
        return std::unexpected(std::string{"session registry record length is invalid"});
    }
    std::string payload(static_cast<std::size_t>(payload_size), '\0');
    if (auto read =
            read_at(descriptor, std::span<char>{payload.data(), payload.size()}, offset + 4U);
        !read) {
        return std::unexpected(read.error());
    }
    std::array<unsigned char, 4> suffix{};
    if (auto read = read_at(descriptor, std::span{suffix}, offset + 4U + payload_size); !read) {
        return std::unexpected(read.error());
    }
    if (decode_u32(suffix) != payload_size) {
        return std::unexpected(std::string{"session registry record footer mismatch"});
    }
    auto record = decode_record(payload);
    if (!record) {
        return std::unexpected(record.error());
    }
    return decoded_persisted_record{
        .record = std::move(*record),
        .next_offset = offset + payload_size + 8U,
    };
}

auto accept_recovered_record(
    session_registry::implementation& state,
    wire::persisted_session record,
    std::string_view previous_hash
) -> std::expected<void, std::string> {
    const auto sequence = static_cast<std::uint64_t>(state.records.size()) + 1U;
    if (!valid_record_shape(record, sequence) || record.previous_hash != previous_hash ||
        state.requests.contains(record.idempotency_key)) {
        return std::unexpected(std::string{"session registry record is invalid"});
    }
    auto plan_digest = hash_plan(record.canonical_plan_json);
    auto record_hash = hash_record(record);
    if (!plan_digest || !record_hash || *plan_digest != record.plan_content_digest ||
        *record_hash != record.this_hash) {
        return std::unexpected(std::string{"session registry content commitment mismatch"});
    }
    const auto existing = state.sessions.find(record.session_id);
    const bool enqueue_intent = record.operation == "enqueue_observation_intent_v1";
    const bool set_intent_disposition = record.operation == "set_observation_intent_disposition_v1";
    std::string observation_key;
    std::optional<observation_quarantine_reason> quarantine_reason;
    bool quarantined_disposition = false;
    if (enqueue_intent || set_intent_disposition) {
        if (existing == state.sessions.end() || !record.observation_intent) {
            return std::unexpected(std::string{"session registry observation intent is orphaned"});
        }
        const auto& current_session = state.records[existing->second];
        if (!same_session_snapshot(record, current_session)) {
            return std::unexpected(
                std::string{"session registry observation intent crossed its session binding"}
            );
        }
        const auto body = observation_body_from_wire(*record.observation_intent);
        const auto context = observation_context_from_wire(record, *record.observation_intent);
        auto body_digest = hash_observation_intent_body(body);
        observation_key = observation_intent_key(
            record.session_id,
            record.observation_intent->channel_generation,
            record.observation_intent->intent_id
        );
        if (!body_digest || *body_digest != record.observation_intent->intent_digest) {
            return std::unexpected(
                std::string{"session registry observation body commitment mismatch"}
            );
        }
        if (enqueue_intent) {
            auto request_digest = hash_observation_intent_request(body, context);
            wire::plan_runtime_header runtime;
            const auto runtime_error =
                glz::read<partial_read_options>(runtime, current_session.canonical_plan_json);
            if (!request_digest || *request_digest != record.request_digest ||
                record.idempotency_key != "intent-enqueue:" + record.request_digest ||
                state.observation_intents.contains(observation_key) ||
                state.quarantined_observation_intents.contains(observation_key) ||
                current_session.state != "running" || runtime_error ||
                runtime.runtime_id != record.observation_intent->runtime_id ||
                record.observation_intent->profile_digest !=
                    current_session.launch_profile_digest ||
                record.observation_intent->issued_at_ms < current_session.running_at_ms) {
                return std::unexpected(
                    std::string{"session registry observation enqueue commitment mismatch"}
                );
            }
            quarantine_reason = historical_observation_quarantine_reason(
                state.channels.get(),
                body,
                record.observation_intent->expires_at_ms - record.observation_intent->issued_at_ms
            );
        } else {
            const auto enqueued = state.observation_intents.find(observation_key);
            const auto quarantined = state.quarantined_observation_intents.find(observation_key);
            const bool active_original = enqueued != state.observation_intents.end();
            const bool quarantined_original =
                quarantined != state.quarantined_observation_intents.end();
            if (active_original == quarantined_original ||
                state.observation_dispositions.contains(observation_key) ||
                (quarantined_original && quarantined->second.disposition_index.has_value())) {
                return std::unexpected(
                    std::string{"session registry observation disposition is orphaned"}
                );
            }
            quarantined_disposition = quarantined_original;
            const auto original_index =
                active_original ? enqueued->second : quarantined->second.enqueue_index;
            const auto& original = state.records[original_index];
            if (!original.observation_intent ||
                !same_observation_intent_binding(
                    *record.observation_intent, *original.observation_intent
                )) {
                return std::unexpected(
                    std::string{"session registry observation disposition crossed its binding"}
                );
            }
            const auto disposition =
                intent_disposition_from_wire(record.observation_intent->disposition);
            const observation_intent_disposition update{
                .session_id = record.session_id,
                .channel_generation = record.observation_intent->channel_generation,
                .intent_id = record.observation_intent->intent_id,
                .intent_digest = record.observation_intent->intent_digest,
                .disposition = disposition.value_or(intent_disposition::pending),
                .decided_at_ms = record.observation_intent->decided_at_ms,
            };
            auto request_digest = hash_observation_intent_disposition(update);
            if (!disposition || *disposition == intent_disposition::pending || !request_digest ||
                *request_digest != record.request_digest ||
                record.idempotency_key != "intent-disposition:" + record.request_digest) {
                return std::unexpected(
                    std::string{"session registry observation disposition commitment mismatch"}
                );
            }
        }
    } else if (record.state == "created") {
        if (existing != state.sessions.end()) {
            return std::unexpected(std::string{"session registry create transition is invalid"});
        }
    } else if (record.state == "preparing") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry start transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "created" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.canonical_plan_json != record.canonical_plan_json ||
            record.authorized_at_ms < record.created_at_ms) {
            return std::unexpected(std::string{"session registry start transition is invalid"});
        }
        const session_start_authorization authorization{
            .schema_version = record.schema_version,
            .authorization_id = record.authorization_id,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .plan_content_digest = record.plan_content_digest,
            .approved_at_ms = record.authorized_at_ms,
            .expires_at_ms = record.authorization_expires_at_ms,
        };
        auto authorization_digest = hash_start_authorization(authorization);
        if (!authorization_digest || *authorization_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry start authorization commitment mismatch"}
            );
        }
    } else if (record.state == "starting") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry starting transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "preparing" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry starting transition is invalid"});
        }
        std::expected<std::string, std::string> binding_digest =
            std::unexpected(std::string{"unknown starting operation"});
        if (record.operation == "mark_managed_starting" && record.managed_runtime_identity) {
            binding_digest = hash_managed_execution_binding(
                managed_session_execution_binding{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .runtime_identity = *record.managed_runtime_identity,
                }
            );
        } else if (
            record.operation == "mark_starting" && record.cgroup_identity &&
            record.filesystem_identity
        ) {
            binding_digest = hash_execution_binding(
                session_execution_binding{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .cgroup_identity = *record.cgroup_identity,
                    .filesystem_identity = *record.filesystem_identity,
                }
            );
        }
        if (!binding_digest || *binding_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry execution binding commitment mismatch"}
            );
        }
    } else if (record.state == "running") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry running transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "starting" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry running transition is invalid"});
        }
        std::expected<std::string, std::string> running_digest =
            std::unexpected(std::string{"unknown running operation"});
        if (record.operation == "mark_managed_running" && record.managed_runtime_identity) {
            running_digest = hash_managed_running_commitment(
                managed_session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .runtime_identity = *record.managed_runtime_identity,
                },
                "glove.managed-session-running-commitment"
            );
        } else if (record.operation == "mark_running" && record.filesystem_identity) {
            auto process_identity = process_identity_from_wire(record);
            if (process_identity) {
                running_digest = hash_running_commitment(
                    session_running_commitment{
                        .schema_version = record.schema_version,
                        .session_id = record.session_id,
                        .controller_plan_digest = record.controller_plan_digest,
                        .plan_content_digest = record.plan_content_digest,
                        .authorization_id = record.authorization_id,
                        .profile_digest = record.launch_profile_digest,
                        .process_identity = std::move(*process_identity),
                        .filesystem_identity = *record.filesystem_identity,
                    }
                );
            }
        }
        if (!running_digest || *running_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry running commitment mismatch"});
        }
    } else if (record.state == "stopping") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry stopping transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "running" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms || !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry stopping transition is invalid"});
        }
        std::expected<std::string, std::string> stopping_digest =
            std::unexpected(std::string{"unknown stopping operation"});
        if (record.operation == "mark_managed_stopping" && record.managed_runtime_identity) {
            stopping_digest = hash_managed_running_commitment(
                managed_session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .runtime_identity = *record.managed_runtime_identity,
                },
                "glove.managed-session-stopping-commitment"
            );
        } else if (record.operation == "mark_stopping" && record.filesystem_identity) {
            auto process_identity = process_identity_from_wire(record);
            if (process_identity) {
                stopping_digest = hash_stopping_commitment(
                    session_running_commitment{
                        .schema_version = record.schema_version,
                        .session_id = record.session_id,
                        .controller_plan_digest = record.controller_plan_digest,
                        .plan_content_digest = record.plan_content_digest,
                        .authorization_id = record.authorization_id,
                        .profile_digest = record.launch_profile_digest,
                        .process_identity = std::move(*process_identity),
                        .filesystem_identity = *record.filesystem_identity,
                    }
                );
            }
        }
        if (!stopping_digest || *stopping_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry stopping commitment mismatch"});
        }
    } else if (record.state == "exited") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry exit transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if ((prior.state != "running" && prior.state != "stopping") ||
            prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms ||
            prior.stopping_at_ms != record.stopping_at_ms ||
            !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry exit transition is invalid"});
        }
        const auto termination = termination_cause_from_wire(record.termination_cause);
        if (!termination) {
            return std::unexpected(std::string{"session registry terminal cause is invalid"});
        }
        const terminal_reference terminal{
            .schema_version = 1,
            .sequence = record.receipt_sequence,
            .key_id = record.receipt_key_id,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .profile_digest = record.launch_profile_digest,
            .receipt_digest = record.receipt_digest,
            .previous_hmac = record.receipt_previous_hmac,
            .this_hmac = record.receipt_hmac,
            .termination_cause = *termination,
            .started_at_ms = record.receipt_started_at_ms,
            .finished_at_ms = record.finished_at_ms,
            .exit_code = record.exit_code,
        };
        auto terminal_digest = hash_terminal_reference(terminal);
        if (!terminal_digest || *terminal_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry terminal envelope commitment mismatch"}
            );
        }
    } else {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry failure transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if ((prior.state != "starting" && prior.state != "running" && prior.state != "stopping") ||
            prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms ||
            prior.stopping_at_ms != record.stopping_at_ms ||
            !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry failure transition is invalid"});
        }
        const auto code = failure_code_from_wire(record.failure_code);
        if (!code) {
            return std::unexpected(std::string{"session registry failure code is invalid"});
        }
        const session_failure_commitment failure{
            .schema_version = record.schema_version,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .plan_content_digest = record.plan_content_digest,
            .authorization_id = record.authorization_id,
            .profile_digest = record.launch_profile_digest,
            .code = *code,
        };
        auto failure_digest = hash_failure_commitment(failure);
        if (!failure_digest || *failure_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry failure commitment mismatch"});
        }
    }
    const auto index = state.records.size();
    if (enqueue_intent) {
        if (quarantine_reason) {
            state.quarantined_observation_intents.emplace(
                observation_key,
                quarantined_observation_state{
                    .enqueue_index = index,
                    .disposition_index = std::nullopt,
                    .reason = *quarantine_reason,
                }
            );
        } else {
            state.observation_intents.emplace(observation_key, index);
        }
    } else if (set_intent_disposition) {
        if (quarantined_disposition) {
            state.quarantined_observation_intents.at(observation_key).disposition_index = index;
        } else {
            state.observation_dispositions.emplace(observation_key, index);
        }
    } else {
        state.sessions.insert_or_assign(record.session_id, index);
    }
    state.requests.emplace(record.idempotency_key, index);
    state.records.push_back(std::move(record));
    return {};
}

auto recover(session_registry::implementation& state) -> std::expected<void, std::string> {
    auto size = inspect_file(state.opened.file.get());
    if (!size || *size < registry_magic.size() || *size > state.max_bytes) {
        return std::unexpected(std::string{"session registry size is invalid"});
    }
    std::array<unsigned char, registry_magic.size()> header{};
    if (auto read = read_at(state.opened.file.get(), std::span{header}, 0); !read) {
        return read;
    }
    if (header != registry_magic) {
        return std::unexpected(std::string{"session registry header mismatch"});
    }

    std::uint64_t offset = registry_magic.size();
    std::string previous_hash(digest_hex_bytes, '0');
    while (offset < *size) {
        if (state.records.size() >= max_records) {
            return std::unexpected(std::string{"session registry record capacity is invalid"});
        }
        auto decoded = read_persisted_record(state.opened.file.get(), *size, offset);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        const auto next_hash = decoded->record.this_hash;
        if (auto accepted =
                accept_recovered_record(state, std::move(decoded->record), previous_hash);
            !accepted) {
            return accepted;
        }
        previous_hash = next_hash;
        offset = decoded->next_offset;
    }
    state.durable_bytes = offset;
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != state.durable_bytes) {
        return std::unexpected(std::string{"session registry identity changed during recovery"});
    }
    state.identity = *identity;
    return {};
}

auto verify_identity(session_registry::implementation& state) -> bool {
    auto identity = capture_identity(state.opened.file.get());

    struct stat path_metadata{};

    const auto path_result = ::fstatat(
        state.opened.parent.get(), state.opened.name.c_str(), &path_metadata, AT_SYMLINK_NOFOLLOW
    );
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto path_permissions =
        static_cast<unsigned int>(path_metadata.st_mode) & permission_mask;
    const bool path_matches =
        path_result == 0 && S_ISREG(path_metadata.st_mode) && path_metadata.st_uid == ::geteuid() &&
        path_permissions == owner_permissions && path_metadata.st_nlink == 1 && identity &&
        static_cast<std::uint64_t>(path_metadata.st_dev) == identity->device &&
        static_cast<std::uint64_t>(path_metadata.st_ino) == identity->inode;
    if (!path_matches || *identity != state.identity || identity->size != state.durable_bytes) {
        state.poisoned = true;
        return false;
    }
    return true;
}

auto rollback_append(session_registry::implementation& state, std::uint64_t original_size) -> bool {
    while (::ftruncate(state.opened.file.get(), static_cast<off_t>(original_size)) != 0) {
        if (errno == EINTR) {
            continue;
        }
        state.poisoned = true;
        return false;
    }
    if (!sync_descriptor(state.opened.file.get(), "sync session registry rollback")) {
        state.poisoned = true;
        return false;
    }
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != original_size) {
        state.poisoned = true;
        return false;
    }
    state.identity = *identity;
    return true;
}

} // namespace glove::control
