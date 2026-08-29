#include "glove/container/digest.hpp"

#include "receipt_audit_wire.hpp"
#include "receipt_handlers.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::control::receipt_handlers {
namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr glz::opts strict_complete_read_options{
    .error_on_unknown_keys = true,
    .error_on_missing_keys = true,
};

template<typename Value>
auto encode_json(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded) {
        return std::unexpected(
            std::string{"control response encode: "} +
            glz::format_error(encoded.error(), std::string{})
        );
    }
    return std::move(*encoded);
}

template<typename Value>
auto decode_strict(std::string_view input) -> std::expected<Value, std::string> {
    Value value{};
    if (const auto error = glz::read<strict_read_options>(value, input); error) {
        return std::unexpected(glz::format_error(error, input));
    }
    return value;
}

template<typename Value>
auto decode_strict_complete(std::string_view input) -> std::expected<Value, std::string> {
    Value value{};
    if (const auto error = glz::read<strict_complete_read_options>(value, input); error) {
        return std::unexpected(glz::format_error(error, input));
    }
    return value;
}

auto mutation_payload_digest(std::string_view method, std::string_view payload)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(method.size() + 1U + payload.size());
    for (const char byte : method) {
        material.push_back(static_cast<unsigned char>(byte));
    }
    material.push_back(0);
    for (const char byte : payload) {
        material.push_back(static_cast<unsigned char>(byte));
    }
    return container::sha256_hex(std::span<const unsigned char>{material});
}

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

} // namespace

using wire::attach_request;
using wire::create_session_request;
using wire::detach_request;
using wire::observation_intent_disposition_result;
using wire::observation_intent_queue_item_wire;
using wire::page_observation_intents_request;
using wire::page_observation_intents_result;
using wire::resize_request;
using wire::rpc_params;
using wire::session_cursor_result;
using wire::session_mutation_result;
using wire::session_record_result;
using wire::session_status_request;
using wire::set_observation_intent_disposition_request;
using wire::signal_request;
using wire::start_session_request;
using wire::stop_session_request;
using wire::transcript_result;
using wire::write_stdin_request;

auto session_profile_digest(const session_registry& sessions, const session_record& record)
    -> std::expected<std::optional<std::string>, session_registry_error> {
    switch (record.state) {
    case session_state::created:
    case session_state::preparing:
        return std::nullopt;
    case session_state::starting: {
        auto status = sessions.starting_status(record.session_id);
        if (status) {
            return status->profile_digest;
        }
        auto managed = sessions.managed_lifecycle_status(record.session_id);
        return managed ? std::expected<
                             std::optional<std::string>,
                             session_registry_error>{managed->profile_digest}
                       : std::unexpected(managed.error());
    }
    case session_state::running: {
        auto status = sessions.running_status(record.session_id);
        if (status) {
            return status->profile_digest;
        }
        auto managed = sessions.managed_lifecycle_status(record.session_id);
        return managed ? std::expected<
                             std::optional<std::string>,
                             session_registry_error>{managed->profile_digest}
                       : std::unexpected(managed.error());
    }
    case session_state::stopping: {
        auto status = sessions.stopping_status(record.session_id);
        if (status) {
            return status->profile_digest;
        }
        auto managed = sessions.managed_lifecycle_status(record.session_id);
        return managed ? std::expected<
                             std::optional<std::string>,
                             session_registry_error>{managed->profile_digest}
                       : std::unexpected(managed.error());
    }
    case session_state::exited: {
        auto status = sessions.exited_status(record.session_id);
        if (status) {
            return status->profile_digest;
        }
        auto managed = sessions.managed_lifecycle_status(record.session_id);
        return managed ? std::expected<
                             std::optional<std::string>,
                             session_registry_error>{managed->profile_digest}
                       : std::unexpected(managed.error());
    }
    case session_state::failed: {
        auto status = sessions.failed_status(record.session_id);
        if (status) {
            return status->profile_digest;
        }
        auto managed = sessions.managed_lifecycle_status(record.session_id);
        return managed ? std::expected<
                             std::optional<std::string>,
                             session_registry_error>{managed->profile_digest}
                       : std::unexpected(managed.error());
    }
    }
    return std::unexpected(
        session_registry_error{
            .code = session_registry_error_code::invalid_state,
            .message = "unknown session state",
        }
    );
}

auto session_result(const session_registry& sessions, const session_record& record)
    -> std::expected<session_record_result, session_registry_error> {
    auto profile_digest = session_profile_digest(sessions, record);
    if (!profile_digest) {
        return std::unexpected(profile_digest.error());
    }
    std::string state;
    switch (record.state) {
    case session_state::created:
        state = "created";
        break;
    case session_state::preparing:
        state = "preparing";
        break;
    case session_state::starting:
        state = "starting";
        break;
    case session_state::running:
        state = "running";
        break;
    case session_state::stopping:
        state = "stopping";
        break;
    case session_state::exited:
        state = "exited";
        break;
    case session_state::failed:
        state = "failed";
        break;
    }
    return session_record_result{
        .schema_version = record.schema_version,
        .session_id = record.session_id,
        .controller_plan_digest = record.controller_plan_digest,
        .plan_content_digest = record.plan_content_digest,
        .state = state,
        .policy_revision = record.policy_revision,
        .expires_at_ms = record.expires_at_ms,
        .created_at_ms = record.created_at_ms,
        .profile_digest = std::move(*profile_digest),
    };
}

auto registry_error_response(std::string_view request_id, const session_registry_error& error)
    -> std::expected<std::string, std::string> {
    switch (error.code) {
    case session_registry_error_code::invalid_request:
        return error_response(request_id, "invalid_request", "invalid session request");
    case session_registry_error_code::invalid_plan:
        return error_response(request_id, "invalid_plan", "session plan was rejected");
    case session_registry_error_code::invalid_authorization:
        return error_response(
            request_id, "invalid_authorization", "session authorization was rejected"
        );
    case session_registry_error_code::invalid_state:
        return error_response(request_id, "invalid_session_state", "session state was rejected");
    case session_registry_error_code::idempotency_conflict:
        return error_response(request_id, "idempotency_conflict", "idempotency payload changed");
    case session_registry_error_code::session_conflict:
        return error_response(request_id, "session_conflict", "session identity already exists");
    case session_registry_error_code::not_found:
        return error_response(request_id, "session_not_found", "session was not found");
    case session_registry_error_code::capacity:
        return error_response(request_id, "session_capacity", "session capacity is unavailable");
    case session_registry_error_code::storage:
        return error_response(request_id, "session_storage_failed", "session storage failed");
    }
    return error_response(request_id, "session_storage_failed", "session storage failed");
}

auto observation_disposition_from_wire(std::string_view value)
    -> std::optional<intent_disposition> {
    if (value == "accepted") {
        return intent_disposition::accepted;
    }
    if (value == "rejected") {
        return intent_disposition::rejected;
    }
    if (value == "expired") {
        return intent_disposition::expired;
    }
    return std::nullopt;
}

auto observation_disposition_wire_name(intent_disposition disposition) -> std::string {
    switch (disposition) {
    case intent_disposition::pending:
        return "pending";
    case intent_disposition::accepted:
        return "accepted";
    case intent_disposition::rejected:
        return "rejected";
    case intent_disposition::expired:
        return "expired";
    }
    return {};
}

auto observation_item_wire(const observation_intent_item& item)
    -> observation_intent_queue_item_wire {
    return observation_intent_queue_item_wire{
        .sequence = item.sequence,
        .body =
            {
                .schema = item.body.schema,
                .intent_id = item.body.intent_id,
                .observation = item.body.observation,
                .value_digest = item.body.value_digest,
                .item_count = item.body.item_count,
            },
        .context =
            {
                .session_id = item.context.session_id,
                .controller_plan_digest = item.context.controller_plan_digest,
                .profile_digest = item.context.profile_digest,
                .runtime_id = item.context.runtime_id,
                .projection_digest = item.context.projection_digest,
                .policy_revision = item.context.policy_revision,
                .channel_id = item.context.channel_id,
                .channel_generation = item.context.channel_generation,
                .issued_at_ms = item.context.issued_at_ms,
                .expires_at_ms = item.context.expires_at_ms,
            },
        .intent_digest = item.intent_digest,
        .disposition = observation_disposition_wire_name(item.disposition),
        .decided_at_ms = item.decided_at_ms,
    };
}

auto observation_registry_error_response(
    std::string_view request_id, const session_registry_error& error
) -> std::expected<std::string, std::string> {
    switch (error.code) {
    case session_registry_error_code::invalid_request:
        return error_response(
            request_id, "invalid_request", "invalid observation intent request"
        );
    case session_registry_error_code::idempotency_conflict:
        return error_response(request_id, "idempotency_conflict", "idempotency payload changed");
    case session_registry_error_code::invalid_state:
        return error_response(
            request_id, "invalid_observation_intent_state", "observation intent state was rejected"
        );
    case session_registry_error_code::not_found:
        return error_response(
            request_id, "observation_intent_not_found", "observation intent was not found"
        );
    case session_registry_error_code::capacity:
        return error_response(
            request_id, "observation_intent_capacity", "observation intent capacity is unavailable"
        );
    case session_registry_error_code::invalid_plan:
    case session_registry_error_code::invalid_authorization:
    case session_registry_error_code::session_conflict:
    case session_registry_error_code::storage:
        break;
    }
    return error_response(
        request_id, "observation_intent_storage_failed", "observation intent storage failed"
    );
}

auto handle_page_observation_intents(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.sessions) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value()) {
        return error_response(
            request_id,
            "invalid_request",
            "read-only observation intent paging forbids idempotency keys"
        );
    }
    auto payload = decode_strict_complete<page_observation_intents_request>(params.payload.str);
    if (!payload || payload->limit == 0 || payload->limit > max_pending_intent_page_size) {
        return error_response(
            request_id, "invalid_request", "invalid observation intent page request"
        );
    }
    auto page = state.sessions->pending_observation_intents(
        payload->after_sequence, payload->limit, now_ms
    );
    if (!page) {
        return observation_registry_error_response(request_id, page.error());
    }
    page_observation_intents_result result{
        .schema_version = 1,
        .items = {},
        .next_after_sequence = std::nullopt,
    };
    result.items.reserve(page->items.size());
    for (const auto& item : page->items) {
        result.items.push_back(observation_item_wire(item));
    }
    result.next_after_sequence = page->next_after_sequence;
    auto encoded = encode_json(result);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return success_response(request_id, std::move(*encoded));
}

auto handle_set_observation_intent_disposition(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.sessions) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(
            request_id, "invalid_request", "observation intent disposition requires idempotency"
        );
    }
    auto payload =
        decode_strict_complete<set_observation_intent_disposition_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id) || payload->channel_generation == 0 ||
        !valid_identifier(payload->intent_id) || !valid_digest(payload->intent_digest)) {
        return error_response(
            request_id, "invalid_request", "invalid observation intent disposition request"
        );
    }
    const auto disposition = observation_disposition_from_wire(payload->disposition);
    if (!disposition) {
        return error_response(
            request_id, "invalid_request", "invalid observation intent disposition request"
        );
    }
    auto payload_digest =
        mutation_payload_digest("set_observation_intent_disposition", params.payload.str);
    if (!payload_digest) {
        return error_response(
            request_id,
            "observation_intent_control_failed",
            "observation intent disposition could not be authorized"
        );
    }
    const std::scoped_lock lock{state.session_mutation_mutex};
    if (const auto existing = state.session_mutation_records.find(std::string{idempotency_key});
        existing != state.session_mutation_records.end()) {
        if (existing->second.method != "set_observation_intent_disposition" ||
            existing->second.payload_digest != *payload_digest) {
            return error_response(
                request_id, "idempotency_conflict", "idempotency payload changed"
            );
        }
        return success_response(request_id, existing->second.result_json);
    }
    if (state.session_mutation_records.size() >= max_idempotency_records) {
        return error_response(
            request_id, "idempotency_capacity", "idempotency capacity is unavailable"
        );
    }
    const observation_intent_disposition registry_disposition{
        .session_id = payload->session_id,
        .channel_generation = payload->channel_generation,
        .intent_id = payload->intent_id,
        .intent_digest = payload->intent_digest,
        .disposition = *disposition,
        .decided_at_ms = now_ms,
    };
    auto updated = state.sessions->set_observation_intent_disposition(registry_disposition);
    if (!updated) {
        return observation_registry_error_response(request_id, updated.error());
    }
    auto encoded = encode_json(
        observation_intent_disposition_result{
            .schema_version = 1,
            .item = observation_item_wire(*updated),
        }
    );
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    state.session_mutation_records.emplace(
        std::string{idempotency_key},
        session_mutation_record{
            .method = "set_observation_intent_disposition",
            .payload_digest = std::move(*payload_digest),
            .result_json = *encoded,
        }
    );
    return success_response(request_id, std::move(*encoded));
}

auto handle_create_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.sessions) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(
            request_id, "invalid_request", "session creation requires idempotency"
        );
    }
    auto payload = decode_strict<create_session_request>(params.payload.str);
    if (!payload) {
        return error_response(request_id, "invalid_request", "invalid session create request");
    }
    auto created = state.sessions->create(
        payload->session_id,
        payload->controller_plan_digest,
        payload->plan.str,
        idempotency_key,
        now_ms
    );
    if (!created) {
        return registry_error_response(request_id, created.error());
    }
    auto response = session_result(*state.sessions, *created);
    if (!response) {
        return registry_error_response(request_id, response.error());
    }
    auto result = encode_json(*response);
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_session_status(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.sessions) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value()) {
        return error_response(
            request_id, "invalid_request", "read-only session status forbids idempotency keys"
        );
    }
    auto payload = decode_strict<session_status_request>(params.payload.str);
    if (!payload) {
        return error_response(request_id, "invalid_request", "invalid session status request");
    }
    auto status = state.sessions->status(payload->session_id);
    if (!status) {
        return registry_error_response(request_id, status.error());
    }
    auto response = session_result(*state.sessions, *status);
    if (!response) {
        return registry_error_response(request_id, response.error());
    }
    auto result = encode_json(*response);
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_start_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key, max_start_idempotency_namespace_bytes)) {
        return error_response(request_id, "invalid_request", "session start requires idempotency");
    }
    auto payload = decode_strict<start_session_request>(params.payload.str);
    if (!payload) {
        return error_response(request_id, "invalid_request", "invalid session start request");
    }
    auto producer = state.initialized_producer();
    if (!producer) {
        return error_response(
            request_id,
            "audit_reconciliation_required",
            "receipt audit paging must initialize the producer"
        );
    }
    if (!(*producer)->bootstrap_reconciled()) {
        return error_response(
            request_id, "audit_reconciliation_required", "receipt audit acknowledgement is required"
        );
    }
    if (auto reconciled = state.session_runtime->reconcile(**producer, now_ms); !reconciled) {
        return error_response(
            request_id,
            "session_reconciliation_failed",
            "supervisor session recovery did not complete"
        );
    }
    auto started =
        state.session_runtime->start(**producer, payload->authorization, idempotency_key, now_ms);
    if (!started) {
        // The authenticated caller receives a stable, non-sensitive denial,
        // while the owner-local service journal retains the actionable host
        // failure needed to repair namespace, mount, or cgroup setup.
        std::fprintf(
            stderr,
            "gloved: managed session %s start failed: %s\n",
            payload->authorization.session_id.c_str(),
            started.error().c_str()
        );
        return error_response(request_id, "session_start_failed", "session start was rejected");
    }
    auto response = session_result(*state.sessions, *started);
    if (!response) {
        return registry_error_response(request_id, response.error());
    }
    auto result = encode_json(*response);
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_stop_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(request_id, "invalid_request", "session stop requires idempotency");
    }
    auto payload = decode_strict<stop_session_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id)) {
        return error_response(request_id, "invalid_request", "invalid session stop request");
    }
    if (auto stopped = state.session_runtime->stop(payload->session_id, idempotency_key);
        !stopped) {
        return error_response(request_id, "session_stop_failed", "session stop was rejected");
    }
    auto status = state.sessions->status(payload->session_id);
    if (!status) {
        return registry_error_response(request_id, status.error());
    }
    auto response = session_result(*state.sessions, *status);
    if (!response) {
        return registry_error_response(request_id, response.error());
    }
    auto result = encode_json(*response);
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_attach(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value()) {
        return error_response(
            request_id, "invalid_request", "read-only attach forbids idempotency keys"
        );
    }
    auto payload = decode_strict<attach_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id) || payload->max_bytes == 0 ||
        payload->max_bytes > max_session_io_bytes) {
        return error_response(request_id, "invalid_request", "invalid session attach request");
    }
    auto read =
        state.session_runtime->read(payload->session_id, payload->cursor, payload->max_bytes);
    if (!read) {
        return error_response(request_id, "session_attach_failed", "session attach was rejected");
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(read->bytes.size());
    for (const char byte : read->bytes) {
        bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(byte)));
    }
    auto result = encode_json(
        transcript_result{
            .session_id = std::move(payload->session_id),
            .oldest_cursor = read->oldest_cursor,
            .next_cursor = read->next_cursor,
            .truncated = read->truncated,
            .eof = read->eof,
            .bytes = std::move(bytes),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

template<typename Operation>
auto handle_idempotent_session_mutation(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    std::string_view method,
    std::string_view payload_json,
    std::string_view idempotency_key,
    std::string_view failure_code,
    std::string_view failure_message,
    std::string session_id,
    Operation&& operation
) -> std::expected<std::string, std::string> {
    auto payload_digest = mutation_payload_digest(method, payload_json);
    if (!payload_digest) {
        return error_response(
            request_id, "session_control_failed", "session mutation could not be authorized"
        );
    }
    const std::scoped_lock lock{state.session_mutation_mutex};
    if (const auto existing = state.session_mutation_records.find(std::string{idempotency_key});
        existing != state.session_mutation_records.end()) {
        if (existing->second.method != method ||
            existing->second.payload_digest != *payload_digest) {
            return error_response(
                request_id, "idempotency_conflict", "idempotency payload changed"
            );
        }
        return success_response(request_id, existing->second.result_json);
    }
    if (state.session_mutation_records.size() >= max_idempotency_records) {
        return error_response(
            request_id, "idempotency_capacity", "idempotency capacity is unavailable"
        );
    }
    if (auto mutated = operation(); !mutated) {
        return error_response(request_id, std::string{failure_code}, std::string{failure_message});
    }
    auto result = encode_json(session_mutation_result{.session_id = std::move(session_id)});
    if (!result) {
        return std::unexpected(result.error());
    }
    state.session_mutation_records.emplace(
        std::string{idempotency_key},
        session_mutation_record{
            .method = std::string{method},
            .payload_digest = std::move(*payload_digest),
            .result_json = *result,
        }
    );
    return success_response(request_id, std::move(*result));
}

auto handle_write_stdin(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(request_id, "invalid_request", "session input requires idempotency");
    }
    auto payload = decode_strict<write_stdin_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id) || payload->bytes.empty() ||
        payload->bytes.size() > max_session_io_bytes) {
        return error_response(request_id, "invalid_request", "invalid session input request");
    }
    const std::string bytes{payload->bytes.begin(), payload->bytes.end()};
    const auto session_id = payload->session_id;
    return handle_idempotent_session_mutation(
        state,
        request_id,
        "write_stdin",
        params.payload.str,
        idempotency_key,
        "session_input_failed",
        "session input was rejected",
        session_id,
        [&state, &session_id, &bytes] {
            return state.session_runtime->write_input(session_id, bytes);
        }
    );
}

auto handle_resize(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(request_id, "invalid_request", "session resize requires idempotency");
    }
    auto payload = decode_strict<resize_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id) || payload->rows == 0 ||
        payload->columns == 0 || payload->rows > max_terminal_dimension ||
        payload->columns > max_terminal_dimension) {
        return error_response(request_id, "invalid_request", "invalid session resize request");
    }
    const auto session_id = payload->session_id;
    const auto rows = payload->rows;
    const auto columns = payload->columns;
    return handle_idempotent_session_mutation(
        state,
        request_id,
        "resize",
        params.payload.str,
        idempotency_key,
        "session_resize_failed",
        "session resize was rejected",
        session_id,
        [&state, &session_id, rows, columns] {
            return state.session_runtime->resize(session_id, rows, columns);
        }
    );
}

auto handle_signal(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(request_id, "invalid_request", "session signal requires idempotency");
    }
    auto payload = decode_strict<signal_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id)) {
        return error_response(request_id, "invalid_request", "invalid session signal request");
    }
    std::optional<session_signal> requested;
    if (payload->signal == "interrupt") {
        requested = session_signal::interrupt;
    } else if (payload->signal == "terminate") {
        requested = session_signal::terminate;
    } else if (payload->signal == "hangup") {
        requested = session_signal::hangup;
    }
    if (!requested) {
        return error_response(request_id, "invalid_request", "invalid session signal request");
    }
    const auto session_id = payload->session_id;
    return handle_idempotent_session_mutation(
        state,
        request_id,
        "signal",
        params.payload.str,
        idempotency_key,
        "session_signal_failed",
        "session signal was rejected",
        session_id,
        [&state, &session_id, requested = *requested] {
            return state.session_runtime->signal(session_id, requested);
        }
    );
}

auto handle_detach(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(request_id, "invalid_request", "session detach requires idempotency");
    }
    auto payload = decode_strict<detach_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id)) {
        return error_response(request_id, "invalid_request", "invalid session detach request");
    }
    auto payload_digest = mutation_payload_digest("detach", params.payload.str);
    if (!payload_digest) {
        return error_response(
            request_id, "session_control_failed", "session mutation could not be authorized"
        );
    }
    const std::scoped_lock lock{state.session_mutation_mutex};
    if (const auto existing = state.session_mutation_records.find(idempotency_key);
        existing != state.session_mutation_records.end()) {
        if (existing->second.method != "detach" ||
            existing->second.payload_digest != *payload_digest) {
            return error_response(
                request_id, "idempotency_conflict", "idempotency payload changed"
            );
        }
        return success_response(request_id, existing->second.result_json);
    }
    if (state.session_mutation_records.size() >= max_idempotency_records) {
        return error_response(
            request_id, "idempotency_capacity", "idempotency capacity is unavailable"
        );
    }
    if (auto cursor =
            state.session_runtime->read(payload->session_id, payload->transcript_cursor, 1);
        !cursor) {
        return error_response(request_id, "session_detach_failed", "session detach was rejected");
    }
    auto result = encode_json(
        session_cursor_result{
            .session_id = payload->session_id,
            .transcript_cursor = payload->transcript_cursor,
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    state.session_mutation_records.emplace(
        idempotency_key,
        session_mutation_record{
            .method = "detach",
            .payload_digest = std::move(*payload_digest),
            .result_json = *result,
        }
    );
    return success_response(request_id, std::move(*result));
}

auto handle_cleanup_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime || !state.session_runtime->lifecycle_operational()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(
            request_id, "invalid_request", "session cleanup requires idempotency"
        );
    }
    auto payload = decode_strict<session_status_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id)) {
        return error_response(request_id, "invalid_request", "invalid session cleanup request");
    }
    const auto session_id = payload->session_id;
    return handle_idempotent_session_mutation(
        state,
        request_id,
        "cleanup_session",
        params.payload.str,
        idempotency_key,
        "session_cleanup_failed",
        "session cleanup was rejected",
        session_id,
        [&state, &session_id] { return state.session_runtime->cleanup(session_id); }
    );
}

} // namespace glove::control::receipt_handlers
