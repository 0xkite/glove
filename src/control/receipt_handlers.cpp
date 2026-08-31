#include "receipt_handlers.hpp"

#include "receipt_audit_wire.hpp"

#if defined(__linux__)
#    include "glove/control/local_service_proxy.hpp"
#endif

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::control {

receipt_audit_protocol::implementation::~implementation() {
    receipt_handlers::wipe(bootstrap_secret);
}

auto receipt_audit_protocol::implementation::producer_after(
    const container::receipt_audit_anchor& sage_anchor
) -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string> {
    const std::scoped_lock lock{producer_mutex};
    if (producer) {
        return producer;
    }
    if (!producer_config) {
        return std::unexpected(std::string{"receipt audit producer is unavailable"});
    }
    auto bootstrapped = container::receipt_audit_producer::bootstrap(*producer_config, sage_anchor);
    if (!bootstrapped) {
        return std::unexpected(bootstrapped.error());
    }
    producer = *bootstrapped;
    return producer;
}

auto receipt_audit_protocol::implementation::initialized_producer()
    -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string> {
    const std::scoped_lock lock{producer_mutex};
    if (!producer) {
        return std::unexpected(std::string{"receipt audit paging must initialize the producer"});
    }
    return producer;
}

namespace receipt_handlers {
namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

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

auto constant_time_equal(std::string_view left, std::string_view right) -> bool {
    const std::size_t maximum = std::max(left.size(), right.size());
    std::uint32_t difference = static_cast<std::uint32_t>(left.size() ^ right.size());
    for (std::size_t index = 0; index < maximum; ++index) {
        const char left_byte = index < left.size() ? left[index] : 0;
        const char right_byte = index < right.size() ? right[index] : 0;
        difference |= static_cast<std::uint32_t>(static_cast<unsigned char>(left_byte)) ^
                      static_cast<std::uint32_t>(static_cast<unsigned char>(right_byte));
    }
    return difference == 0;
}

} // namespace

auto valid_identifier(std::string_view value, std::size_t max_bytes) noexcept -> bool {
    return !value.empty() && value.size() <= max_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

void wipe(std::string& value) noexcept {
    if (value.empty()) {
        return;
    }
    volatile char* bytes = value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

auto error_response(std::string_view id, std::string code, std::string message)
    -> std::expected<std::string, std::string> {
    return wire::encode_rpc_response(
        wire::rpc_response{
            .id = std::string{id},
            .result = std::nullopt,
            .error = wire::rpc_error{.code = std::move(code), .message = std::move(message)},
        }
    );
}

auto success_response(std::string_view id, std::string result_json)
    -> std::expected<std::string, std::string> {
    auto encoded = wire::encode_rpc_response(
        wire::rpc_response{
            .id = std::string{id},
            .result = glz::raw_json{std::move(result_json)},
            .error = std::nullopt,
        }
    );
    if (!encoded) {
        return encoded;
    }
    if (encoded->size() > max_control_frame_bytes) {
        return error_response(
            id, "response_too_large", "receipt audit response exceeds the control frame"
        );
    }
    return encoded;
}

using wire::acknowledgement_request;
using wire::acknowledgement_result;
using wire::backend_capabilities;
using wire::page_request;
using wire::page_result;
using wire::receipt_audit_capabilities;
using wire::rpc_params;

auto handle_capabilities(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (params.idempotency_key.has_value() || params.payload.str != "null") {
        return error_response(
            request_id, "invalid_request", "capabilities requires a null read-only payload"
        );
    }
    wire::resource_enforcement_capabilities linux_enforcement;
    wire::resource_enforcement_capabilities apple_enforcement;
    const bool lifecycle_operational = state.runtime && state.runtime->lifecycle_operational();
    if (lifecycle_operational) {
        const auto capabilities = state.runtime->resource_capabilities();
        wire::resource_enforcement_capabilities advertised{
            .cpu_time = capabilities.cpu_time,
            .memory = capabilities.memory,
            .pids = capabilities.pids,
            .wall_time = capabilities.wall_time,
            .disk = capabilities.disk,
            .terminal_output = capabilities.terminal_output,
            .receipt_schema_version = capabilities.receipt_schema_version,
        };
        if (state.runtime->backend_id() == "linux_production") {
            linux_enforcement = advertised;
        } else if (state.runtime->backend_id() == "apple_container") {
            apple_enforcement = advertised;
        }
    }
#if defined(__linux__)
    const auto retained_write_schema_version =
        lifecycle_operational && state.runtime->backend_id() == "linux_production" &&
                state.path_exposures
            ? std::uint8_t{1}
            : std::uint8_t{0};
#else
    constexpr std::uint8_t retained_write_schema_version = 0;
#endif
    auto result = encode_json(
        wire::supervisor_capabilities{
            .schema_version = 1,
            .receipt_audit =
                receipt_audit_capabilities{
                    .envelope_schema_version = 1,
                    .algorithm = "hmac_sha256",
                    .key_id = state.audit_key_id,
                },
            .session_control =
                wire::session_control_capabilities{
                    .validate_plan = state.plan_validator != nullptr,
                    .create_session = state.sessions != nullptr,
                    .start_session = lifecycle_operational,
                    .session_status = state.sessions != nullptr,
                    .attach = lifecycle_operational,
                    .resize = lifecycle_operational,
                    .write_stdin = lifecycle_operational,
                    .signal = lifecycle_operational,
                    .detach = lifecycle_operational,
                    .stop_session = lifecycle_operational,
                    .cleanup_session = lifecycle_operational,
                },
            // Managed sessions own a fresh private harness home and
            // derive its native skills from verified Sage library bundles.
            .agent_runtime_adapter_schema_version =
                lifecycle_operational ? state.runtime->agent_runtime_adapter_schema_version()
                                      : std::uint8_t{0},
            .managed_runtime_ids = lifecycle_operational ? state.runtime->managed_runtime_ids()
                                                         : std::vector<std::string>{},
            .path_exposure_admin_schema_version =
                state.path_exposures ? std::uint8_t{1} : std::uint8_t{0},
            .path_exposure_catalog_schema_version =
                state.path_exposures ? std::uint8_t{1} : std::uint8_t{0},
            .retained_write_schema_version = retained_write_schema_version,
            .change_manifest_schema_version = retained_write_schema_version,
            .change_apply_authorization_schema_version = 0,
            .refinement_evaluation_protocol_schema_version =
                lifecycle_operational
                    ? state.runtime->refinement_evaluation_protocol_schema_version()
                    : std::uint8_t{0},
#if defined(__linux__)
            .observation_intent_channel_schema_version =
                state.local_services && state.local_services->operational_for(
                                            state.runtime.get(), state.sessions.get()
                                        )
                    ? std::uint8_t{1}
                    : std::uint8_t{0},
#else
            .observation_intent_channel_schema_version = 0,
#endif
            .backends = {
                backend_capabilities{
                    .backend = "linux_production",
                    .resource_enforcement = linux_enforcement,
                },
                backend_capabilities{
                    .backend = "apple_container",
                    .resource_enforcement = apple_enforcement,
                },
            },
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_health(std::string_view request_id, const rpc_params& params)
    -> std::expected<std::string, std::string> {
    if (params.idempotency_key.has_value() || params.payload.str != "null") {
        return error_response(
            request_id, "invalid_request", "health requires a null read-only payload"
        );
    }
    auto result = encode_json(wire::supervisor_health{});
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_validate_plan(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.plan_validator) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value()) {
        return error_response(
            request_id, "invalid_request", "read-only plan validation forbids idempotency keys"
        );
    }
    auto validation = state.plan_validator->validate_json(params.payload.str, now_ms);
    if (!validation) {
        return error_response(request_id, "invalid_plan", "session plan was rejected");
    }
    auto result = encode_json(*validation);
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_page(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (params.idempotency_key.has_value()) {
        return error_response(
            request_id, "invalid_request", "read-only audit paging forbids idempotency keys"
        );
    }
    auto payload = decode_strict<page_request>(params.payload.str);
    if (!payload || payload->limit == 0 || payload->limit > 1'000U) {
        return error_response(request_id, "invalid_request", "invalid receipt audit page request");
    }
    const auto effective_limit = std::min(payload->limit, max_envelopes_per_control_frame);
    auto producer = state.producer_after(payload->sage_anchor);
    if (!producer) {
        return error_response(
            request_id, "audit_reconciliation_failed", "receipt audit producer bootstrap failed"
        );
    }
    if (state.runtime && state.runtime->lifecycle_operational() &&
        (*producer)->bootstrap_reconciled()) {
        if (auto reconciled = state.runtime->reconcile(**producer, now_ms); !reconciled) {
            return error_response(
                request_id,
                "session_reconciliation_failed",
                "supervisor session recovery did not complete"
            );
        }
    }
    auto page = (*producer)->page_after(payload->sage_anchor, effective_limit);
    if (!page) {
        return error_response(
            request_id, "audit_reconciliation_failed", "receipt audit page rejected"
        );
    }
    auto result = encode_json(
        page_result{
            .envelopes = std::move(page->envelopes),
            .refinement_envelopes = std::move(page->refinement_envelopes),
            .has_more = page->has_more,
            .local_anchor = std::move(page->local_anchor),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_acknowledgement(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(
            request_id, "invalid_request", "audit acknowledgement requires idempotency"
        );
    }
    auto payload = decode_strict<acknowledgement_request>(params.payload.str);
    if (!payload) {
        return error_response(
            request_id, "invalid_request", "invalid receipt audit acknowledgement"
        );
    }
    auto producer = state.initialized_producer();
    if (!producer) {
        return error_response(
            request_id, "audit_reconciliation_failed", "receipt audit paging is required"
        );
    }
    const std::scoped_lock lock{state.idempotency_mutex};
    if (const auto existing = state.idempotency_records.find(idempotency_key);
        existing != state.idempotency_records.end()) {
        if (existing->second.anchor != payload->anchor) {
            return error_response(
                request_id, "idempotency_conflict", "idempotency payload changed"
            );
        }
        return success_response(request_id, existing->second.result_json);
    }
    if (state.idempotency_records.size() >= max_idempotency_records) {
        return error_response(
            request_id, "idempotency_capacity", "idempotency capacity is unavailable"
        );
    }
    if (auto acknowledged = (*producer)->acknowledge_bootstrap(payload->anchor); !acknowledged) {
        return error_response(
            request_id, "audit_reconciliation_failed", "receipt audit head was not accepted"
        );
    }
    if (state.runtime && state.runtime->lifecycle_operational()) {
        if (auto reconciled = state.runtime->reconcile(**producer, now_ms); !reconciled) {
            return error_response(
                request_id,
                "session_reconciliation_failed",
                "supervisor session recovery did not complete"
            );
        }
    }
    auto result = encode_json(
        acknowledgement_result{
            .acknowledged_anchor = payload->anchor,
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    state.idempotency_records.emplace(
        idempotency_key, idempotency_record{.anchor = payload->anchor, .result_json = *result}
    );
    return success_response(request_id, std::move(*result));
}

auto handle_frame(
    receipt_audit_protocol::implementation& state,
    std::string_view frame,
    std::uint64_t now_ms,
    receipt_control_outcome* outcome
) -> std::expected<std::string, std::string> {
    if (outcome != nullptr) {
        *outcome = receipt_control_outcome{};
    }
    if (frame.empty() || frame.size() > max_control_frame_bytes) {
        return error_response("", "invalid_request", "invalid control frame size");
    }
    auto request = wire::decode_rpc_request(frame);
    if (!request) {
        return error_response("", "invalid_request", "invalid JSON-RPC request");
    }
    if (request->jsonrpc != "2.0" || !valid_identifier(request->id) ||
        !valid_identifier(request->method)) {
        return error_response(request->id, "invalid_request", "invalid JSON-RPC envelope");
    }
    if (outcome != nullptr) {
        outcome->method = request->method;
    }
    auto params = wire::decode_rpc_params(request->params.str);
    if (!params) {
        return error_response(request->id, "invalid_request", "invalid method parameters");
    }
    if (!constant_time_equal(params->bootstrap_secret, state.bootstrap_secret)) {
        wipe(params->bootstrap_secret);
        return error_response(request->id, "unauthorized", "supervisor authentication failed");
    }
    wipe(params->bootstrap_secret);
    if (params->schema_version != 1) {
        return error_response(request->id, "unsupported_schema", "unsupported control schema");
    }
    if (params->deadline_ms == 0 || params->deadline_ms < now_ms) {
        return error_response(request->id, "deadline_exceeded", "request deadline elapsed");
    }
    // From here the request is authenticated: degradation may rely on the
    // outcome metadata but never on a re-decode of the raw frame.
    if (outcome != nullptr) {
        outcome->authenticated = true;
    }

    if (request->method == "health") {
        return handle_health(request->id, *params);
    }

    if (request->method == "capabilities") {
        return handle_capabilities(state, request->id, *params);
    }

    if (request->method == "validate_plan") {
        return handle_validate_plan(state, request->id, *params, now_ms);
    }

    if (request->method == "create_path_exposure") {
        return handle_create_path_exposure(state, request->id, *params, now_ms);
    }

    if (request->method == "list_path_exposures") {
        return handle_list_path_exposures(state, request->id, *params, now_ms);
    }

    if (request->method == "revoke_path_exposure") {
        return handle_revoke_path_exposure(state, request->id, *params, now_ms);
    }

    if (request->method == "inspect_retained_changes") {
        return handle_inspect_retained_changes(state, request->id, *params);
    }

    if (request->method == "create_session") {
        return handle_create_session(state, request->id, *params, now_ms);
    }

    if (request->method == "start_session") {
        return handle_start_session(state, request->id, *params, now_ms, outcome);
    }

    if (request->method == "session_status") {
        return handle_session_status(state, request->id, *params);
    }

    if (request->method == "attach") {
        return handle_attach(state, request->id, *params);
    }

    if (request->method == "write_stdin") {
        return handle_write_stdin(state, request->id, *params);
    }

    if (request->method == "resize") {
        return handle_resize(state, request->id, *params);
    }

    if (request->method == "signal") {
        return handle_signal(state, request->id, *params);
    }

    if (request->method == "detach") {
        return handle_detach(state, request->id, *params);
    }

    if (request->method == "stop_session") {
        return handle_stop_session(state, request->id, *params);
    }

    if (request->method == "cleanup_session") {
        return handle_cleanup_session(state, request->id, *params);
    }

    if (request->method == "verify_audit_chain") {
        return handle_page(state, request->id, *params, now_ms);
    }

    if (request->method == "acknowledge_audit_chain") {
        return handle_acknowledgement(state, request->id, *params, now_ms);
    }

    if (request->method == "page_observation_intents") {
        return handle_page_observation_intents(state, request->id, *params, now_ms);
    }

    if (request->method == "set_observation_intent_disposition") {
        return handle_set_observation_intent_disposition(state, request->id, *params, now_ms);
    }

    return error_response(request->id, "method_not_found", "control method is unavailable");
}

} // namespace receipt_handlers
} // namespace glove::control
