#include "glove/control/receipt_audit_protocol.hpp"

#include "glove/container/digest.hpp"

#include "receipt_audit_wire.hpp"

#if defined(__linux__)
#    include "linux_session_executor.hpp"
#endif

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace glove::control {

namespace wire {

struct rpc_request {
    std::string jsonrpc;
    std::string id;
    std::string method;
    glz::raw_json params;
};

struct rpc_params {
    std::uint8_t schema_version = 0;
    std::string bootstrap_secret;
    std::uint64_t deadline_ms = 0;
    std::optional<std::string> idempotency_key;
    glz::raw_json payload;
};

struct rpc_error {
    std::string code;
    std::string message;
};

struct rpc_response {
    std::string jsonrpc = "2.0";
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<rpc_error> error;
};

struct page_request {
    container::receipt_audit_anchor sage_anchor;
    std::size_t limit = 0;
};

struct page_result {
    std::uint8_t schema_version = 1;
    std::vector<container::authenticated_resource_enforcement_receipt> envelopes;
    bool has_more = false;
    container::receipt_audit_anchor local_anchor;
};

struct acknowledgement_request {
    container::receipt_audit_anchor anchor;
};

struct acknowledgement_result {
    std::uint8_t schema_version = 1;
    container::receipt_audit_anchor acknowledged_anchor;
};

struct create_session_request {
    std::string session_id;
    std::string controller_plan_digest;
    glz::raw_json plan;
};

struct session_status_request {
    std::string session_id;
};

struct start_session_request {
    session_start_authorization authorization;
};

struct stop_session_request {
    std::string session_id;
};

struct attach_request {
    std::string session_id;
    std::uint64_t cursor = 0;
    std::size_t max_bytes = 0;
};

struct transcript_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::uint64_t oldest_cursor = 0;
    std::uint64_t next_cursor = 0;
    bool truncated = false;
    bool eof = false;
    std::vector<std::uint8_t> bytes;
};

struct write_stdin_request {
    std::string session_id;
    std::vector<std::uint8_t> bytes;
};

struct resize_request {
    std::string session_id;
    std::uint16_t rows = 0;
    std::uint16_t columns = 0;
};

struct signal_request {
    std::string session_id;
    std::string signal;
};

struct detach_request {
    std::string session_id;
    std::uint64_t transcript_cursor = 0;
};

struct session_cursor_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::uint64_t transcript_cursor = 0;
};

struct session_mutation_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
};

struct session_record_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::optional<std::string> profile_digest;
};

struct receipt_audit_capabilities {
    std::uint8_t envelope_schema_version = 1;
    std::string algorithm = "hmac_sha256";
    std::string key_id;
};

struct session_control_capabilities {
    bool validate_plan = false;
    bool create_session = false;
    bool start_session = false;
    bool session_status = false;
    bool attach = false;
    bool resize = false;
    bool write_stdin = false;
    bool signal = false;
    bool detach = false;
    bool stop_session = false;
    bool cleanup_session = false;
};

struct resource_enforcement_capabilities {
    container::enforcement_mechanism cpu_time = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism memory = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism pids = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism wall_time = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism disk = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism terminal_output =
        container::enforcement_mechanism::unavailable;
    std::uint8_t receipt_schema_version = 0;
};

struct backend_capabilities {
    std::string backend;
    resource_enforcement_capabilities resource_enforcement;
};

struct supervisor_capabilities {
    std::uint8_t schema_version = 1;
    receipt_audit_capabilities receipt_audit;
    session_control_capabilities session_control;
    // Zero until Glove creates a private agent home and expands exact Sage
    // bundles into the selected harness's native discovery locations.
    std::uint8_t agent_runtime_adapter_schema_version = 0;
    std::vector<backend_capabilities> backends;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::size_t max_start_idempotency_namespace_bytes = 112U;
constexpr std::size_t max_idempotency_records = 1'024U;
constexpr std::size_t max_session_io_bytes = std::size_t{64} * 1024U;
constexpr std::uint16_t max_terminal_dimension = 4'096U;
// Fifteen maximum-sized 64 KiB journal envelopes plus the page wrapper fit in
// the 1 MiB control frame. A larger requested count is served across pages.
constexpr std::size_t max_envelopes_per_control_frame = 15U;

using wire::acknowledgement_request;
using wire::acknowledgement_result;
using wire::attach_request;
using wire::backend_capabilities;
using wire::create_session_request;
using wire::detach_request;
using wire::page_request;
using wire::page_result;
using wire::receipt_audit_capabilities;
using wire::resize_request;
using wire::rpc_error;
using wire::rpc_params;
using wire::rpc_request;
using wire::rpc_response;
using wire::session_cursor_result;
using wire::session_mutation_result;
using wire::session_record_result;
using wire::session_status_request;
using wire::signal_request;
using wire::start_session_request;
using wire::stop_session_request;
using wire::transcript_result;
using wire::write_stdin_request;

struct idempotency_record {
    container::receipt_audit_anchor anchor;
    std::string result_json;
};

struct session_mutation_record {
    std::string method;
    std::string payload_digest;
    std::string result_json;
};

auto valid_hex_secret(std::string_view value) noexcept -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_identifier(std::string_view value, std::size_t max_bytes = max_identifier_bytes) noexcept
    -> bool {
    return !value.empty() && value.size() <= max_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool {
    if (left.size() != right.size()) {
        return false;
    }
    std::uint32_t difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint32_t>(static_cast<unsigned char>(left[index])) ^
                      static_cast<std::uint32_t>(static_cast<unsigned char>(right[index]));
    }
    return difference == 0;
}

#if defined(__linux__)
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
#endif

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

auto error_response(std::string_view id, std::string code, std::string message)
    -> std::expected<std::string, std::string> {
    return encode_json(
        rpc_response{
            .id = std::string{id},
            .result = std::nullopt,
            .error = rpc_error{.code = std::move(code), .message = std::move(message)},
        }
    );
}

auto success_response(std::string_view id, std::string result_json)
    -> std::expected<std::string, std::string> {
    auto encoded = encode_json(
        rpc_response{
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

template<typename Value>
auto decode_strict(std::string_view input) -> std::expected<Value, std::string> {
    Value value{};
    if (const auto error = glz::read<strict_read_options>(value, input); error) {
        return std::unexpected(glz::format_error(error, input));
    }
    return value;
}

} // namespace

struct receipt_audit_protocol::implementation {
    std::string bootstrap_secret;
    std::string audit_key_id;
    std::shared_ptr<container::receipt_audit_producer> producer;
    std::optional<container::receipt_audit_producer_config> producer_config;
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator;
    std::shared_ptr<session_registry> sessions;
    std::shared_ptr<linux_detail::linux_session_runtime> session_runtime;
    std::mutex producer_mutex;
    std::mutex idempotency_mutex;
    std::unordered_map<std::string, idempotency_record> idempotency_records;
    std::mutex session_mutation_mutex;
    std::unordered_map<std::string, session_mutation_record> session_mutation_records;

    implementation() = default;
    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;
    implementation(implementation&&) = delete;
    auto operator=(implementation&&) -> implementation& = delete;

    ~implementation() { wipe(bootstrap_secret); }

    auto producer_after(const container::receipt_audit_anchor& sage_anchor)
        -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string> {
        const std::scoped_lock lock{producer_mutex};
        if (producer) {
            return producer;
        }
        if (!producer_config) {
            return std::unexpected(std::string{"receipt audit producer is unavailable"});
        }
        auto bootstrapped =
            container::receipt_audit_producer::bootstrap(*producer_config, sage_anchor);
        if (!bootstrapped) {
            return std::unexpected(bootstrapped.error());
        }
        producer = *bootstrapped;
        return producer;
    }

    auto initialized_producer()
        -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string> {
        const std::scoped_lock lock{producer_mutex};
        if (!producer) {
            return std::unexpected(
                std::string{"receipt audit paging must initialize the producer"}
            );
        }
        return producer;
    }
};

namespace {

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
#if defined(__linux__)
    if (state.session_runtime) {
        const auto capabilities = container::linux_detail::managed_session_capabilities();
        linux_enforcement = {
            .cpu_time = capabilities.cpu_time,
            .memory = capabilities.memory,
            .pids = capabilities.pids,
            .wall_time = capabilities.wall_time,
            .disk = capabilities.disk,
            .terminal_output = capabilities.terminal_output,
            .receipt_schema_version = capabilities.receipt_schema_version,
        };
    }
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
                    .start_session = state.session_runtime != nullptr,
                    .session_status = state.sessions != nullptr,
                    .attach = state.session_runtime != nullptr,
                    .resize = state.session_runtime != nullptr,
                    .write_stdin = state.session_runtime != nullptr,
                    .signal = state.session_runtime != nullptr,
                    .detach = state.session_runtime != nullptr,
                    .stop_session = state.session_runtime != nullptr,
                    .cleanup_session = state.session_runtime != nullptr,
                },
            .agent_runtime_adapter_schema_version = 0,
            .backends = {
                backend_capabilities{
                    .backend = "linux_production",
                    .resource_enforcement = linux_enforcement,
                },
                backend_capabilities{
                    .backend = "macos_experimental",
                    .resource_enforcement = {},
                },
            },
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto session_profile_digest(const session_registry& sessions, const session_record& record)
    -> std::expected<std::optional<std::string>, session_registry_error> {
    switch (record.state) {
    case session_state::created:
    case session_state::preparing:
        return std::nullopt;
    case session_state::starting: {
        auto status = sessions.starting_status(record.session_id);
        if (!status) {
            return std::unexpected(status.error());
        }
        return status->profile_digest;
    }
    case session_state::running: {
        auto status = sessions.running_status(record.session_id);
        if (!status) {
            return std::unexpected(status.error());
        }
        return status->profile_digest;
    }
    case session_state::stopping: {
        auto status = sessions.stopping_status(record.session_id);
        if (!status) {
            return std::unexpected(status.error());
        }
        return status->profile_digest;
    }
    case session_state::exited: {
        auto status = sessions.exited_status(record.session_id);
        if (!status) {
            return std::unexpected(status.error());
        }
        return status->profile_digest;
    }
    case session_state::failed: {
        auto status = sessions.failed_status(record.session_id);
        if (!status) {
            return std::unexpected(status.error());
        }
        return status->profile_digest;
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
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    static_cast<void>(now_ms);
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_stop_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_attach(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

#if defined(__linux__)
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
#endif

auto handle_write_stdin(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
    std::string bytes;
    bytes.reserve(payload->bytes.size());
    for (const auto byte : payload->bytes) {
        bytes.push_back(static_cast<char>(byte));
    }
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_resize(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_signal(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
    std::optional<container::linux_detail::pty_session_signal> requested;
    if (payload->signal == "interrupt") {
        requested = container::linux_detail::pty_session_signal::interrupt;
    } else if (payload->signal == "terminate") {
        requested = container::linux_detail::pty_session_signal::terminate;
    } else if (payload->signal == "hangup") {
        requested = container::linux_detail::pty_session_signal::hangup;
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_detach(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
}

auto handle_cleanup_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (!state.session_runtime) {
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
#if defined(__linux__)
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
#else
    return error_response(request_id, "method_not_found", "control method is unavailable");
#endif
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
#if defined(__linux__)
    if (state.session_runtime && (*producer)->bootstrap_reconciled()) {
        if (auto reconciled = state.session_runtime->reconcile(**producer, now_ms); !reconciled) {
            return error_response(
                request_id,
                "session_reconciliation_failed",
                "supervisor session recovery did not complete"
            );
        }
    }
#else
    static_cast<void>(now_ms);
#endif
    auto page = (*producer)->page_after(payload->sage_anchor, effective_limit);
    if (!page) {
        return error_response(
            request_id, "audit_reconciliation_failed", "receipt audit page rejected"
        );
    }
    auto result = encode_json(
        page_result{
            .envelopes = std::move(page->envelopes),
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
#if defined(__linux__)
    if (state.session_runtime) {
        if (auto reconciled = state.session_runtime->reconcile(**producer, now_ms); !reconciled) {
            return error_response(
                request_id,
                "session_reconciliation_failed",
                "supervisor session recovery did not complete"
            );
        }
    }
#else
    static_cast<void>(now_ms);
#endif
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

} // namespace

receipt_audit_protocol::receipt_audit_protocol(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

receipt_audit_protocol::~receipt_audit_protocol() = default;

auto receipt_audit_protocol::create(
    std::string_view bootstrap_secret_hex,
    std::shared_ptr<container::receipt_audit_producer> producer,
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator,
    std::shared_ptr<session_registry> sessions,
    std::shared_ptr<linux_detail::linux_session_runtime> session_runtime
) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string> {
#if !defined(__linux__)
    if (session_runtime) {
        return std::unexpected(std::string{"receipt audit protocol runtime is unsupported"});
    }
#endif
    if (!valid_hex_secret(bootstrap_secret_hex) || !producer || (sessions && !plan_validator) ||
        (session_runtime && (!sessions || !plan_validator))) {
        return std::unexpected(std::string{"receipt audit protocol configuration is invalid"});
    }
    auto state = std::make_unique<implementation>();
    state->bootstrap_secret = bootstrap_secret_hex;
    state->audit_key_id = producer->anchor().key_id;
    state->producer = std::move(producer);
    state->plan_validator = std::move(plan_validator);
    state->sessions = std::move(sessions);
    state->session_runtime = std::move(session_runtime);
    return std::make_unique<receipt_audit_protocol>(construction_token{}, std::move(state));
}

auto receipt_audit_protocol::create(
    std::string_view bootstrap_secret_hex,
    container::receipt_audit_producer_config producer_config,
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator,
    std::shared_ptr<session_registry> sessions,
    std::shared_ptr<linux_detail::linux_session_runtime> session_runtime
) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string> {
#if !defined(__linux__)
    if (session_runtime) {
        return std::unexpected(std::string{"receipt audit protocol runtime is unsupported"});
    }
#endif
    if (!valid_hex_secret(bootstrap_secret_hex) || producer_config.key_path.empty() ||
        producer_config.journal_path.empty() || (sessions && !plan_validator) ||
        (session_runtime && (!sessions || !plan_validator))) {
        return std::unexpected(std::string{"receipt audit protocol configuration is invalid"});
    }
    auto audit_key_id = container::receipt_audit_producer::audit_key_id(producer_config);
    if (!audit_key_id) {
        return std::unexpected(std::string{"receipt audit protocol key is unavailable"});
    }
    auto state = std::make_unique<implementation>();
    state->bootstrap_secret = bootstrap_secret_hex;
    state->audit_key_id = std::move(*audit_key_id);
    state->producer_config = std::move(producer_config);
    state->plan_validator = std::move(plan_validator);
    state->sessions = std::move(sessions);
    state->session_runtime = std::move(session_runtime);
    return std::make_unique<receipt_audit_protocol>(construction_token{}, std::move(state));
}

auto receipt_audit_protocol::handle_frame(std::string_view frame, std::uint64_t now_ms)
    -> std::expected<std::string, std::string> {
    if (frame.empty() || frame.size() > max_control_frame_bytes) {
        return error_response("", "invalid_request", "invalid control frame size");
    }
    auto request = decode_strict<rpc_request>(frame);
    if (!request) {
        return error_response("", "invalid_request", "invalid JSON-RPC request");
    }
    if (request->jsonrpc != "2.0" || !valid_identifier(request->id) ||
        !valid_identifier(request->method)) {
        return error_response(request->id, "invalid_request", "invalid JSON-RPC envelope");
    }
    auto params = decode_strict<rpc_params>(request->params.str);
    if (!params) {
        return error_response(request->id, "invalid_request", "invalid method parameters");
    }
    if (!constant_time_equal(params->bootstrap_secret, state_->bootstrap_secret)) {
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

    if (request->method == "capabilities") {
        return handle_capabilities(*state_, request->id, *params);
    }

    if (request->method == "validate_plan") {
        return handle_validate_plan(*state_, request->id, *params, now_ms);
    }

    if (request->method == "create_session") {
        return handle_create_session(*state_, request->id, *params, now_ms);
    }

    if (request->method == "start_session") {
        return handle_start_session(*state_, request->id, *params, now_ms);
    }

    if (request->method == "session_status") {
        return handle_session_status(*state_, request->id, *params);
    }

    if (request->method == "attach") {
        return handle_attach(*state_, request->id, *params);
    }

    if (request->method == "write_stdin") {
        return handle_write_stdin(*state_, request->id, *params);
    }

    if (request->method == "resize") {
        return handle_resize(*state_, request->id, *params);
    }

    if (request->method == "signal") {
        return handle_signal(*state_, request->id, *params);
    }

    if (request->method == "detach") {
        return handle_detach(*state_, request->id, *params);
    }

    if (request->method == "stop_session") {
        return handle_stop_session(*state_, request->id, *params);
    }

    if (request->method == "cleanup_session") {
        return handle_cleanup_session(*state_, request->id, *params);
    }

    if (request->method == "verify_audit_chain") {
        return handle_page(*state_, request->id, *params, now_ms);
    }

    if (request->method == "acknowledge_audit_chain") {
        return handle_acknowledgement(*state_, request->id, *params, now_ms);
    }

    return error_response(request->id, "method_not_found", "control method is unavailable");
}

} // namespace glove::control
