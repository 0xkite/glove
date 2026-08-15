#pragma once

#include "glove/control/receipt_audit_protocol.hpp"

#include "receipt_wire.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace glove::control::receipt_handlers {

inline constexpr std::size_t max_identifier_bytes = 128U;
inline constexpr std::size_t max_start_idempotency_namespace_bytes = 112U;
inline constexpr std::size_t max_idempotency_records = 1'024U;
inline constexpr std::size_t max_session_io_bytes = std::size_t{64} * 1024U;
inline constexpr std::uint16_t max_terminal_dimension = 4'096U;
inline constexpr std::size_t max_envelopes_per_control_frame = 15U;

struct idempotency_record {
    container::receipt_audit_anchor anchor;
    std::string result_json;
};

struct session_mutation_record {
    std::string method;
    std::string payload_digest;
    std::string result_json;
};

void wipe(std::string& value) noexcept;

} // namespace glove::control::receipt_handlers

namespace glove::control {

struct receipt_audit_protocol::implementation {
    std::string bootstrap_secret;
    std::string audit_key_id;
    std::shared_ptr<container::receipt_audit_producer> producer;
    std::optional<container::receipt_audit_producer_config> producer_config;
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator;
    std::shared_ptr<session_registry> sessions;
    std::shared_ptr<session_runtime> session_runtime;
    std::shared_ptr<supervisor::path_exposure_registry> path_exposures;
    std::string materialization_root;
    std::mutex producer_mutex;
    std::mutex idempotency_mutex;
    std::unordered_map<std::string, receipt_handlers::idempotency_record> idempotency_records;
    std::mutex session_mutation_mutex;
    std::unordered_map<std::string, receipt_handlers::session_mutation_record>
        session_mutation_records;

    implementation() = default;
    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;
    implementation(implementation&&) = delete;
    auto operator=(implementation&&) -> implementation& = delete;
    ~implementation();

    [[nodiscard]] auto producer_after(const container::receipt_audit_anchor& sage_anchor)
        -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string>;
    [[nodiscard]] auto initialized_producer()
        -> std::expected<std::shared_ptr<container::receipt_audit_producer>, std::string>;
};

namespace receipt_handlers {

[[nodiscard]] auto
valid_identifier(std::string_view value, std::size_t max_bytes = max_identifier_bytes) noexcept
    -> bool;
[[nodiscard]] auto error_response(std::string_view id, std::string code, std::string message)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto success_response(std::string_view id, std::string result_json)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto handle_capabilities(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_health(std::string_view request_id, const wire::rpc_params& params)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_create_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_session_status(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_start_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_stop_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_attach(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_write_stdin(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_resize(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_signal(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_detach(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_cleanup_session(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_create_path_exposure(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_list_path_exposures(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_revoke_path_exposure(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_inspect_retained_changes(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_validate_plan(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_page(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;
[[nodiscard]] auto handle_acknowledgement(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const wire::rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string>;

[[nodiscard]] auto handle_frame(
    receipt_audit_protocol::implementation& state, std::string_view frame, std::uint64_t now_ms
) -> std::expected<std::string, std::string>;

} // namespace receipt_handlers
} // namespace glove::control
