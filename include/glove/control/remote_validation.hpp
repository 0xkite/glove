#pragma once

#include "remote_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace glove::control {

inline constexpr std::size_t max_remote_validation_output_bytes = std::size_t{64U} * 1024U;
inline constexpr std::size_t max_remote_validation_read_bytes = std::size_t{16U} * 1024U;

struct remote_operation_binding {
    std::string session_id;
    // Owner-generated 128-bit epoch encoded as exactly 32 lowercase hex bytes.
    std::string session_epoch;
    std::string descriptor_digest;
    std::string idempotency_key;
    std::string payload_digest;

    auto operator==(const remote_operation_binding&) const -> bool = default;
};

struct remote_prepare_payload {
    remote_operation_binding binding;
    auto operator==(const remote_prepare_payload&) const -> bool = default;
};

struct remote_start_payload {
    remote_operation_binding binding;
    auto operator==(const remote_start_payload&) const -> bool = default;
};

struct remote_read_payload {
    remote_operation_binding binding;
    std::uint64_t cursor = 0;
    std::size_t max_bytes = 0;
    auto operator==(const remote_read_payload&) const -> bool = default;
};

struct remote_wait_payload {
    remote_operation_binding binding;
    auto operator==(const remote_wait_payload&) const -> bool = default;
};

struct remote_stop_payload {
    remote_operation_binding binding;
    auto operator==(const remote_stop_payload&) const -> bool = default;
};

struct remote_cleanup_payload {
    remote_operation_binding binding;
    auto operator==(const remote_cleanup_payload&) const -> bool = default;
};

using remote_validation_payload = std::variant<
    remote_prepare_payload,
    remote_start_payload,
    remote_read_payload,
    remote_wait_payload,
    remote_stop_payload,
    remote_cleanup_payload>;

struct remote_validation_request {
    std::string id;
    remote_method method = remote_method::remote_health;
    std::uint64_t remaining_ttl_ms = 0;
    remote_validation_payload payload;
};

struct remote_validation_result {
    std::string session_id;
    std::string session_epoch;
    std::string state;
    std::uint64_t cursor = 0;
    std::uint64_t next_cursor = 0;
    bool eof = false;
    std::string bytes;
    std::optional<int> exit_code;
};

// Computes the payload commitment over the canonical method-specific fields.
// The payload_digest field itself is excluded to avoid a circular commitment.
[[nodiscard]] auto
remote_validation_payload_digest(remote_method method, const remote_validation_payload& payload)
    -> std::expected<std::string, std::string>;

// Sets and validates the canonical payload digest. Callers cannot add image,
// argv, path, environment, Docker option, mount, or secret fields.
[[nodiscard]] auto
bind_remote_validation_payload(remote_method method, remote_validation_payload payload)
    -> std::expected<remote_validation_payload, std::string>;

[[nodiscard]] auto encode_remote_validation_request(
    std::string_view id,
    remote_method method,
    std::uint64_t remaining_ttl_ms,
    const remote_validation_payload& payload
) -> std::expected<std::string, std::string>;

[[nodiscard]] auto decode_remote_validation_request(std::string_view frame)
    -> std::expected<remote_validation_request, std::string>;

[[nodiscard]] auto
encode_remote_validation_result(std::string_view id, const remote_validation_result& result)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto
encode_remote_validation_error(std::string_view id, std::string_view code, std::string_view message)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto decode_remote_validation_result(std::string_view frame)
    -> std::expected<remote_validation_result, std::string>;

} // namespace glove::control
