#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace glove::control {

inline constexpr std::size_t max_remote_frame_bytes = std::size_t{1024} * 1024U;
inline constexpr std::uint64_t max_remote_deadline_ms = 60'000U;

enum class remote_method : std::uint8_t {
    remote_health,
    remote_prepare,
    remote_start,
    remote_read,
    remote_write_input,
    remote_resize,
    remote_signal,
    remote_stop,
    remote_wait,
    remote_cleanup,
};

struct remote_executor_identity {
    std::string executor_digest;
    std::string container_image_digest;
    std::string workerd_digest;
    std::string descriptor_digest;
};

struct remote_request_header {
    std::string id;
    remote_method method = remote_method::remote_health;
    std::uint64_t remaining_ttl_ms = 0;
    std::string payload_json;
};

struct remote_protocol_response {
    std::string id;
    std::string status;
    std::string error_code;
    std::string executor_digest;
    std::string container_image_digest;
    std::string observation_authority;
    std::string workerd_digest;
    std::string descriptor_digest;
    std::uint8_t validation_schema_version = 0;
    bool validation_only = false;
    bool lifecycle_operational = false;
    bool independently_verified = false;
};

[[nodiscard]] auto parse_remote_method(std::string_view value)
    -> std::expected<remote_method, std::string>;
[[nodiscard]] auto remote_method_name(remote_method value) noexcept -> std::string_view;

[[nodiscard]] auto decode_remote_request_header(std::string_view frame)
    -> std::expected<remote_request_header, std::string>;

[[nodiscard]] auto encode_remote_request(
    std::string_view id,
    remote_method method,
    std::uint64_t deadline_remaining_ms,
    std::string_view payload_json = "null"
) -> std::expected<std::string, std::string>;

// The request TTL starts at receive_started_at, before the frame is read. The
// returned monotonic deadline subtracts all receive time and rejects expiry.
[[nodiscard]] auto remote_request_deadline(
    std::string_view frame,
    std::chrono::steady_clock::time_point receive_started_at,
    std::chrono::steady_clock::time_point received_at
) -> std::expected<std::chrono::steady_clock::time_point, std::string>;

// Executor-side construction endpoint. Health is truthful and every lifecycle
// method is a stable not_operational denial until a later task wires Docker.
[[nodiscard]] auto
handle_remote_executor_request(std::string_view frame, const remote_executor_identity& identity)
    -> std::expected<std::string, std::string>;

// Truthful health for the separate fixed-descriptor validator. It does not
// advertise the public managed-session lifecycle or resource enforcement.
[[nodiscard]] auto
encode_remote_validation_health(std::string_view id, const remote_executor_identity& identity)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto decode_remote_response(std::string_view frame)
    -> std::expected<remote_protocol_response, std::string>;

// Four-byte big-endian framing with a one-MiB cap and an absolute monotonic
// deadline. These helpers never create a socket or open an SSH connection.
[[nodiscard]] auto read_remote_frame(int descriptor, std::chrono::steady_clock::time_point deadline)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto write_remote_frame(
    int descriptor, std::string_view frame, std::chrono::steady_clock::time_point deadline
) -> std::expected<void, std::string>;

} // namespace glove::control
