#include "../../include/glove/control/remote_protocol.hpp"

#include <arpa/inet.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace glove::control {
namespace wire {

struct request {
    std::string jsonrpc;
    std::string id;
    std::string method;
    std::uint64_t deadline_remaining_ms = 0;
    glz::raw_json payload;
};

struct error {
    std::string code;
    std::string message;
};

struct health_result {
    std::uint8_t schema_version = 0;
    std::string status;
    std::string executor_digest;
    std::string container_image_digest;
    std::string observation_authority;
    std::string workerd_digest;
    std::string descriptor_digest;
    std::uint8_t validation_schema_version = 0;
    bool validation_only = false;
    bool lifecycle_operational = false;
    bool independently_verified = true;
};

struct response {
    std::string jsonrpc;
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<error> error;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t max_request_id_bytes = 128U;

using steady_time = std::chrono::steady_clock::time_point;

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_request_id_bytes && value.front() != '-' &&
           value.front() != '.' && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

template<typename Value>
auto encode_json(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded || encoded->size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"remote protocol encoding failed or exceeded its cap"});
    }
    return std::move(*encoded);
}

auto error_response(std::string_view id, std::string_view code, std::string_view message)
    -> std::expected<std::string, std::string> {
    auto encoded_error =
        encode_json(wire::error{.code = std::string{code}, .message = std::string{message}});
    if (!encoded_error) {
        return std::unexpected(encoded_error.error());
    }
    return encode_json(
        wire::response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = std::nullopt,
            .error = wire::error{.code = std::string{code}, .message = std::string{message}},
        }
    );
}

auto decode_request(std::string_view frame) -> std::expected<wire::request, std::string> {
    if (frame.empty() || frame.size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"invalid remote executor request boundary"});
    }
    std::string parse_buffer{frame};
    wire::request request;
    if (const auto error = glz::read<strict_read_options>(request, parse_buffer);
        error || request.jsonrpc != "2.0" || !valid_identifier(request.id) ||
        request.deadline_remaining_ms == 0 ||
        request.deadline_remaining_ms > max_remote_deadline_ms || request.payload.str.empty()) {
        return std::unexpected(std::string{"invalid remote executor request"});
    }
    return request;
}

auto health_response(
    std::string_view id, const remote_executor_identity& identity, bool validation_available
) -> std::expected<std::string, std::string> {
    auto result = encode_json(
        wire::health_result{
            .schema_version = validation_available ? std::uint8_t{2} : std::uint8_t{1},
            .status = validation_available ? "validation_only" : "not_operational",
            .executor_digest = identity.executor_digest,
            .container_image_digest = identity.container_image_digest,
            .observation_authority = "trusted_remote_claim",
            .workerd_digest = identity.workerd_digest,
            .descriptor_digest = identity.descriptor_digest,
            .validation_schema_version = validation_available ? std::uint8_t{1} : std::uint8_t{0},
            .validation_only = validation_available,
            .lifecycle_operational = false,
            .independently_verified = false,
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return encode_json(
        wire::response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = glz::raw_json{std::move(*result)},
            .error = std::nullopt,
        }
    );
}

auto poll_ready(int descriptor, short events, steady_time deadline)
    -> std::expected<void, std::string> {
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::unexpected(std::string{"remote protocol deadline exceeded"});
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        if (remaining.count() == 0) {
            remaining = std::chrono::milliseconds{1};
        }
        const auto timeout = static_cast<int>(
            std::min<std::int64_t>(remaining.count(), std::numeric_limits<int>::max())
        );
        pollfd candidate{.fd = descriptor, .events = events, .revents = 0};
        const auto polled = ::poll(&candidate, 1, timeout);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled < 0) {
            return std::unexpected(system_error("poll remote protocol descriptor"));
        }
        if (polled == 0) {
            return std::unexpected(std::string{"remote protocol deadline exceeded"});
        }
        if ((candidate.revents & (POLLERR | POLLNVAL)) != 0) {
            return std::unexpected(std::string{"remote protocol descriptor failed"});
        }
        if ((candidate.revents & events) != 0 || (candidate.revents & POLLHUP) != 0) {
            return {};
        }
    }
}

auto read_exact(int descriptor, std::span<unsigned char> output, steady_time deadline)
    -> std::expected<void, std::string> {
    std::size_t consumed = 0;
    while (consumed < output.size()) {
        if (auto ready = poll_ready(descriptor, POLLIN, deadline); !ready) {
            return std::unexpected(ready.error());
        }
        const auto count = ::read(descriptor, output.data() + consumed, output.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            return std::unexpected(system_error("read remote protocol frame"));
        }
        if (count == 0) {
            return std::unexpected(std::string{"remote frame input closed"});
        }
        consumed += static_cast<std::size_t>(count);
    }
    return {};
}

auto write_exact(int descriptor, std::span<const unsigned char> input, steady_time deadline)
    -> std::expected<void, std::string> {
    std::size_t consumed = 0;
    while (consumed < input.size()) {
        if (auto ready = poll_ready(descriptor, POLLOUT, deadline); !ready) {
            return std::unexpected(ready.error());
        }
        const auto count = ::write(descriptor, input.data() + consumed, input.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(system_error("write remote protocol frame"));
        }
        consumed += static_cast<std::size_t>(count);
    }
    return {};
}

} // namespace

auto parse_remote_method(std::string_view value) -> std::expected<remote_method, std::string> {
    if (value == "remote_health") {
        return remote_method::remote_health;
    }
    if (value == "remote_prepare") {
        return remote_method::remote_prepare;
    }
    if (value == "remote_start") {
        return remote_method::remote_start;
    }
    if (value == "remote_read") {
        return remote_method::remote_read;
    }
    if (value == "remote_write_input") {
        return remote_method::remote_write_input;
    }
    if (value == "remote_resize") {
        return remote_method::remote_resize;
    }
    if (value == "remote_signal") {
        return remote_method::remote_signal;
    }
    if (value == "remote_stop") {
        return remote_method::remote_stop;
    }
    if (value == "remote_wait") {
        return remote_method::remote_wait;
    }
    if (value == "remote_cleanup") {
        return remote_method::remote_cleanup;
    }
    return std::unexpected(std::string{"unknown remote protocol method"});
}

auto remote_method_name(remote_method value) noexcept -> std::string_view {
    switch (value) {
    case remote_method::remote_health:
        return "remote_health";
    case remote_method::remote_prepare:
        return "remote_prepare";
    case remote_method::remote_start:
        return "remote_start";
    case remote_method::remote_read:
        return "remote_read";
    case remote_method::remote_write_input:
        return "remote_write_input";
    case remote_method::remote_resize:
        return "remote_resize";
    case remote_method::remote_signal:
        return "remote_signal";
    case remote_method::remote_stop:
        return "remote_stop";
    case remote_method::remote_wait:
        return "remote_wait";
    case remote_method::remote_cleanup:
        return "remote_cleanup";
    }
    return {};
}

auto decode_remote_request_header(std::string_view frame)
    -> std::expected<remote_request_header, std::string> {
    auto decoded = decode_request(frame);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    auto method = parse_remote_method(decoded->method);
    if (!method) {
        return std::unexpected(method.error());
    }
    return remote_request_header{
        .id = std::move(decoded->id),
        .method = *method,
        .remaining_ttl_ms = decoded->deadline_remaining_ms,
        .payload_json = std::move(decoded->payload.str),
    };
}

auto encode_remote_request(
    std::string_view id,
    remote_method method,
    std::uint64_t deadline_remaining_ms,
    std::string_view payload_json
) -> std::expected<std::string, std::string> {
    const auto method_name = remote_method_name(method);
    if (!valid_identifier(id) || method_name.empty() || deadline_remaining_ms == 0 ||
        deadline_remaining_ms > max_remote_deadline_ms || payload_json != "null") {
        return std::unexpected(std::string{"invalid bounded remote protocol request"});
    }
    return encode_json(
        wire::request{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .method = std::string{method_name},
            .deadline_remaining_ms = deadline_remaining_ms,
            .payload = glz::raw_json{"null"},
        }
    );
}

auto remote_request_deadline(
    std::string_view frame,
    std::chrono::steady_clock::time_point receive_started_at,
    std::chrono::steady_clock::time_point received_at
) -> std::expected<std::chrono::steady_clock::time_point, std::string> {
    auto request = decode_request(frame);
    if (!request) {
        return std::unexpected(request.error());
    }
    if (received_at < receive_started_at) {
        return std::unexpected(std::string{"remote protocol monotonic time moved backwards"});
    }
    const auto request_ttl = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
        std::chrono::milliseconds{request->deadline_remaining_ms}
    );
    const auto receive_elapsed = received_at - receive_started_at;
    if (receive_elapsed >= request_ttl) {
        return std::unexpected(
            std::string{"remote protocol deadline exceeded during frame receive"}
        );
    }
    return received_at + (request_ttl - receive_elapsed);
}

auto handle_remote_executor_request(
    std::string_view frame, const remote_executor_identity& identity
) -> std::expected<std::string, std::string> {
    if (!valid_digest(identity.executor_digest) || !valid_digest(identity.container_image_digest)) {
        return std::unexpected(std::string{"invalid remote executor identity"});
    }
    auto decoded = decode_request(frame);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    auto& request = *decoded;
    auto method = parse_remote_method(request.method);
    if (!method) {
        return error_response(request.id, "method_not_found", "remote method is unavailable");
    }
    if (request.payload.str != "null") {
        return std::unexpected(std::string{"construction-only remote payload must be null"});
    }
    if (*method == remote_method::remote_health) {
        return health_response(request.id, identity, false);
    }
    return error_response(request.id, "method_not_found", "remote method is unavailable");
}

auto encode_remote_validation_health(std::string_view id, const remote_executor_identity& identity)
    -> std::expected<std::string, std::string> {
    if (!valid_identifier(id) || !valid_digest(identity.executor_digest) ||
        !valid_digest(identity.container_image_digest) || !valid_digest(identity.workerd_digest) ||
        !valid_digest(identity.descriptor_digest)) {
        return std::unexpected(std::string{"invalid remote validation identity"});
    }
    return health_response(id, identity, true);
}

auto decode_remote_response(std::string_view frame)
    -> std::expected<remote_protocol_response, std::string> {
    if (frame.empty() || frame.size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"invalid remote response size"});
    }
    std::string parse_buffer{frame};
    wire::response response;
    if (const auto error = glz::read<strict_read_options>(response, parse_buffer);
        error || response.jsonrpc != "2.0" || !valid_identifier(response.id) ||
        response.result.has_value() == response.error.has_value()) {
        return std::unexpected(std::string{"invalid remote response envelope"});
    }
    if (response.error) {
        return remote_protocol_response{
            .id = std::move(response.id),
            .status = {},
            .error_code = std::move(response.error->code),
            .executor_digest = {},
            .container_image_digest = {},
            .observation_authority = {},
            .workerd_digest = {},
            .descriptor_digest = {},
            .validation_schema_version = 0,
            .validation_only = false,
            .lifecycle_operational = false,
            .independently_verified = false,
        };
    }
    wire::health_result health;
    std::string result_buffer{response.result->str};
    if (const auto error = glz::read<strict_read_options>(health, result_buffer);
        error || (health.schema_version != 1 && health.schema_version != 2) ||
        (health.status != "not_operational" && health.status != "validation_only") ||
        health.observation_authority != "trusted_remote_claim" || health.independently_verified ||
        health.lifecycle_operational || !valid_digest(health.executor_digest) ||
        !valid_digest(health.container_image_digest) ||
        (health.validation_only != (health.status == "validation_only")) ||
        (health.validation_only &&
         (health.schema_version != 2 || health.validation_schema_version != 1 ||
          !valid_digest(health.workerd_digest) || !valid_digest(health.descriptor_digest)))) {
        return std::unexpected(std::string{"invalid remote health response"});
    }
    return remote_protocol_response{
        .id = std::move(response.id),
        .status = std::move(health.status),
        .error_code = {},
        .executor_digest = std::move(health.executor_digest),
        .container_image_digest = std::move(health.container_image_digest),
        .observation_authority = std::move(health.observation_authority),
        .workerd_digest = std::move(health.workerd_digest),
        .descriptor_digest = std::move(health.descriptor_digest),
        .validation_schema_version = health.validation_schema_version,
        .validation_only = health.validation_only,
        .lifecycle_operational = health.lifecycle_operational,
        .independently_verified = health.independently_verified,
    };
}

auto read_remote_frame(int descriptor, steady_time deadline)
    -> std::expected<std::string, std::string> {
    std::array<unsigned char, 4> header{};
    if (auto read = read_exact(descriptor, header, deadline); !read) {
        return std::unexpected(read.error());
    }
    const auto network_length = (static_cast<std::uint32_t>(header[0]) << 24U) |
                                (static_cast<std::uint32_t>(header[1]) << 16U) |
                                (static_cast<std::uint32_t>(header[2]) << 8U) |
                                static_cast<std::uint32_t>(header[3]);
    if (network_length == 0 || network_length > max_remote_frame_bytes) {
        return std::unexpected(std::string{"remote frame length is outside the one-MiB bound"});
    }
    std::string frame(network_length, '\0');
    auto bytes =
        std::span<unsigned char>{reinterpret_cast<unsigned char*>(frame.data()), frame.size()};
    if (auto read = read_exact(descriptor, bytes, deadline); !read) {
        return std::unexpected(read.error());
    }
    return frame;
}

auto write_remote_frame(int descriptor, std::string_view frame, steady_time deadline)
    -> std::expected<void, std::string> {
    if (frame.empty() || frame.size() > max_remote_frame_bytes ||
        frame.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"remote frame length is outside the one-MiB bound"});
    }
    const auto length = static_cast<std::uint32_t>(frame.size());
    const std::array<unsigned char, 4> header{
        static_cast<unsigned char>((length >> 24U) & 0xffU),
        static_cast<unsigned char>((length >> 16U) & 0xffU),
        static_cast<unsigned char>((length >> 8U) & 0xffU),
        static_cast<unsigned char>(length & 0xffU),
    };
    if (auto wrote = write_exact(descriptor, header, deadline); !wrote) {
        return std::unexpected(wrote.error());
    }
    return write_exact(
        descriptor,
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(frame.data()), frame.size()
        },
        deadline
    );
}

} // namespace glove::control
