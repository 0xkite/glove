#include "glove/control/remote_validation.hpp"

#include "glove/container/digest.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <charconv>
#include <optional>
#include <string>
#include <utility>

namespace glove::control {
namespace wire {

struct validation_envelope {
    std::string jsonrpc;
    std::string id;
    std::string method;
    std::uint64_t deadline_remaining_ms = 0;
    glz::raw_json payload;
};

struct validation_payload {
    std::uint8_t schema_version = 0;
    std::string session_id;
    std::string session_epoch;
    std::string descriptor_digest;
    std::string idempotency_key;
    std::string payload_digest;
    std::optional<std::uint64_t> cursor;
    std::optional<std::uint64_t> max_bytes;
};

struct validation_result {
    std::uint8_t schema_version = 0;
    std::string session_id;
    std::string session_epoch;
    std::string state;
    std::uint64_t cursor = 0;
    std::uint64_t next_cursor = 0;
    bool eof = false;
    std::string bytes;
    std::optional<int> exit_code;
};

struct validation_error {
    std::string code;
    std::string message;
};

struct validation_response {
    std::string jsonrpc;
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<validation_error> error;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t max_session_id_bytes = 64U;
constexpr std::size_t max_idempotency_key_bytes = 96U;
constexpr std::size_t max_request_id_bytes = 128U;

[[nodiscard]] auto valid_identifier(std::string_view value, std::size_t maximum) -> bool {
    return !value.empty() && value.size() <= maximum && value.front() != '-' &&
           value.front() != '.' && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

[[nodiscard]] auto valid_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto valid_epoch(std::string_view value) -> bool {
    return value.size() == 32U && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto binding_of(const remote_validation_payload& payload)
    -> const remote_operation_binding& {
    return std::visit(
        [](const auto& value) -> const remote_operation_binding& { return value.binding; }, payload
    );
}

[[nodiscard]] auto binding_of(remote_validation_payload& payload) -> remote_operation_binding& {
    return std::visit(
        [](auto& value) -> remote_operation_binding& { return value.binding; }, payload
    );
}

[[nodiscard]] auto
method_matches_payload(remote_method method, const remote_validation_payload& payload) -> bool {
    switch (method) {
    case remote_method::remote_prepare:
        return std::holds_alternative<remote_prepare_payload>(payload);
    case remote_method::remote_start:
        return std::holds_alternative<remote_start_payload>(payload);
    case remote_method::remote_read:
        return std::holds_alternative<remote_read_payload>(payload);
    case remote_method::remote_wait:
        return std::holds_alternative<remote_wait_payload>(payload);
    case remote_method::remote_stop:
        return std::holds_alternative<remote_stop_payload>(payload);
    case remote_method::remote_cleanup:
        return std::holds_alternative<remote_cleanup_payload>(payload);
    case remote_method::remote_health:
    case remote_method::remote_write_input:
    case remote_method::remote_resize:
    case remote_method::remote_signal:
        return false;
    }
    return false;
}

[[nodiscard]] auto validate_binding(const remote_operation_binding& binding) -> bool {
    return valid_identifier(binding.session_id, max_session_id_bytes) &&
           valid_epoch(binding.session_epoch) && valid_digest(binding.descriptor_digest) &&
           valid_identifier(binding.idempotency_key, max_idempotency_key_bytes) &&
           valid_digest(binding.payload_digest);
}

void append_number(std::string& canonical, std::uint64_t value) {
    std::array<char, 32> buffer{};
    const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (error == std::errc{}) {
        canonical.append(buffer.data(), end);
    }
}

[[nodiscard]] auto canonical_payload(remote_method method, const remote_validation_payload& payload)
    -> std::expected<std::string, std::string> {
    if (!method_matches_payload(method, payload)) {
        return std::unexpected(std::string{"remote validation method/payload mismatch"});
    }
    const auto& binding = binding_of(payload);
    if (!valid_identifier(binding.session_id, max_session_id_bytes) ||
        !valid_epoch(binding.session_epoch) || !valid_digest(binding.descriptor_digest) ||
        !valid_identifier(binding.idempotency_key, max_idempotency_key_bytes)) {
        return std::unexpected(std::string{"invalid remote validation binding"});
    }
    std::string canonical{"glove-remote-validation-v1\nmethod="};
    canonical += remote_method_name(method);
    canonical += "\nsession_id=";
    canonical += binding.session_id;
    canonical += "\nsession_epoch=";
    canonical += binding.session_epoch;
    canonical += "\ndescriptor_digest=";
    canonical += binding.descriptor_digest;
    canonical += "\nidempotency_key=";
    canonical += binding.idempotency_key;
    if (const auto* read = std::get_if<remote_read_payload>(&payload); read != nullptr) {
        if (read->max_bytes == 0U || read->max_bytes > max_remote_validation_read_bytes) {
            return std::unexpected(std::string{"invalid remote validation read bound"});
        }
        canonical += "\ncursor=";
        append_number(canonical, read->cursor);
        canonical += "\nmax_bytes=";
        append_number(canonical, read->max_bytes);
    }
    canonical += '\n';
    return canonical;
}

template<typename Value>
[[nodiscard]] auto encode_json(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded || encoded->empty() || encoded->size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"remote validation encoding failed"});
    }
    return std::move(*encoded);
}

[[nodiscard]] auto to_wire(const remote_validation_payload& payload) -> wire::validation_payload {
    const auto& binding = binding_of(payload);
    wire::validation_payload encoded{
        .schema_version = 1,
        .session_id = binding.session_id,
        .session_epoch = binding.session_epoch,
        .descriptor_digest = binding.descriptor_digest,
        .idempotency_key = binding.idempotency_key,
        .payload_digest = binding.payload_digest,
    };
    if (const auto* read = std::get_if<remote_read_payload>(&payload); read != nullptr) {
        encoded.cursor = read->cursor;
        encoded.max_bytes = read->max_bytes;
    }
    return encoded;
}

[[nodiscard]] auto from_wire(remote_method method, wire::validation_payload encoded)
    -> std::expected<remote_validation_payload, std::string> {
    remote_operation_binding binding{
        .session_id = std::move(encoded.session_id),
        .session_epoch = std::move(encoded.session_epoch),
        .descriptor_digest = std::move(encoded.descriptor_digest),
        .idempotency_key = std::move(encoded.idempotency_key),
        .payload_digest = std::move(encoded.payload_digest),
    };
    if (encoded.schema_version != 1 || !validate_binding(binding)) {
        return std::unexpected(std::string{"invalid remote validation payload"});
    }
    remote_validation_payload payload = remote_prepare_payload{.binding = std::move(binding)};
    switch (method) {
    case remote_method::remote_prepare:
        if (encoded.cursor || encoded.max_bytes) {
            return std::unexpected(std::string{"unexpected remote prepare fields"});
        }
        break;
    case remote_method::remote_start:
        payload = remote_start_payload{
            .binding = std::move(std::get<remote_prepare_payload>(payload).binding)
        };
        break;
    case remote_method::remote_read:
        if (!encoded.cursor || !encoded.max_bytes || *encoded.max_bytes == 0U ||
            *encoded.max_bytes > max_remote_validation_read_bytes) {
            return std::unexpected(std::string{"invalid remote read payload"});
        }
        payload = remote_read_payload{
            .binding = std::move(std::get<remote_prepare_payload>(payload).binding),
            .cursor = *encoded.cursor,
            .max_bytes = static_cast<std::size_t>(*encoded.max_bytes),
        };
        break;
    case remote_method::remote_wait:
        payload = remote_wait_payload{
            .binding = std::move(std::get<remote_prepare_payload>(payload).binding)
        };
        break;
    case remote_method::remote_stop:
        payload = remote_stop_payload{
            .binding = std::move(std::get<remote_prepare_payload>(payload).binding)
        };
        break;
    case remote_method::remote_cleanup:
        payload = remote_cleanup_payload{
            .binding = std::move(std::get<remote_prepare_payload>(payload).binding)
        };
        break;
    case remote_method::remote_health:
    case remote_method::remote_write_input:
    case remote_method::remote_resize:
    case remote_method::remote_signal:
        return std::unexpected(std::string{"remote method has no validation payload"});
    }
    if (method != remote_method::remote_read && (encoded.cursor || encoded.max_bytes)) {
        return std::unexpected(std::string{"unexpected remote validation payload fields"});
    }
    auto expected_digest = remote_validation_payload_digest(method, payload);
    if (!expected_digest || *expected_digest != binding_of(payload).payload_digest) {
        return std::unexpected(std::string{"remote validation payload digest mismatch"});
    }
    return payload;
}

} // namespace

auto remote_validation_payload_digest(
    remote_method method, const remote_validation_payload& payload
) -> std::expected<std::string, std::string> {
    auto canonical = canonical_payload(method, payload);
    if (!canonical) {
        return std::unexpected(canonical.error());
    }
    auto digest = container::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(canonical->data()), canonical->size()
        }
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return "sha256:" + *digest;
}

auto bind_remote_validation_payload(remote_method method, remote_validation_payload payload)
    -> std::expected<remote_validation_payload, std::string> {
    binding_of(payload).payload_digest = "sha256:" + std::string(64U, '0');
    auto digest = remote_validation_payload_digest(method, payload);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    binding_of(payload).payload_digest = std::move(*digest);
    return payload;
}

auto encode_remote_validation_request(
    std::string_view id,
    remote_method method,
    std::uint64_t remaining_ttl_ms,
    const remote_validation_payload& payload
) -> std::expected<std::string, std::string> {
    auto expected_digest = remote_validation_payload_digest(method, payload);
    if (!valid_identifier(id, max_request_id_bytes) || remaining_ttl_ms == 0U ||
        remaining_ttl_ms > max_remote_deadline_ms || !expected_digest ||
        *expected_digest != binding_of(payload).payload_digest) {
        return std::unexpected(std::string{"invalid bounded remote validation request"});
    }
    auto encoded_payload = encode_json(to_wire(payload));
    if (!encoded_payload) {
        return std::unexpected(encoded_payload.error());
    }
    return encode_json(
        wire::validation_envelope{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .method = std::string{remote_method_name(method)},
            .deadline_remaining_ms = remaining_ttl_ms,
            .payload = glz::raw_json{std::move(*encoded_payload)},
        }
    );
}

auto decode_remote_validation_request(std::string_view frame)
    -> std::expected<remote_validation_request, std::string> {
    if (frame.empty() || frame.size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"invalid remote validation request boundary"});
    }
    std::string parse_buffer{frame};
    wire::validation_envelope envelope;
    if (const auto error = glz::read<strict_read_options>(envelope, parse_buffer);
        error || envelope.jsonrpc != "2.0" ||
        !valid_identifier(envelope.id, max_request_id_bytes) ||
        envelope.deadline_remaining_ms == 0U ||
        envelope.deadline_remaining_ms > max_remote_deadline_ms) {
        return std::unexpected(std::string{"invalid remote validation request envelope"});
    }
    auto method = parse_remote_method(envelope.method);
    if (!method || *method == remote_method::remote_health ||
        *method == remote_method::remote_write_input || *method == remote_method::remote_resize ||
        *method == remote_method::remote_signal) {
        return std::unexpected(std::string{"remote method has no validation payload"});
    }
    wire::validation_payload encoded;
    std::string payload_buffer{envelope.payload.str};
    if (const auto error = glz::read<strict_read_options>(encoded, payload_buffer); error) {
        return std::unexpected(std::string{"invalid remote validation payload"});
    }
    auto payload = from_wire(*method, std::move(encoded));
    if (!payload) {
        return std::unexpected(payload.error());
    }
    return remote_validation_request{
        .id = std::move(envelope.id),
        .method = *method,
        .remaining_ttl_ms = envelope.deadline_remaining_ms,
        .payload = std::move(*payload),
    };
}

auto encode_remote_validation_result(std::string_view id, const remote_validation_result& result)
    -> std::expected<std::string, std::string> {
    if (!valid_identifier(id, max_request_id_bytes) ||
        !valid_identifier(result.session_id, max_session_id_bytes) ||
        !valid_epoch(result.session_epoch) || result.state.empty() ||
        result.bytes.size() > max_remote_validation_read_bytes) {
        return std::unexpected(std::string{"invalid remote validation result"});
    }
    auto encoded_result = encode_json(
        wire::validation_result{
            .schema_version = 1,
            .session_id = result.session_id,
            .session_epoch = result.session_epoch,
            .state = result.state,
            .cursor = result.cursor,
            .next_cursor = result.next_cursor,
            .eof = result.eof,
            .bytes = result.bytes,
            .exit_code = result.exit_code,
        }
    );
    if (!encoded_result) {
        return std::unexpected(encoded_result.error());
    }
    return encode_json(
        wire::validation_response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = glz::raw_json{std::move(*encoded_result)},
            .error = std::nullopt,
        }
    );
}

auto encode_remote_validation_error(
    std::string_view id, std::string_view code, std::string_view message
) -> std::expected<std::string, std::string> {
    if (!valid_identifier(id, max_request_id_bytes) || code.empty() || code.size() > 64U ||
        message.empty() || message.size() > 256U) {
        return std::unexpected(std::string{"invalid remote validation error"});
    }
    return encode_json(
        wire::validation_response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = std::nullopt,
            .error =
                wire::validation_error{.code = std::string{code}, .message = std::string{message}},
        }
    );
}

auto decode_remote_validation_result(std::string_view frame)
    -> std::expected<remote_validation_result, std::string> {
    if (frame.empty() || frame.size() > max_remote_frame_bytes) {
        return std::unexpected(std::string{"invalid remote validation response boundary"});
    }
    std::string parse_buffer{frame};
    wire::validation_response response;
    if (const auto error = glz::read<strict_read_options>(response, parse_buffer);
        error || response.jsonrpc != "2.0" ||
        !valid_identifier(response.id, max_request_id_bytes) ||
        response.result.has_value() == response.error.has_value()) {
        return std::unexpected(std::string{"invalid remote validation response envelope"});
    }
    if (response.error) {
        return std::unexpected(response.error->code);
    }
    wire::validation_result result;
    std::string result_buffer{response.result->str};
    if (const auto error = glz::read<strict_read_options>(result, result_buffer);
        error || result.schema_version != 1 ||
        !valid_identifier(result.session_id, max_session_id_bytes) ||
        !valid_epoch(result.session_epoch) || result.state.empty() ||
        result.bytes.size() > max_remote_validation_read_bytes) {
        return std::unexpected(std::string{"invalid remote validation result"});
    }
    return remote_validation_result{
        .session_id = std::move(result.session_id),
        .session_epoch = std::move(result.session_epoch),
        .state = std::move(result.state),
        .cursor = result.cursor,
        .next_cursor = result.next_cursor,
        .eof = result.eof,
        .bytes = std::move(result.bytes),
        .exit_code = result.exit_code,
    };
}

} // namespace glove::control
