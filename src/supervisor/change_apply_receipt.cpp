#include "glove/supervisor/change_apply_receipt.hpp"

#include "glove/container/digest.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace glove::supervisor {

namespace apply_receipt_wire {

struct receipt_body {
    std::uint8_t schema_version = change_apply_receipt_schema_version;
    std::string state;
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t completed_at_ms = 0;
};

struct receipt_envelope {
    std::uint8_t schema_version = change_apply_receipt_schema_version;
    std::string state;
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t completed_at_ms = 0;
    std::string receipt_digest;
};

} // namespace apply_receipt_wire

namespace {

using apply_receipt_wire::receipt_body;
using apply_receipt_wire::receipt_envelope;

constexpr std::size_t max_receipt_bytes = 8U * 1024U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr glz::opts strict_read_options{.null_terminated = false, .error_on_unknown_keys = true};

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto body(const receipt_envelope& envelope) -> receipt_body {
    return {
        .schema_version = envelope.schema_version,
        .state = envelope.state,
        .grant_id = envelope.grant_id,
        .authorization_digest = envelope.authorization_digest,
        .manifest_digest = envelope.manifest_digest,
        .session_id = envelope.session_id,
        .exposure_id = envelope.exposure_id,
        .generation = envelope.generation,
        .scope_digest = envelope.scope_digest,
        .baseline_tree_digest = envelope.baseline_tree_digest,
        .staged_tree_digest = envelope.staged_tree_digest,
        .final_source_identity_digest = envelope.final_source_identity_digest,
        .failure_code = envelope.failure_code,
        .completed_at_ms = envelope.completed_at_ms,
    };
}

auto digest(const receipt_body& value) -> result<std::string> {
    auto json = glz::write_json(value);
    if (!json) {
        return std::unexpected(std::string{"encode change apply receipt body"});
    }
    return container::sha256_hex(
        std::span{
            reinterpret_cast<const unsigned char*>(json->data()),
            json->size(),
        }
    );
}

auto validate(const receipt_envelope& value) -> result<void> {
    const bool valid_outcome = (value.state == "applied" && value.failure_code.empty()) ||
                               (value.state == "failed" && valid_identifier(value.failure_code));
    if (value.schema_version != change_apply_receipt_schema_version || !valid_outcome ||
        !valid_identifier(value.grant_id) || !valid_digest(value.authorization_digest) ||
        !valid_digest(value.manifest_digest) || !valid_identifier(value.session_id) ||
        !valid_identifier(value.exposure_id) || value.generation == 0 ||
        !valid_digest(value.scope_digest) || !valid_digest(value.baseline_tree_digest) ||
        !valid_digest(value.staged_tree_digest) ||
        !valid_digest(value.final_source_identity_digest) || value.completed_at_ms == 0 ||
        !valid_digest(value.receipt_digest)) {
        return std::unexpected(std::string{"change apply receipt fields are invalid"});
    }
    return {};
}

auto materialize(receipt_envelope envelope, std::string canonical_json) -> change_apply_receipt {
    return {
        .schema_version = envelope.schema_version,
        .state = std::move(envelope.state),
        .grant_id = std::move(envelope.grant_id),
        .authorization_digest = std::move(envelope.authorization_digest),
        .manifest_digest = std::move(envelope.manifest_digest),
        .session_id = std::move(envelope.session_id),
        .exposure_id = std::move(envelope.exposure_id),
        .generation = envelope.generation,
        .scope_digest = std::move(envelope.scope_digest),
        .baseline_tree_digest = std::move(envelope.baseline_tree_digest),
        .staged_tree_digest = std::move(envelope.staged_tree_digest),
        .final_source_identity_digest = std::move(envelope.final_source_identity_digest),
        .failure_code = std::move(envelope.failure_code),
        .completed_at_ms = envelope.completed_at_ms,
        .receipt_digest = std::move(envelope.receipt_digest),
        .canonical_json = std::move(canonical_json),
    };
}

} // namespace

auto build_change_apply_receipt(
    const change_apply_reservation_record& reservation,
    const change_apply_exchange_result& exchange,
    std::uint64_t completed_at_ms
) -> result<change_apply_receipt> {
    if (exchange.final_tree_digest != reservation.staged_tree_digest ||
        completed_at_ms < reservation.reserved_at_ms) {
        return std::unexpected(std::string{"change apply receipt outcome mismatch"});
    }
    receipt_envelope envelope{
        .schema_version = change_apply_receipt_schema_version,
        .state = "applied",
        .grant_id = reservation.grant_id,
        .authorization_digest = reservation.authorization_digest,
        .manifest_digest = reservation.manifest_digest,
        .session_id = reservation.session_id,
        .exposure_id = reservation.exposure_id,
        .generation = reservation.generation,
        .scope_digest = reservation.scope_digest,
        .baseline_tree_digest = reservation.baseline_tree_digest,
        .staged_tree_digest = reservation.staged_tree_digest,
        .final_source_identity_digest = exchange.final_source_identity_digest,
        .failure_code = {},
        .completed_at_ms = completed_at_ms,
        .receipt_digest = {},
    };
    auto receipt_digest = digest(body(envelope));
    if (!receipt_digest) {
        return std::unexpected(receipt_digest.error());
    }
    envelope.receipt_digest = std::move(*receipt_digest);
    if (auto valid = validate(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    auto canonical = glz::write_json(envelope);
    if (!canonical || canonical->empty() || canonical->size() > max_receipt_bytes) {
        return std::unexpected(std::string{"encode change apply receipt envelope"});
    }
    return materialize(std::move(envelope), std::move(*canonical));
}

auto build_failed_change_apply_receipt(
    const change_apply_reservation_record& reservation,
    std::string_view final_source_identity_digest,
    std::string_view failure_code,
    std::uint64_t completed_at_ms
) -> result<change_apply_receipt> {
    if (!valid_digest(final_source_identity_digest) || !valid_identifier(failure_code) ||
        completed_at_ms < reservation.reserved_at_ms) {
        return std::unexpected(std::string{"change apply failed receipt outcome mismatch"});
    }
    receipt_envelope envelope{
        .schema_version = change_apply_receipt_schema_version,
        .state = "failed",
        .grant_id = reservation.grant_id,
        .authorization_digest = reservation.authorization_digest,
        .manifest_digest = reservation.manifest_digest,
        .session_id = reservation.session_id,
        .exposure_id = reservation.exposure_id,
        .generation = reservation.generation,
        .scope_digest = reservation.scope_digest,
        .baseline_tree_digest = reservation.baseline_tree_digest,
        .staged_tree_digest = reservation.staged_tree_digest,
        .final_source_identity_digest = std::string{final_source_identity_digest},
        .failure_code = std::string{failure_code},
        .completed_at_ms = completed_at_ms,
        .receipt_digest = {},
    };
    auto receipt_digest = digest(body(envelope));
    if (!receipt_digest) {
        return std::unexpected(receipt_digest.error());
    }
    envelope.receipt_digest = std::move(*receipt_digest);
    if (auto valid = validate(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    auto canonical = glz::write_json(envelope);
    if (!canonical || canonical->empty() || canonical->size() > max_receipt_bytes) {
        return std::unexpected(std::string{"encode failed change apply receipt envelope"});
    }
    return materialize(std::move(envelope), std::move(*canonical));
}

auto decode_change_apply_receipt(std::string_view canonical_json) -> result<change_apply_receipt> {
    if (canonical_json.empty() || canonical_json.size() > max_receipt_bytes) {
        return std::unexpected(std::string{"change apply receipt exceeds its bound"});
    }
    receipt_envelope envelope;
    if (const auto error = glz::read<strict_read_options>(envelope, canonical_json); error) {
        return std::unexpected(std::string{"decode change apply receipt"});
    }
    if (auto valid = validate(envelope); !valid) {
        return std::unexpected(valid.error());
    }
    auto expected_digest = digest(body(envelope));
    if (!expected_digest || *expected_digest != envelope.receipt_digest) {
        return std::unexpected(
            expected_digest ? std::string{"change apply receipt digest mismatch"}
                            : expected_digest.error()
        );
    }
    auto canonical = glz::write_json(envelope);
    if (!canonical || *canonical != canonical_json) {
        return std::unexpected(std::string{"change apply receipt is not canonical"});
    }
    return materialize(std::move(envelope), std::move(*canonical));
}

auto reconstruct_change_apply_receipt(
    const change_apply_reservation_record& reservation, const change_apply_terminal_record& terminal
) -> result<change_apply_receipt> {
    if (terminal.grant_id != reservation.grant_id ||
        terminal.authorization_digest != reservation.authorization_digest ||
        terminal.manifest_digest != reservation.manifest_digest) {
        return std::unexpected(std::string{"change apply receipt journal binding mismatch"});
    }
    result<change_apply_receipt> receipt = [&]() -> result<change_apply_receipt> {
        if (terminal.state == change_apply_terminal_state::applied) {
            const change_apply_exchange_result exchange{
                .candidate_name = {},
                .final_source_identity_digest = terminal.final_source_identity_digest,
                .final_tree_digest = reservation.staged_tree_digest,
            };
            return build_change_apply_receipt(reservation, exchange, terminal.completed_at_ms);
        }
        if (terminal.state == change_apply_terminal_state::failed) {
            return build_failed_change_apply_receipt(
                reservation,
                terminal.final_source_identity_digest,
                terminal.failure_code,
                terminal.completed_at_ms
            );
        }
        return std::unexpected(std::string{"change apply receipt terminal state is unsupported"});
    }();
    if (!receipt || receipt->receipt_digest != terminal.receipt_digest) {
        return std::unexpected(
            receipt ? std::string{"change apply reconstructed receipt digest mismatch"}
                    : receipt.error()
        );
    }
    return receipt;
}

} // namespace glove::supervisor
