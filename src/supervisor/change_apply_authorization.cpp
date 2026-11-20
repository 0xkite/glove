#include "glove/supervisor/change_apply_authorization.hpp"

#include "glove/container/digest.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace glove::supervisor {

namespace authorization_wire {

struct wire_claims {
    std::uint8_t schema_version = 0;
    std::string audience;
    std::string key_id;
    std::string grant_id;
    std::string executor_node_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string manifest_digest;
    std::uint64_t policy_revision = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
};

struct wire_signed_envelope {
    std::uint8_t schema_version = 0;
    std::string audience;
    std::string key_id;
    std::string grant_id;
    std::string executor_node_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string manifest_digest;
    std::uint64_t policy_revision = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
    std::string signature;
};

struct wire_authorization {
    std::uint8_t schema_version = 0;
    std::string audience;
    std::string key_id;
    std::string grant_id;
    std::string executor_node_id;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string manifest_digest;
    std::uint64_t policy_revision = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
    std::string signature;
    std::string authorization_digest;
};

} // namespace authorization_wire

namespace {

using authorization_wire::wire_authorization;
using authorization_wire::wire_claims;
using authorization_wire::wire_signed_envelope;

constexpr std::size_t max_authorization_bytes = std::size_t{16} * 1024U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::size_t max_signature_bytes = 1'024U;
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

auto valid_signature(std::string_view value) -> bool {
    return value.size() >= 16U && value.size() <= max_signature_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '=';
           });
}

auto valid_claims(const change_apply_authorization_claims& claims) -> bool {
    return claims.schema_version == change_apply_authorization_schema_version &&
           claims.audience == "gloved" && valid_identifier(claims.key_id) &&
           valid_identifier(claims.grant_id) && valid_identifier(claims.executor_node_id) &&
           valid_identifier(claims.session_id) && valid_digest(claims.controller_plan_digest) &&
           valid_digest(claims.plan_content_digest) && valid_identifier(claims.exposure_id) &&
           claims.generation != 0 && valid_digest(claims.scope_digest) &&
           valid_digest(claims.manifest_digest) && claims.policy_revision != 0 &&
           claims.issued_at_ms != 0 && claims.expires_at_ms > claims.issued_at_ms &&
           claims.expires_at_ms - claims.issued_at_ms <=
               maximum_change_apply_authorization_lifetime_ms;
}

auto wire(const change_apply_authorization_claims& claims) -> wire_claims {
    return {
        .schema_version = claims.schema_version,
        .audience = claims.audience,
        .key_id = claims.key_id,
        .grant_id = claims.grant_id,
        .executor_node_id = claims.executor_node_id,
        .session_id = claims.session_id,
        .controller_plan_digest = claims.controller_plan_digest,
        .plan_content_digest = claims.plan_content_digest,
        .exposure_id = claims.exposure_id,
        .generation = claims.generation,
        .scope_digest = claims.scope_digest,
        .manifest_digest = claims.manifest_digest,
        .policy_revision = claims.policy_revision,
        .issued_at_ms = claims.issued_at_ms,
        .expires_at_ms = claims.expires_at_ms,
    };
}

auto claims(const wire_authorization& encoded) -> change_apply_authorization_claims {
    return {
        .schema_version = encoded.schema_version,
        .audience = encoded.audience,
        .key_id = encoded.key_id,
        .grant_id = encoded.grant_id,
        .executor_node_id = encoded.executor_node_id,
        .session_id = encoded.session_id,
        .controller_plan_digest = encoded.controller_plan_digest,
        .plan_content_digest = encoded.plan_content_digest,
        .exposure_id = encoded.exposure_id,
        .generation = encoded.generation,
        .scope_digest = encoded.scope_digest,
        .manifest_digest = encoded.manifest_digest,
        .policy_revision = encoded.policy_revision,
        .issued_at_ms = encoded.issued_at_ms,
        .expires_at_ms = encoded.expires_at_ms,
    };
}

auto signed_wire(const change_apply_authorization_claims& value, std::string signature)
    -> wire_signed_envelope {
    return {
        .schema_version = value.schema_version,
        .audience = value.audience,
        .key_id = value.key_id,
        .grant_id = value.grant_id,
        .executor_node_id = value.executor_node_id,
        .session_id = value.session_id,
        .controller_plan_digest = value.controller_plan_digest,
        .plan_content_digest = value.plan_content_digest,
        .exposure_id = value.exposure_id,
        .generation = value.generation,
        .scope_digest = value.scope_digest,
        .manifest_digest = value.manifest_digest,
        .policy_revision = value.policy_revision,
        .issued_at_ms = value.issued_at_ms,
        .expires_at_ms = value.expires_at_ms,
        .signature = std::move(signature),
    };
}

auto final_wire(
    const change_apply_authorization_claims& value,
    std::string signature,
    std::string authorization_digest
) -> wire_authorization {
    return {
        .schema_version = value.schema_version,
        .audience = value.audience,
        .key_id = value.key_id,
        .grant_id = value.grant_id,
        .executor_node_id = value.executor_node_id,
        .session_id = value.session_id,
        .controller_plan_digest = value.controller_plan_digest,
        .plan_content_digest = value.plan_content_digest,
        .exposure_id = value.exposure_id,
        .generation = value.generation,
        .scope_digest = value.scope_digest,
        .manifest_digest = value.manifest_digest,
        .policy_revision = value.policy_revision,
        .issued_at_ms = value.issued_at_ms,
        .expires_at_ms = value.expires_at_ms,
        .signature = std::move(signature),
        .authorization_digest = std::move(authorization_digest),
    };
}

auto digest_json(std::string_view json) -> result<std::string> {
    return container::sha256_hex(
        std::span{
            reinterpret_cast<const unsigned char*>(json.data()),
            json.size(),
        }
    );
}

auto context_matches(
    const change_apply_authorization_claims& value,
    const change_apply_authorization_context& expected
) -> bool {
    return value.executor_node_id == expected.executor_node_id &&
           value.session_id == expected.session_id &&
           value.controller_plan_digest == expected.controller_plan_digest &&
           value.plan_content_digest == expected.plan_content_digest &&
           value.exposure_id == expected.exposure_id && value.generation == expected.generation &&
           value.scope_digest == expected.scope_digest &&
           value.manifest_digest == expected.manifest_digest &&
           value.policy_revision == expected.policy_revision;
}

} // namespace

auto change_apply_authorization_signing_payload(const change_apply_authorization_claims& claims)
    -> result<std::string> {
    if (!valid_claims(claims)) {
        return std::unexpected(std::string{"change apply authorization claims are invalid"});
    }
    auto payload = glz::write_json(wire(claims));
    if (!payload || payload->empty() || payload->size() > max_authorization_bytes) {
        return std::unexpected(std::string{"encode change apply authorization claims"});
    }
    return std::move(*payload);
}

auto encode_change_apply_authorization(
    const change_apply_authorization_claims& claims, std::string signature
) -> result<change_apply_authorization> {
    auto payload = change_apply_authorization_signing_payload(claims);
    if (!payload || !valid_signature(signature)) {
        return std::unexpected(
            payload ? std::string{"change apply authorization signature is invalid"}
                    : payload.error()
        );
    }
    auto signed_envelope = glz::write_json(signed_wire(claims, signature));
    if (!signed_envelope || signed_envelope->empty() ||
        signed_envelope->size() > max_authorization_bytes) {
        return std::unexpected(std::string{"encode signed change apply authorization"});
    }
    auto digest = digest_json(*signed_envelope);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    auto envelope = glz::write_json(final_wire(claims, signature, *digest));
    if (!envelope || envelope->empty() || envelope->size() > max_authorization_bytes) {
        return std::unexpected(std::string{"encode change apply authorization envelope"});
    }
    return change_apply_authorization{
        .claims = claims,
        .signature = std::move(signature),
        .authorization_digest = std::move(*digest),
        .canonical_json = std::move(*envelope),
    };
}

auto verify_change_apply_authorization(
    std::string_view canonical_json,
    const change_apply_authorization_context& expected,
    std::uint64_t now_ms,
    const change_apply_signature_verifier& verifier
) -> result<change_apply_authorization> {
    if (canonical_json.empty() || canonical_json.size() > max_authorization_bytes) {
        return std::unexpected(std::string{"change apply authorization exceeds its bound"});
    }
    wire_authorization encoded;
    if (const auto error = glz::read<strict_read_options>(encoded, canonical_json); error) {
        return std::unexpected(std::string{"change apply authorization schema is invalid"});
    }
    auto value = claims(encoded);
    if (!valid_claims(value) || !valid_signature(encoded.signature) ||
        !valid_digest(encoded.authorization_digest)) {
        return std::unexpected(std::string{"change apply authorization fields are invalid"});
    }
    auto payload = change_apply_authorization_signing_payload(value);
    auto signed_envelope = glz::write_json(signed_wire(value, encoded.signature));
    auto digest = signed_envelope
                      ? digest_json(*signed_envelope)
                      : result<std::string>{
                            std::unexpected(std::string{"encode signed change apply authorization"})
                        };
    if (!payload || !signed_envelope || !digest || *digest != encoded.authorization_digest) {
        return std::unexpected(std::string{"change apply authorization digest mismatch"});
    }
    auto reencoded = glz::write_json(encoded);
    if (!reencoded || *reencoded != canonical_json) {
        return std::unexpected(std::string{"change apply authorization is not canonical"});
    }
    if (!context_matches(value, expected)) {
        return std::unexpected(std::string{"change apply authorization context mismatch"});
    }
    if (now_ms < value.issued_at_ms || now_ms >= value.expires_at_ms) {
        return std::unexpected(std::string{"change apply authorization is not currently valid"});
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(payload->data()),
        payload->size(),
    };
    if (auto verified = verifier.verify(value, bytes, encoded.signature, now_ms); !verified) {
        return std::unexpected(
            std::string{"change apply authorization signature rejected: "} + verified.error()
        );
    }
    return change_apply_authorization{
        .claims = std::move(value),
        .signature = std::move(encoded.signature),
        .authorization_digest = std::move(encoded.authorization_digest),
        .canonical_json = std::string{canonical_json},
    };
}

} // namespace glove::supervisor
