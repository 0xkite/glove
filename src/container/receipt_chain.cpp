#include "glove/container/receipt_chain.hpp"

#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

constexpr std::size_t digest_bytes = 32;
constexpr std::size_t hmac_block_bytes = 64;
constexpr std::size_t max_identifier_bytes = 128;

class canonical_encoder {
public:
    void append_u8(std::uint8_t value) { bytes_.push_back(value); }

    void append_u32(std::uint32_t value) {
        bytes_.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>(value & 0xffU));
    }

    void append_u64(std::uint64_t value) {
        bytes_.push_back(static_cast<unsigned char>((value >> 56U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 48U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 40U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 32U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
        bytes_.push_back(static_cast<unsigned char>(value & 0xffU));
    }

    void append_string(std::string_view value) {
        append_u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

    void wipe() noexcept { std::ranges::fill(bytes_, 0U); }

private:
    std::vector<unsigned char> bytes_;
};

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_identifier(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto hex_nibble(unsigned char value) -> std::expected<unsigned char, std::string> {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned char>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned char>(value - 'a' + 10U);
    }
    return std::unexpected(std::string{"invalid lowercase hexadecimal input"});
}

auto decode_digest(std::string_view value)
    -> std::expected<std::array<unsigned char, digest_bytes>, std::string> {
    if (!valid_digest(value)) {
        return std::unexpected(std::string{"expected 32-byte lowercase hexadecimal input"});
    }
    std::array<unsigned char, digest_bytes> decoded{};
    const auto* input = value.data();
    for (auto& byte : decoded) {
        auto high = hex_nibble(static_cast<unsigned char>(*input++));
        auto low = hex_nibble(static_cast<unsigned char>(*input++));
        if (!high || !low) {
            return std::unexpected(std::string{"invalid lowercase hexadecimal input"});
        }
        byte = static_cast<unsigned char>(
            (static_cast<unsigned int>(*high) << 4U) | static_cast<unsigned int>(*low)
        );
    }
    return decoded;
}

auto backend_name(sandbox_backend backend) noexcept -> std::string_view {
    switch (backend) {
    case sandbox_backend::linux_production:
        return "linux_production";
    case sandbox_backend::apple_container:
        return "apple_container";
    case sandbox_backend::macos_experimental:
        return "macos_experimental";
    }
    return {};
}

auto mechanism_name(enforcement_mechanism mechanism) noexcept -> std::string_view {
    switch (mechanism) {
    case enforcement_mechanism::unavailable:
        return "unavailable";
    case enforcement_mechanism::rlimit:
        return "rlimit";
    case enforcement_mechanism::cgroup_v2:
        return "cgroup_v2";
    case enforcement_mechanism::watchdog:
        return "watchdog";
    case enforcement_mechanism::filesystem_quota:
        return "filesystem_quota";
    case enforcement_mechanism::byte_counter:
        return "byte_counter";
    }
    return {};
}

auto termination_name(resource_termination_cause cause) noexcept -> std::string_view {
    switch (cause) {
    case resource_termination_cause::exited:
        return "exited";
    case resource_termination_cause::signaled:
        return "signaled";
    case resource_termination_cause::cpu_time_limit:
        return "cpu_time_limit";
    case resource_termination_cause::memory_limit:
        return "memory_limit";
    case resource_termination_cause::pid_limit:
        return "pid_limit";
    case resource_termination_cause::wall_time_limit:
        return "wall_time_limit";
    case resource_termination_cause::disk_limit:
        return "disk_limit";
    case resource_termination_cause::terminal_output_limit:
        return "terminal_output_limit";
    case resource_termination_cause::supervisor_error:
        return "supervisor_error";
    }
    return {};
}

void append_limits(canonical_encoder& encoder, const resource_limits& limits) {
    encoder.append_u64(limits.cpu_time_ms);
    encoder.append_u64(limits.memory_bytes);
    encoder.append_u32(limits.pids);
    encoder.append_u64(limits.wall_time_ms);
    encoder.append_u64(limits.disk_bytes);
    encoder.append_u64(limits.terminal_output_bytes);
}

void append_capabilities(
    canonical_encoder& encoder, const resource_enforcement_capabilities& capabilities
) {
    encoder.append_string(mechanism_name(capabilities.cpu_time));
    encoder.append_string(mechanism_name(capabilities.memory));
    encoder.append_string(mechanism_name(capabilities.pids));
    encoder.append_string(mechanism_name(capabilities.wall_time));
    encoder.append_string(mechanism_name(capabilities.disk));
    encoder.append_string(mechanism_name(capabilities.terminal_output));
    encoder.append_u8(capabilities.receipt_schema_version);
}

auto encode_receipt(const resource_enforcement_receipt& receipt)
    -> std::expected<canonical_encoder, std::string> {
    auto valid = validate_resource_enforcement_receipt(
        receipt,
        receipt.configured_limits,
        receipt.mechanisms,
        receipt.backend,
        receipt.profile_digest
    );
    if (!valid) {
        return std::unexpected(std::string{"invalid receipt for audit: "} + valid.error());
    }
    const auto backend = backend_name(receipt.backend);
    const auto termination = termination_name(receipt.termination_cause);
    if (backend.empty() || termination.empty()) {
        return std::unexpected(std::string{"receipt contains an unknown enum value"});
    }
    canonical_encoder encoder;
    encoder.append_string("glove.resource-enforcement-receipt");
    encoder.append_u8(1);
    encoder.append_u8(receipt.schema_version);
    encoder.append_string(receipt.profile_digest);
    encoder.append_string(backend);
    encoder.append_string(receipt.backend_id);
    append_limits(encoder, receipt.configured_limits);
    append_capabilities(encoder, receipt.mechanisms);
    encoder.append_u64(receipt.observed.cpu_time_ms);
    encoder.append_u64(receipt.observed.peak_memory_bytes);
    encoder.append_u32(receipt.observed.peak_pids);
    encoder.append_u64(receipt.observed.wall_time_ms);
    encoder.append_u64(receipt.observed.disk_bytes);
    encoder.append_u64(receipt.observed.terminal_output_bytes);
    encoder.append_string(termination);
    encoder.append_u8(receipt.exit_code.has_value() ? 1U : 0U);
    if (receipt.exit_code) {
        encoder.append_u32(static_cast<std::uint32_t>(*receipt.exit_code));
    }
    encoder.append_u64(receipt.started_at_ms);
    encoder.append_u64(receipt.finished_at_ms);
    if (!receipt.library_projections.empty()) {
        encoder.append_string("glove.library-projection-receipts");
        encoder.append_u8(1);
        encoder.append_u32(static_cast<std::uint32_t>(receipt.library_projections.size()));
        for (const auto& projection : receipt.library_projections) {
            encoder.append_string(projection.projection_id);
            encoder.append_string(projection.destination_alias);
            encoder.append_string(projection.target_path);
            encoder.append_string(projection.content_digest);
        }
    }
    if (!receipt.retained_changes.empty()) {
        encoder.append_string("glove.retained-change-receipts");
        encoder.append_u8(1);
        encoder.append_u32(static_cast<std::uint32_t>(receipt.retained_changes.size()));
        for (const auto& change : receipt.retained_changes) {
            encoder.append_string(change.exposure_id);
            encoder.append_u64(change.generation);
            encoder.append_string(change.scope_digest);
            encoder.append_string(change.source_identity_digest);
            encoder.append_string(change.baseline_tree_digest);
            encoder.append_string(change.staged_tree_digest);
            encoder.append_string(change.manifest_digest);
            encoder.append_u64(change.created);
            encoder.append_u64(change.modified);
            encoder.append_u64(change.renamed);
            encoder.append_u64(change.removed);
            encoder.append_u64(change.before_bytes);
            encoder.append_u64(change.after_bytes);
        }
    }
    return encoder;
}

auto derive_key_id(std::span<const unsigned char> key) -> std::expected<std::string, std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.audit-key-id");
    encoder.append_u8(1);
    encoder.append_u32(static_cast<std::uint32_t>(key.size()));
    for (const auto byte : key) {
        encoder.append_u8(byte);
    }
    auto key_id = detail::sha256_hex(encoder.bytes());
    encoder.wipe();
    return key_id;
}

auto hmac_sha256_hex(std::span<const unsigned char> key, std::span<const unsigned char> message)
    -> std::expected<std::string, std::string> {
    if (key.size() > hmac_block_bytes) {
        return std::unexpected(std::string{"HMAC key exceeds one SHA-256 block"});
    }
    std::array<unsigned char, hmac_block_bytes> inner_pad{};
    std::array<unsigned char, hmac_block_bytes> outer_pad{};
    std::ranges::fill(inner_pad, 0x36U);
    std::ranges::fill(outer_pad, 0x5cU);
    auto* inner_cursor = inner_pad.data();
    auto* outer_cursor = outer_pad.data();
    for (const auto byte : key) {
        *inner_cursor++ ^= byte;
        *outer_cursor++ ^= byte;
    }
    std::vector<unsigned char> inner;
    inner.reserve(inner_pad.size() + message.size());
    inner.insert(inner.end(), inner_pad.begin(), inner_pad.end());
    inner.insert(inner.end(), message.begin(), message.end());
    auto inner_hex = detail::sha256_hex(inner);
    std::ranges::fill(inner_pad, 0U);
    std::ranges::fill(inner, 0U);
    if (!inner_hex) {
        std::ranges::fill(outer_pad, 0U);
        return std::unexpected(inner_hex.error());
    }
    auto inner_digest = decode_digest(*inner_hex);
    if (!inner_digest) {
        std::ranges::fill(outer_pad, 0U);
        return std::unexpected(inner_digest.error());
    }
    std::vector<unsigned char> outer;
    outer.reserve(outer_pad.size() + inner_digest->size());
    outer.insert(outer.end(), outer_pad.begin(), outer_pad.end());
    outer.insert(outer.end(), inner_digest->begin(), inner_digest->end());
    auto digest = detail::sha256_hex(outer);
    std::ranges::fill(outer_pad, 0U);
    std::ranges::fill(*inner_digest, 0U);
    std::ranges::fill(outer, 0U);
    return digest;
}

auto envelope_material(
    std::uint64_t sequence,
    std::string_view key_id,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view receipt_digest,
    std::string_view previous_hmac
) -> canonical_encoder {
    canonical_encoder encoder;
    encoder.append_string("glove.receipt-audit-envelope");
    encoder.append_u8(1);
    encoder.append_u64(sequence);
    encoder.append_string(key_id);
    encoder.append_string(session_id);
    encoder.append_string(controller_plan_digest);
    encoder.append_string(receipt_digest);
    encoder.append_string(previous_hmac);
    return encoder;
}

auto constant_time_digest_equal(std::string_view left, std::string_view right) -> bool {
    auto left_bytes = decode_digest(left);
    auto right_bytes = decode_digest(right);
    if (!left_bytes || !right_bytes) {
        return false;
    }
    unsigned char difference = 0;
    auto* right_cursor = right_bytes->data();
    for (const auto left_byte : *left_bytes) {
        difference |= static_cast<unsigned char>(left_byte ^ *right_cursor++);
    }
    return difference == 0;
}

} // namespace

receipt_audit_chain::receipt_audit_chain(
    [[maybe_unused]] construction_token token,
    std::array<unsigned char, digest_bytes> key,
    std::string key_id
)
    : key_{key}, key_id_{std::move(key_id)} {}

receipt_audit_chain::~receipt_audit_chain() {
    std::ranges::fill(key_, 0U);
}

auto receipt_audit_chain::create(std::string_view key_hex)
    -> std::expected<std::unique_ptr<receipt_audit_chain>, std::string> {
    auto key = decode_digest(key_hex);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto key_id = derive_key_id(*key);
    if (!key_id) {
        std::ranges::fill(*key, 0U);
        return std::unexpected(key_id.error());
    }
    auto chain =
        std::make_unique<receipt_audit_chain>(construction_token{}, *key, std::move(*key_id));
    std::ranges::fill(*key, 0U);
    return chain;
}

auto receipt_audit_chain::append(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const resource_enforcement_receipt& receipt
) -> std::expected<authenticated_resource_enforcement_receipt, std::string> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(std::string{"invalid receipt audit session identity"});
    }
    if (!valid_digest(controller_plan_digest)) {
        return std::unexpected(std::string{"invalid receipt audit controller plan digest"});
    }
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(std::string{"receipt audit sequence exhausted"});
    }
    auto receipt_digest = resource_enforcement_receipt_digest(receipt);
    if (!receipt_digest) {
        return std::unexpected(receipt_digest.error());
    }
    const auto next_sequence = sequence_ + 1U;
    const auto material = envelope_material(
        next_sequence, key_id_, session_id, controller_plan_digest, *receipt_digest, head_hmac_
    );
    auto this_hmac = hmac_sha256_hex(key_, material.bytes());
    if (!this_hmac) {
        return std::unexpected(this_hmac.error());
    }
    authenticated_resource_enforcement_receipt envelope{
        .schema_version = 1,
        .sequence = next_sequence,
        .key_id = key_id_,
        .session_id = std::string{session_id},
        .controller_plan_digest = std::string{controller_plan_digest},
        .receipt = receipt,
        .receipt_digest = std::move(*receipt_digest),
        .previous_hmac = head_hmac_,
        .this_hmac = std::move(*this_hmac),
    };
    sequence_ = envelope.sequence;
    head_hmac_ = envelope.this_hmac;
    return envelope;
}

auto receipt_audit_anchor::create(std::string_view key_hex)
    -> std::expected<std::unique_ptr<receipt_audit_anchor>, std::string> {
    auto key = decode_digest(key_hex);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto key_id = derive_key_id(*key);
    std::ranges::fill(*key, 0U);
    if (!key_id) {
        return std::unexpected(key_id.error());
    }
    return std::make_unique<receipt_audit_anchor>(receipt_audit_anchor{
        .key_id = std::move(*key_id),
        .sequence = 0,
        .head_hmac = std::string(64, '0'),
    });
}

auto resource_enforcement_receipt_digest(const resource_enforcement_receipt& receipt)
    -> std::expected<std::string, std::string> {
    auto encoded = encode_receipt(receipt);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return detail::sha256_hex(encoded->bytes());
}

auto verify_receipt_audit_envelope(
    const authenticated_resource_enforcement_receipt& envelope,
    std::string_view key_hex,
    std::string_view expected_session_id,
    std::string_view expected_controller_plan_digest,
    receipt_audit_anchor& anchor
) -> std::expected<void, std::string> {
    auto key = decode_digest(key_hex);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto key_id = derive_key_id(*key);
    if (!key_id) {
        std::ranges::fill(*key, 0U);
        return std::unexpected(key_id.error());
    }
    auto fail = [&](std::string message) -> std::expected<void, std::string> {
        std::ranges::fill(*key, 0U);
        return std::unexpected(std::move(message));
    };
    if (envelope.schema_version != 1) {
        return fail("unsupported receipt audit envelope schema");
    }
    if (!valid_identifier(expected_session_id) || envelope.session_id != expected_session_id) {
        return fail("receipt audit session identity mismatch");
    }
    if (!valid_digest(expected_controller_plan_digest) ||
        envelope.controller_plan_digest != expected_controller_plan_digest) {
        return fail("receipt audit controller plan digest mismatch");
    }
    if (anchor.key_id != *key_id || envelope.key_id != *key_id) {
        return fail("receipt audit key identity mismatch");
    }
    if (anchor.sequence == std::numeric_limits<std::uint64_t>::max() ||
        envelope.sequence != anchor.sequence + 1U) {
        return fail("receipt audit sequence mismatch");
    }
    if (!constant_time_digest_equal(envelope.previous_hmac, anchor.head_hmac)) {
        return fail("receipt audit previous HMAC mismatch");
    }
    auto receipt_digest = resource_enforcement_receipt_digest(envelope.receipt);
    if (!receipt_digest || !constant_time_digest_equal(envelope.receipt_digest, *receipt_digest)) {
        return fail("receipt audit resource receipt digest mismatch");
    }
    const auto material = envelope_material(
        envelope.sequence,
        envelope.key_id,
        envelope.session_id,
        envelope.controller_plan_digest,
        envelope.receipt_digest,
        envelope.previous_hmac
    );
    auto expected_hmac = hmac_sha256_hex(*key, material.bytes());
    std::ranges::fill(*key, 0U);
    if (!expected_hmac || !constant_time_digest_equal(envelope.this_hmac, *expected_hmac)) {
        return std::unexpected(std::string{"receipt audit HMAC mismatch"});
    }
    anchor.sequence = envelope.sequence;
    anchor.head_hmac = envelope.this_hmac;
    return {};
}

} // namespace glove::container
