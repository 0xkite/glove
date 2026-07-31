#pragma once

#include "glove/container/profile.hpp"
#include "glove/container/refinement_protocol.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace glove::container {

// Authenticated terminal evidence emitted by the Glove-owned lifecycle. The
// receipt digest covers the complete structural receipt; the HMAC covers its
// digest plus the exact session, controller plan, sequence, key, and prior
// chain head.
struct authenticated_resource_enforcement_receipt {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string key_id;
    std::string session_id;
    std::string controller_plan_digest;
    resource_enforcement_receipt receipt;
    std::string receipt_digest;
    std::string previous_hmac;
    std::string this_hmac;

    auto operator==(const authenticated_resource_enforcement_receipt&) const -> bool = default;
};

// Separate authenticated envelope for refinement evidence. It cannot be
// decoded as or substituted for the resource-enforcement V1 envelope.
struct authenticated_refinement_evaluation_receipt {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string key_id;
    std::string session_id;
    std::string controller_plan_digest;
    refinement_evaluation_receipt receipt;
    std::string receipt_digest;
    std::string previous_hmac;
    std::string this_hmac;

    auto operator==(const authenticated_refinement_evaluation_receipt&) const -> bool = default;
};

// Trusted verifier state. Persisting this anchor makes replay, reordering,
// deletion before the head, and cross-key substitution observable.
struct receipt_audit_anchor {
    std::string key_id;
    std::uint64_t sequence = 0;
    std::string head_hmac;

    [[nodiscard]] static auto create(std::string_view key_hex)
        -> std::expected<std::unique_ptr<receipt_audit_anchor>, std::string>;

    auto operator==(const receipt_audit_anchor&) const -> bool = default;
};

// In-memory producer state intended to be owned by one supervisor boot. The
// 32-byte key is supplied out-of-band and wiped when the chain is destroyed.
class receipt_audit_chain {
public:
    class construction_token {
    private:
        construction_token() = default;
        friend class receipt_audit_chain;
    };

    receipt_audit_chain(
        construction_token token, std::array<unsigned char, 32> key, std::string key_id
    );
    receipt_audit_chain(const receipt_audit_chain&) = delete;
    auto operator=(const receipt_audit_chain&) -> receipt_audit_chain& = delete;
    receipt_audit_chain(receipt_audit_chain&&) = delete;
    auto operator=(receipt_audit_chain&&) -> receipt_audit_chain& = delete;
    ~receipt_audit_chain();

    [[nodiscard]] static auto create(std::string_view key_hex)
        -> std::expected<std::unique_ptr<receipt_audit_chain>, std::string>;

    [[nodiscard]] auto append(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        const resource_enforcement_receipt& receipt
    ) -> std::expected<authenticated_resource_enforcement_receipt, std::string>;

    [[nodiscard]] auto append_refinement(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        const refinement_evaluation_receipt& receipt
    ) -> std::expected<authenticated_refinement_evaluation_receipt, std::string>;

    [[nodiscard]] auto key_id() const noexcept -> std::string_view { return key_id_; }

    [[nodiscard]] auto sequence() const noexcept -> std::uint64_t { return sequence_; }

    [[nodiscard]] auto head_hmac() const noexcept -> std::string_view { return head_hmac_; }

private:
    friend class receipt_audit_journal;

    std::array<unsigned char, 32> key_{};
    std::string key_id_;
    std::uint64_t sequence_ = 0;
    std::string head_hmac_ = std::string(64, '0');
};

[[nodiscard]] auto resource_enforcement_receipt_digest(const resource_enforcement_receipt& receipt)
    -> std::expected<std::string, std::string>;

// Low-level stateless helper retained for verifier tests. Production append
// sequencing is owned by receipt_audit_chain and receipt_audit_journal.
[[nodiscard]] auto make_authenticated_refinement_evaluation_receipt(
    std::string_view key_hex,
    std::uint64_t sequence,
    std::string_view previous_hmac,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const refinement_evaluation_receipt& receipt
) -> std::expected<authenticated_refinement_evaluation_receipt, std::string>;

// Verify without advancing on failure. `anchor` must be durable trusted state,
// not a value supplied by the envelope or its remote controller.
[[nodiscard]] auto verify_receipt_audit_envelope(
    const authenticated_resource_enforcement_receipt& envelope,
    std::string_view key_hex,
    std::string_view expected_session_id,
    std::string_view expected_controller_plan_digest,
    receipt_audit_anchor& anchor
) -> std::expected<void, std::string>;

[[nodiscard]] auto verify_refinement_receipt_audit_envelope(
    const authenticated_refinement_evaluation_receipt& envelope,
    std::string_view key_hex,
    std::string_view expected_session_id,
    std::string_view expected_controller_plan_digest,
    receipt_audit_anchor& anchor
) -> std::expected<void, std::string>;

} // namespace glove::container
