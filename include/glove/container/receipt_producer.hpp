#pragma once

#include "glove/container/receipt_journal.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace glove::container {

struct receipt_audit_producer_config {
    std::filesystem::path key_path;
    std::filesystem::path journal_path;
    std::uint64_t max_journal_bytes = default_receipt_journal_bytes;
};

// Supervisor-owned durable receipt producer. Bootstrap reconciliation is an
// explicit gate: terminal capacity cannot be reserved until an authenticated
// controller confirms the exact local head.
class receipt_audit_producer final : public std::enable_shared_from_this<receipt_audit_producer> {
public:
    class construction_token {
    private:
        construction_token() = default;
        friend class receipt_audit_producer;
    };

    class terminal_reservation {
    public:
        terminal_reservation(const terminal_reservation&) = delete;
        auto operator=(const terminal_reservation&) -> terminal_reservation& = delete;
        terminal_reservation(terminal_reservation&& other) noexcept;
        auto operator=(terminal_reservation&&) -> terminal_reservation& = delete;
        ~terminal_reservation();

        [[nodiscard]] auto matches_execution(
            std::string_view session_id,
            std::string_view controller_plan_digest,
            std::string_view profile_digest
        ) const noexcept -> bool;

    private:
        terminal_reservation(
            construction_token token,
            std::shared_ptr<receipt_audit_producer> owner,
            std::string session_id = {},
            std::string controller_plan_digest = {},
            std::string profile_digest = {}
        );
        void release() noexcept;

        std::shared_ptr<receipt_audit_producer> owner_;
        std::string session_id_;
        std::string controller_plan_digest_;
        std::string profile_digest_;
        friend class receipt_audit_producer;
    };

    explicit receipt_audit_producer(construction_token token);
    receipt_audit_producer(const receipt_audit_producer&) = delete;
    auto operator=(const receipt_audit_producer&) -> receipt_audit_producer& = delete;
    receipt_audit_producer(receipt_audit_producer&&) = delete;
    auto operator=(receipt_audit_producer&&) -> receipt_audit_producer& = delete;
    ~receipt_audit_producer();

    [[nodiscard]] static auto initialize(const receipt_audit_producer_config& config)
        -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string>;

    // Create only when the journal path is absent; otherwise recover from the
    // authenticated Sage prefix. A path race fails closed.
    [[nodiscard]] static auto bootstrap(
        const receipt_audit_producer_config& config, const receipt_audit_anchor& trusted_sage_anchor
    ) -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string>;

    // Recovery always starts from a Sage-owned trusted anchor. A behind anchor
    // may page pending envelopes but cannot reserve a new terminal record until
    // `acknowledge_bootstrap` confirms the exact current local head.
    [[nodiscard]] static auto recover(
        const receipt_audit_producer_config& config, const receipt_audit_anchor& trusted_sage_anchor
    ) -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string>;

    // Read-only capability discovery uses the same hardened key loader as
    // producer startup without creating, opening, or reconciling a journal.
    [[nodiscard]] static auto audit_key_id(const receipt_audit_producer_config& config)
        -> std::expected<std::string, std::string>;

    // The caller must be the authenticated local supervisor control path; this
    // primitive performs exact-anchor reconciliation, not caller authentication.
    [[nodiscard]] auto acknowledge_bootstrap(const receipt_audit_anchor& sage_anchor)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto bootstrap_reconciled() const -> bool;

    // Reserve the maximum possible framed envelope before starting a child so
    // journal capacity exhaustion is a pre-launch failure.
    [[nodiscard]] auto reserve_terminal() -> std::expected<terminal_reservation, std::string>;
    // Execution-bound reservations cannot be used to commit another session,
    // controller plan, or prepared profile and can serve as typed evidence for
    // the registry's durable starting transition.
    [[nodiscard]] auto reserve_terminal(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        std::string_view profile_digest
    ) -> std::expected<terminal_reservation, std::string>;

    // Success means the complete authenticated envelope is durably synced.
    [[nodiscard]] auto commit_terminal(
        terminal_reservation reservation,
        std::string_view session_id,
        std::string_view controller_plan_digest,
        const resource_enforcement_receipt& receipt
    ) -> std::expected<authenticated_resource_enforcement_receipt, std::string>;
    [[nodiscard]] auto commit_refinement_terminal(
        terminal_reservation reservation,
        std::string_view session_id,
        std::string_view controller_plan_digest,
        const refinement_evaluation_receipt& receipt
    ) -> std::expected<authenticated_refinement_evaluation_receipt, std::string>;

    // Exact durable-membership confirmation for registry terminalization and
    // crash recovery. The envelope is not trusted merely because the caller
    // possesses it; it must match the producer's authenticated journal.
    [[nodiscard]] auto
    confirms_terminal(const authenticated_resource_enforcement_receipt& envelope) const
        -> std::expected<bool, std::string>;
    [[nodiscard]] auto
    confirms_terminal(const authenticated_refinement_evaluation_receipt& envelope) const
        -> std::expected<bool, std::string>;
    [[nodiscard]] auto terminal_for_execution(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        std::string_view profile_digest
    ) const
        -> std::expected<std::optional<authenticated_resource_enforcement_receipt>, std::string>;
    [[nodiscard]] auto refinement_terminal_for_execution(
        std::string_view session_id,
        std::string_view controller_plan_digest,
        std::string_view profile_digest
    ) const
        -> std::expected<std::optional<authenticated_refinement_evaluation_receipt>, std::string>;

    [[nodiscard]] auto
    page_after(const receipt_audit_anchor& trusted_sage_anchor, std::size_t limit) const
        -> std::expected<receipt_journal_page, std::string>;
    [[nodiscard]] auto anchor() const -> receipt_audit_anchor;

private:
    void release_reservation() noexcept;

    mutable std::mutex mutex_;
    std::unique_ptr<receipt_audit_journal> journal_;
    std::uint64_t reserved_bytes_ = 0;
    bool bootstrap_reconciled_ = false;
};

} // namespace glove::container
