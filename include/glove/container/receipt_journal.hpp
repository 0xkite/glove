#pragma once

#include "glove/container/receipt_chain.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

inline constexpr std::uint64_t default_receipt_journal_bytes = std::uint64_t{64} * 1024U * 1024U;
inline constexpr std::uint64_t max_receipt_journal_record_payload_bytes = std::uint64_t{64} * 1024U;
inline constexpr std::uint64_t max_receipt_journal_record_bytes =
    max_receipt_journal_record_payload_bytes + 8U;
inline constexpr std::size_t max_receipt_reconciliation_page = 1'000U;

struct receipt_journal_page {
    std::vector<authenticated_resource_enforcement_receipt> envelopes;
    std::vector<authenticated_refinement_evaluation_receipt> refinement_envelopes;
    bool has_more = false;
    receipt_audit_anchor local_anchor;
};

struct receipt_journal_record {
    std::string kind;
    std::optional<authenticated_resource_enforcement_receipt> resource;
    std::optional<authenticated_refinement_evaluation_receipt> refinement;

    auto operator==(const receipt_journal_record&) const -> bool = default;
};

// Durable Glove-owned receipt production. One live handle owns a nonblocking
// exclusive advisory lock. The journal is intentionally a private supervisor
// primitive: it neither launches a process nor exposes a remote control method.
class receipt_audit_journal {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class receipt_audit_journal;
    };

    receipt_audit_journal(construction_token token, std::unique_ptr<implementation> state);
    receipt_audit_journal(const receipt_audit_journal&) = delete;
    auto operator=(const receipt_audit_journal&) -> receipt_audit_journal& = delete;
    receipt_audit_journal(receipt_audit_journal&&) = delete;
    auto operator=(receipt_audit_journal&&) -> receipt_audit_journal& = delete;
    ~receipt_audit_journal();

    [[nodiscard]] static auto create_new(
        const std::filesystem::path& path,
        std::string_view key_hex,
        std::uint64_t max_bytes = default_receipt_journal_bytes
    ) -> std::expected<std::unique_ptr<receipt_audit_journal>, std::string>;

    // A partial final record is never repaired without a trusted Sage anchor.
    // When supplied, the anchor must be an exact prefix of every complete
    // record retained by recovery.
    [[nodiscard]] static auto open_existing(
        const std::filesystem::path& path,
        std::string_view key_hex,
        std::optional<receipt_audit_anchor> trusted_peer_anchor = std::nullopt,
        std::uint64_t max_bytes = default_receipt_journal_bytes
    ) -> std::expected<std::unique_ptr<receipt_audit_journal>, std::string>;

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

    // This bounded exact-prefix page is a local reconciliation primitive, not
    // an authenticated transport or acknowledgement protocol.
    [[nodiscard]] auto
    page_after(const receipt_audit_anchor& trusted_peer_anchor, std::size_t limit) const
        -> std::expected<receipt_journal_page, std::string>;

    // Confirm that an exact authenticated envelope is present in the durable
    // journal. This is the supervisor-side bridge used to close a session
    // registry record after a terminal receipt has already been fsynced.
    [[nodiscard]] auto
    contains_exact(const authenticated_resource_enforcement_receipt& envelope) const
        -> std::expected<bool, std::string>;
    [[nodiscard]] auto
    contains_exact(const authenticated_refinement_evaluation_receipt& envelope) const
        -> std::expected<bool, std::string>;

    // Locate the one durable terminal envelope for an immutable execution.
    // Multiple matches are treated as journal corruption rather than choosing
    // an arbitrary terminal result during restart reconciliation.
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

    [[nodiscard]] auto anchor() const -> receipt_audit_anchor;
    [[nodiscard]] auto record_count() const -> std::uint64_t;
    [[nodiscard]] auto durable_bytes() const -> std::uint64_t;
    [[nodiscard]] auto remaining_capacity() const -> std::expected<std::uint64_t, std::string>;
    [[nodiscard]] auto repaired_torn_tail() const -> bool;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::container
