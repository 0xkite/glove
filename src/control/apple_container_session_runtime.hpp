#pragma once

#include "glove/control/session_runtime.hpp"
#include "glove/audit/sink.hpp"

#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace glove::control::apple_detail {

struct apple_container_runtime_config {
    std::filesystem::path container_cli;
    std::string image_reference;
    // Exact OCI index digest, including the sha256: prefix.
    std::string image_digest;
    // Exact sha256 digest of the package lock embedded in Glove's managed
    // harness image. Empty retains the restricted image-contained probe lane.
    std::optional<std::string> harness_closure_digest;
    std::shared_ptr<audit::sink> egress_audit;
    std::filesystem::path session_root;
    std::size_t max_sessions = 64;
};

// Apple Silicon implementation of the authenticated managed-session seam.
// The initial implementation deliberately accepts only no-network,
// image-contained closures with memory-backed writable state. Host workspace,
// credential, library, and egress projections are rejected until their
// separately audited brokers are configured.
class apple_container_session_runtime final : public session_runtime {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class apple_container_session_runtime;
    };

    apple_container_session_runtime(
        construction_token token, std::unique_ptr<implementation> state
    );
    apple_container_session_runtime(const apple_container_session_runtime&) = delete;
    auto operator=(const apple_container_session_runtime&)
        -> apple_container_session_runtime& = delete;
    apple_container_session_runtime(apple_container_session_runtime&&) = delete;
    auto operator=(apple_container_session_runtime&&)
        -> apple_container_session_runtime& = delete;
    ~apple_container_session_runtime();

    [[nodiscard]] static auto
    create(session_registry& registry, apple_container_runtime_config config)
        -> std::expected<std::unique_ptr<apple_container_session_runtime>, std::string>;

    [[nodiscard]] auto backend_id() const noexcept -> std::string_view override {
        return "apple_container";
    }
    [[nodiscard]] auto agent_runtime_adapter_schema_version() const noexcept
        -> std::uint8_t override;
    [[nodiscard]] auto managed_runtime_ids() const -> std::vector<std::string> override;
    [[nodiscard]] auto resource_capabilities() const noexcept
        -> container::resource_enforcement_capabilities override;
    [[nodiscard]] auto start(
        container::receipt_audit_producer& receipt_producer,
        const session_start_authorization& authorization,
        std::string_view idempotency_namespace,
        std::uint64_t now_ms
    ) -> std::expected<session_record, std::string> override;
    [[nodiscard]] auto
    reconcile(container::receipt_audit_producer& receipt_producer, std::uint64_t now_ms)
        -> std::expected<session_reconciliation_report, std::string> override;
    [[nodiscard]] auto list() const
        -> std::expected<std::vector<std::string>, std::string> override;
    [[nodiscard]] auto
    read(std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<session_transcript_read, std::string> override;
    [[nodiscard]] auto wait_read(
        std::string_view session_id,
        std::uint64_t cursor,
        std::size_t max_bytes,
        std::uint64_t timeout_ms
    ) -> std::expected<session_transcript_read, std::string> override;
    [[nodiscard]] auto write_input(std::string_view session_id, std::string_view bytes)
        -> std::expected<void, std::string> override;
    [[nodiscard]] auto
    resize(std::string_view session_id, std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string> override;
    [[nodiscard]] auto signal(std::string_view session_id, session_signal requested)
        -> std::expected<void, std::string> override;
    [[nodiscard]] auto stop(std::string_view session_id)
        -> std::expected<void, std::string> override;
    [[nodiscard]] auto stop(std::string_view session_id, std::string_view idempotency_key)
        -> std::expected<void, std::string> override;
    [[nodiscard]] auto wait(std::string_view session_id)
        -> std::expected<session_terminal_record, std::string> override;
    [[nodiscard]] auto cleanup(std::string_view session_id)
        -> std::expected<void, std::string> override;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control::apple_detail
