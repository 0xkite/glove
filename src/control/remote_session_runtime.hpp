#pragma once

#include "../../include/glove/control/session_runtime.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {

struct remote_session_runtime_config {
    std::vector<std::string> ssh_argv;
    std::string executor_digest;
    std::string container_image;
    std::string container_image_digest;
    std::uint64_t channel_timeout_ms = 0;
    std::uint64_t max_clock_skew_ms = 0;
    std::uint32_t max_sessions = 0;
    std::filesystem::path staging_root;
};

class remote_session_runtime final : public session_runtime {
public:
    class construction_token {
    private:
        construction_token() = default;
        friend class remote_session_runtime;
    };

    remote_session_runtime(construction_token token, remote_session_runtime_config configured);

    [[nodiscard]] static auto create(remote_session_runtime_config configured)
        -> std::expected<std::shared_ptr<remote_session_runtime>, std::string>;

    [[nodiscard]] auto backend_id() const noexcept -> std::string_view override;

    [[nodiscard]] auto lifecycle_operational() const noexcept -> bool override { return false; }

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
    ) -> std::expected<session_start_result, std::string> override;
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

    [[nodiscard]] auto ssh_argv() const noexcept -> const std::vector<std::string>& {
        return configured_.ssh_argv;
    }

    [[nodiscard]] auto container_image() const noexcept -> std::string_view {
        return configured_.container_image;
    }

    [[nodiscard]] auto container_image_digest() const noexcept -> std::string_view {
        return configured_.container_image_digest;
    }

private:
    remote_session_runtime_config configured_;
};

} // namespace glove::control
