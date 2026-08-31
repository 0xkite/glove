#pragma once

#include "glove/audit/sink.hpp"
#include "glove/control/session_runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace glove::control::apple_detail {

struct sage_guest_runtime_identity {
    std::string binary_digest;
    std::string source_revision;
    std::uint8_t policy_schema_version = 0;
    std::string library_projection_schema;

    auto operator==(const sage_guest_runtime_identity&) const -> bool = default;
};

struct apple_image_ownership_expectation {
    std::string image_digest;
    std::optional<std::string> harness_closure_digest;
    std::optional<sage_guest_runtime_identity> sage_guest;
};

struct apple_instance_ownership_expectation {
    std::string instance_name;
    std::string image_digest;
    std::string launch_identity_digest;
};

// Pure, bounded construction helpers. Apple lifecycle remains unavailable; these
// seams let tests lock the exact stdout-only identity contract without starting
// Apple Container or weakening capability discovery.
[[nodiscard]] auto validate_image_inspection_json(
    std::string_view standard_output,
    std::string_view standard_error,
    const apple_image_ownership_expectation& expected
) -> std::expected<void, std::string>;
[[nodiscard]] auto validate_instance_inspection_json(
    std::string_view standard_output,
    std::string_view standard_error,
    const apple_instance_ownership_expectation& expected
) -> std::expected<void, std::string>;
[[nodiscard]] auto validate_sage_projection_target(
    std::string_view destination_alias,
    std::string_view target_path,
    std::string_view content_digest
) -> std::expected<void, std::string>;

struct apple_container_runtime_config {
    std::filesystem::path container_cli;
    std::string image_reference;
    // Exact OCI index digest, including the sha256: prefix.
    std::string image_digest;
    // Exact sha256 digest of the package lock embedded in Glove's managed
    // harness image. Empty retains the restricted image-contained probe lane.
    std::optional<std::string> harness_closure_digest;
    std::optional<sage_guest_runtime_identity> sage_guest;
    std::shared_ptr<audit::sink> egress_audit;
    std::filesystem::path session_root;
    std::size_t max_sessions = 64;
};

struct apple_container_stats_observation {
    std::uint64_t cpu_usage_usec = 0;
    std::uint64_t memory_usage_bytes = 0;
    std::uint64_t memory_limit_bytes = 0;
    std::uint32_t num_processes = 0;
    std::uint64_t block_write_bytes = 0;

    auto operator==(const apple_container_stats_observation&) const -> bool = default;
};

[[nodiscard]] auto
parse_apple_container_stats(std::string_view json, std::string_view expected_instance_id)
    -> std::expected<apple_container_stats_observation, std::string>;

[[nodiscard]] auto apple_container_tmpfs_sizes(std::uint64_t disk_bytes)
    -> std::expected<std::pair<std::uint64_t, std::uint64_t>, std::string>;

// Apple Silicon implementation of the authenticated managed-session seam.
// The implementation is construction-ready but does not advertise the managed
// lifecycle until Apple Container can prove the shared six-limit receipt
// contract. Image-contained harness, credential, egress, and library brokers
// remain independently validated for bounded test and future shipping lanes.
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
    auto operator=(apple_container_session_runtime&&) -> apple_container_session_runtime& = delete;
    ~apple_container_session_runtime();

    [[nodiscard]] static auto
    create(session_registry& registry, apple_container_runtime_config config)
        -> std::expected<std::unique_ptr<apple_container_session_runtime>, std::string>;

    [[nodiscard]] auto backend_id() const noexcept -> std::string_view override {
        return "apple_container";
    }

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

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control::apple_detail
