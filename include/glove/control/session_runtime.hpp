#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/container/spawner.hpp"
#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {

struct session_transcript_read {
    std::uint64_t oldest_cursor = 0;
    std::uint64_t next_cursor = 0;
    bool truncated = false;
    bool eof = false;
    std::string bytes;

    auto operator==(const session_transcript_read&) const -> bool = default;
};

// Backend-neutral terminal projection returned by a live runtime owner. The
// backend-specific durable recovery identity stays in the registry; protocol
// callers need only the authenticated terminal facts shared by every backend.
struct session_terminal_record {
    session_record session;
    std::string profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::uint64_t finished_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_hmac;
    container::resource_termination_cause termination_cause =
        container::resource_termination_cause::supervisor_error;
    std::optional<int> exit_code;

    auto operator==(const session_terminal_record&) const -> bool = default;
};

enum class session_signal : std::uint8_t {
    interrupt,
    terminate,
    hangup,
};

// Result of an authenticated session start, with the explicit fresh-launch
// vs replay disposition required by the outcome contract. A replay returns
// the existing durable record without launching; it is a success response
// but never a freshly applied launch, so protocol callers must not grant
// connection-scoped teardown authority for it.
struct session_start_result {
    session_record record;
    bool fresh_launch = false;

    auto operator==(const session_start_result&) const -> bool = default;
};

struct session_reconciliation_report {
    std::size_t inspected = 0;
    std::size_t recovered_exited = 0;
    std::size_t recovered_failed = 0;
    std::size_t recovered_terminated = 0;
    std::size_t orphan_materializations_inspected = 0;
    std::size_t orphan_materializations_removed = 0;
    std::size_t orphan_retained_changes_recovered = 0;
    std::vector<std::string> unresolved_running_session_ids;
    std::vector<std::string> live_running_session_ids;
    std::vector<std::string> identity_mismatch_session_ids;

    auto operator==(const session_reconciliation_report&) const -> bool = default;
};

// Platform-neutral control seam used by the authenticated Glove protocol.
// Backends may differ internally, but every advertised managed runtime must
// implement this exact lifecycle and produce the shared authenticated receipt
// and durable session projections.
class session_runtime {
public:
    session_runtime() = default;
    session_runtime(const session_runtime&) = delete;
    auto operator=(const session_runtime&) -> session_runtime& = delete;
    session_runtime(session_runtime&&) = delete;
    auto operator=(session_runtime&&) -> session_runtime& = delete;
    virtual ~session_runtime() = default;

    [[nodiscard]] virtual auto backend_id() const noexcept -> std::string_view = 0;

    // Constructed diagnostic backends may remain deliberately non-operational.
    // Protocol discovery and dispatch must not infer lifecycle support from a
    // non-null runtime object alone.
    [[nodiscard]] virtual auto lifecycle_operational() const noexcept -> bool { return true; }

    [[nodiscard]] virtual auto agent_runtime_adapter_schema_version() const noexcept
        -> std::uint8_t = 0;
    // Exact runtime identifiers the configured managed closure can launch.
    // An adapter schema without this bounded set is not runtime-specific proof.
    [[nodiscard]] virtual auto managed_runtime_ids() const -> std::vector<std::string> = 0;

    [[nodiscard]] virtual auto refinement_evaluation_protocol_schema_version() const noexcept
        -> std::uint8_t {
        return 0;
    }

    [[nodiscard]] virtual auto resource_capabilities() const noexcept
        -> container::resource_enforcement_capabilities = 0;
    [[nodiscard]] virtual auto start(
        container::receipt_audit_producer& receipt_producer,
        const session_start_authorization& authorization,
        std::string_view idempotency_namespace,
        std::uint64_t now_ms
    ) -> std::expected<session_start_result, std::string> = 0;
    [[nodiscard]] virtual auto
    reconcile(container::receipt_audit_producer& receipt_producer, std::uint64_t now_ms)
        -> std::expected<session_reconciliation_report, std::string> = 0;
    [[nodiscard]] virtual auto list() const
        -> std::expected<std::vector<std::string>, std::string> = 0;
    [[nodiscard]] virtual auto
    read(std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<session_transcript_read, std::string> = 0;
    [[nodiscard]] virtual auto wait_read(
        std::string_view session_id,
        std::uint64_t cursor,
        std::size_t max_bytes,
        std::uint64_t timeout_ms
    ) -> std::expected<session_transcript_read, std::string> = 0;
    [[nodiscard]] virtual auto write_input(std::string_view session_id, std::string_view bytes)
        -> std::expected<void, std::string> = 0;
    [[nodiscard]] virtual auto
    resize(std::string_view session_id, std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string> = 0;
    [[nodiscard]] virtual auto signal(std::string_view session_id, session_signal requested)
        -> std::expected<void, std::string> = 0;
    [[nodiscard]] virtual auto stop(std::string_view session_id)
        -> std::expected<void, std::string> = 0;
    [[nodiscard]] virtual auto stop(std::string_view session_id, std::string_view idempotency_key)
        -> std::expected<void, std::string> = 0;
    [[nodiscard]] virtual auto wait(std::string_view session_id)
        -> std::expected<session_terminal_record, std::string> = 0;
    [[nodiscard]] virtual auto cleanup(std::string_view session_id)
        -> std::expected<void, std::string> = 0;
};

} // namespace glove::control
