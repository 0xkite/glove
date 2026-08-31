#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/control/session_runtime.hpp"

#include "linux_session_preparation.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control::linux_detail {

struct linux_session_execution_request {
    std::string session_id;
    std::string authorization_id;
    std::string idempotency_namespace;
};

class linux_pty_session {
public:
    struct implementation;

    explicit linux_pty_session(std::unique_ptr<implementation> state) noexcept;
    linux_pty_session(const linux_pty_session&) = delete;
    auto operator=(const linux_pty_session&) -> linux_pty_session& = delete;
    linux_pty_session(linux_pty_session&&) = delete;
    auto operator=(linux_pty_session&&) -> linux_pty_session& = delete;
    ~linux_pty_session();

    [[nodiscard]] auto read(std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<container::linux_detail::pty_transcript_read, std::string>;
    [[nodiscard]] auto
    wait_read(std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms)
        -> std::expected<container::linux_detail::pty_transcript_read, std::string>;
    [[nodiscard]] auto write_input(std::string_view bytes) -> std::expected<void, std::string>;
    [[nodiscard]] auto resize(std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto signal(container::linux_detail::pty_session_signal requested)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto stop() -> std::expected<void, std::string>;
    [[nodiscard]] auto stop(std::string_view idempotency_key) -> std::expected<void, std::string>;
    [[nodiscard]] auto wait() -> std::expected<session_exited_record, std::string>;
    [[nodiscard]] auto session_id() const noexcept -> std::string_view;
    [[nodiscard]] auto finished() const -> bool;

private:
    friend auto start_linux_pty_session(
        session_registry& registry,
        linux_session_preparer& preparer,
        container::receipt_audit_producer& receipt_producer,
        const linux_session_execution_request& request,
        container::linux_detail::managed_pty_session_options options
    ) -> std::expected<std::unique_ptr<linux_pty_session>, std::string>;

    std::unique_ptr<implementation> state_;
};

inline constexpr std::size_t default_max_live_linux_pty_sessions = 64U;

// Bounded process-local owner for attachable sessions. Operations snapshot one
// shared owner under the index lock and perform I/O/wait/stop after releasing
// it, so a slow session cannot block control of unrelated sessions.
class linux_pty_session_index final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class linux_pty_session_index;
    };

    linux_pty_session_index(construction_token token, std::unique_ptr<implementation> state);
    linux_pty_session_index(const linux_pty_session_index&) = delete;
    auto operator=(const linux_pty_session_index&) -> linux_pty_session_index& = delete;
    linux_pty_session_index(linux_pty_session_index&&) = delete;
    auto operator=(linux_pty_session_index&&) -> linux_pty_session_index& = delete;
    ~linux_pty_session_index();

    [[nodiscard]] static auto create(std::size_t max_sessions = default_max_live_linux_pty_sessions)
        -> std::expected<std::unique_ptr<linux_pty_session_index>, std::string>;

    [[nodiscard]] auto adopt(std::unique_ptr<linux_pty_session> session)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto contains(std::string_view session_id) const -> bool;
    [[nodiscard]] auto list() const -> std::expected<std::vector<std::string>, std::string>;
    [[nodiscard]] auto
    read(std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<container::linux_detail::pty_transcript_read, std::string>;
    [[nodiscard]] auto wait_read(
        std::string_view session_id,
        std::uint64_t cursor,
        std::size_t max_bytes,
        std::uint64_t timeout_ms
    ) -> std::expected<container::linux_detail::pty_transcript_read, std::string>;
    [[nodiscard]] auto write_input(std::string_view session_id, std::string_view bytes)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto
    resize(std::string_view session_id, std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto
    signal(std::string_view session_id, container::linux_detail::pty_session_signal requested)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto stop(std::string_view session_id) -> std::expected<void, std::string>;
    [[nodiscard]] auto stop(std::string_view session_id, std::string_view idempotency_key)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto wait(std::string_view session_id)
        -> std::expected<session_exited_record, std::string>;
    // Cleanup is nonblocking and succeeds only after the exact owner has
    // durably projected a terminal result.
    [[nodiscard]] auto cleanup(std::string_view session_id) -> std::expected<void, std::string>;

private:
    std::unique_ptr<implementation> state_;
};

// Private Linux runtime composition root. It serializes resource preparation,
// durably reserves start authorization, and adopts each launched PTY into the
// bounded nonblocking index. Exact start retries return the current durable
// record instead of spawning a duplicate process.
class linux_session_runtime final : public session_runtime {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class linux_session_runtime;
    };

    linux_session_runtime(construction_token token, std::unique_ptr<implementation> state);
    linux_session_runtime(const linux_session_runtime&) = delete;
    auto operator=(const linux_session_runtime&) -> linux_session_runtime& = delete;
    linux_session_runtime(linux_session_runtime&&) = delete;
    auto operator=(linux_session_runtime&&) -> linux_session_runtime& = delete;
    ~linux_session_runtime() override;

    [[nodiscard]] static auto create(
        std::shared_ptr<session_registry> registry,
        std::shared_ptr<linux_session_preparer> preparer,
        container::linux_detail::managed_pty_session_options options,
        std::size_t max_sessions = default_max_live_linux_pty_sessions
    ) -> std::expected<std::unique_ptr<linux_session_runtime>, std::string>;

    [[nodiscard]] auto backend_id() const noexcept -> std::string_view override {
        return "linux_production";
    }

    [[nodiscard]] auto agent_runtime_adapter_schema_version() const noexcept
        -> std::uint8_t override {
        return 1;
    }

    [[nodiscard]] auto managed_runtime_ids() const -> std::vector<std::string> override;

    [[nodiscard]] auto refinement_evaluation_protocol_schema_version() const noexcept
        -> std::uint8_t override;

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
    friend class local_service_proxy_factory;
    friend class local_service_proxy_capability;
    [[nodiscard]] auto local_service_factory() const noexcept -> const local_service_proxy_factory*;
    [[nodiscard]] auto registry_identity() const noexcept -> const session_registry*;
    [[nodiscard]] auto
    local_service_runtime_intersection(const local_service_proxy_factory& factory) const noexcept
        -> bool;

    std::unique_ptr<implementation> state_;
};

[[nodiscard]] auto start_linux_pty_session(
    session_registry& registry,
    linux_session_preparer& preparer,
    container::receipt_audit_producer& receipt_producer,
    const linux_session_execution_request& request,
    container::linux_detail::managed_pty_session_options options
) -> std::expected<std::unique_ptr<linux_pty_session>, std::string>;

// Private synchronous composition seam. It is intentionally absent from the
// public control protocol: capability discovery must continue to advertise
// start_session=false until attach, stop, recovery, and daemon ownership are
// complete. Success proves both the authenticated receipt and exited registry
// projection are durable.
[[nodiscard]] auto execute_linux_session(
    session_registry& registry,
    linux_session_preparer& preparer,
    container::receipt_audit_producer& receipt_producer,
    const linux_session_execution_request& request
) -> std::expected<session_exited_record, std::string>;

} // namespace glove::control::linux_detail
