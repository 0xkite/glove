#pragma once

#include "glove/audit/sink.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/control/session_runtime.hpp"
#include "glove/supervisor/path_exposure.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace glove::control {
namespace linux_detail {
class local_service_proxy_capability;
}

struct receipt_audit_unix_server_config {
    std::filesystem::path socket_path;
    std::filesystem::path bootstrap_secret_path;
    container::receipt_audit_producer_config producer;
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator;
    std::shared_ptr<session_registry> sessions;
    // Named `runtime`, not `session_runtime`: a member sharing its class type's
    // name changes the meaning of that name in this scope, which GCC 14
    // rejects (-Wchanges-meaning) where clang accepts it.
    std::shared_ptr<session_runtime> runtime;
    std::shared_ptr<const linux_detail::local_service_proxy_capability> local_services;
    std::shared_ptr<supervisor::path_exposure_registry> path_exposures;
    std::string materialization_root;
    std::uint64_t io_timeout_ms = 5'000;
    // Optional structured audit journal for connection-scoped control
    // delivery failures. When absent, degradation still applies; only the
    // JSONL event record is skipped.
    std::shared_ptr<audit::sink> control_audit;
};

// Result of serving exactly one connection.
// - `served`: the bounded request was handled and its response delivered.
// - `connection_failed`: a transport-level write failure scoped to that one
//   connection (for example a broken pipe after the client vanished). The
//   failure never reaches the audit journal, the receipt chain, or any
//   integrity boundary; the affected session is degraded and the server
//   keeps serving subsequent connections.
enum class receipt_audit_serve_outcome : std::uint8_t {
    served,
    connection_failed,
};

// Owner-only, one-request-per-connection transport for receipt reconciliation.
// Session launch methods are advertised only when the Linux runtime is
// explicitly composed. Attach/tunnel methods remain unavailable.
class receipt_audit_unix_server final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class receipt_audit_unix_server;
    };

    receipt_audit_unix_server(construction_token token, std::unique_ptr<implementation> state);
    receipt_audit_unix_server(const receipt_audit_unix_server&) = delete;
    auto operator=(const receipt_audit_unix_server&) -> receipt_audit_unix_server& = delete;
    receipt_audit_unix_server(receipt_audit_unix_server&&) = delete;
    auto operator=(receipt_audit_unix_server&&) -> receipt_audit_unix_server& = delete;
    ~receipt_audit_unix_server();

    [[nodiscard]] static auto create(receipt_audit_unix_server_config config)
        -> std::expected<std::unique_ptr<receipt_audit_unix_server>, std::string>;

    // Accept and serve exactly one bounded request. Client/protocol failures
    // are isolated to that connection and reported to the caller.
    // Returns `connection_failed` when the only failure was a transport-level
    // write to the already-authenticated connection (the client vanished or
    // stopped reading). Listener, authentication, frame-integrity, and
    // audit-chain failures remain errors: they fail closed and are fatal for
    // the daemon.
    [[nodiscard]] auto serve_one() -> std::expected<receipt_audit_serve_outcome, std::string>;

    // Wait for and serve at most one request. An empty optional means the
    // accept deadline elapsed or a signal interrupted the wait before a
    // connection was accepted. This lets a foreground supervisor observe
    // shutdown requests without making the listener itself own signal state.
    [[nodiscard]] auto serve_one_for(std::uint64_t accept_timeout_ms)
        -> std::expected<std::optional<receipt_audit_serve_outcome>, std::string>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
