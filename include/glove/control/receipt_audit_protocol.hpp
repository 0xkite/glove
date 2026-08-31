#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/control/session_runtime.hpp"
#include "glove/supervisor/path_exposure.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace glove::control {
namespace linux_detail {
class local_service_proxy_capability;
}

inline constexpr std::size_t max_control_frame_bytes = std::size_t{1024} * 1024U;

// Structured, per-request outcome metadata produced by handle_frame. It is
// the ONLY source of degradation authority for the control transport: the
// server must never infer what a connection asked for by re-decoding its raw
// frame, because a re-decode has no authentication, schema, deadline, or
// application evidence. Fields stay unset until the corresponding stage of
// the real dispatch actually passed.
struct receipt_control_outcome {
    // The bootstrap secret, schema, and deadline checks all passed.
    bool authenticated = false;
    // The dispatched handler applied the request and returned a success
    // (JSON-RPC result) response. Denied, rejected, and replayed requests are
    // never "applied".
    bool applied = false;
    // The dispatched start_session was an idempotent replay of an
    // already-recorded start rather than a fresh launch. Replays carry
    // application evidence but never teardown authority; the control audit
    // event for a replayed-degrade still reflects the replay disposition.
    bool replay = false;
    // The response frame is a result rather than an error.
    bool response_success = false;
    // The request envelope's method (set once the envelope is valid).
    std::string method;
    // The typed, post-authentication session identifier carried by a
    // session-scoped request; empty for every other method.
    std::string session_id;
};

// Authenticated request handler for the receipt-reconciliation subset of the
// future gloved control plane. Socket ownership and peer credentials remain the
// transport's responsibility; this layer independently checks the bootstrap
// secret, deadline, strict schema, and mutation idempotency.
class receipt_audit_protocol final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class receipt_audit_protocol;
    };

    receipt_audit_protocol(construction_token token, std::unique_ptr<implementation> state);
    receipt_audit_protocol(const receipt_audit_protocol&) = delete;
    auto operator=(const receipt_audit_protocol&) -> receipt_audit_protocol& = delete;
    receipt_audit_protocol(receipt_audit_protocol&&) = delete;
    auto operator=(receipt_audit_protocol&&) -> receipt_audit_protocol& = delete;
    ~receipt_audit_protocol();

    [[nodiscard]] static auto create(
        std::string_view bootstrap_secret_hex,
        std::shared_ptr<container::receipt_audit_producer> producer,
        std::shared_ptr<const supervisor::session_plan_validator> plan_validator = {},
        std::shared_ptr<session_registry> sessions = {},
        std::shared_ptr<session_runtime> managed_runtime = {},
        std::shared_ptr<supervisor::path_exposure_registry> path_exposures = {},
        std::string materialization_root = {},
        std::shared_ptr<const linux_detail::local_service_proxy_capability> local_services = {}
    ) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string>;

    // The first authenticated page supplies Sage's trusted prefix and lazily
    // creates or recovers the exclusive producer. Acknowledgement cannot
    // bootstrap the producer by itself.
    [[nodiscard]] static auto create(
        std::string_view bootstrap_secret_hex,
        container::receipt_audit_producer_config producer_config,
        std::shared_ptr<const supervisor::session_plan_validator> plan_validator = {},
        std::shared_ptr<session_registry> sessions = {},
        std::shared_ptr<session_runtime> managed_runtime = {},
        std::shared_ptr<supervisor::path_exposure_registry> path_exposures = {},
        std::string materialization_root = {},
        std::shared_ptr<const linux_detail::local_service_proxy_capability> local_services = {}
    ) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string>;

    // Request failures are encoded as stable JSON-RPC errors. `unexpected` is
    // reserved for local response-encoding failures. The two-argument overload
    // discards outcome metadata.
    [[nodiscard]] auto handle_frame(std::string_view frame, std::uint64_t now_ms)
        -> std::expected<std::string, std::string>;
    // Same dispatch, plus structured authenticated/applied outcome metadata in
    // `*outcome` (reset at entry; never null-dereferenced when nullptr). The
    // control transport's degrade path must consume this metadata instead of
    // re-decoding the raw frame: only genuinely authenticated and applied
    // requests may drive connection-scoped teardown.
    [[nodiscard]] auto
    handle_frame(std::string_view frame, std::uint64_t now_ms, receipt_control_outcome* outcome)
        -> std::expected<std::string, std::string>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
