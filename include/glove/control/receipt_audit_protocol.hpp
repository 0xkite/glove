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

inline constexpr std::size_t max_control_frame_bytes = std::size_t{1024} * 1024U;

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
        std::string materialization_root = {}
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
        std::string materialization_root = {}
    ) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string>;

    // Request failures are encoded as stable JSON-RPC errors. `unexpected` is
    // reserved for local response-encoding failures.
    [[nodiscard]] auto handle_frame(std::string_view frame, std::uint64_t now_ms)
        -> std::expected<std::string, std::string>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
