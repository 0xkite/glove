#pragma once

#include "glove/container/receipt_producer.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/control/session_runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace glove::control {

enum class session_process_observation : std::uint8_t {
    exact,
    absent,
    mismatch,
    terminated,
};

using session_process_observer = std::function<
    std::expected<session_process_observation, std::string>(const session_recovery_record&)>;

// Startup-only registry/journal repair. A starting child was never released,
// so it can be closed as recovered_without_process. A running session is
// terminalized only from its exact durable authenticated receipt. On Linux,
// receipt-less running records are classified from the complete durable process
// identity; PID alone is never authority. Other platforms report them as
// unresolved until they provide an equivalent observer.
[[nodiscard]] auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string>;

// Observer-injected form used by the Linux daemon and deterministic tests. An
// absent exact identity is closed without signaling any process. A mismatch is
// reported but remains running until exact cgroup ownership can be resolved.
[[nodiscard]] auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms,
    const session_process_observer& process_observer
) -> std::expected<session_reconciliation_report, std::string>;

} // namespace glove::control
