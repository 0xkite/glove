#include "session_reconciliation.hpp"

#include "glove/container/digest.hpp"
#if defined(__linux__)
#    include "linux_process_identity.hpp"
#endif

#include <bit>
#include <span>
#include <string>
#include <string_view>

namespace glove::control {

namespace {

auto registry_error(std::string_view operation, const session_registry_error& error)
    -> std::string {
    return std::string{operation} + ": " + error.message;
}

auto recovery_failure_key(const session_recovery_record& candidate)
    -> std::expected<std::string, std::string> {
    const auto material = candidate.session.session_id + ":" + candidate.authorization_id + ":" +
                          candidate.profile_digest + ":" + std::to_string(candidate.starting_at_ms);
    auto digest = container::sha256_hex(
        std::span<const unsigned char>{
            std::bit_cast<const unsigned char*>(material.data()), material.size()
        }
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return "recovery-fail-" + *digest;
}

auto close_recovered_without_process(
    session_registry& registry,
    const session_recovery_record& candidate,
    session_failure_code code,
    std::uint64_t now_ms
) -> std::expected<void, std::string> {
    auto idempotency_key = recovery_failure_key(candidate);
    if (!idempotency_key) {
        return std::unexpected(
            std::string{"derive session recovery key: "} + idempotency_key.error()
        );
    }
    const session_failure_commitment failure{
        .schema_version = 1,
        .session_id = candidate.session.session_id,
        .controller_plan_digest = candidate.session.controller_plan_digest,
        .plan_content_digest = candidate.session.plan_content_digest,
        .authorization_id = candidate.authorization_id,
        .profile_digest = candidate.profile_digest,
        .code = code,
    };
    auto failed = registry.mark_failed(failure, *idempotency_key, now_ms);
    if (!failed) {
        return std::unexpected(
            registry_error("close session without an exact process", failed.error())
        );
    }
    return {};
}

auto classify_receiptless_running(
    session_registry& registry,
    const session_recovery_record& candidate,
    std::uint64_t now_ms,
    const session_process_observer* process_observer,
    session_reconciliation_report& report
) -> std::expected<void, std::string> {
    if (process_observer == nullptr) {
        report.unresolved_running_session_ids.push_back(candidate.session.session_id);
        return {};
    }
    if (!candidate.process_identity) {
        return std::unexpected(std::string{"running recovery candidate has no process identity"});
    }
    auto observation = (*process_observer)(candidate);
    if (!observation) {
        return std::unexpected(
            std::string{"observe recovered Linux process: "} + observation.error()
        );
    }
    switch (*observation) {
    case session_process_observation::exact:
        report.live_running_session_ids.push_back(candidate.session.session_id);
        return {};
    case session_process_observation::mismatch:
        report.identity_mismatch_session_ids.push_back(candidate.session.session_id);
        return {};
    case session_process_observation::absent:
        if (auto closed = close_recovered_without_process(
                registry, candidate, session_failure_code::recovered_without_process, now_ms
            );
            !closed) {
            return closed;
        }
        ++report.recovered_failed;
        return {};
    case session_process_observation::terminated:
        if (auto closed = close_recovered_without_process(
                registry, candidate, session_failure_code::recovered_terminated, now_ms
            );
            !closed) {
            return closed;
        }
        ++report.recovered_failed;
        ++report.recovered_terminated;
        return {};
    }
    return std::unexpected(std::string{"session process observation is invalid"});
}

auto reconcile_session_registry_impl(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms,
    const session_process_observer* process_observer
) -> std::expected<session_reconciliation_report, std::string> {
    if (now_ms == 0) {
        return std::unexpected(std::string{"session reconciliation requires a current time"});
    }
    auto candidates = registry.recovery_candidates();
    if (!candidates) {
        return std::unexpected(registry_error("inventory session recovery", candidates.error()));
    }
    session_reconciliation_report report;
    report.inspected = candidates->size();
    report.unresolved_running_session_ids.reserve(candidates->size());
    report.live_running_session_ids.reserve(candidates->size());
    report.identity_mismatch_session_ids.reserve(candidates->size());
    for (const auto& candidate : *candidates) {
        if (candidate.session.state == session_state::starting) {
            if (auto closed = close_recovered_without_process(
                    registry, candidate, session_failure_code::recovered_without_process, now_ms
                );
                !closed) {
                return std::unexpected(closed.error());
            }
            ++report.recovered_failed;
            continue;
        }
        std::optional<container::authenticated_resource_enforcement_receipt> terminal;
        std::optional<container::authenticated_refinement_evaluation_receipt> refinement_terminal;
        if (candidate.requires_refinement_receipt) {
            auto found = receipt_producer.refinement_terminal_for_execution(
                candidate.session.session_id,
                candidate.session.controller_plan_digest,
                candidate.profile_digest
            );
            if (!found) {
                return std::unexpected(
                    std::string{"lookup durable refinement receipt: "} + found.error()
                );
            }
            refinement_terminal = std::move(*found);
        } else {
            auto found = receipt_producer.terminal_for_execution(
                candidate.session.session_id,
                candidate.session.controller_plan_digest,
                candidate.profile_digest
            );
            if (!found) {
                return std::unexpected(
                    std::string{"lookup durable terminal receipt: "} + found.error()
                );
            }
            terminal = std::move(*found);
        }
        if (!terminal && !refinement_terminal) {
            if (auto classified = classify_receiptless_running(
                    registry, candidate, now_ms, process_observer, report
                );
                !classified) {
                return std::unexpected(classified.error());
            }
            continue;
        }
        const auto sequence = terminal ? terminal->sequence : refinement_terminal->sequence;
        const auto idempotency_key = "recovery-exit-" + std::to_string(sequence);
        auto exited = terminal ? registry.mark_exited(*terminal, receipt_producer, idempotency_key)
                               : registry.mark_refinement_exited(
                                     *refinement_terminal, receipt_producer, idempotency_key
                                 );
        if (!exited) {
            return std::unexpected(
                registry_error("project durable terminal receipt", exited.error())
            );
        }
        ++report.recovered_exited;
    }
    return report;
}

} // namespace

auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string> {
#if defined(__linux__)
    const session_process_observer process_observer = [](const session_recovery_record& candidate)
        -> std::expected<session_process_observation, std::string> {
        if (!candidate.process_identity) {
            return std::unexpected(
                std::string{"running recovery candidate has no process identity"}
            );
        }
        auto observed = linux_detail::observe_linux_process_identity(*candidate.process_identity);
        if (!observed) {
            return std::unexpected(observed.error());
        }
        switch (*observed) {
        case linux_detail::linux_process_identity_observation::exact:
            return session_process_observation::exact;
        case linux_detail::linux_process_identity_observation::absent:
            return session_process_observation::absent;
        case linux_detail::linux_process_identity_observation::mismatch:
            return session_process_observation::mismatch;
        }
        return std::unexpected(std::string{"Linux process observation is invalid"});
    };
    return reconcile_session_registry_impl(registry, receipt_producer, now_ms, &process_observer);
#else
    return reconcile_session_registry_impl(registry, receipt_producer, now_ms, nullptr);
#endif
}

auto reconcile_session_registry(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms,
    const session_process_observer& process_observer
) -> std::expected<session_reconciliation_report, std::string> {
    if (!process_observer) {
        return std::unexpected(std::string{"session reconciliation process observer is empty"});
    }
    return reconcile_session_registry_impl(registry, receipt_producer, now_ms, &process_observer);
}

} // namespace glove::control
