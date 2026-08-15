#pragma once

#include "glove/audit/sink.hpp"
#include "glove/container/profile.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/net/egress_proxy.hpp"

#include "cgroup_v2.hpp"
#include "linux_managed_session.hpp"
#include "linux_resource_lifecycle.hpp"
#include "session_reconciliation.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace glove::control::linux_detail {

// Internal, reversible ownership boundary between an approved registry
// reservation and process creation. Holding this value pins every writable
// filesystem, cgroup, launch field, and authorization needed by the private
// execution composer. Destruction releases those resources without launching.
struct linux_prepared_session {
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string authorization_id;
    std::uint64_t authorization_expires_at_ms = 0;
    container::profile profile;
    std::vector<std::string> argv;
    container::linux_detail::managed_launch_binding binding;
    linux_cgroup_recovery_identity cgroup_identity;
    linux_filesystem_recovery_identity filesystem_identity;
    std::unique_ptr<container::linux_detail::linux_resource_lifecycle> lifecycle;
    std::unique_ptr<net::egress_proxy> egress_proxy;
    std::shared_ptr<container::refinement_transcript_evaluator> refinement_evaluator;

    [[nodiscard]] auto execution_binding() const -> session_execution_binding {
        return {
            .schema_version = 1,
            .session_id = session_id,
            .controller_plan_digest = controller_plan_digest,
            .plan_content_digest = plan_content_digest,
            .authorization_id = authorization_id,
            .profile_digest = binding.profile_digest,
            .cgroup_identity = cgroup_identity,
            .filesystem_identity = filesystem_identity,
        };
    }
};

// Linux-only reversible preparation boundary. It exposes no protocol operation
// and performs no clone itself. The separate private executor composes it with
// durable lifecycle transitions; public start remains unavailable.
class linux_session_preparer final {
public:
    linux_session_preparer(const linux_session_preparer&) = delete;
    auto operator=(const linux_session_preparer&) -> linux_session_preparer& = delete;
    linux_session_preparer(linux_session_preparer&&) noexcept = default;
    auto operator=(linux_session_preparer&&) -> linux_session_preparer& = delete;
    ~linux_session_preparer() = default;

    [[nodiscard]] static auto
    create(std::string materialization_root, std::shared_ptr<audit::sink> egress_audit = {})
        -> std::expected<linux_session_preparer, std::string>;

    [[nodiscard]] auto prepare(session_start_inputs&& inputs, std::uint64_t started_at_ms)
        -> std::expected<linux_prepared_session, std::string>;

    [[nodiscard]] auto reconcile(
        session_registry& registry,
        container::receipt_audit_producer& receipt_producer,
        std::uint64_t now_ms
    ) -> std::expected<session_reconciliation_report, std::string>;

private:
    linux_session_preparer(
        std::string materialization_root,
        container::linux_detail::cgroup_v2_root cgroup_root,
        std::shared_ptr<audit::sink> egress_audit
    ) noexcept;

    std::string materialization_root_;
    container::linux_detail::cgroup_v2_root cgroup_root_;
    std::shared_ptr<audit::sink> egress_audit_;
};

} // namespace glove::control::linux_detail
