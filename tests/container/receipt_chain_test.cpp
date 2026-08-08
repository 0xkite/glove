#include "glove/container/profile.hpp"
#include "glove/container/receipt_chain.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view profile_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

auto receipt() -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::string{profile_digest},
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 60'000,
                .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                .pids = 128,
                .wall_time_ms = 120'000,
                .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 500,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = 1024,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections = {},
        .retained_changes = {},
    };
}

auto run() -> int {
    auto chain = glove::container::receipt_audit_chain::create(audit_key);
    REQUIRE(chain.has_value());
    auto anchor = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(anchor.has_value());

    auto first = (*chain)->append("session-1", controller_plan_digest, receipt());
    REQUIRE(first.has_value());
    REQUIRE(first->sequence == 1);
    REQUIRE(first->previous_hmac == std::string(64, '0'));
    REQUIRE(
        first->receipt_digest == "cf4dfdc1627c93e00c10a83a780937dba2a9493c03f0f91843af49ee17ed11a4"
    );
    REQUIRE(first->key_id == "b97d6f8d2ae381761ea00f360c230cf75e8de5fdc6a8d25624a5c36b97f0d475");
    REQUIRE(first->this_hmac == "57bafec7db274bd24763fdbe4cfb680f6d19c46121bb79649ef3456532458f12");
    REQUIRE(
        glove::container::verify_receipt_audit_envelope(
            *first, audit_key, "session-1", controller_plan_digest, **anchor
        )
            .has_value()
    );

    auto projected_receipt = receipt();
    projected_receipt.library_projections.push_back({
        .projection_id = "sage-core",
        .destination_alias = "libraries",
        .target_path = "/opt/sage/library-bundles/" + std::string(64U, 'd') + ".json",
        .content_digest = std::string(64U, 'd'),
    });
    auto projected_digest =
        glove::container::resource_enforcement_receipt_digest(projected_receipt);
    REQUIRE(projected_digest.has_value());
    REQUIRE(*projected_digest != first->receipt_digest);
    projected_receipt.library_projections.front().content_digest = std::string(64U, 'e');
    REQUIRE(!glove::container::resource_enforcement_receipt_digest(projected_receipt).has_value());

    auto second_receipt = receipt();
    ++second_receipt.observed.cpu_time_ms;
    auto second = (*chain)->append("session-2", controller_plan_digest, second_receipt);
    REQUIRE(second.has_value());
    REQUIRE(second->sequence == 2);
    REQUIRE(second->previous_hmac == first->this_hmac);
    REQUIRE(
        glove::container::verify_receipt_audit_envelope(
            *second, audit_key, "session-2", controller_plan_digest, **anchor
        )
            .has_value()
    );

    const auto stable_anchor = **anchor;
    REQUIRE(!glove::container::verify_receipt_audit_envelope(
                 *first, audit_key, "session-1", controller_plan_digest, **anchor
    )
                 .has_value());
    REQUIRE(**anchor == stable_anchor);

    auto tampered = *first;
    ++tampered.receipt.observed.disk_bytes;
    auto fresh_anchor = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(fresh_anchor.has_value());
    REQUIRE(!glove::container::verify_receipt_audit_envelope(
                 tampered, audit_key, "session-1", controller_plan_digest, **fresh_anchor
    )
                 .has_value());
    REQUIRE((**fresh_anchor).sequence == 0);

    tampered = *first;
    tampered.this_hmac[0] = tampered.this_hmac[0] == 'a' ? 'b' : 'a';
    REQUIRE(!glove::container::verify_receipt_audit_envelope(
                 tampered, audit_key, "session-1", controller_plan_digest, **fresh_anchor
    )
                 .has_value());
    REQUIRE((**fresh_anchor).sequence == 0);

    tampered = *first;
    tampered.session_id = "session-2";
    REQUIRE(!glove::container::verify_receipt_audit_envelope(
                 tampered, audit_key, "session-1", controller_plan_digest, **fresh_anchor
    )
                 .has_value());
    REQUIRE((**fresh_anchor).sequence == 0);

    auto remote_claim = receipt();
    remote_claim.backend = glove::container::sandbox_backend::remote_linux_container;
    remote_claim.backend_id = "remote-linux-container:trusted-operator-v1";
    remote_claim.observation_authority =
        glove::container::receipt_observation_authority::trusted_remote_claim;
    remote_claim.independently_verified = false;
    auto remote = (*chain)->append("session-remote", controller_plan_digest, remote_claim);
    REQUIRE(remote.has_value());
    REQUIRE(
        remote->receipt.observation_authority ==
        glove::container::receipt_observation_authority::trusted_remote_claim
    );
    auto changed_authority = remote_claim;
    changed_authority.independently_verified = true;
    REQUIRE(!glove::container::resource_enforcement_receipt_digest(changed_authority).has_value());

    auto invalid_receipt = receipt();
    invalid_receipt.backend_id.clear();
    REQUIRE(!(*chain)->append("session-3", controller_plan_digest, invalid_receipt).has_value());
    REQUIRE((*chain)->sequence() == 3);
    REQUIRE((*chain)->head_hmac() == remote->this_hmac);

    REQUIRE(!glove::container::receipt_audit_chain::create("not-a-key").has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
