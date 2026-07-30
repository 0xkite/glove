#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

// One host path exposed to the contained agent. Paths are canonicalised before
// launch. A rule grants read access and, only when requested, write access.
// Everything not covered by a rule or the platform's fixed runtime surface is
// denied by the OS sandbox.
struct fs_rule {
    std::string path;
    bool writable = false;
};

struct proxy_settings {
    std::uint16_t port = 0;
    // Credential-bearing loopback URL injected into the standard proxy
    // variables. The proxy rejects requests without its per-run credential.
    std::string url;
};

// Hard limits required by an external session planner. Supplying this block
// is an all-or-nothing request: a platform spawner must prove it enforces all
// six limits before it may launch the process.
struct resource_limits {
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t memory_bytes = 0;
    std::uint32_t pids = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t terminal_output_bytes = 0;

    auto operator==(const resource_limits&) const -> bool = default;
};

enum class enforcement_mechanism : std::uint8_t {
    unavailable,
    rlimit,
    cgroup_v2,
    watchdog,
    filesystem_quota,
    byte_counter,
};

// Observable capability report owned by a concrete platform spawner. A
// non-unavailable value means that mechanism is installed for the child and
// can be represented in an enforcement receipt.
struct resource_enforcement_capabilities {
    enforcement_mechanism cpu_time = enforcement_mechanism::unavailable;
    enforcement_mechanism memory = enforcement_mechanism::unavailable;
    enforcement_mechanism pids = enforcement_mechanism::unavailable;
    enforcement_mechanism wall_time = enforcement_mechanism::unavailable;
    enforcement_mechanism disk = enforcement_mechanism::unavailable;
    enforcement_mechanism terminal_output = enforcement_mechanism::unavailable;
    // Zero means no receipt support. Version 1 records configured limits,
    // mechanisms, observed usage, termination cause, and backend identity.
    std::uint8_t receipt_schema_version = 0;

    [[nodiscard]] auto complete() const noexcept -> bool;
    auto operator==(const resource_enforcement_capabilities&) const -> bool = default;
};

enum class resource_termination_cause : std::uint8_t {
    exited,
    signaled,
    cpu_time_limit,
    memory_limit,
    pid_limit,
    wall_time_limit,
    disk_limit,
    terminal_output_limit,
    supervisor_error,
};

enum class sandbox_backend : std::uint8_t {
    linux_production,
    apple_container,
    macos_experimental,
};

// High-water/aggregate observations captured by the enforcing backend. These
// values are evidence, not a replacement for kernel enforcement events: a
// cgroup or watchdog may terminate between sampling intervals.
struct resource_usage {
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t peak_memory_bytes = 0;
    std::uint32_t peak_pids = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t terminal_output_bytes = 0;

    auto operator==(const resource_usage&) const -> bool = default;
};

// Redacted evidence for one exact Sage library object projected into the
// sandbox. Host source paths are deliberately absent.
struct library_projection_receipt {
    std::string projection_id;
    std::string destination_alias;
    std::string target_path;
    std::string content_digest;

    auto operator==(const library_projection_receipt&) const -> bool = default;
};

// Redacted evidence for one retained, isolated workspace finalized at session
// exit. The manifest digest commits to the bounded path-level consequences;
// no host path or protected-root identifier is present.
struct retained_change_receipt {
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string manifest_digest;
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;

    auto operator==(const retained_change_receipt&) const -> bool = default;
};

// Version-1 receipt returned only after a mandatory-limit process reaches a
// terminal state. The profile digest binds the receipt to the immutable launch
// profile; the configured limits and mechanisms prevent a caller from treating
// a partial or differently configured sandbox as equivalent.
struct resource_enforcement_receipt {
    std::uint8_t schema_version = 0;
    std::string profile_digest;
    sandbox_backend backend = sandbox_backend::macos_experimental;
    std::string backend_id;
    resource_limits configured_limits;
    resource_enforcement_capabilities mechanisms;
    resource_usage observed;
    resource_termination_cause termination_cause = resource_termination_cause::supervisor_error;
    std::optional<int> exit_code;
    std::uint64_t started_at_ms = 0;
    std::uint64_t finished_at_ms = 0;
    std::vector<library_projection_receipt> library_projections;
    std::vector<retained_change_receipt> retained_changes;

    auto operator==(const resource_enforcement_receipt&) const -> bool = default;
};

// Declarative, fail-closed description of the contained process. This type
// deliberately contains no "full access" mode and no advisory fields: every
// option below is enforced by both platform spawners or rejected at launch.
struct profile {
    std::vector<fs_rule> filesystem;

    // Immutable harness runtime files derived only from an executor-owned
    // runtime template. Managed-session binding rejects ordinary filesystem
    // grants and accepts this read-only surface separately.
    std::vector<fs_rule> runtime_filesystem;

    // Complete environment inherited by the agent, expressed as NAME=VALUE.
    // The host environment is never copied implicitly.
    std::vector<std::string> environment;

    std::optional<std::string> home_dir;
    // A private home derived by a managed runtime adapter, never a general
    // filesystem grant. Linux managed binding admits it only when the exact
    // lifecycle mount proves a supported adapter context.
    std::optional<std::string> managed_home_dir;
    std::optional<std::string> temp_dir;
    std::optional<std::string> work_dir;

    // Set only by the runner after starting the authenticated egress proxy.
    std::optional<proxy_settings> proxy;

    // When present, launch is rejected unless the selected spawner reports
    // complete enforcement and observable receipts for every limit.
    std::optional<resource_limits> required_limits;
};

// Validate and canonicalise a profile. Invalid, overlapping, contradictory,
// or root-wide grants are rejected before a sandbox process is started.
auto validate(const profile& p) -> std::expected<profile, std::string>;

// Verify that a validated profile can be enforced by a platform capability
// report. This check is intentionally separate from structural validation so
// profiles can be planned and inspected on machines that cannot run them.
auto require_resource_enforcement(
    const profile& p, const resource_enforcement_capabilities& capabilities
) -> std::expected<void, std::string>;

// Validate a terminal receipt against the exact launch inputs. This verifies
// structure and binding; receipt authenticity belongs to the supervisor's
// audit-chain/signature layer.
auto validate_resource_enforcement_receipt(
    const resource_enforcement_receipt& receipt,
    const resource_limits& expected_limits,
    const resource_enforcement_capabilities& expected_capabilities,
    sandbox_backend expected_backend,
    std::string_view expected_profile_digest
) -> std::expected<void, std::string>;

} // namespace glove::container
