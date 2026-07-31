#pragma once

#include "glove/container/profile.hpp"
#include "glove/container/receipt_producer.hpp"

#include "linux_resource_lifecycle.hpp"
#include "pty_session_channel.hpp"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container::linux_detail {

using managed_session_start_gate =
    std::function<std::expected<void, std::string>(::pid_t child_pid)>;
using managed_session_stop_gate = std::function<std::expected<void, std::string>()>;

// Immutable two-level commitment. The controller plan digest binds Sage's
// approved canonical plan; the profile digest additionally commits to the
// exact Glove-resolved argv, executable content/identity, environment, limits,
// and lifecycle mount identities/quota partitions.
struct managed_launch_binding {
    std::string controller_plan_digest;
    std::string profile_digest;
    std::vector<library_projection_receipt> library_projections;

    auto operator==(const managed_launch_binding&) const -> bool = default;
};

struct managed_pty_session_options {
    std::size_t transcript_bytes = std::size_t{4} * 1024U * 1024U;
    std::size_t max_read_bytes = std::size_t{64} * 1024U;
    std::size_t max_input_frame_bytes = std::size_t{64} * 1024U;
    std::uint64_t input_timeout_ms = 1'000;
    std::uint16_t initial_rows = 24;
    std::uint16_t initial_columns = 80;
    std::shared_ptr<refinement_transcript_evaluator> refinement_evaluator;
};

class managed_pty_session {
public:
    struct implementation;

    managed_pty_session(const managed_pty_session&) = delete;
    auto operator=(const managed_pty_session&) -> managed_pty_session& = delete;
    managed_pty_session(managed_pty_session&&) = delete;
    auto operator=(managed_pty_session&&) -> managed_pty_session& = delete;
    ~managed_pty_session();
    explicit managed_pty_session(std::unique_ptr<implementation> state) noexcept;

    [[nodiscard]] auto pid() const noexcept -> ::pid_t;
    [[nodiscard]] auto read(std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<pty_transcript_read, std::string>;
    [[nodiscard]] auto
    wait_read(std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms)
        -> std::expected<pty_transcript_read, std::string>;
    [[nodiscard]] auto write_input(std::string_view bytes) -> std::expected<void, std::string>;
    [[nodiscard]] auto resize(std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto signal(pty_session_signal requested) -> std::expected<void, std::string>;
    [[nodiscard]] auto stop() -> std::expected<void, std::string>;
    // Executes the durable controller transition while terminal completion is
    // excluded. The gate is skipped when the waiter has already published a
    // terminal result, so callers cannot append stop intent after completion.
    [[nodiscard]] auto stop(const managed_session_stop_gate& before_stop)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto wait() -> std::expected<resource_enforcement_receipt, std::string>;
    [[nodiscard]] auto wait_refinement()
        -> std::expected<std::optional<refinement_evaluation_receipt>, std::string>;

private:
    friend auto start_managed_pty_session(
        const profile& prof,
        const std::vector<std::string>& argv,
        const managed_launch_binding& expected_binding,
        std::unique_ptr<linux_resource_lifecycle> lifecycle,
        managed_pty_session_options options,
        const managed_session_start_gate& before_child_release
    ) -> std::expected<std::unique_ptr<managed_pty_session>, std::string>;

    std::unique_ptr<implementation> state_;
};

// Private capability contract used only by the lifecycle-complete managed
// seam. The public spawner remains unavailable until daemon recovery and the
// attachable local supervisor protocol are complete.
[[nodiscard]] auto managed_session_capabilities() noexcept -> resource_enforcement_capabilities;

// Canonical encoder seam for an already-resolved launch projection. It is
// public only inside the Linux container target so planning and start share
// byte-for-byte digest logic.
[[nodiscard]] auto bind_managed_launch_projection(
    const profile& prof,
    const std::vector<std::string>& resolved_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    std::string_view controller_plan_digest
) -> std::expected<managed_launch_binding, std::string>;

// Same canonical encoder over a borrowed, already-pinned executable. Start
// uses this form so the descriptor hashed for the commitment is also the
// object mounted into the child root.
[[nodiscard]] auto bind_managed_launch_projection_from_fd(
    const profile& prof,
    const std::vector<std::string>& resolved_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    std::string_view controller_plan_digest,
    int executable_fd
) -> std::expected<managed_launch_binding, std::string>;

// Recomputable planning operation. Start repeats the same resolution and
// refuses to clone if either immutable commitment changed.
[[nodiscard]] auto bind_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const linux_resource_lifecycle& lifecycle,
    std::string_view controller_plan_digest
) -> std::expected<managed_launch_binding, std::string>;

// Internal supervisor seam for a launch whose cgroup and writable filesystems
// are already owned by one lifecycle. The returned receipt is structurally
// validated but remains unauthenticated until its caller commits it through
// the receipt producer.
[[nodiscard]] auto exec_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle
) -> std::expected<resource_enforcement_receipt, std::string>;

[[nodiscard]] auto start_managed_pty_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    managed_pty_session_options options,
    const managed_session_start_gate& before_child_release
) -> std::expected<std::unique_ptr<managed_pty_session>, std::string>;

// The gate runs after clone, UID mapping, cgroup attachment, and output-pump
// creation while the child is still blocked on its private sync pipe. Failure
// kills and reaps the child before any agent code can execute.
[[nodiscard]] auto exec_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    const managed_session_start_gate& before_child_release
) -> std::expected<resource_enforcement_receipt, std::string>;

// Lifecycle-complete authenticated seam. The producer reserves worst-case
// journal capacity before launch and returns success only after the terminal
// envelope has been durably synced.
[[nodiscard]] auto exec_managed_session_authenticated(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::string_view session_id,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    receipt_audit_producer& audit_producer
) -> std::expected<authenticated_resource_enforcement_receipt, std::string>;

} // namespace glove::container::linux_detail
