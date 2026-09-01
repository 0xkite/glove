#pragma once

#include "glove/supervisor/linux_session_filesystem.hpp"

#include "../resource_monitor.hpp"
#include "cgroup_v2.hpp"
#include "inherited_stream_descriptor.hpp"

#include <sys/types.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace glove::container::linux_detail {

// Terminal evidence produced by the cgroup/watchdog/output/filesystem owner.
// This is deliberately not a v1 enforcement receipt: the managed-session
// owner binds it to the immutable launch commitment, while audit authentication
// still remains outside this lifecycle.
struct linux_resource_terminal_observation {
    resource_usage observed;
    resource_termination_cause termination_cause = resource_termination_cause::supervisor_error;
    std::optional<int> exit_code;
    std::uint64_t started_at_ms = 0;
    std::uint64_t finished_at_ms = 0;
    bool termination_callback_failed = false;
    std::vector<supervisor::retained_change_manifest> retained_changes;

    auto operator==(const linux_resource_terminal_observation&) const -> bool = default;
};

// Owns the resource-enforcement lifetime around one already-created Linux
// cgroup. It does not make the public spawner eligible by itself: the caller
// still must mount the borrowed filesystem descriptors into the sandbox child,
// attach that child, and route both output streams through the returned monitor.
class linux_resource_lifecycle {
    struct construction_token {};

public:
    linux_resource_lifecycle(
        [[maybe_unused]] construction_token token,
        cgroup_v2_session cgroup,
        supervisor::linux_detail::linux_session_filesystem filesystem,
        resource_limits limits,
        std::uint64_t started_at_ms
    );

    linux_resource_lifecycle(const linux_resource_lifecycle&) = delete;
    auto operator=(const linux_resource_lifecycle&) -> linux_resource_lifecycle& = delete;
    linux_resource_lifecycle(linux_resource_lifecycle&&) = delete;
    auto operator=(linux_resource_lifecycle&&) -> linux_resource_lifecycle& = delete;
    ~linux_resource_lifecycle() noexcept;

    [[nodiscard]] static auto create(
        cgroup_v2_session cgroup,
        supervisor::linux_detail::linux_session_filesystem filesystem,
        resource_limits limits,
        std::uint64_t started_at_ms
    ) -> std::expected<std::unique_ptr<linux_resource_lifecycle>, std::string>;

    [[nodiscard]] auto attach(::pid_t pid) -> std::expected<void, std::string>;
    [[nodiscard]] auto request_stop() -> std::expected<void, std::string>;

    [[nodiscard]] auto monitor() const noexcept
        -> const std::shared_ptr<detail::wall_output_monitor>& {
        return monitor_;
    }

    [[nodiscard]] auto cgroup_fd() const noexcept -> int { return cgroup_.directory_fd(); }

    [[nodiscard]] auto limits() const noexcept -> const resource_limits& { return limits_; }

    [[nodiscard]] auto mounts() const -> std::vector<supervisor::linux_detail::session_mount> {
        auto mounts = filesystem_.mounts();
        mounts.insert(mounts.end(), secret_mounts_.begin(), secret_mounts_.end());
        mounts.insert(mounts.end(), service_mounts_.begin(), service_mounts_.end());
        return mounts;
    }

    [[nodiscard]] auto install_secret_mounts(
        std::vector<supervisor::linux_detail::session_mount> mounts,
        std::vector<int> lease_locks = {}
    ) -> std::expected<void, std::string>;
    [[nodiscard]] auto install_service_mount(supervisor::linux_detail::session_mount mount)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto
    install_inherited_streams(std::vector<inherited_stream_descriptor> descriptors)
        -> std::expected<void, std::string>;

    [[nodiscard]] auto inherited_streams() const noexcept
        -> const std::vector<inherited_stream_descriptor>& {
        return inherited_streams_;
    }

    void close_inherited_streams_after_clone() noexcept;

    [[nodiscard]] auto finish(int wait_status, std::uint64_t finished_at_ms)
        -> std::expected<linux_resource_terminal_observation, std::string>;

private:
    void poll_resources() noexcept;
    void stop_poller() noexcept;
    [[nodiscard]] auto kill_cgroup() noexcept -> bool;
    [[nodiscard]] auto observe_cgroup() -> std::expected<cgroup_observation, std::string>;
    [[nodiscard]] auto observe_filesystem()
        -> supervisor::result<supervisor::linux_detail::session_filesystem_usage>;
    [[nodiscard]] auto cleanup_cgroup() -> std::expected<void, std::string>;
    [[nodiscard]] auto cleanup_filesystem() -> std::expected<void, std::string>;
    [[nodiscard]] auto cleanup_resources() -> std::expected<void, std::string>;
    void release_secret_resources() noexcept;

    cgroup_v2_session cgroup_;
    supervisor::linux_detail::linux_session_filesystem filesystem_;
    resource_limits limits_;
    std::uint64_t started_at_ms_ = 0;
    std::shared_ptr<detail::wall_output_monitor> monitor_;

    std::mutex cgroup_mutex_;
    // The monitor callback publishes this before attempting the cgroup kill.
    // Sequential consistency keeps attach-vs-kill ordering simple and explicit.
    std::atomic_bool termination_started_{false};
    std::mutex poll_mutex_;
    std::condition_variable poll_changed_;
    bool stop_requested_ = false;
    std::thread poller_;

    std::mutex finish_mutex_;
    bool attached_ = false;
    bool cgroup_cleaned_ = false;
    bool filesystem_cleaned_ = false;
    std::optional<linux_resource_terminal_observation> pending_terminal_;
    std::optional<linux_resource_terminal_observation> terminal_;
    std::vector<supervisor::linux_detail::session_mount> secret_mounts_;
    std::vector<supervisor::linux_detail::session_mount> service_mounts_;
    std::vector<inherited_stream_descriptor> inherited_streams_;
    // These descriptors carry exclusive flock(2) leases for rotating
    // credentials. They intentionally outlive process creation and remain
    // held until the child and its isolated resources are terminal.
    std::vector<int> secret_lease_locks_;
};

} // namespace glove::container::linux_detail
