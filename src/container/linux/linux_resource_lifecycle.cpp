#include "linux_resource_lifecycle.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <new>
#include <system_error>
#include <type_traits>
#include <utility>

namespace glove::container::linux_detail {

namespace {

class input_fd_guard final {
public:
    explicit input_fd_guard(int descriptor) noexcept : descriptor_{descriptor} {}

    input_fd_guard(const input_fd_guard&) = delete;
    auto operator=(const input_fd_guard&) -> input_fd_guard& = delete;
    input_fd_guard(input_fd_guard&&) = delete;
    auto operator=(input_fd_guard&&) -> input_fd_guard& = delete;

    ~input_fd_guard() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    void release() noexcept { descriptor_ = -1; }

private:
    int descriptor_ = -1;
};

class cgroup_termination_failure final : public std::exception {
public:
    [[nodiscard]] auto what() const noexcept -> const char* override {
        return "terminate Linux resource cgroup";
    }
};

auto map_event(cgroup_limit_event event) noexcept -> resource_termination_cause {
    switch (event) {
    case cgroup_limit_event::cpu_time:
        return resource_termination_cause::cpu_time_limit;
    case cgroup_limit_event::memory:
        return resource_termination_cause::memory_limit;
    case cgroup_limit_event::pids:
        return resource_termination_cause::pid_limit;
    }
    return resource_termination_cause::supervisor_error;
}

auto terminal_cause(
    const detail::wall_output_snapshot& monitor,
    const cgroup_observation& cgroup,
    const resource_limits& limits,
    const supervisor::linux_detail::session_filesystem_usage& filesystem,
    int wait_status
) -> resource_termination_cause {
    if (monitor.forced_cause) {
        return *monitor.forced_cause;
    }
    if (cgroup.memory_limit_hit) {
        return resource_termination_cause::memory_limit;
    }
    if (cgroup.pid_limit_hit) {
        return resource_termination_cause::pid_limit;
    }
    if (cgroup.cpu_time_ms >= limits.cpu_time_ms) {
        return resource_termination_cause::cpu_time_limit;
    }
    if (filesystem.limit_hit || filesystem.filesystem_bytes > limits.disk_bytes) {
        return resource_termination_cause::disk_limit;
    }
    if (WIFEXITED(wait_status)) {
        return resource_termination_cause::exited;
    }
    if (WIFSIGNALED(wait_status)) {
        return resource_termination_cause::signaled;
    }
    return resource_termination_cause::supervisor_error;
}

} // namespace

linux_resource_lifecycle::linux_resource_lifecycle(
    [[maybe_unused]] construction_token token,
    cgroup_v2_session cgroup,
    supervisor::linux_detail::linux_session_filesystem filesystem,
    resource_limits limits,
    std::uint64_t started_at_ms
)
    : cgroup_{std::move(cgroup)},
      filesystem_{std::move(filesystem)},
      limits_{limits},
      started_at_ms_{started_at_ms} {}

linux_resource_lifecycle::~linux_resource_lifecycle() noexcept {
    stop_poller();
    if (monitor_) {
        monitor_->finish();
    }
    try {
        [[maybe_unused]] auto cleanup = cleanup_resources();
    } catch (...) { // NOLINT(bugprone-empty-catch) -- destruction is best-effort and non-throwing.
        // Owned resource destructors retry best-effort cleanup without throwing.
    }
    release_secret_resources();
}

void linux_resource_lifecycle::release_secret_resources() noexcept {
    for (auto& mount : secret_mounts_) {
        if (mount.descriptor_fd >= 0) {
            ::close(mount.descriptor_fd);
            mount.descriptor_fd = -1;
        }
    }
    for (const int descriptor : secret_lease_locks_) {
        if (descriptor >= 0) {
            ::close(descriptor);
        }
    }
    for (auto& mount : service_mounts_) {
        if (mount.descriptor_fd >= 0) {
            ::close(mount.descriptor_fd);
            mount.descriptor_fd = -1;
        }
    }
    secret_mounts_.clear();
    secret_lease_locks_.clear();
    service_mounts_.clear();
}

auto linux_resource_lifecycle::install_secret_mounts(
    std::vector<supervisor::linux_detail::session_mount> mounts, std::vector<int> lease_locks
) -> std::expected<void, std::string> {
    const auto close_inputs = [&] {
        for (auto& mount : mounts) {
            if (mount.descriptor_fd >= 0) {
                ::close(mount.descriptor_fd);
                mount.descriptor_fd = -1;
            }
        }
        for (const int descriptor : lease_locks) {
            if (descriptor >= 0) {
                ::close(descriptor);
            }
        }
    };
    if (!secret_mounts_.empty() || !secret_lease_locks_.empty() || mounts.size() > 32U ||
        mounts.size() != lease_locks.size() ||
        std::ranges::any_of(
            mounts,
            [](const auto& mount) {
                return mount.descriptor_fd < 0 || !mount.secret_handle ||
                       !mount.secret_runtime_id || !mount.writable || mount.directory;
            }
        ) ||
        std::ranges::any_of(lease_locks, [](int descriptor) { return descriptor < 0; })) {
        close_inputs();
        return std::unexpected(std::string{"invalid Linux secret mount set"});
    }
    secret_mounts_ = std::move(mounts);
    secret_lease_locks_ = std::move(lease_locks);
    return {};
}

auto linux_resource_lifecycle::install_service_mount(supervisor::linux_detail::session_mount mount)
    -> std::expected<void, std::string> {
    input_fd_guard input{mount.descriptor_fd};
    if (!service_mounts_.empty() || mount.descriptor_fd < 0 || mount.writable || !mount.directory ||
        mount.alias != "local-services" || mount.target_path != "/run/glove-services/local" ||
        !mount.source_identity || !mount.service_proxy_manifest_digest) {
        return std::unexpected(std::string{"invalid Linux local service mount"});
    }
    try {
        service_mounts_.reserve(1U);
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux local service mount"});
    }
    static_assert(std::is_nothrow_move_constructible_v<decltype(mount)>);
    service_mounts_.push_back(std::move(mount));
    input.release();
    return {};
}

auto linux_resource_lifecycle::create(
    cgroup_v2_session cgroup,
    supervisor::linux_detail::linux_session_filesystem filesystem,
    resource_limits limits,
    std::uint64_t started_at_ms
) -> std::expected<std::unique_ptr<linux_resource_lifecycle>, std::string> {
    if (cgroup.directory_fd() < 0 || started_at_ms == 0 || limits.cpu_time_ms == 0 ||
        limits.memory_bytes == 0 || limits.pids == 0 || limits.wall_time_ms == 0 ||
        limits.disk_bytes == 0 || limits.terminal_output_bytes == 0) {
        return std::unexpected(std::string{"invalid Linux resource lifecycle configuration"});
    }
    auto filesystem_usage = filesystem.observe();
    if (!filesystem_usage || filesystem_usage->quota_bytes != limits.disk_bytes) {
        return std::unexpected(
            filesystem_usage ? std::string{"Linux lifecycle filesystem quota mismatch"}
                             : filesystem_usage.error()
        );
    }
    try {
        auto owner = std::make_unique<linux_resource_lifecycle>(
            construction_token{}, std::move(cgroup), std::move(filesystem), limits, started_at_ms
        );
        auto monitor = detail::wall_output_monitor::create(
            limits.wall_time_ms,
            limits.terminal_output_bytes,
            [lifecycle = owner.get()](resource_termination_cause) {
                if (!lifecycle->kill_cgroup()) {
                    throw cgroup_termination_failure{};
                }
            }
        );
        if (!monitor) {
            return std::unexpected(monitor.error());
        }
        owner->monitor_ = std::move(*monitor);
        owner->poller_ = std::thread{[lifecycle = owner.get()] { lifecycle->poll_resources(); }};
        return owner;
    } catch (const std::system_error& error) {
        return std::unexpected(std::string{"start Linux resource lifecycle: "} + error.what());
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux resource lifecycle"});
    }
}

auto linux_resource_lifecycle::attach(::pid_t pid) -> std::expected<void, std::string> {
    const std::lock_guard finish_lock{finish_mutex_};
    if (terminal_) {
        return std::unexpected(std::string{"resource lifecycle is already finished"});
    }
    if (attached_) {
        return std::unexpected(std::string{"resource lifecycle already has a child"});
    }
    const std::lock_guard cgroup_lock{cgroup_mutex_};
    if (termination_started_.load()) {
        return std::unexpected(std::string{"resource lifecycle terminated before child attach"});
    }
    auto attached = cgroup_.attach(pid);
    if (attached) {
        attached_ = true;
    }
    return attached;
}

auto linux_resource_lifecycle::request_stop() -> std::expected<void, std::string> {
    const std::lock_guard finish_lock{finish_mutex_};
    if (terminal_ || pending_terminal_ || cgroup_cleaned_) {
        return {};
    }
    if (!attached_) {
        return std::unexpected(std::string{"resource lifecycle has no attached child"});
    }
    const std::lock_guard cgroup_lock{cgroup_mutex_};
    if (termination_started_.load()) {
        return {};
    }
    auto killed = cgroup_.kill_all();
    if (killed) {
        termination_started_.store(true);
    }
    return killed;
}

void linux_resource_lifecycle::poll_resources() noexcept {
    for (;;) {
        {
            std::unique_lock lock{poll_mutex_};
            if (poll_changed_.wait_for(lock, std::chrono::milliseconds{1}, [this] {
                    return stop_requested_;
                })) {
                return;
            }
        }
        cgroup_limit_result event;
        {
            const std::lock_guard lock{cgroup_mutex_};
            event = cgroup_.triggered_limit(limits_);
        }
        if (!event) {
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::supervisor_error)
            );
            return;
        }
        if (event->has_value()) {
            const auto limit_event = event->value_or(cgroup_limit_event::cpu_time);
            static_cast<void>(monitor_->request_termination(map_event(limit_event)));
            return;
        }
        auto filesystem = observe_filesystem();
        if (!filesystem) {
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::supervisor_error)
            );
            return;
        }
        if (filesystem->limit_hit || filesystem->filesystem_bytes > limits_.disk_bytes) {
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::disk_limit)
            );
            return;
        }
        if (monitor_->snapshot().forced_cause) {
            return;
        }
    }
}

void linux_resource_lifecycle::stop_poller() noexcept {
    {
        const std::lock_guard lock{poll_mutex_};
        stop_requested_ = true;
        poll_changed_.notify_all();
    }
    if (poller_.joinable() && poller_.get_id() != std::this_thread::get_id()) {
        poller_.join();
    }
}

auto linux_resource_lifecycle::kill_cgroup() noexcept -> bool {
    termination_started_.store(true);
    try {
        const std::lock_guard lock{cgroup_mutex_};
        return cgroup_.kill_all().has_value();
    } catch (...) {
        return false;
    }
}

auto linux_resource_lifecycle::observe_cgroup() -> std::expected<cgroup_observation, std::string> {
    const std::lock_guard lock{cgroup_mutex_};
    return cgroup_.observe();
}

auto linux_resource_lifecycle::observe_filesystem()
    -> supervisor::result<supervisor::linux_detail::session_filesystem_usage> {
    return filesystem_.observe();
}

auto linux_resource_lifecycle::cleanup_cgroup() -> std::expected<void, std::string> {
    if (cgroup_cleaned_) {
        return {};
    }
    const std::lock_guard lock{cgroup_mutex_};
    auto cleaned = cgroup_.cleanup();
    if (cleaned) {
        cgroup_cleaned_ = true;
    }
    return cleaned;
}

auto linux_resource_lifecycle::cleanup_filesystem() -> std::expected<void, std::string> {
    if (filesystem_cleaned_) {
        return {};
    }
    auto cleaned = filesystem_.cleanup();
    if (cleaned) {
        filesystem_cleaned_ = true;
    }
    return cleaned;
}

auto linux_resource_lifecycle::cleanup_resources() -> std::expected<void, std::string> {
    std::string first_error;
    if (auto cleaned = cleanup_cgroup(); !cleaned) {
        first_error = cleaned.error();
    }
    if (auto cleaned = cleanup_filesystem(); !cleaned && first_error.empty()) {
        first_error = cleaned.error();
    }
    if (!first_error.empty()) {
        return std::unexpected(std::move(first_error));
    }
    // The child is gone and its isolated resources are finalized. Credential
    // rotation must persist for the next session, while the terminal
    // transcript may remain queryable until explicit session cleanup.
    release_secret_resources();
    return {};
}

auto linux_resource_lifecycle::finish(int wait_status, std::uint64_t finished_at_ms)
    -> std::expected<linux_resource_terminal_observation, std::string> {
    const std::lock_guard finish_lock{finish_mutex_};
    if (terminal_) {
        return *terminal_;
    }
    if (pending_terminal_) {
        if (auto cleaned = cleanup_resources(); !cleaned) {
            return std::unexpected(cleaned.error());
        }
        terminal_ = *pending_terminal_;
        pending_terminal_.reset();
        return *terminal_;
    }
    if (!attached_) {
        return std::unexpected(std::string{"resource lifecycle has no attached child"});
    }
    if (finished_at_ms < started_at_ms_) {
        return std::unexpected(std::string{"resource lifecycle has invalid terminal time"});
    }
    stop_poller();
    monitor_->finish();
    auto cgroup = observe_cgroup();
    if (!cgroup) {
        return std::unexpected(cgroup.error());
    }
    auto filesystem = observe_filesystem();
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    auto retained_changes = filesystem_.finalize_retained_changes();
    if (!retained_changes) {
        return std::unexpected(retained_changes.error());
    }
    const auto wall_output = monitor_->snapshot();
    const auto cause = terminal_cause(wall_output, *cgroup, limits_, *filesystem, wait_status);
    const linux_resource_terminal_observation terminal{
        .observed =
            {
                .cpu_time_ms = cgroup->cpu_time_ms,
                .peak_memory_bytes = cgroup->peak_memory_bytes,
                .peak_pids = cgroup->peak_pids,
                .wall_time_ms = wall_output.wall_time_ms,
                .disk_bytes = filesystem->filesystem_bytes,
                .terminal_output_bytes = wall_output.terminal_output_bytes,
            },
        .termination_cause = cause,
        .exit_code = cause == resource_termination_cause::exited
                         ? std::optional<int>{WEXITSTATUS(wait_status)}
                         : std::nullopt,
        .started_at_ms = started_at_ms_,
        .finished_at_ms = finished_at_ms,
        .termination_callback_failed = wall_output.termination_callback_failed,
        .retained_changes = std::move(*retained_changes),
    };
    pending_terminal_ = terminal;
    if (auto cleaned = cleanup_resources(); !cleaned) {
        return std::unexpected(cleaned.error());
    }
    terminal_ = *pending_terminal_;
    pending_terminal_.reset();
    return *terminal_;
}

} // namespace glove::container::linux_detail
