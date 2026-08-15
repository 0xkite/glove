#include "glove/container/profile.hpp"
#include "glove/supervisor/linux_session_filesystem.hpp"

#include "cgroup_v2.hpp"
#include "linux_resource_lifecycle.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef GLOVE_CGROUP_PROBE_AGENT_BIN
#    error "GLOVE_CGROUP_PROBE_AGENT_BIN must point at the cgroup probe agent"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::resource_limits;
using glove::container::resource_termination_cause;
using glove::container::linux_detail::cgroup_v2_root;
using glove::container::linux_detail::linux_resource_lifecycle;
using glove::supervisor::linux_detail::linux_session_filesystem;

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-resource-lifecycle-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto materialization_root() const -> std::filesystem::path {
        return root_ / "materializations";
    }

    [[nodiscard]] auto prepare() const -> bool {
        const auto root = materialization_root();
        return !root_.empty() && std::filesystem::create_directory(root) &&
               ::chmod(root.c_str(), 0700) == 0;
    }

private:
    std::filesystem::path root_;
};

auto epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto stopped_probe(const char* mode, const char* argument = nullptr) -> ::pid_t {
    const ::pid_t child = ::fork();
    if (child == 0) {
        ::raise(SIGSTOP);
        if (argument == nullptr) {
            ::execl(GLOVE_CGROUP_PROBE_AGENT_BIN, GLOVE_CGROUP_PROBE_AGENT_BIN, mode, nullptr);
        } else {
            ::execl(
                GLOVE_CGROUP_PROBE_AGENT_BIN, GLOVE_CGROUP_PROBE_AGENT_BIN, mode, argument, nullptr
            );
        }
        std::_Exit(50);
    }
    return child;
}

auto wait_stopped(::pid_t child) -> bool {
    int status = 0;
    while (::waitpid(child, &status, WUNTRACED) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    return WIFSTOPPED(status);
}

auto wait_bounded(::pid_t child) -> std::expected<int, std::string> {
    for (unsigned int attempt = 0; attempt < 5'000; ++attempt) {
        int status = 0;
        const ::pid_t result = ::waitpid(child, &status, WNOHANG);
        if (result == child) {
            return status;
        }
        if (result < 0 && errno != EINTR) {
            return std::unexpected(std::string{"waitpid failed"});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    static_cast<void>(::kill(child, SIGKILL));
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return std::unexpected(std::string{"child did not terminate within test bound"});
}

auto fill_until_quota(int directory_fd, std::uint64_t quota_bytes) -> bool {
    const int fd = ::openat(
        directory_fd, "pressure", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    );
    if (fd < 0) {
        return errno == ENOSPC || errno == EDQUOT;
    }
    std::array<char, 4096> block{};
    bool denied = false;
    for (std::uint64_t attempt = 0; attempt < quota_bytes / block.size() + 32; ++attempt) {
        if (::write(fd, block.data(), block.size()) < 0) {
            denied = errno == ENOSPC || errno == EDQUOT;
            break;
        }
    }
    ::close(fd);
    return denied;
}

auto limits_with(std::uint64_t wall_time_ms, std::uint64_t output_bytes) -> resource_limits {
    return {
        .cpu_time_ms = 10'000,
        .memory_bytes = 256U * 1024U * 1024U,
        .pids = 8,
        .wall_time_ms = wall_time_ms,
        .disk_bytes = 16U * 1024U * 1024U,
        .terminal_output_bytes = output_bytes,
    };
}

auto make_lifecycle(
    cgroup_v2_root& root,
    const std::filesystem::path& materialization_root,
    std::string_view session_id,
    const resource_limits& limits,
    std::uint64_t started_at_ms
) -> std::expected<std::unique_ptr<linux_resource_lifecycle>, std::string> {
    auto cgroup = root.create_session(session_id, limits);
    if (!cgroup) {
        return std::unexpected(cgroup.error());
    }
    auto filesystem = linux_session_filesystem::create(
        materialization_root.string(), session_id, limits.disk_bytes, {}
    );
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    return linux_resource_lifecycle::create(
        std::move(*cgroup), std::move(*filesystem), limits, started_at_ms
    );
}

auto natural_exit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    const auto limits = limits_with(10'000, 1024);
    const auto started = epoch_ms();
    auto child = stopped_probe("exit", "7");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle = make_lifecycle(root, materialization_root, "lifecycle-exit", limits, started);
    REQUIRE(lifecycle.has_value());
    temporary_tree lease_tree;
    REQUIRE(lease_tree.prepare());
    const auto lease_path = lease_tree.materialization_root() / "terminal-secret-lease";
    const int lease_lock =
        ::open(lease_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    REQUIRE(lease_lock >= 0);
    REQUIRE(::flock(lease_lock, LOCK_EX | LOCK_NB) == 0);
    const int mount_descriptor = ::dup(lease_lock);
    REQUIRE(mount_descriptor >= 0);
    REQUIRE((*lifecycle)
                ->install_secret_mounts(
                    {{
                        .descriptor_fd = mount_descriptor,
                        .target_path = "/home/agent/.codex/auth.json",
                        .alias = "secret:codex-auth",
                        .quota_partition = {},
                        .quota_bytes = 0,
                        .source_identity = std::nullopt,
                        .source_content_digest = std::nullopt,
                        .projection_id = std::nullopt,
                        .projection_destination_alias = std::nullopt,
                        .runtime_adapter_id = std::nullopt,
                        .runtime_context_digest = std::nullopt,
                        .runtime_adoption_manifest_digest = std::nullopt,
                        .runtime_adoption_snapshot_digest = std::nullopt,
                        .secret_handle = "codex-auth",
                        .secret_runtime_id = "codex",
                        .writable = true,
                        .directory = false,
                    }},
                    {lease_lock}
                )
                .has_value());
    const int contender = ::open(lease_path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(contender >= 0);
    REQUIRE(::flock(contender, LOCK_EX | LOCK_NB) != 0);
    REQUIRE(errno == EWOULDBLOCK || errno == EAGAIN);
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::exited);
    REQUIRE(terminal->exit_code == 7);
    REQUIRE(terminal->observed.disk_bytes <= limits.disk_bytes);
    REQUIRE(::flock(contender, LOCK_EX | LOCK_NB) == 0);
    REQUIRE(::close(contender) == 0);
    auto repeated = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(repeated == terminal);
    return 0;
}

auto expired_before_attach_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    const auto limits = limits_with(1, 1024);
    auto child = stopped_probe("sleep");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-expired", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    auto attached = (*lifecycle)->attach(child);
    static_cast<void>(::kill(child, SIGKILL));
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    REQUIRE(!attached.has_value());
    return 0;
}

auto wall_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    const auto limits = limits_with(25, 1024);
    auto child = stopped_probe("sleep");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-wall", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    REQUIRE(WIFSIGNALED(*status));
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::wall_time_limit);
    REQUIRE(!terminal->exit_code.has_value());
    REQUIRE(terminal->observed.wall_time_ms >= limits.wall_time_ms);
    return 0;
}

auto output_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    const auto limits = limits_with(10'000, 10);
    auto child = stopped_probe("sleep");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-output", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    REQUIRE(!(*lifecycle)->monitor()->account_terminal_output(11));
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::terminal_output_limit);
    REQUIRE(terminal->observed.terminal_output_bytes == 11);
    return 0;
}

auto disk_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    auto limits = limits_with(10'000, 1024);
    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    limits.disk_bytes = static_cast<std::uint64_t>(page_size) * 16U;
    auto child = stopped_probe("sleep");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-disk", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    const auto mounts = (*lifecycle)->mounts();
    const auto tmp = std::ranges::find(
        mounts, std::string{"/tmp"}, &glove::supervisor::linux_detail::session_mount::target_path
    );
    REQUIRE(tmp != mounts.end());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    REQUIRE(fill_until_quota(tmp->descriptor_fd, limits.disk_bytes));
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    REQUIRE(WIFSIGNALED(*status));
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::disk_limit);
    REQUIRE(terminal->observed.disk_bytes > 0);
    REQUIRE(terminal->observed.disk_bytes <= limits.disk_bytes);
    return 0;
}

auto cpu_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    auto limits = limits_with(10'000, 1024);
    limits.cpu_time_ms = 25;
    auto child = stopped_probe("cpu");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-cpu", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::cpu_time_limit);
    REQUIRE(terminal->observed.cpu_time_ms >= limits.cpu_time_ms);
    return 0;
}

auto memory_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    auto limits = limits_with(10'000, 1024);
    limits.memory_bytes = 96U * 1024U * 1024U;
    auto child = stopped_probe("memory", "402653184");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-memory", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::memory_limit);
    REQUIRE(terminal->observed.peak_memory_bytes > 0);
    return 0;
}

auto pid_limit_terminal_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root
) -> int {
    auto limits = limits_with(10'000, 1024);
    limits.pids = 2;
    auto child = stopped_probe("pids");
    REQUIRE(child > 0);
    REQUIRE(wait_stopped(child));
    auto lifecycle =
        make_lifecycle(root, materialization_root, "lifecycle-pids", limits, epoch_ms());
    REQUIRE(lifecycle.has_value());
    REQUIRE((*lifecycle)->attach(child).has_value());
    REQUIRE(::kill(child, SIGCONT) == 0);
    auto status = wait_bounded(child);
    REQUIRE(status.has_value());
    auto terminal = (*lifecycle)->finish(*status, epoch_ms());
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::pid_limit);
    REQUIRE(terminal->observed.peak_pids == limits.pids);
    return 0;
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(tree.prepare());
    const auto materialization_root = tree.materialization_root();
    auto root = cgroup_v2_root::prepare_for_current_process();
    if (!root) {
        std::fprintf(
            stderr, "cgroup v2 lifecycle topology unavailable: %s\n", root.error().c_str()
        );
        return 77;
    }
    REQUIRE(expired_before_attach_test(*root, materialization_root) == 0);
    REQUIRE(natural_exit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(wall_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(output_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(disk_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(cpu_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(memory_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(pid_limit_terminal_test(*root, materialization_root) == 0);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
