// Linux container spawner. A clone3 child creates its own:
//
//   - user   namespace (CLONE_NEWUSER) — rootless; the contained agent runs
//     as fake-root in its own UID space, mapped from the calling user.
//   - mount  namespace (CLONE_NEWNS)  — an allowlisted rootfs followed by
//     pivot_root; host paths not explicitly bound do not exist there.
//   - pid    namespace (CLONE_NEWPID) — agent runs as PID 1 in its own
//     process tree; cannot see or signal host processes.
//   - net    namespace (CLONE_NEWNET) — only loopback is available; no
//     route to the host's network adapters.
//   - ipc    namespace (CLONE_NEWIPC) — own SysV / POSIX IPC keyspace.
//   - uts    namespace (CLONE_NEWUTS) — own hostname / domainname.
//
// A seccomp deny list is installed after setup and before exec. The public
// Mandatory resource profiles are rejected until every declared limit and an
// observable receipt are enforced by this backend.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include "linux_egress_bridge.hpp"
#include "linux_managed_session.hpp"
#include "output_pump.hpp"

#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <seccomp.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

// kernel uapi struct clone_args (linux/sched.h); declared inline to avoid
// the standard header conflict between <sched.h> and <linux/sched.h>.
struct clone_args_v3 {
    std::uint64_t flags;
    std::uint64_t pidfd;
    std::uint64_t child_tid;
    std::uint64_t parent_tid;
    std::uint64_t exit_signal;
    std::uint64_t stack;
    std::uint64_t stack_size;
    std::uint64_t tls;
    std::uint64_t set_tid;
    std::uint64_t set_tid_size;
    std::uint64_t cgroup;
};

auto sys_clone3(clone_args_v3* args, std::size_t size) -> long {
    return ::syscall(SYS_clone3, args, size);
}

// mount_setattr(2) uapi (linux/mount.h), declared inline to avoid the header
// clash between <sys/mount.h> and <linux/mount.h>. Used to flip a whole bound
// subtree read-only in one call (kernel >= 5.12).
#ifndef AT_RECURSIVE
#    define AT_RECURSIVE 0x8000
#endif
struct mount_attr_v {
    std::uint64_t attr_set;
    std::uint64_t attr_clr;
    std::uint64_t propagation;
    std::uint64_t userns_fd;
};

constexpr std::uint64_t glove_mount_attr_rdonly = 0x00000001ULL;
constexpr std::uint64_t glove_mount_attr_nosuid = 0x00000002ULL;
constexpr std::uint64_t glove_mount_attr_nodev = 0x00000004ULL;
constexpr unsigned int glove_move_mount_empty_path = 0x00000004U;

#if defined(CLONE_INTO_CGROUP)
constexpr std::uint64_t glove_clone_into_cgroup = CLONE_INTO_CGROUP;
#else
constexpr std::uint64_t glove_clone_into_cgroup = 0x200000000ULL;
#endif

struct child_stdio_capture {
    int stdout_read_close = -1;
    int stdout_write = -1;
    int stderr_read_close = -1;
    int stderr_write = -1;
    int terminal_master_close = -1;
    int terminal_slave = -1;
};

struct launched_sandbox_child {
    ::pid_t pid = -1;
    std::unique_ptr<detail::output_pump> output;
    std::unique_ptr<linux_detail::host_egress_bridge> egress;
};

struct launched_pty_child {
    ::pid_t pid = -1;
    std::unique_ptr<linux_detail::pty_session_channel> terminal;
    std::unique_ptr<linux_detail::host_egress_bridge> egress;
};

class owned_fd {
public:
    explicit owned_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    owned_fd(const owned_fd&) = delete;
    auto operator=(const owned_fd&) -> owned_fd& = delete;

    owned_fd(owned_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(owned_fd&& other) noexcept -> owned_fd& {
        if (this != &other) {
            close();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~owned_fd() { close(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    void close() noexcept {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

auto errno_message(int error) -> std::string {
    return std::error_code{error, std::generic_category()}.message();
}

auto install_child_output_capture(const child_stdio_capture& capture)
    -> std::expected<void, std::string> {
    const std::array descriptors = {
        capture.stdout_read_close,
        capture.stdout_write,
        capture.stderr_read_close,
        capture.stderr_write,
    };
    const bool requested = std::ranges::any_of(descriptors, [](int fd) { return fd >= 0; });
    const bool terminal_requested =
        capture.terminal_master_close >= 0 || capture.terminal_slave >= 0;
    if (requested && terminal_requested) {
        return std::unexpected(std::string{"conflicting child output capture"});
    }
    if (terminal_requested) {
        if (capture.terminal_master_close < 0 || capture.terminal_slave < 0) {
            return std::unexpected(std::string{"incomplete PTY capture"});
        }
        ::close(capture.terminal_master_close);
        if (::setsid() < 0) {
            return std::unexpected(std::string{"setsid PTY child: "} + errno_message(errno));
        }
        if (::ioctl(capture.terminal_slave, TIOCSCTTY, 0) < 0) {
            return std::unexpected(
                std::string{"set PTY controlling terminal: "} + errno_message(errno)
            );
        }
        for (const int descriptor : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
            if (::dup2(capture.terminal_slave, descriptor) < 0) {
                return std::unexpected(std::string{"dup2 PTY stdio: "} + errno_message(errno));
            }
        }
        if (capture.terminal_slave > STDERR_FILENO) {
            ::close(capture.terminal_slave);
        }
        return {};
    }
    if (!requested) {
        return {};
    }
    if (std::ranges::any_of(descriptors, [](int fd) { return fd < 0; })) {
        return std::unexpected(std::string{"incomplete output capture"});
    }
    if (::dup2(capture.stdout_write, STDOUT_FILENO) < 0) {
        return std::unexpected(std::string{"dup2 stdout: "} + errno_message(errno));
    }
    if (::dup2(capture.stderr_write, STDERR_FILENO) < 0) {
        return std::unexpected(std::string{"dup2 stderr: "} + errno_message(errno));
    }
    for (const int fd : descriptors) {
        ::close(fd);
    }
    return {};
}

auto sys_mount_setattr(const char* path, unsigned int flags, mount_attr_v* attr) -> long {
    return ::syscall(SYS_mount_setattr, AT_FDCWD, path, flags, attr, sizeof(*attr));
}

class pipe_transport final : public glove::mcp::transport {
public:
    pipe_transport(int write_fd, std::unique_ptr<detail::output_pump> output)
        : write_fd_{write_fd}, output_{std::move(output)} {}

    pipe_transport(const pipe_transport&) = delete;
    pipe_transport& operator=(const pipe_transport&) = delete;
    pipe_transport(pipe_transport&&) = delete;
    pipe_transport& operator=(pipe_transport&&) = delete;

    ~pipe_transport() override {
        if (write_fd_ >= 0) {
            ::close(write_fd_);
        }
        output_->stop();
    }

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        if (frame.find('\n') != std::string_view::npos ||
            frame.find('\r') != std::string_view::npos) {
            return std::unexpected(std::string{"frame contains a line delimiter"});
        }
        std::string line;
        line.reserve(frame.size() + 1);
        line.append(frame);
        line.push_back('\n');
        const char* cursor = line.data();
        std::size_t remaining = line.size();
        while (remaining > 0) {
            ::ssize_t written = ::write(write_fd_, cursor, remaining);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"write: "} + std::strerror(errno));
            }
            cursor += written;
            remaining -= static_cast<std::size_t>(written);
        }
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        return output_->recv_frame();
    }

private:
    int write_fd_;
    std::unique_ptr<detail::output_pump> output_;
};

class linux_agent_handle final : public agent_handle {
public:
    linux_agent_handle(
        ::pid_t pid,
        std::unique_ptr<pipe_transport> t,
        std::unique_ptr<linux_detail::host_egress_bridge> egress
    )
        : pid_{pid}, transport_{std::move(t)}, egress_{std::move(egress)} {}

    ~linux_agent_handle() override {
        transport_.reset();
        if (!waited_) {
            (void)wait();
        }
    }

    auto transport() -> glove::mcp::transport& override { return *transport_; }

    auto wait() -> std::expected<int, std::string> override {
        if (waited_) {
            return cached_code_;
        }
        int status = 0;
        for (int spins = 0; spins < 50; ++spins) {
            ::pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) {
                waited_ = true;
                cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                return cached_code_;
            }
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
            }
            ::usleep(10 * 1000);
        }
        (void)::kill(pid_, SIGTERM);
        for (int spins = 0; spins < 50; ++spins) {
            ::pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) {
                waited_ = true;
                cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                return cached_code_;
            }
            if (r < 0 && errno != EINTR) {
                return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
            }
            ::usleep(10 * 1000);
        }
        (void)::kill(pid_, SIGKILL);
        while (::waitpid(pid_, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
        }
        waited_ = true;
        cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return cached_code_;
    }

    [[nodiscard]] auto resource_receipt() const
        -> std::expected<resource_enforcement_receipt, std::string> override {
        return std::unexpected(std::string{"resource enforcement receipt unavailable"});
    }

private:
    ::pid_t pid_;
    std::unique_ptr<pipe_transport> transport_;
    std::unique_ptr<linux_detail::host_egress_bridge> egress_;
    bool waited_ = false;
    int cached_code_ = -1;
};

void close_fd(int& fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

void close_pipe_pair(int (&fds)[2]) noexcept {
    close_fd(fds[0]);
    close_fd(fds[1]);
}

// Write `value` to the file at `path`, returning false on failure. Used for
// the user-namespace uid_map/gid_map dance.
auto write_file(const char* path, std::string_view value) -> bool {
    int fd = ::open(path, O_WRONLY | O_CLOEXEC); // NOLINT
    if (fd < 0) {
        return false;
    }
    bool ok = true;
    std::size_t off = 0;
    while (off < value.size()) {
        ::ssize_t n = ::write(fd, value.data() + off, value.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return ok;
}

auto setup_uid_map(::pid_t child) -> std::expected<void, std::string> {
    const auto host_uid = ::getuid();
    const auto host_gid = ::getgid();

    char buf[64];

    std::snprintf(buf, sizeof(buf), "/proc/%d/uid_map", child);
    std::string uid_line = "0 ";
    uid_line.append(std::to_string(host_uid));
    uid_line.append(" 1\n");
    if (!write_file(buf, uid_line)) {
        return std::unexpected(std::string{"write uid_map: "} + std::strerror(errno));
    }

    // Modern kernels disallow gid_map writes unless setgroups is denied
    // first. This is the only safe path for unprivileged user namespaces.
    std::snprintf(buf, sizeof(buf), "/proc/%d/setgroups", child);
    if (!write_file(buf, "deny\n")) {
        // Older kernels may not have this file; tolerate ENOENT only.
        if (errno != ENOENT) {
            return std::unexpected(std::string{"write setgroups: "} + std::strerror(errno));
        }
    }

    std::snprintf(buf, sizeof(buf), "/proc/%d/gid_map", child);
    std::string gid_line = "0 ";
    gid_line.append(std::to_string(host_gid));
    gid_line.append(" 1\n");
    if (!write_file(buf, gid_line)) {
        return std::unexpected(std::string{"write gid_map: "} + std::strerror(errno));
    }
    return {};
}

auto make_mount_target(const std::string& target, const struct ::stat& source_stat)
    -> std::expected<void, std::string> {
    std::error_code ec;
    if (S_ISDIR(source_stat.st_mode)) {
        std::filesystem::create_directories(target, ec);
    } else {
        std::filesystem::create_directories(std::filesystem::path{target}.parent_path(), ec);
        if (!ec) {
            const int fd = ::open(target.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0600);
            if (fd < 0) {
                ec = std::error_code{errno, std::generic_category()};
            } else {
                ::close(fd);
            }
        }
    }
    if (ec) {
        return std::unexpected(
            std::string{"create mount target '"} + target + "': " + ec.message()
        );
    }
    return {};
}

auto bind_path(const std::string& new_root, std::string_view source, bool writable)
    -> std::expected<void, std::string> {
    struct ::stat source_stat{};

    const std::string source_string{source};
    if (::stat(source_string.c_str(), &source_stat) < 0) {
        return std::unexpected(
            std::string{"stat bind source '"} + source_string + "': " + std::strerror(errno)
        );
    }
    const std::string target = new_root + source_string;
    if (auto made = make_mount_target(target, source_stat); !made) {
        return made;
    }
    const unsigned long flags = MS_BIND | (S_ISDIR(source_stat.st_mode) ? MS_REC : 0UL);
    if (::mount(source_string.c_str(), target.c_str(), nullptr, flags, nullptr) < 0) {
        return std::unexpected(
            std::string{"bind '"} + source_string + "': " + std::strerror(errno)
        );
    }
    if (!writable) {
        mount_attr_v attributes{};
        attributes.attr_set = glove_mount_attr_rdonly;
        const unsigned int attribute_flags = S_ISDIR(source_stat.st_mode) ? AT_RECURSIVE : 0U;
        if (sys_mount_setattr(target.c_str(), attribute_flags, &attributes) < 0) {
            return std::unexpected(
                std::string{"make read-only '"} + source_string + "': " + std::strerror(errno)
            );
        }
    }
    return {};
}

auto bind_program_descriptor(
    const std::string& new_root, std::string_view target_path, int descriptor
) -> std::expected<void, std::string> {
    struct ::stat source_status{};

    if (descriptor < 0 || ::fstat(descriptor, &source_status) < 0 ||
        !S_ISREG(source_status.st_mode)) {
        return std::unexpected(std::string{"invalid managed executable descriptor"});
    }
    const std::string target = new_root + std::string{target_path};
    if (auto made = make_mount_target(target, source_status); !made) {
        return made;
    }
    // Linux has no typed libc wrapper for move_mount(2).
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    if (::syscall(
            SYS_move_mount, descriptor, "", AT_FDCWD, target.c_str(), glove_move_mount_empty_path
        ) < 0) {
        return std::unexpected(
            std::string{"move managed executable descriptor: "} + errno_message(errno)
        );
    }
    mount_attr_v attributes{};
    attributes.attr_set = glove_mount_attr_rdonly;
    if (sys_mount_setattr(target.c_str(), 0, &attributes) < 0) {
        return std::unexpected(
            std::string{"make managed executable read-only: "} + errno_message(errno)
        );
    }

    struct ::stat target_status{};

    if (::stat(target.c_str(), &target_status) < 0 ||
        target_status.st_dev != source_status.st_dev ||
        target_status.st_ino != source_status.st_ino) {
        return std::unexpected(std::string{"managed executable identity mismatch after bind"});
    }
    return {};
}

auto bind_session_mount(
    const std::string& new_root, const supervisor::linux_detail::session_mount& mount
) -> std::expected<void, std::string> {
    if (mount.descriptor_fd < 0) {
        return std::unexpected(std::string{"session mount descriptor is closed"});
    }

    struct ::stat source_status{};

    if (::fstat(mount.descriptor_fd, &source_status) < 0) {
        return std::unexpected(
            std::string{"inspect session mount descriptor: "} + errno_message(errno)
        );
    }
    const bool source_is_directory = S_ISDIR(source_status.st_mode);
    if ((!source_is_directory && !S_ISREG(source_status.st_mode)) ||
        source_is_directory != mount.directory) {
        return std::unexpected(std::string{"session mount descriptor type mismatch"});
    }
    const std::string target = new_root + mount.target_path;
    if (auto made = make_mount_target(target, source_status); !made) {
        return made;
    }
    // Linux has no typed libc wrapper for move_mount(2).
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    if (::syscall(
            SYS_move_mount,
            mount.descriptor_fd,
            "",
            AT_FDCWD,
            target.c_str(),
            glove_move_mount_empty_path
        ) < 0) {
        const int saved = errno;
        ::close(mount.descriptor_fd);
        return std::unexpected(
            std::string{"attach session mount '"} + mount.alias + "': " + errno_message(saved)
        );
    }
    ::close(mount.descriptor_fd);
    mount_attr_v attributes{};
    attributes.attr_set = glove_mount_attr_nosuid | glove_mount_attr_nodev;
    if (!mount.writable) {
        attributes.attr_set |= glove_mount_attr_rdonly;
    }
    const unsigned int flags = source_is_directory ? AT_RECURSIVE : 0U;
    if (sys_mount_setattr(target.c_str(), flags, &attributes) < 0) {
        return std::unexpected(
            std::string{"harden session mount '"} + mount.alias + "': " + errno_message(errno)
        );
    }

    struct ::stat target_status{};

    if (::stat(target.c_str(), &target_status) < 0 ||
        target_status.st_dev != source_status.st_dev ||
        target_status.st_ino != source_status.st_ino) {
        return std::unexpected(std::string{"session mount identity mismatch after bind"});
    }
    return {};
}

auto bind_if_present(const std::string& new_root, std::string_view source)
    -> std::expected<void, std::string> {
    struct ::stat source_stat{};

    const std::string source_string{source};
    if (::stat(source_string.c_str(), &source_stat) < 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(
            std::string{"stat runtime path '"} + source_string + "': " + std::strerror(errno)
        );
    }
    return bind_path(new_root, source, false);
}

// Construct an empty root and add only immutable runtime paths, the selected
// executable, and explicit profile grants. The host root is never recursively
// bound, so unrelated repositories, homes, and secret stores do not exist in
// the agent's mount namespace.
auto build_rootfs(
    const std::string& new_root,
    const profile& prof,
    std::string_view agent_program,
    std::span<const supervisor::linux_detail::session_mount> session_mounts,
    int agent_program_fd
) -> std::expected<void, std::string> {
    constexpr const char* runtime_paths[] = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    };
    for (const auto* runtime : runtime_paths) {
        if (auto bound = bind_if_present(new_root, runtime); !bound) {
            return bound;
        }
    }
    for (const auto* directory : {"/proc", "/tmp", "/var", "/var/tmp"}) {
        std::error_code ec;
        std::filesystem::create_directories(new_root + directory, ec);
        if (ec) {
            return std::unexpected(
                std::string{"create private mount point "} + directory + ": " + ec.message()
            );
        }
    }
    const std::string proc = new_root + "/proc";
    if (::mount("proc", proc.c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) < 0) {
        return std::unexpected(std::string{"mount /proc: "} + std::strerror(errno));
    }
    if (session_mounts.empty()) {
        for (const auto* directory : {"/tmp", "/var/tmp"}) {
            const std::string target = new_root + directory;
            if (::mount("tmpfs", target.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "size=512M") < 0) {
                return std::unexpected(
                    std::string{"mount private "} + directory + ": " + std::strerror(errno)
                );
            }
        }
    }
    // Explicit grants are layered after private /tmp and /var/tmp so a
    // selected file beneath either path remains visible instead of being
    // hidden by the tmpfs mount.
    auto program_bound = agent_program_fd >= 0
                             ? bind_program_descriptor(new_root, agent_program, agent_program_fd)
                             : bind_path(new_root, agent_program, false);
    if (!program_bound) {
        return program_bound;
    }
    for (const auto& rule : prof.runtime_filesystem) {
        if (auto bound = bind_path(new_root, rule.path, false); !bound) {
            return bound;
        }
    }
    for (const auto& rule : prof.filesystem) {
        if (auto bound = bind_path(new_root, rule.path, rule.writable); !bound) {
            return bound;
        }
    }
    for (const auto& mount : session_mounts) {
        if (auto bound = bind_session_mount(new_root, mount); !bound) {
            return bound;
        }
    }
    mount_attr_v root_attributes{};
    root_attributes.attr_set = glove_mount_attr_rdonly;
    if (sys_mount_setattr(new_root.c_str(), 0, &root_attributes) < 0) {
        return std::unexpected(std::string{"make root read-only: "} + std::strerror(errno));
    }
    return {};
}

auto resolve_program(const profile& prof, std::string_view program)
    -> std::expected<std::string, std::string> {
    std::vector<std::filesystem::path> candidates;
    if (program.find('/') != std::string_view::npos) {
        candidates.emplace_back(program);
    } else {
        std::string path = "/usr/bin:/bin:/usr/sbin:/sbin";
        for (const auto& entry : prof.environment) {
            if (entry.starts_with("PATH=")) {
                path = entry.substr(5);
                break;
            }
        }
        std::string_view remaining{path};
        while (true) {
            const auto colon = remaining.find(':');
            const auto part = remaining.substr(0, colon);
            if (!part.empty()) {
                candidates.emplace_back(std::filesystem::path{part} / program);
            }
            if (colon == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(colon + 1);
        }
    }
    for (const auto& candidate : candidates) {
        if (::access(candidate.c_str(), X_OK) != 0) {
            continue;
        }
        std::error_code ec;
        auto canonical = std::filesystem::canonical(candidate, ec);
        if (!ec) {
            return canonical.string();
        }
    }
    return std::unexpected(std::string{"cannot resolve executable: "} + std::string{program});
}

auto install_environment(const profile& prof) -> std::expected<void, std::string> {
    if (::clearenv() != 0) {
        return std::unexpected(std::string{"clearenv: "} + std::strerror(errno));
    }
    for (const auto& entry : prof.environment) {
        const auto equals = entry.find('=');
        const std::string name = entry.substr(0, equals);
        if (::setenv(name.c_str(), entry.c_str() + equals + 1, 1) != 0) {
            return std::unexpected(std::string{"setenv "} + name + ": " + std::strerror(errno));
        }
    }
    const auto& home_dir = prof.managed_home_dir ? prof.managed_home_dir : prof.home_dir;
    if (home_dir && ::setenv("HOME", home_dir->c_str(), 1) != 0) {
        return std::unexpected(std::string{"setenv HOME: "} + std::strerror(errno));
    }
    if (prof.temp_dir && ::setenv("TMPDIR", prof.temp_dir->c_str(), 1) != 0) {
        return std::unexpected(std::string{"setenv TMPDIR: "} + std::strerror(errno));
    }
    if (::setenv("GLOVE_SANDBOXED", "1", 1) != 0) {
        return std::unexpected(std::string{"setenv GLOVE_SANDBOXED: "} + std::strerror(errno));
    }
    if (prof.proxy) {
        for (const char* name :
             {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"}) {
            if (::setenv(name, prof.proxy->url.c_str(), 1) != 0) {
                return std::unexpected(std::string{"setenv "} + name + ": " + std::strerror(errno));
            }
        }
    }
    return {};
}

// Install a seccomp-bpf filter that denies new-socket-creation syscalls and
// other namespace-mutating operations. Existing fds (our inherited stdio
// pipes) are unaffected — read/write still work.
//
// This is the v0.1 conservative cut: default ALLOW + deny list. The
// alternative — default DENY + minimal allow list — is the production
// configuration we'll layer on once we have evidence about which syscalls
// real agents need. Production-grade seccomp profiles must be data-driven;
// premature minimisation breaks debuggers, sanitizers, and language
// runtimes that grow new syscall use across releases.
auto setup_seccomp(bool proxy_enabled) -> std::expected<void, std::string> {
    ::scmp_filter_ctx ctx = ::seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == nullptr) {
        return std::unexpected(std::string{"seccomp_init failed"});
    }

    auto deny = [&](int syscall_nr) -> int {
        return ::seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_nr, 0);
    };

    // Network: deny all Internet-capable socket creation. A local AF_UNIX
    // socketpair is safe inside the private IPC namespace and lets runtimes use
    // their signal helpers; it cannot connect to a host or network endpoint.
    // The kernel-mediated MCP pipe is already open (file descriptors survive
    // seccomp_load), so the agent can still read/write its existing channel.
    const int always_denied_net_syscalls[] = {
        SCMP_SYS(bind),
        SCMP_SYS(listen),
        SCMP_SYS(accept),
        SCMP_SYS(accept4),
    };
    for (int sc : always_denied_net_syscalls) {
        if (int rc = deny(sc); rc != 0) {
            ::seccomp_release(ctx);
            return std::unexpected(std::string{"deny network syscall: "} + std::strerror(-rc));
        }
    }
    if (!proxy_enabled) {
        const int offline_net_syscalls[] = {
            SCMP_SYS(socket),
            SCMP_SYS(connect),
            SCMP_SYS(getsockname),
            SCMP_SYS(getpeername),
            SCMP_SYS(setsockopt),
            SCMP_SYS(getsockopt),
        };
        for (int sc : offline_net_syscalls) {
            if (int rc = deny(sc); rc != 0) {
                ::seccomp_release(ctx);
                return std::unexpected(
                    std::string{"deny offline network syscall: "} + std::strerror(-rc)
                );
            }
        }
    } else {
        // The agent may create AF_INET stream sockets only inside its private
        // network namespace. That namespace has no external route and exposes
        // one private-loopback listener backed by the descriptor bridge.
        const scmp_arg_cmp unspecified_domain{
            .arg = 0,
            .op = SCMP_CMP_EQ,
            .datum_a = AF_UNSPEC,
            .datum_b = 0,
        };
        if (int rc = ::seccomp_rule_add(
                ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, unspecified_domain
            );
            rc != 0) {
            ::seccomp_release(ctx);
            return std::unexpected(
                std::string{"restrict proxy socket domain: "} + std::strerror(-rc)
            );
        }
        const scmp_arg_cmp unsupported_domain{
            .arg = 0,
            .op = SCMP_CMP_GT,
            .datum_a = AF_INET,
            .datum_b = 0,
        };
        if (int rc = ::seccomp_rule_add(
                ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, unsupported_domain
            );
            rc != 0) {
            ::seccomp_release(ctx);
            return std::unexpected(
                std::string{"restrict proxy socket family: "} + std::strerror(-rc)
            );
        }
    }
    const scmp_arg_cmp socketpair_domain{
        .arg = 0,
        .op = SCMP_CMP_NE,
        .datum_a = AF_UNIX,
        .datum_b = 0,
    };
    if (int rc = ::seccomp_rule_add(
            ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 1, socketpair_domain
        );
        rc != 0) {
        ::seccomp_release(ctx);
        return std::unexpected(std::string{"deny non-Unix socketpair: "} + std::strerror(-rc));
    }

    // Namespace + mount manipulation: an already-contained agent has no
    // legitimate need to set up its own namespaces or mount things.
    const int ns_syscalls[] = {
        SCMP_SYS(unshare),
        SCMP_SYS(setns),
        SCMP_SYS(mount),
        SCMP_SYS(umount2),
        SCMP_SYS(pivot_root),
        SCMP_SYS(chroot),
    };
    for (int sc : ns_syscalls) {
        if (int rc = deny(sc); rc != 0) {
            ::seccomp_release(ctx);
            return std::unexpected(std::string{"deny ns syscall: "} + std::strerror(-rc));
        }
    }

    // Kernel-surface mutation: bpf, kexec, modules, ptrace, audit, keyring.
    // None of these are reachable by an unprivileged process inside a user
    // namespace anyway, but we belt-and-brace the policy so the agent's own
    // misbehaviour cannot probe the surface.
    const int kernel_syscalls[] = {
        SCMP_SYS(bpf),
        SCMP_SYS(kexec_load),
        SCMP_SYS(kexec_file_load),
        SCMP_SYS(init_module),
        SCMP_SYS(finit_module),
        SCMP_SYS(delete_module),
        SCMP_SYS(ptrace),
        SCMP_SYS(process_vm_readv),
        SCMP_SYS(process_vm_writev),
        SCMP_SYS(keyctl),
        SCMP_SYS(add_key),
        SCMP_SYS(request_key),
        SCMP_SYS(reboot),
        SCMP_SYS(swapon),
        SCMP_SYS(swapoff),
    };
    for (int sc : kernel_syscalls) {
        if (int rc = deny(sc); rc != 0) {
            ::seccomp_release(ctx);
            return std::unexpected(std::string{"deny kernel syscall: "} + std::strerror(-rc));
        }
    }

    if (int rc = ::seccomp_load(ctx); rc != 0) {
        ::seccomp_release(ctx);
        return std::unexpected(std::string{"seccomp_load: "} + std::strerror(-rc));
    }
    ::seccomp_release(ctx);
    return {};
}

auto pivot_into(const std::string& new_root) -> std::expected<void, std::string> {
    // The `pivot_root(".", ".")` idiom (see pivot_root(2) NOTES): put_old ==
    // new_root, then detach the old root that ends up stacked on top of ".".
    // This needs no writable `.old` directory — essential now that new_root is
    // the real filesystem bound read-only.
    if (::chdir(new_root.c_str()) < 0) {
        return std::unexpected(std::string{"chdir new_root: "} + std::strerror(errno));
    }
    if (::syscall(SYS_pivot_root, ".", ".") < 0) {
        return std::unexpected(std::string{"pivot_root: "} + std::strerror(errno));
    }
    if (::umount2(".", MNT_DETACH) < 0) {
        return std::unexpected(std::string{"umount old root: "} + std::strerror(errno));
    }
    if (::chdir("/") < 0) {
        return std::unexpected(std::string{"chdir /: "} + std::strerror(errno));
    }
    return {};
}

// Run inside the contained child between clone3 and exec. The signal pipe is
// the parent's mechanism for telling us the uid_map/gid_map are written —
// without that, all setuid/setgid calls in the child fail with EPERM.
[[noreturn]] void child_setup_and_exec(
    int sync_read_fd,
    int pipe_in_read,
    int pipe_in_write_close,
    int pipe_out_read_close,
    int pipe_out_write,
    int pipe_error_read_close,
    int pipe_error_write,
    int egress_channel_fd,
    const profile& prof,
    std::vector<std::string> argv,
    std::span<const supervisor::linux_detail::session_mount> session_mounts
) {
    char ack = 0;
    while (true) {
        ::ssize_t n = ::read(sync_read_fd, &ack, 1);
        if (n == 1) {
            break;
        }
        if (n == 0) {
            std::_Exit(110);
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        std::fprintf(stderr, "glove child: sync read failed: %s\n", std::strerror(errno));
        std::_Exit(110);
    }
    ::close(sync_read_fd);

    // FS perimeter: make our mount namespace private, bind a minimal
    // rootfs, pivot_root into it.
    if (::mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
        std::fprintf(stderr, "glove child: mount-private /: %s\n", std::strerror(errno));
        std::_Exit(120);
    }

    char new_root_buf[] = "/tmp/glove-rootfs-XXXXXX";
    char* new_root_cstr = ::mkdtemp(new_root_buf);
    if (new_root_cstr == nullptr) {
        std::fprintf(stderr, "glove child: mkdtemp: %s\n", std::strerror(errno));
        std::_Exit(121);
    }
    if (::mount("tmpfs", new_root_cstr, "tmpfs", MS_NOSUID, "size=128M") < 0) {
        std::fprintf(stderr, "glove child: mount tmpfs new_root: %s\n", std::strerror(errno));
        std::_Exit(122);
    }
    std::string new_root = new_root_cstr;

    if (auto r = build_rootfs(
            new_root, prof, argv.empty() ? std::string_view{} : argv[0], session_mounts, -1
        );
        !r) {
        std::fprintf(stderr, "glove child: rootfs: %s\n", r.error().c_str());
        std::_Exit(123);
    }
    if (auto r = pivot_into(new_root); !r) {
        std::fprintf(stderr, "glove child: pivot: %s\n", r.error().c_str());
        std::_Exit(124);
    }
    if (prof.proxy) {
        if (auto installed =
                linux_detail::install_sandbox_egress_bridge(egress_channel_fd, prof.proxy->port);
            !installed) {
            std::fprintf(stderr, "glove child: egress bridge: %s\n", installed.error().c_str());
            std::_Exit(125);
        }
    } else {
        close_fd(egress_channel_fd);
    }

    // Seccomp filter goes after the rootfs pivot (so we don't accidentally
    // deny syscalls our setup needs) but before the agent's exec, so the
    // agent inherits the filter as its starting policy.
    if (auto r = setup_seccomp(prof.proxy.has_value()); !r) {
        std::fprintf(stderr, "glove child: seccomp: %s\n", r.error().c_str());
        std::_Exit(125);
    }

    if (::dup2(pipe_in_read, STDIN_FILENO) < 0) {
        std::fprintf(stderr, "glove child: dup2 stdin: %s\n", std::strerror(errno));
        std::_Exit(111);
    }
    if (::dup2(pipe_out_write, STDOUT_FILENO) < 0) {
        std::fprintf(stderr, "glove child: dup2 stdout: %s\n", std::strerror(errno));
        std::_Exit(112);
    }
    if (::dup2(pipe_error_write, STDERR_FILENO) < 0) {
        std::fprintf(stderr, "glove child: dup2 stderr: %s\n", std::strerror(errno));
        std::_Exit(113);
    }
    ::close(pipe_in_read);
    ::close(pipe_in_write_close);
    ::close(pipe_out_read_close);
    ::close(pipe_out_write);
    ::close(pipe_error_read_close);
    ::close(pipe_error_write);

    if (prof.work_dir && ::chdir(prof.work_dir->c_str()) < 0) {
        std::fprintf(stderr, "glove child: chdir work_dir: %s\n", std::strerror(errno));
        std::_Exit(126);
    }
    if (auto environment = install_environment(prof); !environment) {
        std::fprintf(stderr, "glove child: environment: %s\n", environment.error().c_str());
        std::_Exit(126);
    }

    // Belt-and-braces over per-fd O_CLOEXEC: close anything else the host left
    // open (sockets, upstream-server pipes) so the only descriptors crossing
    // into the agent are stdio. Without this, a non-cloexec fd would hand the
    // agent a channel that bypasses the kernel's policy and audit.
#if defined(SYS_close_range)
    ::syscall(SYS_close_range, STDERR_FILENO + 1, ~0U, 0);
#endif

    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argv.size() + 1);
    for (auto& a : argv) {
        argv_ptrs.push_back(a.data());
    }
    argv_ptrs.push_back(nullptr);

    ::execv(argv_ptrs[0], argv_ptrs.data());
    std::fprintf(stderr, "glove child: execv(%s): %s\n", argv_ptrs[0], std::strerror(errno));
    std::_Exit(127);
}

// Passthrough variant of the child path for `glove exec`: identical namespace +
// rootfs + seccomp setup, but the agent inherits the parent's stdio (0/1/2)
// instead of being wired to an MCP pipe. For running a real, self-driving agent
// contained but not driven as an MCP client.
[[noreturn]] void child_setup_and_exec_passthrough(
    int sync_read_fd,
    const profile& prof,
    std::vector<std::string> argv,
    std::span<const supervisor::linux_detail::session_mount> session_mounts,
    int agent_program_fd,
    int egress_channel_fd,
    child_stdio_capture capture
) {
    char ack = 0;
    while (true) {
        ::ssize_t n = ::read(sync_read_fd, &ack, 1);
        if (n == 1) {
            break;
        }
        if (n == 0) {
            std::_Exit(110);
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        std::fprintf(stderr, "glove child: sync read failed: %s\n", std::strerror(errno));
        std::_Exit(110);
    }
    ::close(sync_read_fd);

    if (::mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
        std::fprintf(stderr, "glove child: mount-private /: %s\n", std::strerror(errno));
        std::_Exit(120);
    }
    char new_root_buf[] = "/tmp/glove-rootfs-XXXXXX";
    char* new_root_cstr = ::mkdtemp(new_root_buf);
    if (new_root_cstr == nullptr) {
        std::fprintf(stderr, "glove child: mkdtemp: %s\n", std::strerror(errno));
        std::_Exit(121);
    }
    if (::mount("tmpfs", new_root_cstr, "tmpfs", MS_NOSUID, "size=128M") < 0) {
        std::fprintf(stderr, "glove child: mount tmpfs new_root: %s\n", std::strerror(errno));
        std::_Exit(122);
    }
    std::string new_root = new_root_cstr;
    if (auto r = build_rootfs(
            new_root,
            prof,
            argv.empty() ? std::string_view{} : argv[0],
            session_mounts,
            agent_program_fd
        );
        !r) {
        std::fprintf(stderr, "glove child: rootfs: %s\n", r.error().c_str());
        std::_Exit(123);
    }
    if (auto r = pivot_into(new_root); !r) {
        std::fprintf(stderr, "glove child: pivot: %s\n", r.error().c_str());
        std::_Exit(124);
    }
    if (auto captured = install_child_output_capture(capture); !captured) {
        std::fprintf(stderr, "glove child: %s\n", captured.error().c_str());
        std::_Exit(126);
    }

    if (prof.proxy) {
        if (auto installed =
                linux_detail::install_sandbox_egress_bridge(egress_channel_fd, prof.proxy->port);
            !installed) {
            std::fprintf(stderr, "glove child: egress bridge: %s\n", installed.error().c_str());
            std::_Exit(125);
        }
    } else {
        close_fd(egress_channel_fd);
    }

    if (auto r = setup_seccomp(prof.proxy.has_value()); !r) {
        std::fprintf(stderr, "glove child: seccomp: %s\n", r.error().c_str());
        std::_Exit(125);
    }

    // Start in the workspace so a coding agent operates on the project.
    if (prof.work_dir && !prof.work_dir->empty()) {
        if (::chdir(prof.work_dir->c_str()) < 0) {
            std::fprintf(stderr, "glove child: chdir work_dir: %s\n", std::strerror(errno));
            std::_Exit(126);
        }
    }

    if (auto environment = install_environment(prof); !environment) {
        std::fprintf(stderr, "glove child: environment: %s\n", environment.error().c_str());
        std::_Exit(126);
    }

    // stdio (0/1/2) is inherited; drop every other inherited descriptor so no
    // host fd leaks into the agent.
#if defined(SYS_close_range)
    ::syscall(SYS_close_range, STDERR_FILENO + 1, ~0U, 0);
#endif

    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argv.size() + 1);
    for (auto& a : argv) {
        argv_ptrs.push_back(a.data());
    }
    argv_ptrs.push_back(nullptr);

    ::execv(argv_ptrs[0], argv_ptrs.data());
    std::fprintf(stderr, "glove child: execv(%s): %s\n", argv_ptrs[0], std::strerror(errno));
    std::_Exit(127);
}

auto linux_resource_capabilities() noexcept -> resource_enforcement_capabilities {
    // The private managed seam composes Linux enforcement and structural
    // receipts. The public MCP child is not owned by that lifecycle and still
    // lacks authenticated audit/receipt delivery.
    return {};
}

class linux_spawner final : public spawner {
public:
    [[nodiscard]] auto resource_capabilities() const noexcept
        -> resource_enforcement_capabilities override {
        return linux_resource_capabilities();
    }

    auto spawn(const profile& prof, const std::vector<std::string>& argv)
        -> std::expected<std::unique_ptr<agent_handle>, std::string> override {
        if (argv.empty()) {
            return std::unexpected(std::string{"spawner: empty argv"});
        }
        auto checked = validate(prof);
        if (!checked) {
            return std::unexpected(std::string{"profile: "} + checked.error());
        }
        if (auto limits = require_resource_enforcement(*checked, resource_capabilities());
            !limits) {
            return std::unexpected(limits.error());
        }
        std::vector<std::string> launch_argv = argv;
        auto program = resolve_program(*checked, launch_argv.front());
        if (!program) {
            return std::unexpected(program.error());
        }
        launch_argv.front() = std::move(*program);

        int pipe_in[2] = {-1, -1};    // parent writes pipe_in[1] -> child stdin
        int pipe_out[2] = {-1, -1};   // child stdout -> parent reads pipe_out[0]
        int pipe_error[2] = {-1, -1}; // child stderr -> parent drain worker
        int sync_pipe[2] = {-1, -1};  // parent → child uid-map ack
        int egress_host_fd = -1;
        int egress_sandbox_fd = -1;

        if (::pipe2(pipe_in, O_CLOEXEC) != 0) {
            return std::unexpected(std::string{"pipe2(in): "} + std::strerror(errno));
        }
        if (::pipe2(pipe_out, O_CLOEXEC) != 0) {
            const int saved = errno;
            close_pipe_pair(pipe_in);
            return std::unexpected(std::string{"pipe2(out): "} + std::strerror(saved));
        }
        if (::pipe2(pipe_error, O_CLOEXEC) != 0) {
            const int saved = errno;
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"pipe2(error): "} + std::strerror(saved));
        }
        if (::pipe2(sync_pipe, O_CLOEXEC) != 0) {
            const int saved = errno;
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            close_pipe_pair(pipe_error);
            return std::unexpected(std::string{"pipe2(sync): "} + std::strerror(saved));
        }
        if (checked->proxy) {
            auto channel = linux_detail::create_egress_channel();
            if (!channel) {
                close_pipe_pair(pipe_in);
                close_pipe_pair(pipe_out);
                close_pipe_pair(pipe_error);
                close_pipe_pair(sync_pipe);
                return std::unexpected(channel.error());
            }
            egress_host_fd = channel->host_fd;
            egress_sandbox_fd = channel->sandbox_fd;
        }

        clone_args_v3 ca{};
        ca.flags = static_cast<std::uint64_t>(CLONE_NEWUSER) | CLONE_NEWNS | CLONE_NEWPID |
                   CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS;
        ca.exit_signal = SIGCHLD;

        const long pid = sys_clone3(&ca, sizeof(ca));
        if (pid < 0) {
            const int saved = errno;
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            close_pipe_pair(pipe_error);
            close_pipe_pair(sync_pipe);
            close_fd(egress_host_fd);
            close_fd(egress_sandbox_fd);
            return std::unexpected(std::string{"clone3: "} + std::strerror(saved));
        }

        if (pid == 0) {
            // Child. Close the parent-only ends; the helper handles the
            // rest. fcntl(F_SETFD) on inherited fds was set to CLOEXEC by
            // pipe2; clear that on the ones we keep.
            ::close(sync_pipe[1]);
            ::fcntl(pipe_in[0], F_SETFD, 0);
            ::fcntl(pipe_out[1], F_SETFD, 0);
            ::fcntl(pipe_error[1], F_SETFD, 0);
            close_fd(egress_host_fd);
            child_setup_and_exec(
                sync_pipe[0],
                pipe_in[0],
                pipe_in[1],
                pipe_out[0],
                pipe_out[1],
                pipe_error[0],
                pipe_error[1],
                egress_sandbox_fd,
                *checked,
                launch_argv,
                {}
            );
        }

        // Parent.
        const ::pid_t child = static_cast<::pid_t>(pid);
        ::close(pipe_in[0]);
        ::close(pipe_out[1]);
        ::close(pipe_error[1]);
        ::close(sync_pipe[0]);
        close_fd(egress_sandbox_fd);

        if (auto uid_ok = setup_uid_map(child); !uid_ok) {
            ::close(pipe_in[1]);
            ::close(pipe_out[0]);
            ::close(pipe_error[0]);
            ::close(sync_pipe[1]);
            close_fd(egress_host_fd);
            ::kill(child, SIGKILL);
            int status = 0;
            ::waitpid(child, &status, 0);
            return std::unexpected(uid_ok.error());
        }

        std::unique_ptr<linux_detail::host_egress_bridge> egress;
        if (checked->proxy) {
            auto started =
                linux_detail::start_host_egress_bridge(egress_host_fd, checked->proxy->port);
            egress_host_fd = -1;
            if (!started) {
                ::close(pipe_in[1]);
                ::close(pipe_out[0]);
                ::close(pipe_error[0]);
                ::close(sync_pipe[1]);
                ::kill(child, SIGKILL);
                int status = 0;
                ::waitpid(child, &status, 0);
                return std::unexpected(started.error());
            }
            egress = std::move(*started);
        }

        // Tell the child it can proceed with exec.
        const char go = '1';
        if (::write(sync_pipe[1], &go, 1) != 1) {
            const int saved = errno;
            ::close(pipe_in[1]);
            ::close(pipe_out[0]);
            ::close(pipe_error[0]);
            ::close(sync_pipe[1]);
            egress.reset();
            ::kill(child, SIGKILL);
            int status = 0;
            ::waitpid(child, &status, 0);
            return std::unexpected(std::string{"sync write: "} + std::strerror(saved));
        }
        ::close(sync_pipe[1]);

        detail::output_pump_options output_options;
        output_options.stdout_fd = pipe_out[0];
        output_options.stderr_fd = pipe_error[0];
        // A bounded Sage event sink is not connected yet. Draining without a
        // sink prevents inherited-terminal backpressure from stalling output
        // accounting or the MCP stdout channel.
        auto output = detail::output_pump::create(std::move(output_options));
        if (!output) {
            ::close(pipe_in[1]);
            ::close(pipe_out[0]);
            ::close(pipe_error[0]);
            egress.reset();
            ::kill(child, SIGKILL);
            int status = 0;
            ::waitpid(child, &status, 0);
            return std::unexpected(output.error());
        }
        auto t = std::make_unique<pipe_transport>(pipe_in[1], std::move(*output));
        return std::make_unique<linux_agent_handle>(child, std::move(t), std::move(egress));
    }
};

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto validate_managed_mounts(
    std::span<const supervisor::linux_detail::session_mount> mounts, std::string_view agent_program
) -> std::expected<void, std::string> {
    if (mounts.size() < 2) {
        return std::unexpected(std::string{"managed session is missing scratch mounts"});
    }
    bool has_tmp = false;
    bool has_var_tmp = false;
    std::set<std::string> targets;
    std::vector<std::filesystem::path> target_paths;
    target_paths.reserve(mounts.size());
    const std::filesystem::path program{agent_program};
    for (const auto& mount : mounts) {
        const std::filesystem::path target{mount.target_path};
        if (mount.descriptor_fd < 0 || !target.is_absolute() || target == target.root_path() ||
            target.lexically_normal() != target || !targets.insert(mount.target_path).second ||
            path_within(target, program) || path_within(program, target)) {
            return std::unexpected(std::string{"invalid managed session mount set"});
        }

        struct ::stat status{};

        if (::fstat(mount.descriptor_fd, &status) < 0 ||
            (mount.directory != static_cast<bool>(S_ISDIR(status.st_mode))) ||
            (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode))) {
            return std::unexpected(std::string{"invalid managed session mount descriptor"});
        }
        for (const auto& existing : target_paths) {
            if (path_within(target, existing) || path_within(existing, target)) {
                return std::unexpected(std::string{"overlapping managed session mount targets"});
            }
        }
        target_paths.push_back(target);
        has_tmp = has_tmp || mount.target_path == "/tmp";
        has_var_tmp = has_var_tmp || mount.target_path == "/var/tmp";
    }
    if (!has_tmp || !has_var_tmp) {
        return std::unexpected(std::string{"managed session requires /tmp and /var/tmp mounts"});
    }
    return {};
}

struct prepared_managed_launch {
    profile checked_profile;
    std::vector<std::string> argv;
    std::vector<supervisor::linux_detail::session_mount> mounts;
    owned_fd executable_mount;
    linux_detail::managed_launch_binding binding;
};

auto prepare_managed_launch(
    const profile& prof,
    const std::vector<std::string>& argv,
    const linux_detail::linux_resource_lifecycle& lifecycle,
    std::string_view controller_plan_digest
) -> std::expected<prepared_managed_launch, std::string> {
    if (argv.empty()) {
        return std::unexpected(std::string{"managed session: empty argv"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (checked->required_limits != std::optional<resource_limits>{lifecycle.limits()}) {
        return std::unexpected(std::string{"managed session resource limits mismatch"});
    }
    std::vector<std::string> launch_argv = argv;
    auto program = resolve_program(*checked, launch_argv.front());
    if (!program) {
        return std::unexpected(program.error());
    }
    launch_argv.front() = std::move(*program);
    const owned_fd executable{::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        launch_argv.front().c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (executable.get() < 0) {
        return std::unexpected(std::string{"open managed executable: "} + errno_message(errno));
    }
    auto mounts = lifecycle.mounts();
    if (auto valid = validate_managed_mounts(mounts, launch_argv.front()); !valid) {
        return std::unexpected(valid.error());
    }
    auto binding = linux_detail::bind_managed_launch_projection_from_fd(
        *checked, launch_argv, mounts, controller_plan_digest, executable.get()
    );
    if (!binding) {
        return std::unexpected(binding.error());
    }
    owned_fd executable_mount{static_cast<int>(
        // Linux has no typed libc wrapper for open_tree(2).
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::syscall(
            SYS_open_tree, executable.get(), "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
        )
    )};
    if (executable_mount.get() < 0) {
        return std::unexpected(
            std::string{"clone managed executable mount: "} + errno_message(errno)
        );
    }
    return prepared_managed_launch{
        .checked_profile = std::move(*checked),
        .argv = std::move(launch_argv),
        .mounts = std::move(mounts),
        .executable_mount = std::move(executable_mount),
        .binding = std::move(*binding),
    };
}

auto launch_passthrough_child(
    const profile& prof,
    const std::vector<std::string>& launch_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    linux_detail::linux_resource_lifecycle* lifecycle,
    int agent_program_fd,
    bool capture_output,
    const linux_detail::managed_session_start_gate* before_child_release
) -> std::expected<launched_sandbox_child, std::string> {
    if (capture_output && lifecycle == nullptr) {
        return std::unexpected(std::string{"captured output requires a resource lifecycle"});
    }
    int sync_pipe[2] = {-1, -1};
    if (::pipe2(sync_pipe, O_CLOEXEC) != 0) {
        return std::unexpected(std::string{"pipe2(sync): "} + errno_message(errno));
    }
    int pipe_out[2] = {-1, -1};
    int pipe_error[2] = {-1, -1};
    int egress_host_fd = -1;
    int egress_sandbox_fd = -1;
    if (capture_output && ::pipe2(pipe_out, O_CLOEXEC) != 0) {
        const int saved = errno;
        close_pipe_pair(sync_pipe);
        return std::unexpected(std::string{"pipe2(managed stdout): "} + errno_message(saved));
    }
    if (capture_output && ::pipe2(pipe_error, O_CLOEXEC) != 0) {
        const int saved = errno;
        close_pipe_pair(sync_pipe);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"pipe2(managed stderr): "} + errno_message(saved));
    }
    if (prof.proxy) {
        auto channel = linux_detail::create_egress_channel();
        if (!channel) {
            close_pipe_pair(sync_pipe);
            close_pipe_pair(pipe_out);
            close_pipe_pair(pipe_error);
            return std::unexpected(channel.error());
        }
        egress_host_fd = channel->host_fd;
        egress_sandbox_fd = channel->sandbox_fd;
    }

    clone_args_v3 arguments{};
    arguments.flags = static_cast<std::uint64_t>(CLONE_NEWUSER) | CLONE_NEWNS | CLONE_NEWPID |
                      CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS;
    arguments.exit_signal = SIGCHLD;
    if (lifecycle != nullptr) {
        if (lifecycle->cgroup_fd() < 0) {
            close_pipe_pair(sync_pipe);
            close_pipe_pair(pipe_out);
            close_pipe_pair(pipe_error);
            return std::unexpected(std::string{"managed session cgroup is closed"});
        }
        arguments.flags |= glove_clone_into_cgroup;
        arguments.cgroup = static_cast<std::uint64_t>(lifecycle->cgroup_fd());
    }

    const long pid = sys_clone3(&arguments, sizeof(arguments));
    if (pid < 0) {
        const int saved = errno;
        close_pipe_pair(sync_pipe);
        close_pipe_pair(pipe_out);
        close_pipe_pair(pipe_error);
        close_fd(egress_host_fd);
        close_fd(egress_sandbox_fd);
        return std::unexpected(std::string{"clone3: "} + errno_message(saved));
    }
    if (pid == 0) {
        ::close(sync_pipe[1]);
        close_fd(egress_host_fd);
        child_setup_and_exec_passthrough(
            sync_pipe[0],
            prof,
            launch_argv,
            mounts,
            agent_program_fd,
            egress_sandbox_fd,
            {
                .stdout_read_close = pipe_out[0],
                .stdout_write = pipe_out[1],
                .stderr_read_close = pipe_error[0],
                .stderr_write = pipe_error[1],
            }
        );
    }

    const ::pid_t child = static_cast<::pid_t>(pid);
    ::close(sync_pipe[0]);
    ::close(pipe_out[1]);
    pipe_out[1] = -1;
    ::close(pipe_error[1]);
    pipe_error[1] = -1;
    close_fd(egress_sandbox_fd);
    std::unique_ptr<linux_detail::host_egress_bridge> egress;
    auto fail = [&](std::string message) -> std::expected<launched_sandbox_child, std::string> {
        ::close(sync_pipe[1]);
        close_pipe_pair(pipe_out);
        close_pipe_pair(pipe_error);
        close_fd(egress_host_fd);
        egress.reset();
        static_cast<void>(::kill(child, SIGKILL));
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        return std::unexpected(std::move(message));
    };
    if (auto mapped = setup_uid_map(child); !mapped) {
        return fail(mapped.error());
    }
    if (lifecycle != nullptr) {
        if (auto attached = lifecycle->attach(child); !attached) {
            return fail(attached.error());
        }
    }
    if (prof.proxy) {
        auto started = linux_detail::start_host_egress_bridge(egress_host_fd, prof.proxy->port);
        egress_host_fd = -1;
        if (!started) {
            return fail(started.error());
        }
        egress = std::move(*started);
    }
    std::unique_ptr<detail::output_pump> output;
    if (capture_output) {
        detail::output_pump_options options;
        options.stdout_fd = pipe_out[0];
        options.stderr_fd = pipe_error[0];
        options.discard_stdout = true;
        options.monitor = lifecycle->monitor();
        auto created = detail::output_pump::create(std::move(options));
        if (!created) {
            return fail(created.error());
        }
        output = std::move(*created);
        pipe_out[0] = -1;
        pipe_error[0] = -1;
    }
    if (before_child_release != nullptr && *before_child_release) {
        try {
            if (auto released = (*before_child_release)(child); !released) {
                return fail(std::string{"managed session child-release gate: "} + released.error());
            }
        } catch (const std::exception& error) {
            return fail(std::string{"managed session child-release gate threw: "} + error.what());
        } catch (...) {
            return fail(std::string{"managed session child-release gate threw"});
        }
    }
    const char proceed = '1';
    if (::write(sync_pipe[1], &proceed, 1) != 1) {
        return fail(std::string{"sync write: "} + errno_message(errno));
    }
    ::close(sync_pipe[1]);
    return launched_sandbox_child{
        .pid = child, .output = std::move(output), .egress = std::move(egress)
    };
}

auto launch_pty_child(
    const profile& prof,
    const std::vector<std::string>& launch_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    linux_detail::linux_resource_lifecycle& lifecycle,
    int agent_program_fd,
    const linux_detail::managed_pty_session_options& options,
    const linux_detail::managed_session_start_gate& before_child_release
) -> std::expected<launched_pty_child, std::string> {
    if (lifecycle.cgroup_fd() < 0) {
        return std::unexpected(std::string{"managed PTY session cgroup is closed"});
    }
    auto terminal_pair = linux_detail::open_pty_pair();
    if (!terminal_pair) {
        return std::unexpected(terminal_pair.error());
    }
    int sync_pipe[2] = {-1, -1};
    if (::pipe2(sync_pipe, O_CLOEXEC) != 0) {
        return std::unexpected(std::string{"pipe2(PTY sync): "} + errno_message(errno));
    }
    int egress_host_fd = -1;
    int egress_sandbox_fd = -1;
    if (prof.proxy) {
        auto channel = linux_detail::create_egress_channel();
        if (!channel) {
            close_pipe_pair(sync_pipe);
            return std::unexpected(channel.error());
        }
        egress_host_fd = channel->host_fd;
        egress_sandbox_fd = channel->sandbox_fd;
    }

    clone_args_v3 arguments{};
    arguments.flags = static_cast<std::uint64_t>(CLONE_NEWUSER) | CLONE_NEWNS | CLONE_NEWPID |
                      CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | glove_clone_into_cgroup;
    arguments.exit_signal = SIGCHLD;
    arguments.cgroup = static_cast<std::uint64_t>(lifecycle.cgroup_fd());
    const long pid = sys_clone3(&arguments, sizeof(arguments));
    if (pid < 0) {
        const int saved = errno;
        close_pipe_pair(sync_pipe);
        close_fd(egress_host_fd);
        close_fd(egress_sandbox_fd);
        return std::unexpected(std::string{"clone3 PTY child: "} + errno_message(saved));
    }
    if (pid == 0) {
        ::close(sync_pipe[1]);
        close_fd(egress_host_fd);
        child_setup_and_exec_passthrough(
            sync_pipe[0],
            prof,
            launch_argv,
            mounts,
            agent_program_fd,
            egress_sandbox_fd,
            {
                .terminal_master_close = terminal_pair->master_fd(),
                .terminal_slave = terminal_pair->slave_fd(),
            }
        );
    }

    const ::pid_t child = static_cast<::pid_t>(pid);
    ::close(sync_pipe[0]);
    sync_pipe[0] = -1;
    terminal_pair->close_slave();
    close_fd(egress_sandbox_fd);
    std::unique_ptr<linux_detail::host_egress_bridge> egress;
    std::unique_ptr<linux_detail::pty_session_channel> terminal;
    auto fail = [&](std::string message) -> std::expected<launched_pty_child, std::string> {
        close_pipe_pair(sync_pipe);
        close_fd(egress_host_fd);
        egress.reset();
        terminal.reset();
        static_cast<void>(::kill(child, SIGKILL));
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        return std::unexpected(std::move(message));
    };
    if (auto mapped = setup_uid_map(child); !mapped) {
        return fail(mapped.error());
    }
    if (auto attached = lifecycle.attach(child); !attached) {
        return fail(attached.error());
    }
    if (prof.proxy) {
        auto started = linux_detail::start_host_egress_bridge(egress_host_fd, prof.proxy->port);
        egress_host_fd = -1;
        if (!started) {
            return fail(started.error());
        }
        egress = std::move(*started);
    }
    auto channel = linux_detail::pty_session_channel::create({
        .master_fd = terminal_pair->release_master(),
        .transcript_bytes = options.transcript_bytes,
        .max_read_bytes = options.max_read_bytes,
        .max_input_frame_bytes = options.max_input_frame_bytes,
        .input_timeout_ms = options.input_timeout_ms,
        .monitor = lifecycle.monitor(),
    });
    if (!channel) {
        return fail(channel.error());
    }
    terminal = std::move(*channel);
    if (auto resized = terminal->resize(options.initial_rows, options.initial_columns); !resized) {
        return fail(resized.error());
    }
    if (before_child_release) {
        try {
            if (auto released = before_child_release(child); !released) {
                return fail(std::string{"managed PTY child-release gate: "} + released.error());
            }
        } catch (const std::exception& error) {
            return fail(std::string{"managed PTY child-release gate threw: "} + error.what());
        } catch (...) {
            return fail(std::string{"managed PTY child-release gate threw"});
        }
    }
    constexpr char proceed = '1';
    if (::write(sync_pipe[1], &proceed, 1) != 1) {
        return fail(std::string{"PTY sync write: "} + errno_message(errno));
    }
    ::close(sync_pipe[1]);
    sync_pipe[1] = -1;
    return launched_pty_child{
        .pid = child, .terminal = std::move(terminal), .egress = std::move(egress)
    };
}

auto wait_for_child(::pid_t child) -> std::expected<int, std::string> {
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(std::string{"waitpid: "} + errno_message(errno));
    }
    return status;
}

auto current_epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto make_managed_receipt(
    const resource_limits& limits,
    const linux_detail::managed_launch_binding& binding,
    const linux_detail::linux_resource_terminal_observation& terminal
) -> std::expected<resource_enforcement_receipt, std::string> {
    resource_enforcement_receipt receipt{
        .schema_version = 1,
        .profile_digest = binding.profile_digest,
        .backend = sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits = limits,
        .mechanisms = linux_detail::managed_session_capabilities(),
        .observed = terminal.observed,
        .termination_cause = terminal.termination_cause,
        .exit_code = terminal.exit_code,
        .started_at_ms = terminal.started_at_ms,
        .finished_at_ms = terminal.finished_at_ms,
        .library_projections = binding.library_projections,
        .retained_changes = {},
    };
    receipt.retained_changes.reserve(terminal.retained_changes.size());
    for (const auto& manifest : terminal.retained_changes) {
        receipt.retained_changes.push_back({
            .exposure_id = manifest.exposure_id,
            .generation = manifest.generation,
            .scope_digest = manifest.scope_digest,
            .source_identity_digest = manifest.source_identity_digest,
            .baseline_tree_digest = manifest.baseline_tree_digest,
            .staged_tree_digest = manifest.staged_tree_digest,
            .manifest_digest = manifest.manifest_digest,
            .created = manifest.created,
            .modified = manifest.modified,
            .renamed = manifest.renamed,
            .removed = manifest.removed,
            .before_bytes = manifest.before_bytes,
            .after_bytes = manifest.after_bytes,
        });
    }
    auto valid = validate_resource_enforcement_receipt(
        receipt,
        limits,
        linux_detail::managed_session_capabilities(),
        sandbox_backend::linux_production,
        binding.profile_digest
    );
    if (!valid) {
        return std::unexpected(
            std::string{"managed session produced invalid receipt: "} + valid.error()
        );
    }
    return receipt;
}

} // namespace

struct linux_detail::managed_pty_session::implementation {
    implementation(
        ::pid_t child_pid,
        managed_launch_binding launch_binding,
        resource_limits configured_limits,
        std::unique_ptr<linux_resource_lifecycle> resource_lifecycle,
        std::unique_ptr<pty_session_channel> terminal_channel
    )
        : child{child_pid},
          binding{std::move(launch_binding)},
          limits{configured_limits},
          lifecycle{std::move(resource_lifecycle)},
          terminal{std::move(terminal_channel)} {}

    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;

    ~implementation() {
        if (waiter.joinable() && waiter.get_id() != std::this_thread::get_id()) {
            waiter.join();
        }
    }

    auto start_waiter() -> std::expected<void, std::string> {
        try {
            waiter = std::thread{[this] { wait_for_terminal(); }};
            return {};
        } catch (const std::system_error& error) {
            return std::unexpected(std::string{"start managed PTY waiter: "} + error.what());
        }
    }

    void wait_for_terminal() noexcept {
        try {
            auto status = wait_for_child(child);
            if (!status) {
                publish_error(status.error());
                return;
            }
            const std::lock_guard lock{state_mutex};
            if (auto drained = terminal->finish_draining(); !drained) {
                static_cast<void>(lifecycle->monitor()->request_termination(
                    resource_termination_cause::supervisor_error
                ));
            }
            auto observation = lifecycle->finish(*status, current_epoch_ms());
            if (!observation) {
                publish_error_locked(observation.error());
                return;
            }
            auto produced = make_managed_receipt(limits, binding, *observation);
            if (!produced) {
                publish_error_locked(produced.error());
                return;
            }
            receipt = std::move(*produced);
            finished = true;
            state_changed.notify_all();
        } catch (const std::exception& error) {
            publish_error(std::string{"managed PTY waiter failed: "} + error.what());
        } catch (...) {
            publish_error(std::string{"managed PTY waiter failed"});
        }
    }

    void publish_error(std::string message) noexcept {
        const std::lock_guard lock{state_mutex};
        publish_error_locked(std::move(message));
    }

    void publish_error_locked(std::string message) noexcept {
        try {
            error = std::move(message);
            finished = true;
            state_changed.notify_all();
        } catch (...) {
            finished = true;
            state_changed.notify_all();
        }
    }

    ::pid_t child = -1;
    managed_launch_binding binding;
    resource_limits limits;
    std::unique_ptr<linux_resource_lifecycle> lifecycle;
    std::unique_ptr<pty_session_channel> terminal;
    std::unique_ptr<host_egress_bridge> egress;
    std::mutex state_mutex;
    std::condition_variable state_changed;
    bool finished = false;
    std::optional<resource_enforcement_receipt> receipt;
    std::string error;
    std::thread waiter;
};

auto make_default_spawner() -> std::unique_ptr<spawner> {
    return std::make_unique<linux_spawner>();
}

linux_detail::managed_pty_session::managed_pty_session(
    std::unique_ptr<implementation> state
) noexcept
    : state_{std::move(state)} {}

linux_detail::managed_pty_session::~managed_pty_session() {
    if (state_) {
        static_cast<void>(stop());
        static_cast<void>(wait());
    }
}

auto linux_detail::managed_pty_session::pid() const noexcept -> ::pid_t {
    return state_ ? state_->child : -1;
}

auto linux_detail::managed_pty_session::read(std::uint64_t cursor, std::size_t max_bytes) const
    -> std::expected<pty_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    return state_->terminal->read(cursor, max_bytes);
}

auto linux_detail::managed_pty_session::wait_read(
    std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms
) -> std::expected<pty_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    return state_->terminal->wait_read(cursor, max_bytes, timeout_ms);
}

auto linux_detail::managed_pty_session::write_input(std::string_view bytes)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    return state_->terminal->write_input(bytes);
}

auto linux_detail::managed_pty_session::resize(std::uint16_t rows, std::uint16_t columns)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    return state_->terminal->resize(rows, columns);
}

auto linux_detail::managed_pty_session::signal(pty_session_signal requested)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    return state_->terminal->signal(requested);
}

auto linux_detail::managed_pty_session::stop() -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    {
        const std::lock_guard lock{state_->state_mutex};
        if (state_->finished) {
            return {};
        }
    }
    return state_->lifecycle->request_stop();
}

auto linux_detail::managed_pty_session::stop(const managed_session_stop_gate& before_stop)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    if (!before_stop) {
        return std::unexpected(std::string{"managed PTY stop gate is empty"});
    }
    const std::lock_guard lock{state_->state_mutex};
    if (state_->finished) {
        return {};
    }
    if (auto allowed = before_stop(); !allowed) {
        return std::unexpected(allowed.error());
    }
    return state_->lifecycle->request_stop();
}

auto linux_detail::managed_pty_session::wait()
    -> std::expected<resource_enforcement_receipt, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"managed PTY session is empty"});
    }
    std::unique_lock lock{state_->state_mutex};
    state_->state_changed.wait(lock, [this] { return state_->finished; });
    if (!state_->receipt) {
        return std::unexpected(
            state_->error.empty() ? std::string{"managed PTY session failed"} : state_->error
        );
    }
    return *state_->receipt;
}

auto linux_detail::start_managed_pty_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    managed_pty_session_options options,
    const managed_session_start_gate& before_child_release
) -> std::expected<std::unique_ptr<managed_pty_session>, std::string> {
    if (!lifecycle || !before_child_release) {
        return std::unexpected(
            std::string{"managed PTY session lifecycle and child-release gate are required"}
        );
    }
    auto prepared =
        prepare_managed_launch(prof, argv, *lifecycle, expected_binding.controller_plan_digest);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    if (prepared->binding != expected_binding) {
        return std::unexpected(std::string{"managed PTY session launch binding mismatch"});
    }
    const auto limits = lifecycle->limits();
    std::unique_ptr<managed_pty_session::implementation> state;
    try {
        state = std::make_unique<managed_pty_session::implementation>(
            -1, expected_binding, limits, std::move(lifecycle), nullptr
        );
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate managed PTY session state"});
    }
    std::unique_ptr<managed_pty_session> session;
    try {
        session = std::unique_ptr<managed_pty_session>{new managed_pty_session{std::move(state)}};
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate managed PTY session owner"});
    }
    auto child = launch_pty_child(
        prepared->checked_profile,
        prepared->argv,
        prepared->mounts,
        *session->state_->lifecycle,
        prepared->executable_mount.get(),
        options,
        before_child_release
    );
    if (!child) {
        session->state_->publish_error(child.error());
        return std::unexpected(child.error());
    }
    session->state_->child = child->pid;
    session->state_->terminal = std::move(child->terminal);
    session->state_->egress = std::move(child->egress);
    auto started = session->state_->start_waiter();
    if (!started) {
        static_cast<void>(session->state_->lifecycle->request_stop());
        auto status = wait_for_child(session->state_->child);
        static_cast<void>(session->state_->terminal->finish_draining());
        if (status) {
            static_cast<void>(session->state_->lifecycle->finish(*status, current_epoch_ms()));
        }
        session->state_->publish_error(started.error());
        return std::unexpected(started.error());
    }
    return session;
}

auto exec_contained(const profile& prof, const std::vector<std::string>& argv)
    -> std::expected<int, std::string> {
    if (argv.empty()) {
        return std::unexpected(std::string{"spawner: empty argv"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (auto limits = require_resource_enforcement(*checked, linux_resource_capabilities());
        !limits) {
        return std::unexpected(limits.error());
    }
    std::vector<std::string> launch_argv = argv;
    auto program = resolve_program(*checked, launch_argv.front());
    if (!program) {
        return std::unexpected(program.error());
    }
    launch_argv.front() = std::move(*program);
    auto child = launch_passthrough_child(*checked, launch_argv, {}, nullptr, -1, false, nullptr);
    if (!child) {
        return std::unexpected(child.error());
    }
    auto status = wait_for_child(child->pid);
    if (!status) {
        return std::unexpected(status.error());
    }
    return WIFEXITED(*status) ? WEXITSTATUS(*status) : -1;
}

auto linux_detail::bind_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const linux_resource_lifecycle& lifecycle,
    std::string_view controller_plan_digest
) -> std::expected<managed_launch_binding, std::string> {
    auto prepared = prepare_managed_launch(prof, argv, lifecycle, controller_plan_digest);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    return std::move(prepared->binding);
}

auto linux_detail::exec_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle
) -> std::expected<resource_enforcement_receipt, std::string> {
    return exec_managed_session(
        prof, argv, expected_binding, std::move(lifecycle), managed_session_start_gate{}
    );
}

auto linux_detail::exec_managed_session(
    const profile& prof,
    const std::vector<std::string>& argv,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    const managed_session_start_gate& before_child_release
) -> std::expected<resource_enforcement_receipt, std::string> {
    if (!lifecycle) {
        return std::unexpected(std::string{"managed session lifecycle is required"});
    }
    auto prepared =
        prepare_managed_launch(prof, argv, *lifecycle, expected_binding.controller_plan_digest);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    if (prepared->binding != expected_binding) {
        return std::unexpected(std::string{"managed session launch binding mismatch"});
    }
    const auto limits = lifecycle->limits();
    auto child = launch_passthrough_child(
        prepared->checked_profile,
        prepared->argv,
        prepared->mounts,
        lifecycle.get(),
        prepared->executable_mount.get(),
        true,
        &before_child_release
    );
    if (!child) {
        return std::unexpected(child.error());
    }
    auto status = wait_for_child(child->pid);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (auto drained = child->output->finish_draining(); !drained) {
        static_cast<void>(
            lifecycle->monitor()->request_termination(resource_termination_cause::supervisor_error)
        );
    }
    auto terminal = lifecycle->finish(*status, current_epoch_ms());
    if (!terminal) {
        return std::unexpected(terminal.error());
    }
    return make_managed_receipt(limits, expected_binding, *terminal);
}

auto linux_detail::exec_managed_session_authenticated(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::string_view session_id,
    const managed_launch_binding& expected_binding,
    std::unique_ptr<linux_resource_lifecycle> lifecycle,
    receipt_audit_producer& audit_producer
) -> std::expected<authenticated_resource_enforcement_receipt, std::string> {
    auto reservation = audit_producer.reserve_terminal();
    if (!reservation) {
        return std::unexpected(reservation.error());
    }
    auto receipt = exec_managed_session(prof, argv, expected_binding, std::move(lifecycle));
    if (!receipt) {
        return std::unexpected(receipt.error());
    }
    return audit_producer.commit_terminal(
        std::move(*reservation), session_id, expected_binding.controller_plan_digest, *receipt
    );
}

} // namespace glove::container
