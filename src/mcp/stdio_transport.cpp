#include "glove/mcp/stdio_transport.hpp"

#include "glove/mcp/transport.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#    include <sched.h>
#    include <sys/prctl.h>
#endif

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::mcp {

namespace {

constexpr std::size_t recv_chunk_bytes = 4096;

// Hard ceiling on a single newline-framed frame. A peer that streams bytes
// without ever sending a newline would otherwise grow this buffer without
// bound and OOM the glove host. 16 MiB is far above any legitimate MCP frame
// while still bounding a hostile or buggy peer.
constexpr std::size_t max_frame_bytes = 16U * 1024U * 1024U;

class stdio_transport final : public transport {
public:
    stdio_transport(int write_fd, int read_fd, ::pid_t pid)
        : write_fd_{write_fd}, read_fd_{read_fd}, pid_{pid} {}

    stdio_transport(const stdio_transport&) = delete;
    stdio_transport& operator=(const stdio_transport&) = delete;
    stdio_transport(stdio_transport&&) = delete;
    stdio_transport& operator=(stdio_transport&&) = delete;

    ~stdio_transport() override {
        // Closing stdin lets a well-behaved child (cat, MCP server) exit on
        // its own. SIGTERM is a fallback; waitpid here is blocking but bounded
        // by the SIGTERM path.
        if (write_fd_ >= 0) {
            ::close(write_fd_);
        }
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
        if (pid_ > 0) {
            const ::pid_t process_group = pid_;
            (void)::kill(-process_group, SIGTERM);
            int status = 0;
            bool leader_reaped = false;
            for (int attempts = 0; attempts < 50; ++attempts) {
                if (!leader_reaped) {
                    const ::pid_t result = ::waitpid(pid_, &status, WNOHANG);
                    if (result == pid_ || (result < 0 && errno == ECHILD)) {
                        leader_reaped = true;
                    } else if (result < 0 && errno != EINTR) {
                        leader_reaped = true;
                    }
                }
                errno = 0;
                const bool group_alive = ::kill(-process_group, 0) == 0 || errno == EPERM;
                if (leader_reaped && !group_alive) {
                    pid_ = -1;
                    return;
                }
                ::usleep(10 * 1000);
            }
            (void)::kill(-process_group, SIGKILL);
            if (!leader_reaped) {
                while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
            }
#if defined(__linux__)
            // PR_SET_CHILD_SUBREAPER makes orphaned upstream helpers our
            // children, so collect every killed member of the process group
            // instead of leaving zombies to the host's PID 1.
            while (true) {
                const ::pid_t reaped = ::waitpid(-process_group, &status, 0);
                if (reaped > 0 || (reaped < 0 && errno == EINTR)) {
                    continue;
                }
                break;
            }
#endif
            pid_ = -1;
        }
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
        for (;;) {
            auto nl = buffer_.find('\n');
            if (nl != std::string::npos) {
                std::string out = buffer_.substr(0, nl);
                buffer_.erase(0, nl + 1);
                return out;
            }
            std::array<char, recv_chunk_bytes> chunk{};
            const ::ssize_t got = ::read(read_fd_, chunk.data(), chunk.size());
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"read: "} + std::strerror(errno));
            }
            if (got == 0) {
                return std::unexpected(std::string{"unexpected eof from child"});
            }
            if (buffer_.size() + static_cast<std::size_t>(got) > max_frame_bytes) {
                return std::unexpected(std::string{"frame exceeds max_frame_bytes"});
            }
            buffer_.append(chunk.data(), static_cast<std::size_t>(got));
        }
    }

private:
    int write_fd_;
    int read_fd_;
    ::pid_t pid_;
    std::string buffer_;
};

void close_pipe_pair(int (&fds)[2]) {
    if (fds[0] >= 0) {
        ::close(fds[0]);
    }
    if (fds[1] >= 0) {
        ::close(fds[1]);
    }
}

// Mark a pipe close-on-exec. The parent-side ends of an upstream's pipes must
// NOT survive into the contained agent: if they did, the agent could read and
// write an upstream MCP server directly, bypassing the kernel's policy and
// audit. Setting FD_CLOEXEC means the ends vanish when the agent execvp()s,
// while staying open in the (non-exec'ing) glove host process. The child-side
// ends are re-targeted onto fds 0/1 via posix_spawn_file_actions_adddup2,
// which produces non-cloexec descriptors, so the upstream server itself keeps
// its stdio. (macOS has no pipe2(), so this is a pipe()+fcntl pair; glove
// spawns sequentially here, so the brief pre-fcntl window is not a concern.)
auto set_cloexec(int fd) -> bool {
    const int flags = ::fcntl(fd, F_GETFD);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

} // namespace

auto make_stdio_transport(const stdio_child_options& opts)
    -> std::expected<std::unique_ptr<transport>, std::string> {
#if defined(__linux__)
    if (::prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        return std::unexpected(
            std::string{"prctl(PR_SET_CHILD_SUBREAPER): "} + std::strerror(errno)
        );
    }
#endif
    int pipe_in[2] = {-1, -1};  // child stdin: parent writes pipe_in[1]
    int pipe_out[2] = {-1, -1}; // child stdout: parent reads pipe_out[0]

    if (::pipe(pipe_in) != 0) {
        return std::unexpected(std::string{"pipe(in): "} + std::strerror(errno));
    }
    if (::pipe(pipe_out) != 0) {
        int saved = errno;
        close_pipe_pair(pipe_in);
        return std::unexpected(std::string{"pipe(out): "} + std::strerror(saved));
    }
    for (int fd : {pipe_in[0], pipe_in[1], pipe_out[0], pipe_out[1]}) {
        if (!set_cloexec(fd)) {
            int saved = errno;
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"fcntl(FD_CLOEXEC): "} + std::strerror(saved));
        }
    }

    std::vector<char*> argv_storage;
    std::vector<std::string> argv_owned;
    if (opts.args.empty()) {
        argv_owned.push_back(opts.program);
    } else {
        argv_owned = opts.args;
    }
    argv_storage.reserve(argv_owned.size() + 1);
    for (auto& a : argv_owned) {
        argv_storage.push_back(a.data());
    }
    argv_storage.push_back(nullptr);

    std::vector<std::string> environment_owned = opts.environment;
    if (environment_owned.empty()) {
        environment_owned.emplace_back("PATH=/usr/bin:/bin:/usr/sbin:/sbin");
    }
    std::vector<char*> environment;
    environment.reserve(environment_owned.size() + 1);
    for (auto& entry : environment_owned) {
        environment.push_back(entry.data());
    }
    environment.push_back(nullptr);

    if (opts.sandbox.enabled) {
#if defined(__linux__)
        const ::uid_t host_uid = ::geteuid();
        const ::gid_t host_gid = ::getegid();
        if (host_uid == 0) {
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(
                std::string{"stdio_transport sandbox refuses to run as host root (euid 0)"}
            );
        }

        int err_pipe[2] = {-1, -1};
        if (::pipe(err_pipe) != 0) {
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"pipe(err): "} + std::strerror(errno));
        }
        if (!set_cloexec(err_pipe[0]) || !set_cloexec(err_pipe[1])) {
            const int saved = errno;
            close_pipe_pair(err_pipe);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"fcntl(FD_CLOEXEC): "} + std::strerror(saved));
        }

        char uid_map_buf[64]{};
        char gid_map_buf[64]{};
        const int uid_len =
            std::snprintf(uid_map_buf, sizeof(uid_map_buf), "0 %u 1\n", host_uid);
        const int gid_len =
            std::snprintf(gid_map_buf, sizeof(gid_map_buf), "0 %u 1\n", host_gid);
        if (uid_len <= 0 || static_cast<std::size_t>(uid_len) >= sizeof(uid_map_buf) ||
            gid_len <= 0 || static_cast<std::size_t>(gid_len) >= sizeof(gid_map_buf)) {
            close_pipe_pair(err_pipe);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"snprintf(uid/gid map) failed"});
        }

        const ::pid_t parent_pid = ::getpid();
        const char* const program_cstr = opts.program.c_str();
        const int clone_flags = CLONE_NEWUSER | (opts.sandbox.allow_network ? 0 : CLONE_NEWNET);
        const ::pid_t child_pid = ::fork();
        if (child_pid < 0) {
            const int saved = errno;
            close_pipe_pair(err_pipe);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"fork: "} + std::strerror(saved));
        }
        if (child_pid == 0) {
            ::close(err_pipe[0]);
            auto fail_child = [&](const char* msg, std::size_t len) -> void {
                (void)::write(err_pipe[1], msg, len);
                ::_exit(127);
            };
            auto write_proc_file = [&](const char* path, const char* data, std::size_t len) -> bool {
                const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
                if (fd < 0) {
                    return false;
                }
                const ::ssize_t written = ::write(fd, data, len);
                const int saved = errno;
                ::close(fd);
                errno = saved;
                return written == static_cast<::ssize_t>(len);
            };
            // Arm parent-death kill as the very first child action and verify parent is alive.
            if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
                static constexpr char kErr[] = "prctl(PR_SET_PDEATHSIG) failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            if (::getppid() != parent_pid) {
                ::_exit(127);
            }
            if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                static constexpr char kErr[] = "prctl(PR_SET_NO_NEW_PRIVS) failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            if (::setpgid(0, 0) != 0) {
                static constexpr char kErr[] = "setpgid failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            if (::dup2(pipe_in[0], STDIN_FILENO) < 0 || ::dup2(pipe_out[1], STDOUT_FILENO) < 0) {
                static constexpr char kErr[] = "dup2 failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            if (::unshare(clone_flags) != 0) {
                static constexpr char kErr[] = "unshare: namespace setup failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            static constexpr char kDeny[] = "deny";
            if (!write_proc_file("/proc/self/setgroups", kDeny, sizeof(kDeny) - 1U)) {
                static constexpr char kErr[] = "write /proc/self/setgroups failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            if (!write_proc_file(
                    "/proc/self/uid_map", uid_map_buf, static_cast<std::size_t>(uid_len)
                )) {
                static constexpr char kErr[] = "write /proc/self/uid_map failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            if (!write_proc_file(
                    "/proc/self/gid_map", gid_map_buf, static_cast<std::size_t>(gid_len)
                )) {
                static constexpr char kErr[] = "write /proc/self/gid_map failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            environ = environment.data();
            ::execvp(program_cstr, argv_storage.data());
            static constexpr char kErr[] = "execvp failed";
            fail_child(kErr, sizeof(kErr) - 1U);
        }

        ::close(err_pipe[1]);
        std::string child_error;
        std::array<char, 256> err_buf{};
        while (true) {
            const ::ssize_t n = ::read(err_pipe[0], err_buf.data(), err_buf.size());
            if (n > 0) {
                child_error.append(err_buf.data(), static_cast<std::size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        ::close(err_pipe[0]);
        if (!child_error.empty()) {
            int status = 0;
            while (::waitpid(child_pid, &status, 0) < 0 && errno == EINTR) {}
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"sandboxed spawn: "} + child_error);
        }
        ::close(pipe_in[0]);
        ::close(pipe_out[1]);
        return std::make_unique<stdio_transport>(pipe_in[1], pipe_out[0], child_pid);
#else
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"stdio_transport sandbox is only supported on Linux"});
#endif
    }

    ::posix_spawn_file_actions_t actions{};
    if (int rc = ::posix_spawn_file_actions_init(&actions); rc != 0) {
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"file_actions_init: "} + std::strerror(rc));
    }

    ::posix_spawn_file_actions_adddup2(&actions, pipe_in[0], STDIN_FILENO);
    ::posix_spawn_file_actions_adddup2(&actions, pipe_out[1], STDOUT_FILENO);
    ::posix_spawn_file_actions_addclose(&actions, pipe_in[0]);
    ::posix_spawn_file_actions_addclose(&actions, pipe_in[1]);
    ::posix_spawn_file_actions_addclose(&actions, pipe_out[0]);
    ::posix_spawn_file_actions_addclose(&actions, pipe_out[1]);

    ::posix_spawnattr_t attributes{};
    if (int rc = ::posix_spawnattr_init(&attributes); rc != 0) {
        ::posix_spawn_file_actions_destroy(&actions);
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"spawnattr_init: "} + std::strerror(rc));
    }
    if (int rc = ::posix_spawnattr_setpgroup(&attributes, 0); rc != 0) {
        ::posix_spawnattr_destroy(&attributes);
        ::posix_spawn_file_actions_destroy(&actions);
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"spawnattr_setpgroup: "} + std::strerror(rc));
    }
    if (int rc = ::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP); rc != 0) {
        ::posix_spawnattr_destroy(&attributes);
        ::posix_spawn_file_actions_destroy(&actions);
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"spawnattr_setflags: "} + std::strerror(rc));
    }

    ::pid_t pid = -1;
    int rc = ::posix_spawnp(
        &pid, opts.program.c_str(), &actions, &attributes, argv_storage.data(), environment.data()
    );
    ::posix_spawnattr_destroy(&attributes);
    ::posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        close_pipe_pair(pipe_in);
        close_pipe_pair(pipe_out);
        return std::unexpected(std::string{"posix_spawnp: "} + std::strerror(rc));
    }

    // Parent closes the child-side ends after spawn.
    ::close(pipe_in[0]);
    ::close(pipe_out[1]);
    return std::make_unique<stdio_transport>(pipe_in[1], pipe_out[0], pid);
}

} // namespace glove::mcp
