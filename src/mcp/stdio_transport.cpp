#include "glove/mcp/stdio_transport.hpp"

#include "glove/mcp/transport.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#    include <arpa/inet.h>
#    include <linux/capability.h>
#    include <net/if.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <sched.h>
#    include <sys/ioctl.h>
#    include <sys/prctl.h>
#    include <sys/socket.h>
#    include <sys/syscall.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace glove::mcp {

namespace {

constexpr std::size_t recv_chunk_bytes = 65536;

// Hard ceiling on a single newline-framed frame. A peer that streams bytes
// without ever sending a newline would otherwise grow this buffer without
// bound and OOM the glove host. 16 MiB is far above any legitimate MCP frame
// while still bounding a hostile or buggy peer.
constexpr std::size_t max_frame_bytes = 16U * 1024U * 1024U;

#if defined(__linux__)
constexpr std::size_t max_upstream_service_ports = 16U;

auto send_service_descriptor(int channel, std::uint16_t target_port, int descriptor) noexcept
    -> bool {
    ::iovec payload{.iov_base = &target_port, .iov_len = sizeof(target_port)};
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    ::msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    auto* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    while (::sendmsg(channel, &message, MSG_NOSIGNAL) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

auto receive_service_descriptor(int channel, std::uint16_t& target_port) noexcept -> int {
    target_port = 0;
    ::iovec payload{.iov_base = &target_port, .iov_len = sizeof(target_port)};
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    ::msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ::ssize_t received = -1;
    do {
        received = ::recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<::ssize_t>(sizeof(target_port)) ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        return -1;
    }
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
            header->cmsg_len == CMSG_LEN(sizeof(int))) {
            int descriptor = -1;
            std::memcpy(&descriptor, CMSG_DATA(header), sizeof(descriptor));
            return descriptor;
        }
    }
    return -1;
}

auto connect_host_loopback(std::uint16_t port) noexcept -> int {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while (::connect(fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) < 0) {
        if (errno == EINTR) {
            continue;
        }
        ::close(fd);
        return -1;
    }
    return fd;
}

auto write_all_socket(int fd, const char* data, std::size_t size) noexcept -> bool {
    while (size > 0) {
        const auto written = ::send(fd, data, size, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

void relay_service_pair(int left, int right, const std::atomic<bool>& stopping) noexcept {
    std::array<char, 16 * 1024> buffer{};
    std::array<::pollfd, 2> fds{{
        {.fd = left, .events = POLLIN, .revents = 0},
        {.fd = right, .events = POLLIN, .revents = 0},
    }};
    std::array<bool, 2> readable{{true, true}};
    while (!stopping.load(std::memory_order_relaxed)) {
        const int ready = ::poll(fds.data(), fds.size(), 250);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            continue;
        }
        bool done = false;
        for (std::size_t i = 0; i < fds.size(); ++i) {
            const auto ev = fds[i].revents;
            if ((ev & (POLLERR | POLLNVAL)) != 0) {
                done = true;
                break;
            }
            if (!readable[i] || (ev & (POLLIN | POLLHUP)) == 0) {
                continue;
            }
            const auto n = ::recv(fds[i].fd, buffer.data(), buffer.size(), 0);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0) {
                done = true;
                break;
            }
            if (n == 0) {
                readable[i] = false;
                fds[i].events = 0;
                (void)::shutdown(fds[1 - i].fd, SHUT_WR);
                continue;
            }
            if (!write_all_socket(fds[1 - i].fd, buffer.data(), static_cast<std::size_t>(n))) {
                done = true;
                break;
            }
        }
        if (done || (!readable[0] && !readable[1])) {
            break;
        }
    }
    (void)::shutdown(left, SHUT_RDWR);
    (void)::shutdown(right, SHUT_RDWR);
    ::close(left);
    ::close(right);
}

class upstream_service_bridge final {
public:
    upstream_service_bridge(int channel_fd, std::vector<std::uint16_t> allowed_ports)
        : channel_fd_{channel_fd}, allowed_ports_{std::move(allowed_ports)} {
        receiver_ = std::thread{[this] { receive_loop(); }};
    }

    upstream_service_bridge(const upstream_service_bridge&) = delete;
    auto operator=(const upstream_service_bridge&) -> upstream_service_bridge& = delete;

    ~upstream_service_bridge() {
        stopping_.store(true, std::memory_order_relaxed);
        if (channel_fd_ >= 0) {
            (void)::shutdown(channel_fd_, SHUT_RDWR);
        }
        if (receiver_.joinable()) {
            receiver_.join();
        }
        if (channel_fd_ >= 0) {
            ::close(channel_fd_);
            channel_fd_ = -1;
        }
        const std::lock_guard lock{workers_mutex_};
        for (auto& w : workers_) {
            if (w.thread.joinable()) {
                w.thread.join();
            }
        }
    }

private:
    struct worker_record {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> finished;
    };

    void reap_workers() {
        const std::lock_guard lock{workers_mutex_};
        auto it = workers_.begin();
        while (it != workers_.end()) {
            if (!it->finished->load(std::memory_order_acquire)) {
                ++it;
                continue;
            }
            if (it->thread.joinable()) {
                it->thread.join();
            }
            it = workers_.erase(it);
        }
    }

    void receive_loop() noexcept {
        constexpr std::size_t max_relays = 64U;
        while (!stopping_.load(std::memory_order_relaxed)) {
            std::uint16_t port = 0;
            const int client = receive_service_descriptor(channel_fd_, port);
            if (client < 0) {
                break;
            }
            if (std::ranges::find(allowed_ports_, port) == allowed_ports_.end()) {
                ::close(client);
                continue;
            }
            reap_workers();
            {
                const std::lock_guard lock{workers_mutex_};
                if (workers_.size() >= max_relays) {
                    ::close(client);
                    continue;
                }
            }
            const int target = connect_host_loopback(port);
            if (target < 0) {
                ::close(client);
                continue;
            }
            try {
                auto finished = std::make_shared<std::atomic<bool>>(false);
                const std::lock_guard lock{workers_mutex_};
                workers_.push_back({
                    .thread = std::thread{[this, client, target, finished] {
                        relay_service_pair(client, target, stopping_);
                        finished->store(true, std::memory_order_release);
                    }},
                    .finished = std::move(finished),
                });
            } catch (...) {
                ::close(client);
                ::close(target);
                break;
            }
        }
    }

    int channel_fd_ = -1;
    std::vector<std::uint16_t> allowed_ports_;
    std::atomic<bool> stopping_{false};
    std::thread receiver_;
    std::mutex workers_mutex_;
    std::vector<worker_record> workers_;
};

[[noreturn]] void run_upstream_service_forwarder(
    const std::array<int, max_upstream_service_ports>& listeners,
    const std::array<std::uint16_t, max_upstream_service_ports>& ports,
    std::size_t count,
    int channel_fd
) noexcept {
    std::array<int, max_upstream_service_ports + 1U> keep{};
    std::size_t keep_count = 0;
    if (channel_fd > STDERR_FILENO) {
        keep[keep_count++] = channel_fd;
    }
    for (std::size_t i = 0; i < count; ++i) {
        if (listeners[i] > STDERR_FILENO) {
            keep[keep_count++] = listeners[i];
        }
    }
    std::sort(keep.begin(), keep.begin() + static_cast<std::ptrdiff_t>(keep_count));
#    if defined(SYS_close_range)
    int cursor = STDERR_FILENO + 1;
    for (std::size_t i = 0; i < keep_count; ++i) {
        if (keep[i] > cursor) {
            (void)::syscall(SYS_close_range, cursor, keep[i] - 1, 0);
        }
        cursor = std::max(cursor, keep[i] + 1);
    }
    (void)::syscall(SYS_close_range, cursor, ~0U, 0);
#    else
    const long max_fd = ::sysconf(_SC_OPEN_MAX);
    for (int fd = STDERR_FILENO + 1; fd < max_fd; ++fd) {
        bool retained = false;
        for (std::size_t i = 0; i < keep_count; ++i) {
            if (keep[i] == fd) {
                retained = true;
                break;
            }
        }
        if (!retained) {
            ::close(fd);
        }
    }
#    endif
    std::array<::pollfd, max_upstream_service_ports + 1U> pfds{};
    for (std::size_t i = 0; i < count; ++i) {
        pfds[i] = {.fd = listeners[i], .events = POLLIN, .revents = 0};
    }
    pfds[count] = {.fd = channel_fd, .events = POLLHUP | POLLERR, .revents = 0};
    while (true) {
        const int ready = ::poll(pfds.data(), count + 1U, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::_exit(0);
        }
        if ((pfds[count].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            ::_exit(0);
        }
        for (std::size_t i = 0; i < count; ++i) {
            if ((pfds[i].revents & (POLLERR | POLLNVAL)) != 0) {
                ::_exit(0);
            }
            if ((pfds[i].revents & POLLIN) == 0) {
                continue;
            }
            int client = -1;
            do {
                client = ::accept4(listeners[i], nullptr, nullptr, SOCK_CLOEXEC);
            } while (client < 0 && errno == EINTR);
            if (client < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                    continue;
                }
                ::_exit(0);
            }
            const bool sent = send_service_descriptor(channel_fd, ports[i], client);
            ::close(client);
            if (!sent) {
                ::_exit(0);
            }
        }
    }
}
#endif

class stdio_transport final : public transport {
public:
#if defined(__linux__)
    stdio_transport(
        int write_fd,
        int read_fd,
        ::pid_t pid,
        std::unique_ptr<upstream_service_bridge> service_bridge = nullptr
    )
        : write_fd_{write_fd},
          read_fd_{read_fd},
          pid_{pid},
          service_bridge_{std::move(service_bridge)} {}
#else
    stdio_transport(int write_fd, int read_fd, ::pid_t pid)
        : write_fd_{write_fd}, read_fd_{read_fd}, pid_{pid} {}
#endif

    stdio_transport(const stdio_transport&) = delete;
    stdio_transport& operator=(const stdio_transport&) = delete;
    stdio_transport(stdio_transport&&) = delete;
    stdio_transport& operator=(stdio_transport&&) = delete;

    ~stdio_transport() override {
#if defined(__linux__)
        service_bridge_.reset();
#endif
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
            bool leader_reaped = leader_reaped_;
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
        std::size_t scan_pos = 0;
        for (;;) {
            const auto nl = buffer_.find('\n', scan_pos);
            if (nl != std::string::npos) {
                std::string out = buffer_.substr(0, nl);
                buffer_.erase(0, nl + 1);
                return out;
            }
            std::array<char, recv_chunk_bytes> chunk;
            const ::ssize_t got = ::read(read_fd_, chunk.data(), chunk.size());
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"read: "} + std::strerror(errno));
            }
            if (got == 0) {
                return std::unexpected(format_eof_error());
            }
            if (buffer_.size() + static_cast<std::size_t>(got) > max_frame_bytes) {
                return std::unexpected(std::string{"frame exceeds max_frame_bytes"});
            }
            scan_pos = buffer_.size();
            buffer_.append(chunk.data(), static_cast<std::size_t>(got));
        }
    }

private:
    auto format_eof_error() -> std::string {
        std::string message{"unexpected eof from child"};
        if (pid_ <= 0 || leader_reaped_) {
            return message;
        }
        int status = 0;
        for (int attempt = 0; attempt < 5; ++attempt) {
            const ::pid_t waited = ::waitpid(pid_, &status, WNOHANG);
            if (waited == pid_) {
                leader_reaped_ = true;
                if (WIFEXITED(status)) {
                    message += " (exit status " + std::to_string(WEXITSTATUS(status)) + ")";
                } else if (WIFSIGNALED(status)) {
                    message += " (signal " + std::to_string(WTERMSIG(status)) + ")";
                }
                return message;
            }
            if (waited < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            ::usleep(10 * 1000);
        }
        return message;
    }

    int write_fd_;
    int read_fd_;
    ::pid_t pid_;
    bool leader_reaped_ = false;
#if defined(__linux__)
    std::unique_ptr<upstream_service_bridge> service_bridge_;
#endif
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

        std::array<std::uint16_t, max_upstream_service_ports> service_ports{};
        std::size_t service_port_count = 0;
        if (!opts.sandbox.allow_network) {
            for (const std::uint16_t port : opts.sandbox.service_ports) {
                if (port == 0) {
                    close_pipe_pair(pipe_in);
                    close_pipe_pair(pipe_out);
                    return std::unexpected(std::string{"service port must be non-zero"});
                }
                bool dup = false;
                for (std::size_t i = 0; i < service_port_count; ++i) {
                    if (service_ports[i] == port) {
                        dup = true;
                        break;
                    }
                }
                if (dup) {
                    continue;
                }
                if (service_port_count >= max_upstream_service_ports) {
                    close_pipe_pair(pipe_in);
                    close_pipe_pair(pipe_out);
                    return std::unexpected(
                        std::string{"at most "} + std::to_string(max_upstream_service_ports) +
                        " service ports"
                    );
                }
                service_ports[service_port_count++] = port;
            }
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

        int bridge_sock[2] = {-1, -1};
        if (service_port_count > 0) {
            if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, bridge_sock) != 0) {
                const int saved = errno;
                close_pipe_pair(err_pipe);
                close_pipe_pair(pipe_in);
                close_pipe_pair(pipe_out);
                return std::unexpected(
                    std::string{"socketpair(service_bridge): "} + std::strerror(saved)
                );
            }
        }

        // Identity-map host_uid/host_gid into the user namespace instead of
        // fake-root 0: stdio_transport does not create a mount namespace, and
        // mapping to UID 0 causes runtimes like Python (when HOME is unset) to
        // resolve /root via getpwuid(0), breaking ~/.local site-packages and
        // failing with PermissionError.
        char uid_map_buf[64]{};
        char gid_map_buf[64]{};
        const int uid_len =
            std::snprintf(uid_map_buf, sizeof(uid_map_buf), "%u %u 1\n", host_uid, host_uid);
        const int gid_len =
            std::snprintf(gid_map_buf, sizeof(gid_map_buf), "%u %u 1\n", host_gid, host_gid);
        if (uid_len <= 0 || static_cast<std::size_t>(uid_len) >= sizeof(uid_map_buf) ||
            gid_len <= 0 || static_cast<std::size_t>(gid_len) >= sizeof(gid_map_buf)) {
            close_pipe_pair(err_pipe);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"snprintf(uid/gid map) failed"});
        }

        const ::pid_t parent_pid = ::getpid();
        const char* const program_cstr = opts.program.c_str();
        const unsigned long clone_flags =
            static_cast<unsigned long>(CLONE_NEWUSER) |
            (opts.sandbox.allow_network ? 0UL : static_cast<unsigned long>(CLONE_NEWNET)) |
            static_cast<unsigned long>(SIGCHLD);
        const ::pid_t child_pid =
            static_cast<::pid_t>(::syscall(SYS_clone, clone_flags, 0, nullptr, nullptr, 0));
        if (child_pid < 0) {
            const int saved = errno;
            close_pipe_pair(bridge_sock);
            close_pipe_pair(err_pipe);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(
                std::string{"unshare: clone namespace setup failed: "} + std::strerror(saved)
            );
        }
        if (child_pid == 0) {
            ::close(err_pipe[0]);
            if (bridge_sock[0] >= 0) {
                ::close(bridge_sock[0]);
            }
            auto fail_child = [&](const char* msg, std::size_t len) -> void {
                (void)::write(err_pipe[1], msg, len);
                ::_exit(127);
            };
            auto write_proc_file =
                [&](const char* path, const char* data, std::size_t len) -> bool {
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
            if (!opts.sandbox.allow_network) {
                // Bring private loopback up while CAP_NET_ADMIN is still held
                // in the new netns so local-only sockets (e.g. Python asyncio
                // self-pipes) and forwarded service ports work with zero
                // external routes.
                const int lo_sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (lo_sock >= 0) {
                    struct ::ifreq req{};
                    std::memcpy(req.ifr_name, "lo", 3U);
                    if (::ioctl(lo_sock, SIOCGIFFLAGS, &req) == 0) {
                        req.ifr_flags = static_cast<short>(req.ifr_flags | IFF_UP | IFF_RUNNING);
                        (void)::ioctl(lo_sock, SIOCSIFFLAGS, &req);
                    }
                    ::close(lo_sock);
                }
                if (service_port_count > 0) {
                    std::array<int, max_upstream_service_ports> listeners{};
                    listeners.fill(-1);
                    for (std::size_t i = 0; i < service_port_count; ++i) {
                        const int lfd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
                        if (lfd < 0) {
                            static constexpr char kErr[] = "socket(service_port) failed";
                            fail_child(kErr, sizeof(kErr) - 1U);
                        }
                        const int enabled = 1;
                        (void)::setsockopt(
                            lfd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)
                        );
                        ::sockaddr_in addr{};
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons(service_ports[i]);
                        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        if (::bind(lfd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) <
                                0 ||
                            ::listen(lfd, 16) < 0) {
                            static constexpr char kErr[] = "bind/listen(service_port) failed";
                            fail_child(kErr, sizeof(kErr) - 1U);
                        }
                        listeners[i] = lfd;
                    }
                    const auto fwd_pid = static_cast<::pid_t>(
                        ::syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, nullptr)
                    );
                    if (fwd_pid < 0) {
                        static constexpr char kErr[] = "clone(service_forwarder) failed";
                        fail_child(kErr, sizeof(kErr) - 1U);
                    }
                    if (fwd_pid == 0) {
                        run_upstream_service_forwarder(
                            listeners, service_ports, service_port_count, bridge_sock[1]
                        );
                    }
                    for (std::size_t i = 0; i < service_port_count; ++i) {
                        ::close(listeners[i]);
                    }
                    ::close(bridge_sock[1]);
                }
            }
#    ifdef PR_CAP_AMBIENT_CLEAR_ALL
            if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
                errno != EINVAL) {
                static constexpr char kErr[] = "prctl(PR_CAP_AMBIENT_CLEAR_ALL) failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
#    endif
            for (unsigned long cap = 0; cap < 64UL; ++cap) {
                if (::prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0) {
                    if (errno == EINVAL) {
                        break;
                    }
                    static constexpr char kErr[] = "prctl(PR_CAPBSET_READ) failed";
                    fail_child(kErr, sizeof(kErr) - 1U);
                }
                if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) {
                    static constexpr char kErr[] = "prctl(PR_CAPBSET_DROP) failed";
                    fail_child(kErr, sizeof(kErr) - 1U);
                }
            }
            ::__user_cap_header_struct cap_hdr{};
            cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
            cap_hdr.pid = 0;
            std::array<::__user_cap_data_struct, 2> cap_data{};
            if (::syscall(SYS_capset, &cap_hdr, cap_data.data()) != 0) {
                static constexpr char kErr[] = "capset failed";
                fail_child(kErr, sizeof(kErr) - 1U);
            }
            environ = environment.data();
            ::execvp(program_cstr, argv_storage.data());
            static constexpr char kErr[] = "execvp failed";
            fail_child(kErr, sizeof(kErr) - 1U);
        }

        ::close(err_pipe[1]);
        if (bridge_sock[1] >= 0) {
            ::close(bridge_sock[1]);
        }
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
            if (bridge_sock[0] >= 0) {
                ::close(bridge_sock[0]);
            }
            int status = 0;
            while (::waitpid(child_pid, &status, 0) < 0 && errno == EINTR) {}
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"sandboxed spawn: "} + child_error);
        }
        ::close(pipe_in[0]);
        ::close(pipe_out[1]);
        std::unique_ptr<upstream_service_bridge> service_bridge;
        if (service_port_count > 0 && bridge_sock[0] >= 0) {
            std::vector<std::uint16_t> allowed(
                service_ports.begin(),
                service_ports.begin() + static_cast<std::ptrdiff_t>(service_port_count)
            );
            service_bridge =
                std::make_unique<upstream_service_bridge>(bridge_sock[0], std::move(allowed));
        }
        return std::make_unique<stdio_transport>(
            pipe_in[1], pipe_out[0], child_pid, std::move(service_bridge)
        );
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
