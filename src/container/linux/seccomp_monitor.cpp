#include "seccomp_monitor.hpp"

#include <fcntl.h>
#include <poll.h>
#include <seccomp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

namespace glove::container::linux_detail {

namespace {

auto error_text(std::string_view op, int err = errno) -> std::string {
    return std::string{op} + ": " + std::error_code{err, std::generic_category()}.message();
}

auto describe_syscall(const struct ::seccomp_notif& req) -> std::string {
    if (req.data.nr == __NR_ioctl) {
        const auto cmd = static_cast<std::uint32_t>(req.data.args[1] & 0xFFFFFFFFULL);
#ifdef TIOCSTI
        if (cmd == static_cast<std::uint32_t>(TIOCSTI)) {
            return "ioctl(TIOCSTI)";
        }
#endif
#ifdef TIOCLINUX
        if (cmd == static_cast<std::uint32_t>(TIOCLINUX)) {
            return "ioctl(TIOCLINUX)";
        }
#endif
        return "ioctl(" + std::to_string(cmd) + ")";
    }
    char* resolved = ::seccomp_syscall_resolve_num_arch(req.data.arch, req.data.nr);
    if (resolved != nullptr) {
        std::string name{resolved};
        std::free(resolved);
        return name;
    }
    return "syscall#" + std::to_string(req.data.nr);
}

struct notif_pair_guard final {
    struct ::seccomp_notif* req = nullptr;
    struct ::seccomp_notif_resp* resp = nullptr;

    ~notif_pair_guard() {
        if (req != nullptr || resp != nullptr) {
            ::seccomp_notify_free(req, resp);
        }
    }
};

} // namespace

auto create_seccomp_notify_channel(int (&fds)[2]) -> std::expected<void, std::string> {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
        return std::unexpected(error_text("socketpair(seccomp_notify)"));
    }
    return {};
}

auto send_seccomp_notify_fd_and_wait_ack(int channel_fd, int notif_fd)
    -> std::expected<void, std::string> {
    if (channel_fd < 0 || notif_fd < 0) {
        return std::unexpected(std::string{"invalid seccomp notify channel or fd"});
    }
    char marker = 'N';
    ::iovec payload{.iov_base = &marker, .iov_len = 1};
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
    std::memcpy(CMSG_DATA(header), &notif_fd, sizeof(notif_fd));
    while (::sendmsg(channel_fd, &message, MSG_NOSIGNAL) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(error_text("sendmsg(seccomp_notify)"));
    }
    char ack = 0;
    while (true) {
        const ::ssize_t n = ::recv(channel_fd, &ack, 1, 0);
        if (n == 1 && ack == 'A') {
            return {};
        }
        if (n == 0) {
            return std::unexpected(std::string{"seccomp notify ack channel closed"});
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return std::unexpected(error_text("recv(seccomp_notify ack)"));
    }
}

auto receive_seccomp_notify_fd(int channel_fd) -> std::expected<int, std::string> {
    if (channel_fd < 0) {
        return std::unexpected(std::string{"invalid seccomp notify channel"});
    }
    char marker = 0;
    ::iovec payload{.iov_base = &marker, .iov_len = 1};
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    ::msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ::ssize_t received = -1;
    do {
        received = ::recvmsg(channel_fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
        return std::unexpected(
            received == 0 ? std::string{"seccomp notify channel closed before fd transfer"}
                          : error_text("recvmsg(seccomp_notify)")
        );
    }
    if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        return std::unexpected(std::string{"truncated seccomp notify control message"});
    }
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
            header->cmsg_len == CMSG_LEN(sizeof(int))) {
            int fd = -1;
            std::memcpy(&fd, CMSG_DATA(header), sizeof(fd));
            if (fd < 0) {
                return std::unexpected(std::string{"received invalid seccomp notify fd"});
            }
            return fd;
        }
    }
    return std::unexpected(std::string{"missing seccomp notify fd in control message"});
}

auto send_seccomp_notify_ack(int channel_fd) -> std::expected<void, std::string> {
    constexpr char ack = 'A';
    while (::send(channel_fd, &ack, 1, MSG_NOSIGNAL) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(error_text("send(seccomp_notify ack)"));
    }
    return {};
}

struct seccomp_escape_monitor::implementation final {
    int notif_fd = -1;
    int stop_read_fd = -1;
    int stop_write_fd = -1;
    ::pid_t child_pid = -1;
    notif_pair_guard buffers;
    seccomp_escape_callback on_escape;
    seccomp_kill_callback kill_container;
    std::atomic<bool> escape_detected{false};
    mutable std::mutex mutex;
    std::condition_variable ready_cv;
    bool ready = false;
    std::string detected_syscall;
    std::thread worker;

    ~implementation() {
        if (stop_write_fd >= 0) {
            (void)::close(stop_write_fd);
            stop_write_fd = -1;
        }
        if (worker.joinable()) {
            worker.join();
        }
        if (stop_read_fd >= 0) {
            (void)::close(stop_read_fd);
            stop_read_fd = -1;
        }
        if (notif_fd >= 0) {
            (void)::close(notif_fd);
            notif_fd = -1;
        }
    }

    void terminate_sandbox(::pid_t offending_pid = -1) noexcept {
        if (kill_container) {
            try {
                kill_container();
            } catch (...) {}
        }
        if (offending_pid > 0) {
            (void)::kill(offending_pid, SIGKILL);
        }
        if (child_pid > 0) {
            (void)::kill(child_pid, SIGKILL);
        }
    }

    void run() noexcept {
        {
            const std::lock_guard lock{mutex};
            ready = true;
        }
        ready_cv.notify_all();

        std::array<::pollfd, 2> pfds{{
            {.fd = notif_fd, .events = POLLIN, .revents = 0},
            {.fd = stop_read_fd, .events = POLLIN, .revents = 0},
        }};

        for (;;) {
            pfds[0].revents = 0;
            pfds[1].revents = 0;
            const int ready_count = ::poll(pfds.data(), pfds.size(), -1);
            if (ready_count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                terminate_sandbox();
                break;
            }
            if ((pfds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                break;
            }
            if ((pfds[0].revents & POLLIN) != 0) {
                const int rc = ::seccomp_notify_receive(notif_fd, buffers.req);
                if (rc < 0) {
                    if (rc == -EINTR || rc == -ENOENT) {
                        continue;
                    }
                    terminate_sandbox();
                    break;
                }
                if (::seccomp_notify_id_valid(notif_fd, buffers.req->id) != 0) {
                    continue;
                }
                escape_detected.store(true, std::memory_order_release);
                terminate_sandbox(static_cast<::pid_t>(buffers.req->pid));
                std::string syscall_name;
                try {
                    syscall_name = describe_syscall(*buffers.req);
                    const std::lock_guard lock{mutex};
                    if (detected_syscall.empty()) {
                        detected_syscall = syscall_name;
                    }
                } catch (...) {
                    syscall_name.clear();
                }
                if (on_escape) {
                    try {
                        on_escape(
                            seccomp_escape_info{
                                .syscall_name = syscall_name.empty()
                                                    ? std::string{"seccomp_trapped_syscall"}
                                                    : syscall_name,
                                .pid = static_cast<::pid_t>(buffers.req->pid),
                            }
                        );
                    } catch (...) {}
                }
                buffers.resp->id = buffers.req->id;
                buffers.resp->val = 0;
                buffers.resp->error = -EPERM;
                buffers.resp->flags = 0;
                (void)::seccomp_notify_respond(notif_fd, buffers.resp);
                continue;
            }
            if ((pfds[0].revents & (POLLERR | POLLNVAL)) != 0) {
                terminate_sandbox();
                break;
            }
            if ((pfds[0].revents & POLLHUP) != 0) {
                break;
            }
        }
    }
};

seccomp_escape_monitor::seccomp_escape_monitor(std::unique_ptr<implementation> impl)
    : impl_{std::move(impl)} {}

seccomp_escape_monitor::~seccomp_escape_monitor() = default;

auto seccomp_escape_monitor::start(
    int notif_fd,
    ::pid_t child_pid,
    seccomp_escape_callback on_escape,
    seccomp_kill_callback kill_container
) -> std::expected<std::unique_ptr<seccomp_escape_monitor>, std::string> {
    if (notif_fd < 0) {
        return std::unexpected(std::string{"seccomp_escape_monitor: invalid notif_fd"});
    }
    int stop_pipe[2] = {-1, -1};
    if (::pipe2(stop_pipe, O_CLOEXEC) != 0) {
        const std::string msg = error_text("pipe2(seccomp_monitor stop)");
        (void)::close(notif_fd);
        return std::unexpected(msg);
    }
    auto impl = std::make_unique<implementation>();
    impl->notif_fd = notif_fd;
    impl->stop_read_fd = stop_pipe[0];
    impl->stop_write_fd = stop_pipe[1];
    impl->child_pid = child_pid;
    impl->on_escape = std::move(on_escape);
    impl->kill_container = std::move(kill_container);
    if (::seccomp_notify_alloc(&impl->buffers.req, &impl->buffers.resp) != 0 ||
        impl->buffers.req == nullptr || impl->buffers.resp == nullptr) {
        return std::unexpected(std::string{"seccomp_notify_alloc failed"});
    }
    try {
        impl->worker = std::thread{[raw = impl.get()] { raw->run(); }};
    } catch (const std::system_error& err) {
        return std::unexpected(std::string{"start seccomp_escape_monitor: "} + err.what());
    }
    {
        std::unique_lock lock{impl->mutex};
        impl->ready_cv.wait(lock, [&] { return impl->ready; });
    }
    return std::unique_ptr<seccomp_escape_monitor>{new seccomp_escape_monitor{std::move(impl)}};
}

auto seccomp_escape_monitor::escape_detected() const noexcept -> bool {
    return impl_ != nullptr && impl_->escape_detected.load(std::memory_order_acquire);
}

auto seccomp_escape_monitor::detected_syscall() const -> std::string {
    if (impl_ == nullptr) {
        return {};
    }
    const std::lock_guard lock{impl_->mutex};
    return impl_->detected_syscall;
}

} // namespace glove::container::linux_detail
