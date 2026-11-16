#pragma once

#include <sys/types.h>

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace glove::container::linux_detail {

struct seccomp_escape_info {
    std::string syscall_name;
    ::pid_t pid = -1;
};

using seccomp_escape_callback = std::function<void(const seccomp_escape_info&)>;
using seccomp_kill_callback = std::function<void()>;

// Create an AF_UNIX SOCK_STREAM socketpair with SOCK_CLOEXEC for transferring
// the child's seccomp user-notification descriptor and acknowledging monitor
// readiness before execv().
auto create_seccomp_notify_channel(int (&fds)[2]) -> std::expected<void, std::string>;

// Child side: pass `notif_fd` via SCM_RIGHTS to parent and block on a 1-byte
// readiness acknowledgement so the host monitor is polling before execv().
auto send_seccomp_notify_fd_and_wait_ack(int channel_fd, int notif_fd)
    -> std::expected<void, std::string>;

// Parent side: receive the child's `notif_fd` via SCM_RIGHTS. Does not yet
// send the ack; caller starts `seccomp_escape_monitor` then sends ack.
auto receive_seccomp_notify_fd(int channel_fd) -> std::expected<int, std::string>;

// Parent side: send the 1-byte ack allowing child to proceed to execv().
auto send_seccomp_notify_ack(int channel_fd) -> std::expected<void, std::string>;

class seccomp_escape_monitor final {
public:
    seccomp_escape_monitor() = delete;
    seccomp_escape_monitor(const seccomp_escape_monitor&) = delete;
    auto operator=(const seccomp_escape_monitor&) -> seccomp_escape_monitor& = delete;
    seccomp_escape_monitor(seccomp_escape_monitor&&) = delete;
    auto operator=(seccomp_escape_monitor&&) -> seccomp_escape_monitor& = delete;
    ~seccomp_escape_monitor();

    static auto start(
        int notif_fd,
        ::pid_t child_pid,
        seccomp_escape_callback on_escape,
        seccomp_kill_callback kill_container
    ) -> std::expected<std::unique_ptr<seccomp_escape_monitor>, std::string>;

    [[nodiscard]] auto escape_detected() const noexcept -> bool;
    [[nodiscard]] auto detected_syscall() const -> std::string;

private:
    struct implementation;

    explicit seccomp_escape_monitor(std::unique_ptr<implementation> impl);

    std::unique_ptr<implementation> impl_;
};

} // namespace glove::container::linux_detail
