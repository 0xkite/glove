#include "linux_egress_bridge.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace glove::container::linux_detail {

namespace {

auto error_text(std::string_view operation, int error = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error, std::generic_category()}.message();
}

void close_descriptor(int descriptor) noexcept {
    if (descriptor >= 0) {
        ::close(descriptor);
    }
}

auto send_descriptor(int channel, int descriptor) -> bool {
    char marker = 'C';
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
    std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
    while (::sendmsg(channel, &message, MSG_NOSIGNAL) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

auto receive_descriptor(int channel) -> int {
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
        received = ::recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received <= 0 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
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

auto connect_host_proxy(std::uint16_t port) -> int {
    const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return -1;
    }
    ::sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while (::connect(descriptor, reinterpret_cast<const ::sockaddr*>(&address), sizeof(address)) <
           0) {
        if (errno == EINTR) {
            continue;
        }
        close_descriptor(descriptor);
        return -1;
    }
    return descriptor;
}

auto write_all(int descriptor, const char* data, std::size_t size) -> bool {
    while (size > 0) {
        const auto written = ::send(descriptor, data, size, MSG_NOSIGNAL);
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

void relay(int left, int right, const std::atomic<bool>& stopping) noexcept {
    std::array<char, 16 * 1024> buffer{};
    std::array<::pollfd, 2> descriptors{{
        {.fd = left, .events = POLLIN, .revents = 0},
        {.fd = right, .events = POLLIN, .revents = 0},
    }};
    std::array<bool, 2> readable{{true, true}};
    while (!stopping.load(std::memory_order_relaxed)) {
        const int ready = ::poll(descriptors.data(), descriptors.size(), 250);
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
        for (std::size_t index = 0; index < descriptors.size(); ++index) {
            const auto events = descriptors[index].revents;
            if ((events & (POLLERR | POLLNVAL)) != 0) {
                done = true;
                break;
            }
            if (!readable[index] || (events & (POLLIN | POLLHUP)) == 0) {
                continue;
            }
            const int source = descriptors[index].fd;
            const int destination = descriptors[1 - index].fd;
            const auto count = ::recv(source, buffer.data(), buffer.size(), 0);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0) {
                done = true;
                break;
            }
            if (count == 0) {
                readable[index] = false;
                descriptors[index].events = 0;
                static_cast<void>(::shutdown(destination, SHUT_WR));
                continue;
            }
            if (!write_all(destination, buffer.data(), static_cast<std::size_t>(count))) {
                done = true;
                break;
            }
        }
        if (done || (!readable[0] && !readable[1])) {
            break;
        }
    }
    static_cast<void>(::shutdown(left, SHUT_RDWR));
    static_cast<void>(::shutdown(right, SHUT_RDWR));
    close_descriptor(left);
    close_descriptor(right);
}

class bridge_impl final : public host_egress_bridge {
public:
    bridge_impl(int channel, std::uint16_t port) : channel_{channel}, proxy_port_{port} {}

    auto start() -> std::expected<void, std::string> {
        try {
            workers_.reserve(64);
            receiver_ = std::thread{[this] { receive_loop(); }};
        } catch (const std::exception& error) {
            return std::unexpected(std::string{"start egress bridge: "} + error.what());
        }
        return {};
    }

    ~bridge_impl() override {
        stopping_.store(true, std::memory_order_relaxed);
        static_cast<void>(::shutdown(channel_, SHUT_RDWR));
        close_descriptor(channel_);
        channel_ = -1;
        if (receiver_.joinable()) {
            receiver_.join();
        }
        const std::lock_guard lock{workers_mutex_};
        for (auto& worker : workers_) {
            if (worker.thread.joinable()) {
                worker.thread.join();
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
        auto cursor = workers_.begin();
        while (cursor != workers_.end()) {
            if (!cursor->finished->load(std::memory_order_acquire)) {
                ++cursor;
                continue;
            }
            if (cursor->thread.joinable()) {
                cursor->thread.join();
            }
            cursor = workers_.erase(cursor);
        }
    }

    void receive_loop() noexcept {
        constexpr std::size_t maximum_concurrent_relays = 64;
        while (!stopping_.load(std::memory_order_relaxed)) {
            const int client = receive_descriptor(channel_);
            if (client < 0) {
                break;
            }
            reap_workers();
            {
                const std::lock_guard lock{workers_mutex_};
                if (workers_.size() >= maximum_concurrent_relays) {
                    close_descriptor(client);
                    continue;
                }
            }
            const int proxy = connect_host_proxy(proxy_port_);
            if (proxy < 0) {
                close_descriptor(client);
                continue;
            }
            try {
                auto finished = std::make_shared<std::atomic<bool>>(false);
                const std::lock_guard lock{workers_mutex_};
                workers_.push_back({
                    .thread = std::thread{[this, client, proxy, finished] {
                        relay(client, proxy, stopping_);
                        finished->store(true, std::memory_order_release);
                    }},
                    .finished = std::move(finished),
                });
            } catch (...) {
                close_descriptor(client);
                close_descriptor(proxy);
                break;
            }
        }
    }

    int channel_ = -1;
    std::uint16_t proxy_port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread receiver_;
    std::mutex workers_mutex_;
    std::vector<worker_record> workers_;
};

auto bring_up_loopback() -> std::expected<void, std::string> {
    const int descriptor = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return std::unexpected(error_text("open loopback control socket"));
    }
    ::ifreq request{};
    std::strncpy(request.ifr_name, "lo", IFNAMSIZ - 1);
    if (::ioctl(descriptor, SIOCGIFFLAGS, &request) < 0) {
        const int saved = errno;
        close_descriptor(descriptor);
        return std::unexpected(error_text("read loopback flags", saved));
    }
    request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP | IFF_RUNNING);
    if (::ioctl(descriptor, SIOCSIFFLAGS, &request) < 0) {
        const int saved = errno;
        close_descriptor(descriptor);
        return std::unexpected(error_text("enable loopback", saved));
    }
    close_descriptor(descriptor);
    return {};
}

auto open_private_listener(std::uint16_t port) -> std::expected<int, std::string> {
    const int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return std::unexpected(error_text("open private egress listener"));
    }
    const int enabled = 1;
    static_cast<void>(
        ::setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled))
    );
    ::sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(descriptor, reinterpret_cast<const ::sockaddr*>(&address), sizeof(address)) < 0 ||
        ::listen(descriptor, 16) < 0) {
        const int saved = errno;
        close_descriptor(descriptor);
        return std::unexpected(error_text("bind private egress listener", saved));
    }
    return descriptor;
}

void close_except(int first, int second) noexcept {
    const int lower = std::min(first, second);
    const int upper = std::max(first, second);
#if defined(SYS_close_range)
    if (lower > STDERR_FILENO + 1) {
        static_cast<void>(::syscall(SYS_close_range, STDERR_FILENO + 1, lower - 1, 0));
    }
    if (upper > lower + 1) {
        static_cast<void>(::syscall(SYS_close_range, lower + 1, upper - 1, 0));
    }
    static_cast<void>(::syscall(SYS_close_range, upper + 1, ~0U, 0));
#else
    const long maximum = ::sysconf(_SC_OPEN_MAX);
    for (int descriptor = STDERR_FILENO + 1; descriptor < maximum; ++descriptor) {
        if (descriptor != first && descriptor != second) {
            close_descriptor(descriptor);
        }
    }
#endif
}

[[noreturn]] void sandbox_forwarder(int listener, int channel) noexcept {
    close_except(listener, channel);
    while (true) {
        int client = -1;
        do {
            client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        } while (client < 0 && errno == EINTR);
        if (client < 0) {
            std::_Exit(0);
        }
        const bool sent = send_descriptor(channel, client);
        close_descriptor(client);
        if (!sent) {
            std::_Exit(0);
        }
    }
}

} // namespace

auto create_egress_channel() -> std::expected<egress_channel_pair, std::string> {
    int descriptors[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors) < 0) {
        return std::unexpected(error_text("create egress channel"));
    }
    return egress_channel_pair{.host_fd = descriptors[0], .sandbox_fd = descriptors[1]};
}

auto start_host_egress_bridge(int host_channel_fd, std::uint16_t proxy_port)
    -> std::expected<std::unique_ptr<host_egress_bridge>, std::string> {
    if (host_channel_fd < 0 || proxy_port == 0) {
        close_descriptor(host_channel_fd);
        return std::unexpected(std::string{"invalid host egress bridge configuration"});
    }
    auto bridge = std::make_unique<bridge_impl>(host_channel_fd, proxy_port);
    if (auto started = bridge->start(); !started) {
        return std::unexpected(started.error());
    }
    return bridge;
}

auto install_sandbox_egress_bridge(int sandbox_channel_fd, std::uint16_t proxy_port)
    -> std::expected<void, std::string> {
    if (sandbox_channel_fd < 0 || proxy_port == 0) {
        close_descriptor(sandbox_channel_fd);
        return std::unexpected(std::string{"invalid sandbox egress bridge configuration"});
    }
    if (auto loopback = bring_up_loopback(); !loopback) {
        close_descriptor(sandbox_channel_fd);
        return loopback;
    }
    auto listener = open_private_listener(proxy_port);
    if (!listener) {
        close_descriptor(sandbox_channel_fd);
        return std::unexpected(listener.error());
    }
    const ::pid_t forwarder = ::fork();
    if (forwarder < 0) {
        const int saved = errno;
        close_descriptor(*listener);
        close_descriptor(sandbox_channel_fd);
        return std::unexpected(error_text("fork sandbox egress forwarder", saved));
    }
    if (forwarder == 0) {
        sandbox_forwarder(*listener, sandbox_channel_fd);
    }
    close_descriptor(*listener);
    close_descriptor(sandbox_channel_fd);
    return {};
}

} // namespace glove::container::linux_detail
