#include "wallet_status_managed_session.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::control {
namespace {

using steady_time = std::chrono::steady_clock::time_point;

class owned_fd {
public:
    explicit owned_fd(int descriptor = -1) noexcept : descriptor_(descriptor) {}

    owned_fd(const owned_fd&) = delete;
    auto operator=(const owned_fd&) -> owned_fd& = delete;

    owned_fd(owned_fd&& other) noexcept : descriptor_(std::exchange(other.descriptor_, -1)) {}

    auto operator=(owned_fd&& other) noexcept -> owned_fd& {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~owned_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    auto reset() noexcept -> void {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

[[nodiscard]] auto error_message(std::string_view operation, int error_number = errno)
    -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

[[nodiscard]] auto peer_uid(int descriptor) -> std::expected<uid_t, std::string> {
#if defined(__linux__)
    struct peer_credentials {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } credentials{};

    socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return std::unexpected(error_message("inspect wallet status peer credentials"));
    }
    return credentials.uid;
#elif defined(__APPLE__)
    auto uid = static_cast<uid_t>(-1);
    auto gid = static_cast<gid_t>(-1);
    if (::getpeereid(descriptor, &uid, &gid) != 0) {
        return std::unexpected(error_message("inspect wallet status peer credentials"));
    }
    return uid;
#else
    (void)descriptor;
    return std::unexpected(std::string{"wallet status peer credentials are unsupported"});
#endif
}

[[nodiscard]] auto configure_and_verify(int descriptor, uid_t expected_uid)
    -> std::expected<void, std::string> {
    const auto descriptor_flags = ::fcntl(descriptor, F_GETFD);
    const auto status_flags = ::fcntl(descriptor, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0 ||
        ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return std::unexpected(error_message("configure wallet status descriptor"));
    }

    struct stat status{};
    int socket_type = 0;
    socklen_t socket_type_length = sizeof(socket_type);
    sockaddr_storage local{};
    sockaddr_storage peer{};
    socklen_t local_length = sizeof(local);
    socklen_t peer_length = sizeof(peer);
    const auto actual_peer_uid = peer_uid(descriptor);
    const auto configured_descriptor_flags = ::fcntl(descriptor, F_GETFD);
    const auto configured_status_flags = ::fcntl(descriptor, F_GETFL);
    if (::fstat(descriptor, &status) != 0 || !S_ISSOCK(status.st_mode) ||
        status.st_uid != ::geteuid() ||
        ::getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length) != 0 ||
        socket_type != SOCK_STREAM ||
        ::getsockname(descriptor, reinterpret_cast<sockaddr*>(&local), &local_length) != 0 ||
        ::getpeername(descriptor, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0 ||
        local.ss_family != AF_UNIX || peer.ss_family != AF_UNIX || !actual_peer_uid ||
        *actual_peer_uid != expected_uid || configured_descriptor_flags < 0 ||
        (configured_descriptor_flags & FD_CLOEXEC) == 0 || configured_status_flags < 0 ||
        (configured_status_flags & O_NONBLOCK) == 0) {
        return std::unexpected(std::string{"wallet status descriptor verification failed"});
    }
    return {};
}

[[nodiscard]] auto
wait_for_request(int descriptor, steady_time deadline, const std::stop_token& stop)
    -> std::expected<void, std::string> {
    while (true) {
        if (stop.stop_requested()) {
            return std::unexpected(std::string{"wallet status session cancelled"});
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::unexpected(std::string{"wallet status session expired"});
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        if (remaining.count() == 0) {
            remaining = std::chrono::milliseconds{1};
        }
        const auto timeout = static_cast<int>(std::min<std::int64_t>(remaining.count(), 50));
        pollfd state{.fd = descriptor, .events = POLLIN, .revents = 0};
        const auto result = ::poll(&state, 1, timeout);
        if (stop.stop_requested()) {
            return std::unexpected(std::string{"wallet status session cancelled"});
        }
        if (result > 0) {
            if ((state.revents & (POLLERR | POLLNVAL)) != 0) {
                return std::unexpected(std::string{"wallet status descriptor failed"});
            }
            if ((state.revents & POLLIN) != 0) {
                return {};
            }
            if ((state.revents & POLLHUP) != 0) {
                return std::unexpected(std::string{"wallet status descriptor closed"});
            }
            continue;
        }
        if (result == 0 || errno == EINTR) {
            continue;
        }
        return std::unexpected(error_message("wait for wallet status request"));
    }
}

} // namespace

wallet_status_managed_session::wallet_status_managed_session(
    construction_token /*token*/,
    std::unique_ptr<wallet_status_bridge> bridge,
    wallet_status_managed_session_options options,
    int host_descriptor,
    int guest_descriptor
)
    : bridge_(std::move(bridge)),
      options_(options),
      host_descriptor_(host_descriptor),
      guest_descriptor_(guest_descriptor) {}

wallet_status_managed_session::~wallet_status_managed_session() {
    close();
}

auto wallet_status_managed_session::create(
    std::unique_ptr<wallet_status_bridge> bridge, wallet_status_managed_session_options options
) -> std::expected<std::unique_ptr<wallet_status_managed_session>, std::string> {
    const auto now = std::chrono::steady_clock::now();
    if (!options.enabled) {
        return std::unexpected(std::string{"wallet status managed session is disabled"});
    }
    if (!bridge || options.request_timeout <= std::chrono::milliseconds::zero() ||
        options.request_timeout > std::chrono::milliseconds{max_wallet_status_request_ttl_ms} ||
        options.session_deadline <= now || options.expected_peer_uid != ::geteuid()) {
        return std::unexpected(std::string{"invalid wallet status managed session options"});
    }

    std::array<int, 2> descriptors{-1, -1};
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    constexpr int socket_type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    if (::socketpair(AF_UNIX, socket_type, 0, descriptors.data()) != 0) {
        return std::unexpected(error_message("create wallet status socketpair"));
    }
#else
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors.data()) != 0) {
        return std::unexpected(error_message("create wallet status socketpair"));
    }
#endif
    owned_fd host{descriptors[0]};
    owned_fd guest{descriptors[1]};
    if (auto verified = configure_and_verify(host.get(), options.expected_peer_uid); !verified) {
        return std::unexpected(verified.error());
    }
    if (auto verified = configure_and_verify(guest.get(), options.expected_peer_uid); !verified) {
        return std::unexpected(verified.error());
    }

    auto managed = std::make_unique<wallet_status_managed_session>(
        construction_token{}, std::move(bridge), options, host.get(), guest.get()
    );
    (void)host.release();
    (void)guest.release();
    return managed;
}

auto wallet_status_managed_session::start() -> std::expected<void, std::string> {
    const std::scoped_lock lock{mutex_};
    if (started_ || closing_ || closed_.load() || host_descriptor_ < 0) {
        return std::unexpected(std::string{"wallet status managed session cannot start"});
    }
    try {
        worker_ = std::jthread([this](std::stop_token stop) { run(stop); });
        worker_id_ = worker_.get_id();
        worker_stop_source_ = worker_.get_stop_source();
        worker_joinable_ = true;
        worker_running_ = true;
        started_ = true;
        return {};
    } catch (...) {
        return std::unexpected(std::string{"start wallet status managed session"});
    }
}

auto wallet_status_managed_session::take_guest_descriptor() -> std::expected<int, std::string> {
    const std::scoped_lock lock{mutex_};
    if (closing_ || closed_.load() || guest_released_ || guest_descriptor_ < 0) {
        return std::unexpected(std::string{"wallet status guest descriptor is unavailable"});
    }
    guest_released_ = true;
    return std::exchange(guest_descriptor_, -1);
}

auto wallet_status_managed_session::close() noexcept -> void {
    bool join_worker = false;
    {
        std::unique_lock lock{mutex_};
        closing_ = true;
        (void)worker_stop_source_.request_stop();
        if (host_descriptor_ >= 0) {
            (void)::shutdown(host_descriptor_, SHUT_RDWR);
        }
        if (worker_running_ && worker_id_ == std::this_thread::get_id()) {
            // Reentrant worker teardown must never wait for an external
            // joiner. The run epilogue reaps owned descriptors.
            return;
        }
        close_condition_.wait(lock, [this] { return !join_in_progress_; });
        if (!worker_joinable_ && closed_.load()) {
            return;
        }
        join_in_progress_ = true;
        join_worker = worker_joinable_;
    }

    if (join_worker) {
        // Only the elected non-worker closer may access the jthread. A join
        // failure is an invariant violation; noexcept teardown terminates
        // rather than destroying state while a worker could still use it.
        worker_.join();
        const std::scoped_lock lock{mutex_};
        worker_joinable_ = false;
        worker_id_ = {};
        worker_stop_source_ = std::stop_source{std::nostopstate};
    }
    reap_owned_descriptors();
    {
        const std::scoped_lock lock{mutex_};
        join_in_progress_ = false;
    }
    close_condition_.notify_all();
}

auto wallet_status_managed_session::closed() const noexcept -> bool {
    return closed_.load();
}

auto wallet_status_managed_session::run(const std::stop_token& stop) noexcept -> void {
    try {
        while (!stop.stop_requested()) {
            if (auto ready = wait_for_request(host_descriptor_, options_.session_deadline, stop);
                !ready) {
                break;
            }
            const auto received_at = std::chrono::steady_clock::now();
            const auto deadline =
                std::min(options_.session_deadline, received_at + options_.request_timeout);
            auto request = read_wallet_status_frame(host_descriptor_, deadline, stop);
            if (!request) {
                break;
            }
            auto response = bridge_->handle_request(*request, deadline);
            if (!response) {
                break;
            }
            if (auto written =
                    write_wallet_status_frame(host_descriptor_, *response, deadline, stop);
                !written) {
                break;
            }
        }
    } catch (...) {
        // The worker is an exception firewall. Release processor authorities
        // before publishing terminal state after descriptor reaping.
        bridge_.reset();
    }
    reap_owned_descriptors();
}

auto wallet_status_managed_session::reap_owned_descriptors() noexcept -> void {
    int host = -1;
    int guest = -1;
    {
        const std::scoped_lock lock{mutex_};
        host = std::exchange(host_descriptor_, -1);
        guest = std::exchange(guest_descriptor_, -1);
        worker_running_ = false;
    }
    if (host >= 0) {
        (void)::shutdown(host, SHUT_RDWR);
        (void)::close(host);
    }
    if (guest >= 0) {
        (void)::close(guest);
    }
    closed_.store(true);
    close_condition_.notify_all();
}

} // namespace glove::control
