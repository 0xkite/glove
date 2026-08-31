// Peer credentials require GNU extensions on Linux.
#if defined(__linux__) && !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#endif

#include "glove/control/guest_channel_transport.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <sys/param.h>
#    include <sys/ucred.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::control {
namespace {

class unique_fd {
public:
    explicit unique_fd(int value = -1) noexcept : value_{value} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : value_{std::exchange(other.value_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset(std::exchange(other.value_, -1));
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    void reset(int value = -1) noexcept {
        if (value_ >= 0) {
            static_cast<void>(::close(value_));
        }
        value_ = value;
    }

    int value_ = -1;
};

using error_code = guest_channel_transport_error_code;

auto failure(error_code code, std::string message) -> guest_channel_transport_error {
    return {.code = code, .message = std::move(message)};
}

auto system_failure(std::string_view operation, int code = errno) -> guest_channel_transport_error {
    return failure(
        error_code::io,
        std::string{operation} + ": " + std::error_code{code, std::generic_category()}.message()
    );
}

auto peer_uid(int descriptor) -> std::optional<std::uint32_t> {
#if defined(SO_PEERCRED)
    struct ::ucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return std::nullopt;
    }
    return credentials.uid;
#elif defined(LOCAL_PEERCRED)
    struct xucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &length) != 0 ||
        credentials.cr_version != XUCRED_VERSION) {
        return std::nullopt;
    }
    return credentials.cr_uid;
#else
    (void)descriptor;
    return std::nullopt;
#endif
}

auto verify_socket(int descriptor, std::uint32_t expected_peer_uid)
    -> guest_channel_transport_result<void> {
    int socket_type = 0;
    ::socklen_t type_size = sizeof(socket_type);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socket_type, &type_size) != 0 ||
        type_size != sizeof(socket_type) || socket_type != SOCK_STREAM) {
        return std::unexpected(failure(error_code::invalid_socket, "endpoint is not SOCK_STREAM"));
    }
    ::sockaddr_un peer{};
    ::socklen_t peer_size = sizeof(peer);
    if (::getpeername(descriptor, reinterpret_cast<::sockaddr*>(&peer), &peer_size) != 0 ||
        peer_size < sizeof(peer.sun_family) || peer.sun_family != AF_UNIX) {
        return std::unexpected(failure(error_code::invalid_socket, "endpoint is not AF_UNIX"));
    }
    const auto uid = peer_uid(descriptor);
    if (!uid || *uid != expected_peer_uid) {
        return std::unexpected(failure(error_code::peer_identity, "peer uid mismatch"));
    }
    return {};
}

auto prepare_descriptor(int descriptor) -> guest_channel_transport_result<void> {
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
    const int status_flags = ::fcntl(descriptor, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0 ||
        ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return std::unexpected(system_failure("protect guest channel descriptor"));
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return std::unexpected(system_failure("protect guest channel writes"));
    }
#endif
    return {};
}

auto interruption(std::stop_token stop, guest_channel_deadline deadline)
    -> std::optional<guest_channel_transport_error> {
    if (stop.stop_requested()) {
        return failure(error_code::cancelled, "guest channel operation cancelled");
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return failure(error_code::deadline_exceeded, "guest channel deadline exceeded");
    }
    return std::nullopt;
}

auto wait_ready(int descriptor, short events, guest_channel_deadline deadline, std::stop_token stop)
    -> guest_channel_transport_result<void> {
    for (;;) {
        if (auto interrupted = interruption(stop, deadline)) {
            return std::unexpected(std::move(*interrupted));
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()
        );
        const auto bounded = std::clamp<std::int64_t>(remaining.count(), 1, 25);
        ::pollfd event{.fd = descriptor, .events = events, .revents = 0};
        const int ready = ::poll(&event, 1, static_cast<int>(bounded));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            return std::unexpected(system_failure("poll guest channel"));
        }
        if (ready == 0) {
            continue;
        }
        if ((event.revents & events) != 0) {
            return {};
        }
        if ((event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            return std::unexpected(failure(error_code::disconnected, "guest channel disconnected"));
        }
    }
}

auto read_exact(
    int descriptor,
    void* output,
    std::size_t size,
    guest_channel_deadline deadline,
    std::stop_token stop
) -> guest_channel_transport_result<void> {
    auto* bytes = static_cast<std::byte*>(output);
    std::size_t consumed = 0;
    while (consumed < size) {
        auto ready = wait_ready(descriptor, POLLIN, deadline, stop);
        if (!ready) {
            return ready;
        }
        const auto result = ::read(descriptor, bytes + consumed, size - consumed);
        if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (result < 0) {
            return std::unexpected(system_failure("read guest channel"));
        }
        if (result == 0) {
            return std::unexpected(failure(error_code::disconnected, "guest channel ended"));
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto write_exact(
    int descriptor,
    const void* input,
    std::size_t size,
    guest_channel_deadline deadline,
    std::stop_token stop
) -> guest_channel_transport_result<void> {
    const auto* bytes = static_cast<const std::byte*>(input);
    std::size_t written = 0;
    while (written < size) {
        auto ready = wait_ready(descriptor, POLLOUT, deadline, stop);
        if (!ready) {
            return ready;
        }
#if defined(MSG_NOSIGNAL)
        const auto result = ::send(descriptor, bytes + written, size - written, MSG_NOSIGNAL);
#else
        const auto result = ::write(descriptor, bytes + written, size - written);
#endif
        if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (result < 0) {
            if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN) {
                return std::unexpected(
                    failure(error_code::disconnected, "guest channel disconnected")
                );
            }
            return std::unexpected(system_failure("write guest channel"));
        }
        if (result == 0) {
            return std::unexpected(failure(error_code::disconnected, "guest channel ended"));
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

} // namespace

struct guest_channel_transport::implementation {
    unique_fd descriptor;
    std::size_t max_frame_bytes = 0;
};

guest_channel_transport::guest_channel_transport(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

guest_channel_transport::~guest_channel_transport() {
    shutdown_and_reset();
}

auto guest_channel_transport::adopt(
    int descriptor, std::size_t max_frame_bytes, std::uint32_t expected_peer_uid
) -> guest_channel_transport_result<std::unique_ptr<guest_channel_transport>> {
    unique_fd owned{descriptor};
    if (descriptor < 0) {
        return std::unexpected(failure(error_code::invalid_descriptor, "invalid descriptor"));
    }
    if (max_frame_bytes == 0 ||
        max_frame_bytes > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::unexpected(failure(error_code::invalid_frame, "invalid frame bound"));
    }
    if (auto verified = verify_socket(descriptor, expected_peer_uid); !verified) {
        return std::unexpected(std::move(verified.error()));
    }
    if (auto prepared = prepare_descriptor(descriptor); !prepared) {
        return std::unexpected(std::move(prepared.error()));
    }
    auto state = std::make_unique<implementation>();
    state->descriptor = std::move(owned);
    state->max_frame_bytes = max_frame_bytes;
    return std::make_unique<guest_channel_transport>(construction_token{}, std::move(state));
}

auto guest_channel_transport::receive_frame(guest_channel_deadline deadline, std::stop_token stop)
    -> guest_channel_transport_result<std::string> {
    if (!state_ || state_->descriptor.get() < 0) {
        return std::unexpected(failure(error_code::invalid_descriptor, "closed guest channel"));
    }
    std::uint32_t network_length = 0;
    if (auto read = read_exact(
            state_->descriptor.get(), &network_length, sizeof(network_length), deadline, stop
        );
        !read) {
        return std::unexpected(std::move(read.error()));
    }
    const auto frame_size = static_cast<std::size_t>(ntohl(network_length));
    if (frame_size == 0) {
        return std::unexpected(failure(error_code::invalid_frame, "empty guest channel frame"));
    }
    if (frame_size > state_->max_frame_bytes) {
        return std::unexpected(
            failure(error_code::frame_too_large, "guest channel frame exceeds bound")
        );
    }
    std::string frame(frame_size, '\0');
    if (auto read =
            read_exact(state_->descriptor.get(), frame.data(), frame.size(), deadline, stop);
        !read) {
        return std::unexpected(std::move(read.error()));
    }
    return frame;
}

void guest_channel_transport::shutdown_and_reset() noexcept {
    if (!state_ || state_->descriptor.get() < 0) {
        return;
    }
    static_cast<void>(::shutdown(state_->descriptor.get(), SHUT_RDWR));
    state_.reset();
}

auto guest_channel_transport::send_frame(
    std::string_view payload, guest_channel_deadline deadline, std::stop_token stop
) -> guest_channel_transport_result<void> {
    if (!state_ || state_->descriptor.get() < 0) {
        return std::unexpected(failure(error_code::invalid_descriptor, "closed guest channel"));
    }
    if (payload.empty()) {
        return std::unexpected(failure(error_code::invalid_frame, "empty guest channel frame"));
    }
    if (payload.size() > state_->max_frame_bytes ||
        payload.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::unexpected(
            failure(error_code::frame_too_large, "guest channel frame exceeds bound")
        );
    }
    const auto network_length = htonl(static_cast<std::uint32_t>(payload.size()));
    if (auto written = write_exact(
            state_->descriptor.get(), &network_length, sizeof(network_length), deadline, stop
        );
        !written) {
        return written;
    }
    return write_exact(state_->descriptor.get(), payload.data(), payload.size(), deadline, stop);
}

} // namespace glove::control
