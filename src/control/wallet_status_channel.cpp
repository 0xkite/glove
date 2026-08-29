#include "wallet_status_bridge.hpp"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <limits>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>

namespace glove::control {
namespace {

using steady_time = std::chrono::steady_clock::time_point;

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto classify_poll_event(short returned, short expected) -> std::expected<bool, std::string> {
    if ((returned & (POLLERR | POLLNVAL)) != 0) {
        return std::unexpected(std::string{"wallet status descriptor failed"});
    }
    if ((returned & expected) != 0) {
        return true;
    }
    if ((returned & POLLHUP) != 0) {
        return std::unexpected(std::string{"wallet status descriptor closed"});
    }
    return false;
}

auto poll_ready(int descriptor, short events, steady_time deadline, const std::stop_token& stop)
    -> std::expected<void, std::string> {
    while (true) {
        if (stop.stop_requested()) {
            return std::unexpected(std::string{"wallet status protocol cancelled"});
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::unexpected(std::string{"wallet status protocol deadline exceeded"});
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        if (remaining.count() == 0) {
            remaining = std::chrono::milliseconds{1};
        }
        auto timeout_count = std::min<std::int64_t>(
            remaining.count(), static_cast<std::int64_t>(std::numeric_limits<int>::max())
        );
        if (stop.stop_possible()) {
            timeout_count = std::min<std::int64_t>(timeout_count, 50);
        }
        const auto timeout = static_cast<int>(timeout_count);
        pollfd descriptor_state{.fd = descriptor, .events = events, .revents = 0};
        const auto result = ::poll(&descriptor_state, 1, timeout);
        if (stop.stop_requested()) {
            return std::unexpected(std::string{"wallet status protocol cancelled"});
        }
        if (result > 0) {
            auto readiness = classify_poll_event(descriptor_state.revents, events);
            if (!readiness) {
                return std::unexpected(readiness.error());
            }
            if (*readiness) {
                return {};
            }
            continue;
        }
        if (result == 0) {
            continue;
        }
        if (errno != EINTR) {
            return std::unexpected(system_error("wallet status poll"));
        }
    }
}

auto read_exact(
    int descriptor,
    std::span<unsigned char> output,
    steady_time deadline,
    const std::stop_token& stop
) -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < output.size()) {
        if (auto waited = poll_ready(descriptor, POLLIN, deadline, stop); !waited) {
            return waited;
        }
        const auto count = ::recv(descriptor, output.data() + offset, output.size() - offset, 0);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0) {
            return std::unexpected(std::string{"wallet status descriptor closed"});
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return std::unexpected(system_error("wallet status read"));
        }
    }
    return {};
}

auto write_exact(
    int descriptor,
    std::span<const unsigned char> input,
    steady_time deadline,
    const std::stop_token& stop
) -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < input.size()) {
        if (auto waited = poll_ready(descriptor, POLLOUT, deadline, stop); !waited) {
            return waited;
        }
#if defined(MSG_NOSIGNAL)
        const auto count =
            ::send(descriptor, input.data() + offset, input.size() - offset, MSG_NOSIGNAL);
#else
        const auto count = ::send(descriptor, input.data() + offset, input.size() - offset, 0);
#endif
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count == 0) {
            return std::unexpected(std::string{"wallet status descriptor closed"});
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return std::unexpected(system_error("wallet status write"));
        }
    }
    return {};
}

} // namespace

auto read_wallet_status_frame(int descriptor, steady_time deadline, const std::stop_token& stop)
    -> std::expected<std::string, std::string> {
    std::array<unsigned char, 4> header{};
    if (auto read = read_exact(descriptor, header, deadline, stop); !read) {
        return std::unexpected(read.error());
    }
    const auto length = (static_cast<std::uint32_t>(header[0]) << 24U) |
                        (static_cast<std::uint32_t>(header[1]) << 16U) |
                        (static_cast<std::uint32_t>(header[2]) << 8U) |
                        static_cast<std::uint32_t>(header[3]);
    if (length == 0 || length > max_wallet_status_frame_bytes) {
        return std::unexpected(std::string{"wallet status frame exceeds its 64-KiB bound"});
    }
    std::string frame(length, '\0');
    auto bytes =
        std::span<unsigned char>{reinterpret_cast<unsigned char*>(frame.data()), frame.size()};
    if (auto read = read_exact(descriptor, bytes, deadline, stop); !read) {
        return std::unexpected(read.error());
    }
    return frame;
}

auto write_wallet_status_frame(
    int descriptor, std::string_view frame, steady_time deadline, const std::stop_token& stop
) -> std::expected<void, std::string> {
#if defined(SO_NOSIGPIPE)
    constexpr int enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return std::unexpected(system_error("configure wallet status socket"));
    }
#endif
    if (frame.empty() || frame.size() > max_wallet_status_frame_bytes ||
        frame.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"wallet status frame exceeds its 64-KiB bound"});
    }
    const auto length = static_cast<std::uint32_t>(frame.size());
    const std::array<unsigned char, 4> header{
        static_cast<unsigned char>((length >> 24U) & 0xffU),
        static_cast<unsigned char>((length >> 16U) & 0xffU),
        static_cast<unsigned char>((length >> 8U) & 0xffU),
        static_cast<unsigned char>(length & 0xffU),
    };
    if (auto wrote = write_exact(descriptor, header, deadline, stop); !wrote) {
        return std::unexpected(wrote.error());
    }
    return write_exact(
        descriptor,
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(frame.data()), frame.size()
        },
        deadline,
        stop
    );
}

} // namespace glove::control
