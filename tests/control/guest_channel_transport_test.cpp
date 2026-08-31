#include "glove/control/guest_channel_transport.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <thread>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::control::guest_channel_deadline;
using glove::control::guest_channel_transport;
using glove::control::guest_channel_transport_error_code;

template<typename Value>
concept has_public_close = requires(Value& value) { value.close(); };

template<typename Value>
concept has_public_exchange = requires { &Value::exchange; };

static_assert(!has_public_close<guest_channel_transport>);
static_assert(!has_public_exchange<guest_channel_transport>);

class fd_pair {
public:
    fd_pair() { valid_ = ::socketpair(AF_UNIX, SOCK_STREAM, 0, values_) == 0; }

    fd_pair(const fd_pair&) = delete;
    auto operator=(const fd_pair&) -> fd_pair& = delete;

    ~fd_pair() {
        for (int& value : values_) {
            if (value >= 0) {
                static_cast<void>(::close(value));
            }
        }
    }

    [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }

    [[nodiscard]] auto get(std::size_t index) const noexcept -> int { return values_[index]; }

    [[nodiscard]] auto release(std::size_t index) noexcept -> int {
        const int value = values_[index];
        values_[index] = -1;
        return value;
    }

private:
    int values_[2]{-1, -1};
    bool valid_ = false;
};

auto deadline_after(std::chrono::milliseconds duration) -> guest_channel_deadline {
    return std::chrono::steady_clock::now() + duration;
}

auto write_bytes(int descriptor, const void* input, std::size_t size) -> bool {
    const auto* bytes = static_cast<const std::byte*>(input);
    std::size_t written = 0;
    while (written < size) {
#if defined(MSG_NOSIGNAL)
        const auto result = ::send(descriptor, bytes + written, size - written, MSG_NOSIGNAL);
#else
        const auto result = ::write(descriptor, bytes + written, size - written);
#endif
        if (result <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

auto adopt(fd_pair& pair, std::size_t maximum = 1024U)
    -> glove::control::guest_channel_transport_result<std::unique_ptr<guest_channel_transport>> {
    return guest_channel_transport::adopt(pair.release(0), maximum, ::geteuid());
}

auto run() -> int {
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto channel = adopt(pair);
        REQUIRE(channel.has_value());
        const std::string request = "request";
        const auto length = htonl(static_cast<std::uint32_t>(request.size()));
        REQUIRE(write_bytes(pair.get(1), &length, sizeof(length)));
        REQUIRE(write_bytes(pair.get(1), request.data(), request.size()));
        auto received = (*channel)->receive_frame(deadline_after(std::chrono::seconds{1}));
        REQUIRE(received == request);
        REQUIRE((*channel)->send_frame("response", deadline_after(std::chrono::seconds{1})));
    }

    // Identity is checked before a byte is consumed, and failed adoption closes ownership.
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto rejected = guest_channel_transport::adopt(pair.release(0), 1024U, ::geteuid() + 1U);
        REQUIRE(!rejected.has_value());
        REQUIRE(rejected.error().code == guest_channel_transport_error_code::peer_identity);
        char byte = 0;
        REQUIRE(::read(pair.get(1), &byte, sizeof(byte)) == 0);
    }

    // Successful partial reads do not renew the single absolute deadline.
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto channel = adopt(pair);
        REQUIRE(channel.has_value());
        const auto declared = htonl(8U);
        std::jthread trickle{[descriptor = pair.get(1), declared] {
            const auto* bytes = reinterpret_cast<const std::byte*>(&declared);
            for (std::size_t index = 0; index < sizeof(declared); ++index) {
                static_cast<void>(write_bytes(descriptor, bytes + index, 1U));
                std::this_thread::sleep_for(std::chrono::milliseconds{30});
            }
        }};
        const auto started = std::chrono::steady_clock::now();
        auto received = (*channel)->receive_frame(deadline_after(std::chrono::milliseconds{55}));
        const auto elapsed = std::chrono::steady_clock::now() - started;
        REQUIRE(!received.has_value());
        REQUIRE(received.error().code == guest_channel_transport_error_code::deadline_exceeded);
        REQUIRE(elapsed < std::chrono::milliseconds{150});
    }

    // Cancellation interrupts partial header and body reads within a fixed bound.
    for (const bool partial_body : {false, true}) {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto channel = adopt(pair);
        REQUIRE(channel.has_value());
        if (partial_body) {
            const auto declared = htonl(64U);
            REQUIRE(write_bytes(pair.get(1), &declared, sizeof(declared)));
            REQUIRE(write_bytes(pair.get(1), "x", 1U));
        } else {
            const auto declared = htonl(64U);
            REQUIRE(write_bytes(pair.get(1), &declared, 1U));
        }
        std::atomic<int> result{-1};
        const auto started = std::chrono::steady_clock::now();
        std::jthread reader{[&](std::stop_token stop) {
            auto received =
                (*channel)->receive_frame(deadline_after(std::chrono::seconds{5}), stop);
            result.store(
                received ? 0 : static_cast<int>(received.error().code), std::memory_order_release
            );
        }};
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        reader.request_stop();
        reader.join();
        REQUIRE(
            result.load(std::memory_order_acquire) ==
            static_cast<int>(guest_channel_transport_error_code::cancelled)
        );
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::milliseconds{200});
    }

    // Response cancellation and peer disconnects have distinct typed failures.
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto channel = adopt(pair);
        REQUIRE(channel.has_value());
        std::stop_source stopped;
        stopped.request_stop();
        auto cancelled = (*channel)->send_frame(
            "response", deadline_after(std::chrono::seconds{1}), stopped.get_token()
        );
        REQUIRE(!cancelled.has_value());
        REQUIRE(cancelled.error().code == guest_channel_transport_error_code::cancelled);

        REQUIRE(::close(pair.release(1)) == 0);
        auto disconnected =
            (*channel)->send_frame("response", deadline_after(std::chrono::seconds{1}));
        REQUIRE(!disconnected.has_value());
        REQUIRE(disconnected.error().code == guest_channel_transport_error_code::disconnected);
    }

    // A peer that does not drain a response cannot stall beyond the deadline.
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        int receive_buffer = 1024;
        REQUIRE(
            ::setsockopt(
                pair.get(1), SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)
            ) == 0
        );
        auto channel = adopt(pair, 1024U * 1024U);
        REQUIRE(channel.has_value());
        const std::string response(1024U * 1024U, 'r');
        const auto started = std::chrono::steady_clock::now();
        auto sent = (*channel)->send_frame(response, deadline_after(std::chrono::milliseconds{40}));
        REQUIRE(!sent.has_value());
        REQUIRE(sent.error().code == guest_channel_transport_error_code::deadline_exceeded);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::milliseconds{200});
    }

    // Destruction shuts down and closes the endpoint deterministically.
    {
        fd_pair pair;
        REQUIRE(pair.valid());
        auto channel = adopt(pair);
        REQUIRE(channel.has_value());
        const auto started = std::chrono::steady_clock::now();
        channel->reset();
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::milliseconds{100});
        char byte = 0;
        REQUIRE(::read(pair.get(1), &byte, sizeof(byte)) == 0);
    }
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
