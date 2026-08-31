#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>

namespace glove::control {

enum class guest_channel_transport_error_code : std::uint8_t {
    invalid_descriptor,
    invalid_socket,
    peer_identity,
    invalid_frame,
    frame_too_large,
    deadline_exceeded,
    cancelled,
    disconnected,
    io,
};

struct guest_channel_transport_error {
    guest_channel_transport_error_code code = guest_channel_transport_error_code::io;
    std::string message;
};

template<typename Value>
using guest_channel_transport_result = std::expected<Value, guest_channel_transport_error>;

using guest_channel_deadline = std::chrono::steady_clock::time_point;

// Owns one connected AF_UNIX/SOCK_STREAM endpoint and only performs bounded
// framed I/O. adopt() takes ownership of descriptor on every path, verifies the
// peer uid, and makes the endpoint nonblocking and close-on-exec. All frame
// operations use one caller-supplied absolute steady-clock deadline.
//
// Instances are single-thread confined. The owning worker must stop and join
// before destruction; destruction is the only endpoint shutdown/close path.
class guest_channel_transport final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class guest_channel_transport;
    };

    guest_channel_transport(construction_token, std::unique_ptr<implementation> state);
    guest_channel_transport(const guest_channel_transport&) = delete;
    auto operator=(const guest_channel_transport&) -> guest_channel_transport& = delete;
    guest_channel_transport(guest_channel_transport&&) = delete;
    auto operator=(guest_channel_transport&&) -> guest_channel_transport& = delete;
    ~guest_channel_transport();

    [[nodiscard]] static auto
    adopt(int descriptor, std::size_t max_frame_bytes, std::uint32_t expected_peer_uid)
        -> guest_channel_transport_result<std::unique_ptr<guest_channel_transport>>;

    [[nodiscard]] auto receive_frame(guest_channel_deadline deadline, std::stop_token stop = {})
        -> guest_channel_transport_result<std::string>;
    [[nodiscard]] auto
    send_frame(std::string_view payload, guest_channel_deadline deadline, std::stop_token stop = {})
        -> guest_channel_transport_result<void>;

private:
    void shutdown_and_reset() noexcept;

    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
