#pragma once

#include <chrono>
#include <cstddef>
#include <expected>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

namespace glove::net {

// A connected, ordered byte stream to one upstream. Every call takes the
// caller's stop token and absolute deadline so a stalled peer cannot hold the
// endpoint's single worker past either; the HTTP client above it never sees
// whether the bytes travel over TLS or (under test) a plain socket.
class byte_stream {
public:
    using deadline = std::chrono::steady_clock::time_point;

    byte_stream() = default;
    byte_stream(const byte_stream&) = delete;
    byte_stream& operator=(const byte_stream&) = delete;
    byte_stream(byte_stream&&) = delete;
    byte_stream& operator=(byte_stream&&) = delete;
    virtual ~byte_stream() = default;

    [[nodiscard]] virtual auto
    write_all(std::string_view data, std::stop_token stop, deadline until)
        -> std::expected<void, std::string> = 0;
    // Returns the number of bytes placed in `into`; zero means the peer closed
    // the stream cleanly.
    [[nodiscard]] virtual auto read_some(std::span<char> into, std::stop_token stop, deadline until)
        -> std::expected<std::size_t, std::string> = 0;
};

} // namespace glove::net
