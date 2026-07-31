#pragma once

#include "glove/container/refinement_protocol.hpp"

#include "../resource_monitor.hpp"
#include "../sha256.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace glove::container::linux_detail {

class pty_pair {
public:
    pty_pair() = default;
    pty_pair(const pty_pair&) = delete;
    auto operator=(const pty_pair&) -> pty_pair& = delete;
    pty_pair(pty_pair&& other) noexcept;
    auto operator=(pty_pair&&) -> pty_pair& = delete;
    ~pty_pair();

    [[nodiscard]] auto master_fd() const noexcept -> int { return master_fd_; }

    [[nodiscard]] auto slave_fd() const noexcept -> int { return slave_fd_; }

    [[nodiscard]] auto release_master() noexcept -> int;
    [[nodiscard]] auto release_slave() noexcept -> int;
    void close_slave() noexcept;

private:
    friend auto open_pty_pair() -> std::expected<pty_pair, std::string>;

    pty_pair(int master_fd, int slave_fd) noexcept;
    void close() noexcept;

    int master_fd_ = -1;
    int slave_fd_ = -1;
};

[[nodiscard]] auto open_pty_pair() -> std::expected<pty_pair, std::string>;

struct pty_session_channel_options {
    int master_fd = -1;
    std::size_t transcript_bytes = std::size_t{4} * 1024U * 1024U;
    std::size_t max_read_bytes = std::size_t{64} * 1024U;
    std::size_t max_input_frame_bytes = std::size_t{64} * 1024U;
    std::uint64_t input_timeout_ms = 1'000;
    std::shared_ptr<detail::wall_output_monitor> monitor;
};

struct pty_transcript_read {
    std::uint64_t oldest_cursor = 0;
    std::uint64_t next_cursor = 0;
    bool truncated = false;
    bool eof = false;
    std::string bytes;

    auto operator==(const pty_transcript_read&) const -> bool = default;
};

enum class pty_session_signal : std::uint8_t {
    interrupt,
    terminate,
    hangup,
};

// Owns one PTY master and continuously drains it into a fixed-capacity circular
// transcript. Attach/detach is represented only by cursors; no client can stop
// draining or force an unbounded backlog. All child output is still charged to
// the shared lifecycle monitor even when old transcript bytes are evicted.
class pty_session_channel {
    struct construction_token {};

    enum class error_code : std::uint8_t {
        none,
        stopped,
        poll_failed,
        read_failed,
        output_limit,
        cursor_overflow,
        transcript_digest,
        worker_failure,
    };

public:
    pty_session_channel(const pty_session_channel&) = delete;
    auto operator=(const pty_session_channel&) -> pty_session_channel& = delete;
    pty_session_channel(pty_session_channel&&) = delete;
    auto operator=(pty_session_channel&&) -> pty_session_channel& = delete;
    ~pty_session_channel();

    [[nodiscard]] static auto create(pty_session_channel_options options)
        -> std::expected<std::unique_ptr<pty_session_channel>, std::string>;

    [[nodiscard]] auto read(std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<pty_transcript_read, std::string>;
    [[nodiscard]] auto
    wait_read(std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms)
        -> std::expected<pty_transcript_read, std::string>;
    [[nodiscard]] auto write_input(std::string_view bytes) -> std::expected<void, std::string>;
    [[nodiscard]] auto resize(std::uint16_t rows, std::uint16_t columns)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto signal(pty_session_signal requested) -> std::expected<void, std::string>;
    [[nodiscard]] auto finish_draining() -> std::expected<void, std::string>;
    [[nodiscard]] auto transcript_commitment() const
        -> std::expected<raw_pty_transcript_commitment, std::string>;
    void stop() noexcept;

private:
    pty_session_channel(
        [[maybe_unused]] construction_token token,
        pty_session_channel_options options,
        int wake_read_fd,
        int wake_write_fd,
        std::vector<char> transcript
    );

    void worker_loop() noexcept;
    void drain_loop();
    void append_output(std::string_view bytes);
    [[nodiscard]] auto read_locked(std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<pty_transcript_read, std::string>;
    [[nodiscard]] auto ready_locked(std::uint64_t cursor) const noexcept -> bool;
    void set_error_locked(error_code error, int system_error = 0) noexcept;
    [[nodiscard]] auto error_message_locked() const -> std::string;
    void signal_worker() const noexcept;
    void close_descriptors() noexcept;

    int master_fd_ = -1;
    int wake_read_fd_ = -1;
    int wake_write_fd_ = -1;
    std::size_t max_read_bytes_ = 0;
    std::size_t max_input_frame_bytes_ = 0;
    std::uint64_t input_timeout_ms_ = 0;
    std::shared_ptr<detail::wall_output_monitor> monitor_;

    mutable std::mutex state_mutex_;
    std::condition_variable state_changed_;
    std::vector<char> transcript_;
    std::size_t transcript_head_ = 0;
    std::size_t transcript_size_ = 0;
    std::uint64_t oldest_cursor_ = 0;
    std::uint64_t next_cursor_ = 0;
    detail::sha256_stream transcript_hash_;
    error_code error_ = error_code::none;
    int system_error_ = 0;
    bool eof_ = false;
    bool stop_requested_ = false;
    bool worker_done_ = false;

    std::mutex write_mutex_;
    std::mutex finish_mutex_;
    std::thread worker_;
};

} // namespace glove::container::linux_detail
