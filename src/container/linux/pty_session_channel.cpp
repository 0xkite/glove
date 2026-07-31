#include "pty_session_channel.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <system_error>
#include <utility>

namespace glove::container::linux_detail {

namespace {

constexpr std::size_t max_transcript_bytes = std::size_t{16} * 1024U * 1024U;
constexpr std::size_t max_io_frame_bytes = std::size_t{1024} * 1024U;
constexpr std::uint64_t max_io_timeout_ms = 30'000;
constexpr std::uint16_t max_terminal_dimension = 4'096;
constexpr std::size_t read_chunk_bytes = 4'096;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

    void reset() noexcept {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
            descriptor_ = -1;
        }
    }

private:
    int descriptor_ = -1;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto add_flags(int descriptor, int get_command, int flags) -> bool {
    const int current = ::fcntl(descriptor, get_command);
    if (current < 0) {
        return false;
    }
    const int set_command = get_command == F_GETFD ? F_SETFD : F_SETFL;
    return ::fcntl(descriptor, set_command, current | flags) == 0;
}

auto make_wake_pipe() -> std::expected<std::array<unique_fd, 2>, std::string> {
    std::array<int, 2> descriptors = {-1, -1};
#if defined(__linux__)
    if (::pipe2(descriptors.data(), O_CLOEXEC | O_NONBLOCK) != 0) {
        return std::unexpected(error_message("create PTY channel wake pipe"));
    }
#else
    if (::pipe(descriptors.data()) != 0) {
        return std::unexpected(error_message("create PTY channel wake pipe"));
    }
    if (!add_flags(descriptors[0], F_GETFD, FD_CLOEXEC) ||
        !add_flags(descriptors[1], F_GETFD, FD_CLOEXEC) ||
        !add_flags(descriptors[0], F_GETFL, O_NONBLOCK) ||
        !add_flags(descriptors[1], F_GETFL, O_NONBLOCK)) {
        const int saved = errno;
        static_cast<void>(::close(descriptors[0]));
        static_cast<void>(::close(descriptors[1]));
        return std::unexpected(error_message("configure PTY channel wake pipe", saved));
    }
#endif
    return std::array<unique_fd, 2>{unique_fd{descriptors[0]}, unique_fd{descriptors[1]}};
}

} // namespace

pty_pair::pty_pair(int master_fd, int slave_fd) noexcept
    : master_fd_{master_fd}, slave_fd_{slave_fd} {}

pty_pair::pty_pair(pty_pair&& other) noexcept
    : master_fd_{std::exchange(other.master_fd_, -1)},
      slave_fd_{std::exchange(other.slave_fd_, -1)} {}

pty_pair::~pty_pair() {
    close();
}

auto pty_pair::release_master() noexcept -> int {
    return std::exchange(master_fd_, -1);
}

auto pty_pair::release_slave() noexcept -> int {
    return std::exchange(slave_fd_, -1);
}

void pty_pair::close_slave() noexcept {
    if (slave_fd_ >= 0) {
        static_cast<void>(::close(slave_fd_));
        slave_fd_ = -1;
    }
}

void pty_pair::close() noexcept {
    if (master_fd_ >= 0) {
        static_cast<void>(::close(master_fd_));
        master_fd_ = -1;
    }
    close_slave();
}

auto open_pty_pair() -> std::expected<pty_pair, std::string> {
    unique_fd master{::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK)};
    if (master.get() < 0) {
        return std::unexpected(error_message("open PTY master"));
    }
    if (::grantpt(master.get()) != 0 || ::unlockpt(master.get()) != 0) {
        return std::unexpected(error_message("prepare PTY slave"));
    }
    std::array<char, 256> slave_name{};
#if defined(__APPLE__)
    const char* resolved_slave = ::ptsname(master.get());
    if (resolved_slave == nullptr || std::strlen(resolved_slave) >= slave_name.size()) {
        return std::unexpected(error_message("resolve PTY slave"));
    }
    std::memcpy(slave_name.data(), resolved_slave, std::strlen(resolved_slave) + 1U);
#else
    const int name_result = ::ptsname_r(master.get(), slave_name.data(), slave_name.size());
    if (name_result != 0) {
        return std::unexpected(error_message("resolve PTY slave", name_result));
    }
#endif
    unique_fd slave{::open(slave_name.data(), O_RDWR | O_NOCTTY | O_CLOEXEC)};
    if (slave.get() < 0) {
        return std::unexpected(error_message("open PTY slave"));
    }
    return pty_pair{master.release(), slave.release()};
}

pty_session_channel::pty_session_channel(
    [[maybe_unused]] construction_token token,
    pty_session_channel_options options,
    int wake_read_fd,
    int wake_write_fd,
    std::vector<char> transcript
)
    : master_fd_{options.master_fd},
      wake_read_fd_{wake_read_fd},
      wake_write_fd_{wake_write_fd},
      max_read_bytes_{options.max_read_bytes},
      max_input_frame_bytes_{options.max_input_frame_bytes},
      input_timeout_ms_{options.input_timeout_ms},
      monitor_{std::move(options.monitor)},
      refinement_evaluator_{std::move(options.refinement_evaluator)},
      transcript_{std::move(transcript)} {}

pty_session_channel::~pty_session_channel() {
    stop();
}

auto pty_session_channel::create(pty_session_channel_options options)
    -> std::expected<std::unique_ptr<pty_session_channel>, std::string> {
    if (options.master_fd < 0) {
        return std::unexpected(std::string{"invalid PTY session channel descriptor"});
    }
    unique_fd master{options.master_fd};
    if (options.transcript_bytes == 0 || options.transcript_bytes > max_transcript_bytes ||
        options.max_read_bytes == 0 || options.max_read_bytes > max_io_frame_bytes ||
        options.max_input_frame_bytes == 0 || options.max_input_frame_bytes > max_io_frame_bytes ||
        options.input_timeout_ms == 0 || options.input_timeout_ms > max_io_timeout_ms ||
        !options.monitor) {
        return std::unexpected(std::string{"invalid PTY session channel configuration"});
    }
    if (!add_flags(options.master_fd, F_GETFD, FD_CLOEXEC) ||
        !add_flags(options.master_fd, F_GETFL, O_NONBLOCK)) {
        return std::unexpected(error_message("configure PTY master"));
    }
    auto wake_pipe = make_wake_pipe();
    if (!wake_pipe) {
        return std::unexpected(wake_pipe.error());
    }
    try {
        std::vector<char> transcript(options.transcript_bytes);
        auto channel = std::unique_ptr<pty_session_channel>{new pty_session_channel{
            construction_token{},
            options,
            (*wake_pipe)[0].get(),
            (*wake_pipe)[1].get(),
            std::move(transcript),
        }};
        static_cast<void>(master.release());
        static_cast<void>((*wake_pipe)[0].release());
        static_cast<void>((*wake_pipe)[1].release());
        channel->worker_ = std::thread{[owner = channel.get()] { owner->worker_loop(); }};
        return channel;
    } catch (const std::system_error& error) {
        return std::unexpected(std::string{"start PTY session worker: "} + error.what());
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate PTY session channel"});
    }
}

auto pty_session_channel::read(std::uint64_t cursor, std::size_t max_bytes) const
    -> std::expected<pty_transcript_read, std::string> {
    const std::lock_guard lock{state_mutex_};
    return read_locked(cursor, max_bytes);
}

auto pty_session_channel::wait_read(
    std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms
) -> std::expected<pty_transcript_read, std::string> {
    if (timeout_ms == 0 || timeout_ms > max_io_timeout_ms) {
        return std::unexpected(std::string{"invalid PTY transcript wait timeout"});
    }
    std::unique_lock lock{state_mutex_};
    if (!state_changed_.wait_for(lock, std::chrono::milliseconds{timeout_ms}, [&] {
            return ready_locked(cursor);
        })) {
        return std::unexpected(std::string{"PTY transcript read timed out"});
    }
    return read_locked(cursor, max_bytes);
}

auto pty_session_channel::read_locked(std::uint64_t cursor, std::size_t max_bytes) const
    -> std::expected<pty_transcript_read, std::string> {
    if (max_bytes == 0 || max_bytes > max_read_bytes_) {
        return std::unexpected(std::string{"invalid PTY transcript read bound"});
    }
    if (cursor > next_cursor_) {
        return std::unexpected(std::string{"PTY transcript cursor is ahead of the session"});
    }
    if (error_ != error_code::none) {
        return std::unexpected(error_message_locked());
    }
    const bool truncated = cursor < oldest_cursor_;
    const auto effective_cursor = std::max(cursor, oldest_cursor_);
    const auto available = next_cursor_ - effective_cursor;
    const auto count = std::min<std::uint64_t>(available, max_bytes);
    pty_transcript_read result{
        .oldest_cursor = oldest_cursor_,
        .next_cursor = effective_cursor + count,
        .truncated = truncated,
        .eof = eof_ && effective_cursor + count == next_cursor_,
        .bytes = {},
    };
    result.bytes.resize(static_cast<std::size_t>(count));
    if (count == 0) {
        return result;
    }
    const auto relative = static_cast<std::size_t>(effective_cursor - oldest_cursor_);
    const auto begin = (transcript_head_ + relative) % transcript_.size();
    const auto first = std::min(result.bytes.size(), transcript_.size() - begin);
    std::copy_n(transcript_.data() + begin, first, result.bytes.data());
    std::copy_n(transcript_.data(), result.bytes.size() - first, result.bytes.data() + first);
    return result;
}

auto pty_session_channel::ready_locked(std::uint64_t cursor) const noexcept -> bool {
    return cursor < oldest_cursor_ || cursor < next_cursor_ || eof_ || error_ != error_code::none ||
           stop_requested_ || worker_done_;
}

auto pty_session_channel::write_input(std::string_view bytes) -> std::expected<void, std::string> {
    if (bytes.empty() || bytes.size() > max_input_frame_bytes_) {
        return std::unexpected(std::string{"invalid PTY input frame"});
    }
    const std::lock_guard write_lock{write_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (eof_) {
            return std::unexpected(std::string{"PTY session reached EOF"});
        }
        if (stop_requested_ || error_ != error_code::none) {
            return std::unexpected(error_message_locked());
        }
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{input_timeout_ms_};
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::unexpected(std::string{"PTY input write timed out"});
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto timeout = std::max<std::int64_t>(1, remaining.count());
        ::pollfd descriptor{.fd = master_fd_, .events = POLLOUT, .revents = 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(timeout));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            return std::unexpected(error_message("poll PTY input"));
        }
        if (ready == 0) {
            continue;
        }
        const auto written = ::write(master_fd_, bytes.data() + offset, bytes.size() - offset);
        if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (written < 0) {
            return std::unexpected(error_message("write PTY input"));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto pty_session_channel::resize(std::uint16_t rows, std::uint16_t columns)
    -> std::expected<void, std::string> {
    if (rows == 0 || columns == 0 || rows > max_terminal_dimension ||
        columns > max_terminal_dimension) {
        return std::unexpected(std::string{"invalid PTY dimensions"});
    }
    const std::lock_guard write_lock{write_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (eof_) {
            return std::unexpected(std::string{"PTY session reached EOF"});
        }
        if (stop_requested_ || error_ != error_code::none) {
            return std::unexpected(error_message_locked());
        }
    }

    const struct winsize dimensions{
        .ws_row = rows,
        .ws_col = columns,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };

    if (::ioctl(master_fd_, TIOCSWINSZ, &dimensions) != 0) {
        return std::unexpected(error_message("resize PTY"));
    }
    return {};
}

auto pty_session_channel::signal(pty_session_signal requested) -> std::expected<void, std::string> {
    int signal_number = 0;
    switch (requested) {
    case pty_session_signal::interrupt:
        signal_number = SIGINT;
        break;
    case pty_session_signal::terminate:
        signal_number = SIGTERM;
        break;
    case pty_session_signal::hangup:
        signal_number = SIGHUP;
        break;
    }
    const std::lock_guard write_lock{write_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (eof_) {
            return std::unexpected(std::string{"PTY session reached EOF"});
        }
        if (stop_requested_ || error_ != error_code::none) {
            return std::unexpected(error_message_locked());
        }
    }
    ::pid_t foreground_group = -1;
    if (::ioctl(master_fd_, TIOCGPGRP, &foreground_group) != 0) {
        return std::unexpected(error_message("inspect PTY foreground process group"));
    }
    // Never permit a malformed or namespace-confused terminal identity to
    // target init, gloved's own group, or every process visible to gloved.
    if (foreground_group <= 1 || foreground_group == ::getpgrp()) {
        return std::unexpected(std::string{"invalid PTY foreground process group"});
    }
    if (::killpg(foreground_group, signal_number) != 0) {
        return std::unexpected(error_message("signal PTY foreground process group"));
    }
    return {};
}

auto pty_session_channel::finish_draining() -> std::expected<void, std::string> {
    const std::lock_guard finish_lock{finish_mutex_};
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    const std::lock_guard state_lock{state_mutex_};
    if (error_ == error_code::none || error_ == error_code::output_limit) {
        return {};
    }
    return std::unexpected(error_message_locked());
}

auto pty_session_channel::transcript_commitment() const
    -> std::expected<raw_pty_transcript_commitment, std::string> {
    const std::lock_guard lock{state_mutex_};
    auto digest = transcript_hash_.digest_hex();
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return raw_pty_transcript_commitment{
        .schema = std::string{raw_pty_transcript_schema},
        .digest = std::move(*digest),
        .byte_count = transcript_hash_.byte_count(),
        .complete = eof_ && worker_done_ && error_ == error_code::none,
    };
}

void pty_session_channel::stop() noexcept {
    const std::lock_guard finish_lock{finish_mutex_};
    {
        const std::lock_guard state_lock{state_mutex_};
        if (!stop_requested_) {
            stop_requested_ = true;
            if (error_ == error_code::none && !eof_) {
                error_ = error_code::stopped;
            }
            state_changed_.notify_all();
        }
    }
    signal_worker();
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    const std::lock_guard write_lock{write_mutex_};
    close_descriptors();
}

void pty_session_channel::worker_loop() noexcept {
    try {
        drain_loop();
    } catch (...) {
        {
            const std::lock_guard lock{state_mutex_};
            set_error_locked(error_code::worker_failure);
        }
        static_cast<void>(
            monitor_->request_termination(resource_termination_cause::supervisor_error)
        );
    }
    const std::lock_guard lock{state_mutex_};
    worker_done_ = true;
    state_changed_.notify_all();
}

void pty_session_channel::drain_loop() {
    for (;;) {
        std::array<::pollfd, 2> descriptors = {
            ::pollfd{.fd = wake_read_fd_, .events = POLLIN, .revents = 0},
            ::pollfd{.fd = master_fd_, .events = POLLIN, .revents = 0},
        };
        const int ready = ::poll(descriptors.data(), descriptors.size(), -1);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            const int saved = errno;
            {
                const std::lock_guard lock{state_mutex_};
                set_error_locked(error_code::poll_failed, saved);
            }
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::supervisor_error)
            );
            return;
        }
        if (descriptors[0].revents != 0) {
            std::array<char, 64> discarded{};
            while (::read(wake_read_fd_, discarded.data(), discarded.size()) > 0) {}
            const std::lock_guard lock{state_mutex_};
            if (stop_requested_) {
                return;
            }
        }
        if (descriptors[1].revents == 0) {
            continue;
        }
        std::array<char, read_chunk_bytes> bytes{};
        const auto count = ::read(master_fd_, bytes.data(), bytes.size());
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;
        }
        if (count == 0 || (count < 0 && errno == EIO)) {
            const std::lock_guard lock{state_mutex_};
            eof_ = true;
            state_changed_.notify_all();
            return;
        }
        if (count < 0) {
            const int saved = errno;
            {
                const std::lock_guard lock{state_mutex_};
                set_error_locked(error_code::read_failed, saved);
            }
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::supervisor_error)
            );
            return;
        }
        append_output(std::string_view{bytes.data(), static_cast<std::size_t>(count)});
        const std::lock_guard lock{state_mutex_};
        if (error_ != error_code::none) {
            return;
        }
    }
}

void pty_session_channel::append_output(std::string_view bytes) {
    const auto raw_bytes = std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()
    };
    if (refinement_evaluator_) {
        if (auto consumed = refinement_evaluator_->consume(raw_bytes); !consumed) {
            static_cast<void>(
                monitor_->request_termination(resource_termination_cause::supervisor_error)
            );
            const std::lock_guard lock{state_mutex_};
            set_error_locked(error_code::worker_failure);
            return;
        }
    }
    const bool within_output_limit = monitor_->account_terminal_output(bytes.size());
    const std::lock_guard lock{state_mutex_};
    if (auto hashed = transcript_hash_.update(raw_bytes); !hashed) {
        static_cast<void>(
            monitor_->request_termination(resource_termination_cause::supervisor_error)
        );
        set_error_locked(error_code::transcript_digest);
        return;
    }
    if (!within_output_limit) {
        set_error_locked(error_code::output_limit);
        return;
    }
    if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - next_cursor_) {
        static_cast<void>(
            monitor_->request_termination(resource_termination_cause::supervisor_error)
        );
        set_error_locked(error_code::cursor_overflow);
        return;
    }
    for (const char byte : bytes) {
        if (transcript_size_ == transcript_.size()) {
            transcript_head_ = (transcript_head_ + 1U) % transcript_.size();
            --transcript_size_;
            ++oldest_cursor_;
        }
        const auto tail = (transcript_head_ + transcript_size_) % transcript_.size();
        transcript_[tail] = byte;
        ++transcript_size_;
        ++next_cursor_;
    }
    state_changed_.notify_all();
}

void pty_session_channel::set_error_locked(error_code error, int system_error) noexcept {
    if (error_ == error_code::none) {
        error_ = error;
        system_error_ = system_error;
        state_changed_.notify_all();
    }
}

auto pty_session_channel::error_message_locked() const -> std::string {
    switch (error_) {
    case error_code::none:
        return std::string{"PTY channel has no data"};
    case error_code::stopped:
        return std::string{"PTY session channel stopped"};
    case error_code::poll_failed:
        return error_message("poll PTY output", system_error_);
    case error_code::read_failed:
        return error_message("read PTY output", system_error_);
    case error_code::output_limit:
        return std::string{"terminal output limit exceeded"};
    case error_code::cursor_overflow:
        return std::string{"PTY transcript cursor exhausted"};
    case error_code::transcript_digest:
        return std::string{"PTY transcript digest exhausted"};
    case error_code::worker_failure:
        return std::string{"PTY session worker failed"};
    }
    return std::string{"PTY session worker failed"};
}

void pty_session_channel::signal_worker() const noexcept {
    if (wake_write_fd_ < 0) {
        return;
    }
    constexpr char wake = '1';
    static_cast<void>(::write(wake_write_fd_, &wake, 1));
}

void pty_session_channel::close_descriptors() noexcept {
    for (int* descriptor : {&master_fd_, &wake_read_fd_, &wake_write_fd_}) {
        if (*descriptor >= 0) {
            static_cast<void>(::close(*descriptor));
            *descriptor = -1;
        }
    }
}

} // namespace glove::container::linux_detail
