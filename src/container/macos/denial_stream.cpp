#include "denial_stream.hpp"

#include "darwin_process_group.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace glove::container::macos_detail {

namespace {

constexpr std::size_t max_canaries_per_proof = 64;
constexpr int stop_poll_interval_ms = 10;
constexpr int drain_polls = 100; // ~1 s at stop_poll_interval_ms.
constexpr std::size_t nonce_bytes = 16;

// The kernel provenance check is repeated in the parser; the predicate only
// drops forged and unrelated records at the source.
const std::vector<std::string>& default_argv() {
    static const std::vector<std::string> argv{
        "/usr/bin/log",
        "stream",
        "--style",
        "ndjson",
        "--predicate",
        R"(processID == 0 AND senderImagePath ENDSWITH "/Sandbox" AND eventMessage CONTAINS "deny(")",
    };
    return argv;
}

constexpr std::string_view canary_profile =
    R"((version 1)(deny default)(import "system.sb")(allow process-exec*)(allow file-read* (subpath "/usr") (subpath "/System")))";
constexpr std::string_view canary_path_prefix = "/private/tmp/glove-denial-canary-";

auto errno_text(std::string_view what, int error) -> std::string {
    return std::string{what} + ": errno " + std::to_string(error);
}

void sleep_ms(int milliseconds) noexcept {
    struct timespec delay{};
    delay.tv_sec = milliseconds / 1000;
    delay.tv_nsec = static_cast<long>(milliseconds % 1000) * 1'000'000L;
    (void)::nanosleep(&delay, nullptr);
}

// Spawns argv with stdin and stderr on /dev/null and stdout on stdout_fd (or
// /dev/null when negative). Only descriptors named here are inherited.
auto spawn_child(const std::vector<std::string>& argv, int stdout_fd, bool own_group)
    -> std::expected<::pid_t, int> {
    ::posix_spawn_file_actions_t actions{};
    if (const int rc = ::posix_spawn_file_actions_init(&actions); rc != 0) {
        return std::unexpected(rc);
    }
    ::posix_spawnattr_t attr{};
    if (const int rc = ::posix_spawnattr_init(&attr); rc != 0) {
        ::posix_spawn_file_actions_destroy(&actions);
        return std::unexpected(rc);
    }
    int rc = ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (rc == 0) {
        rc = stdout_fd >= 0 ? ::posix_spawn_file_actions_adddup2(&actions, stdout_fd, STDOUT_FILENO)
                            : ::posix_spawn_file_actions_addopen(
                                  &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0
                              );
    }
    if (rc == 0) {
        rc = ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    }
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT;
    if (own_group) {
        flags |= POSIX_SPAWN_SETPGROUP;
        if (rc == 0) {
            rc = ::posix_spawnattr_setpgroup(&attr, 0);
        }
    }
    if (rc == 0) {
        rc = ::posix_spawnattr_setflags(&attr, flags);
    }
    ::pid_t pid = -1;
    if (rc == 0) {
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const auto& arg : argv) {
            args.push_back(
                const_cast<char*>(arg.c_str())
            ); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        }
        args.push_back(nullptr);
        std::string path_entry = "PATH=/usr/bin:/bin";
        std::array<char*, 2> env{path_entry.data(), nullptr};
        rc = ::posix_spawn(&pid, argv.front().c_str(), &actions, &attr, args.data(), env.data());
    }
    ::posix_spawn_file_actions_destroy(&actions);
    ::posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        return std::unexpected(rc);
    }
    return pid;
}

// The child's exit, observed without consuming it: the zombie keeps pinning
// the PID (and PGID) until the caller reaps.
auto exited_unreaped(::pid_t pid) noexcept -> bool {
    siginfo_t information{};
    int rc = -1;
    do {
        rc = ::waitid(P_PID, static_cast<id_t>(pid), &information, WEXITED | WNOWAIT | WNOHANG);
    } while (rc < 0 && errno == EINTR);
    return rc == 0 && information.si_pid == pid;
}

void reap(::pid_t pid) noexcept {
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

auto make_nonce() -> std::string {
    std::array<unsigned char, nonce_bytes> bytes{};
    ::arc4random_buf(bytes.data(), bytes.size());
    constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char byte : bytes) {
        out.push_back(hex.at(byte >> 4U));
        out.push_back(hex.at(byte & 0x0FU));
    }
    return out;
}

struct canary {
    ::pid_t pid = -1;
    std::string nonce;
};

} // namespace

struct denial_stream::implementation {
    denial_stream_options options;
    ::pid_t child = -1;
    bool child_owned = false;
    int read_fd = -1;

    std::atomic<denial_stream_state> current{denial_stream_state::starting};
    std::atomic<std::uint64_t> lines{0};
    std::atomic<std::uint64_t> events{0};
    std::atomic<std::uint64_t> oversized_lines{0};
    std::atomic<std::uint64_t> rejected_not_json{0};
    std::atomic<std::uint64_t> rejected_provenance{0};
    std::atomic<std::uint64_t> rejected_not_a_denial{0};
    std::atomic<std::uint64_t> rejected_timestamp{0};

    std::mutex canary_mutex;
    std::condition_variable canary_seen;
    std::vector<canary> pending;
    bool canary_observed = false;

    std::jthread reader;

    // The only transition into degraded; a degraded or stopped stream never
    // changes state again, so on_degraded runs at most once.
    void degrade(std::string_view reason) {
        auto expected = current.load();
        while (expected == denial_stream_state::starting || expected == denial_stream_state::live) {
            if (current.compare_exchange_weak(expected, denial_stream_state::degraded)) {
                {
                    const std::lock_guard lock{canary_mutex};
                }
                canary_seen.notify_all();
                if (options.on_degraded) {
                    try {
                        options.on_degraded(reason);
                    } catch (...) { // NOLINT(bugprone-empty-catch): already degraded.
                    }
                }
                return;
            }
        }
    }

    void match_canary(const detail::denial_event& event) {
        if (event.readings.size() != 1) {
            return;
        }
        const auto& reading = event.readings.front();
        if (reading.kind != detail::denial_class::file_write) {
            return;
        }
        const std::lock_guard lock{canary_mutex};
        for (const auto& candidate : pending) {
            if (reading.pid == candidate.pid && reading.target.ends_with(candidate.nonce)) {
                canary_observed = true;
                canary_seen.notify_all();
                return;
            }
        }
    }

    // False stops the reader: the callback failed and the stream degraded.
    auto handle_line(std::string_view line) -> bool {
        lines.fetch_add(1, std::memory_order_relaxed);
        auto parsed = detail::parse_denial_line(line);
        if (!parsed) {
            switch (parsed.error()) {
            case detail::denial_parse_error::oversized:
                oversized_lines.fetch_add(1, std::memory_order_relaxed);
                break;
            case detail::denial_parse_error::not_json:
                rejected_not_json.fetch_add(1, std::memory_order_relaxed);
                break;
            case detail::denial_parse_error::wrong_provenance:
                rejected_provenance.fetch_add(1, std::memory_order_relaxed);
                break;
            case detail::denial_parse_error::not_a_denial:
                rejected_not_a_denial.fetch_add(1, std::memory_order_relaxed);
                break;
            case detail::denial_parse_error::bad_timestamp:
                rejected_timestamp.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            return true;
        }
        events.fetch_add(1, std::memory_order_relaxed);
        match_canary(*parsed);
        if (options.on_event) {
            try {
                options.on_event(*parsed);
            } catch (...) {
                degrade("denial callback failed");
                return false;
            }
        }
        return true;
    }

    // Lines are assembled in a buffer bounded by max_denial_line_bytes; a
    // longer line is counted once and skipped through its newline.
    void read_loop(const std::stop_token& stop) {
        std::string line;
        line.reserve(detail::max_denial_line_bytes);
        bool discarding = false;
        std::array<char, denial_stream_read_chunk_bytes> chunk{};
        while (!stop.stop_requested()) {
            struct pollfd ready{.fd = read_fd, .events = POLLIN, .revents = 0};
            const int polled = ::poll(&ready, 1, denial_stream_poll_ms);
            if (polled < 0) {
                if (errno == EINTR) {
                    continue;
                }
                degrade(errno_text("log stream read", errno));
                return;
            }
            if (polled == 0) {
                continue;
            }
            const ::ssize_t got = ::read(read_fd, chunk.data(), chunk.size());
            if (got < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                if (!stop.stop_requested()) {
                    degrade(errno_text("log stream read", errno));
                }
                return;
            }
            if (got == 0) {
                if (!stop.stop_requested()) {
                    degrade("log stream ended");
                }
                return;
            }
            std::string_view bytes{chunk.data(), static_cast<std::size_t>(got)};
            while (!bytes.empty()) {
                const auto newline = bytes.find('\n');
                const auto piece = bytes.substr(0, newline);
                if (!discarding) {
                    if (line.size() + piece.size() > detail::max_denial_line_bytes) {
                        oversized_lines.fetch_add(1, std::memory_order_relaxed);
                        discarding = true;
                        line.clear();
                    } else {
                        line.append(piece);
                    }
                }
                if (newline == std::string_view::npos) {
                    break;
                }
                if (!discarding && !handle_line(line)) {
                    return;
                }
                line.clear();
                discarding = false;
                bytes.remove_prefix(newline + 1);
            }
        }
    }

    // Signals only while the child is unreaped; nothing after the reap.
    void stop_child() noexcept {
        if (!child_owned) {
            return;
        }
        (void)::kill(-child, SIGTERM);
        (void)::kill(child, SIGTERM);
        bool exited = false;
        for (int waited = 0; waited < denial_stream_stop_grace_ms;
             waited += stop_poll_interval_ms) {
            if (exited_unreaped(child)) {
                exited = true;
                break;
            }
            sleep_ms(stop_poll_interval_ms);
        }
        if (!exited) {
            (void)::kill(-child, SIGKILL);
            (void)::kill(child, SIGKILL);
        }
        // The leader's zombie pins the PGID: kill stragglers until the group
        // is proven empty or the bounded drain ends.
        for (int poll = 0; poll < drain_polls; ++poll) {
            if (!exited_unreaped(child)) {
                sleep_ms(stop_poll_interval_ms);
                continue;
            }
            const auto live = group_has_live_members(child);
            if (live && !*live) {
                break;
            }
            (void)::kill(-child, SIGKILL);
            sleep_ms(stop_poll_interval_ms);
        }
        reap(child);
        child_owned = false;
    }

    auto spawn_canary() -> std::expected<canary, int> {
        std::string nonce = make_nonce();
        const std::vector<std::string> argv{
            "/usr/bin/sandbox-exec",
            "-p",
            std::string{canary_profile},
            "/usr/bin/touch",
            std::string{canary_path_prefix} + nonce,
        };
        auto pid = spawn_child(argv, -1, false);
        if (!pid) {
            return std::unexpected(pid.error());
        }
        return canary{.pid = *pid, .nonce = std::move(nonce)};
    }
};

denial_stream::denial_stream(std::unique_ptr<implementation> impl) noexcept
    : impl_{std::move(impl)} {}

denial_stream::~denial_stream() {
    try {
        impl_->reader.request_stop();
        impl_->stop_child();
        if (impl_->reader.joinable()) {
            impl_->reader.join();
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): a destructor cannot report.
    }
    if (impl_->read_fd >= 0) {
        ::close(impl_->read_fd);
        impl_->read_fd = -1;
    }
    impl_->current.store(denial_stream_state::stopped);
}

auto denial_stream::start(denial_stream_options options)
    -> std::expected<std::unique_ptr<denial_stream>, std::string> {
    if (options.argv.empty()) {
        options.argv = default_argv();
    }
    if (!options.argv.front().starts_with('/')) {
        return std::unexpected(std::string{"denial stream: argv[0] must be an absolute path"});
    }
    std::array<int, 2> pipe_fds{-1, -1};
    if (::pipe(pipe_fds.data()) != 0) {
        return std::unexpected(errno_text("denial stream pipe", errno));
    }
    for (const int fd : pipe_fds) {
        if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            const int error = errno;
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
            return std::unexpected(errno_text("denial stream pipe", error));
        }
    }
    auto pid = spawn_child(options.argv, pipe_fds[1], true);
    ::close(pipe_fds[1]);
    if (!pid) {
        ::close(pipe_fds[0]);
        return std::unexpected(errno_text("denial stream spawn", pid.error()));
    }
    auto impl = std::make_unique<implementation>();
    impl->options = std::move(options);
    impl->child = *pid;
    impl->child_owned = true;
    impl->read_fd = pipe_fds[0];
    // Owned before the reader exists, so a failure below still stops the child.
    auto stream = std::unique_ptr<denial_stream>(new denial_stream(std::move(impl)));
    implementation* const state = stream->impl_.get();
    stream->impl_->reader = std::jthread{[state](const std::stop_token& stop) {
        try {
            state->read_loop(stop);
        } catch (...) {
            state->degrade("denial stream reader failed");
        }
    }};
    return stream;
}

auto denial_stream::state() const noexcept -> denial_stream_state {
    return impl_->current.load();
}

auto denial_stream::counters() const noexcept -> denial_stream_counters {
    return {
        .lines = impl_->lines.load(),
        .events = impl_->events.load(),
        .oversized_lines = impl_->oversized_lines.load(),
        .rejected_not_json = impl_->rejected_not_json.load(),
        .rejected_provenance = impl_->rejected_provenance.load(),
        .rejected_not_a_denial = impl_->rejected_not_a_denial.load(),
        .rejected_timestamp = impl_->rejected_timestamp.load(),
    };
}

auto denial_stream::child_pid_for_test() const noexcept -> ::pid_t {
    return impl_->child;
}

auto denial_stream::prove_live(std::chrono::milliseconds timeout)
    -> std::expected<void, std::string> {
    auto& self = *impl_;
    const auto inactive = [&self] {
        const auto now = self.current.load();
        return now == denial_stream_state::degraded || now == denial_stream_state::stopped;
    };
    if (inactive()) {
        return std::unexpected(std::string{"denial stream is not running"});
    }
    {
        const std::lock_guard lock{self.canary_mutex};
        self.canary_observed = false;
        self.pending.clear();
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<::pid_t> spawned;
    std::string failure;
    bool observed = false;
    for (;;) {
        if (spawned.size() < max_canaries_per_proof) {
            auto next = self.spawn_canary();
            if (!next) {
                failure = errno_text("denial canary spawn", next.error());
                break;
            }
            spawned.push_back(next->pid);
            const std::lock_guard lock{self.canary_mutex};
            self.pending.push_back(std::move(*next));
        }
        const auto wake = std::min(
            deadline,
            std::chrono::steady_clock::now() + std::chrono::milliseconds{denial_canary_interval_ms}
        );
        {
            std::unique_lock lock{self.canary_mutex};
            self.canary_seen.wait_until(lock, wake, [&] {
                return self.canary_observed || inactive();
            });
            observed = self.canary_observed;
        }
        if (observed || inactive() || std::chrono::steady_clock::now() >= deadline) {
            break;
        }
    }
    {
        const std::lock_guard lock{self.canary_mutex};
        self.pending.clear();
    }
    // Every canary is still unreaped here, so these pids are still ours.
    for (const ::pid_t pid : spawned) {
        (void)::kill(pid, SIGKILL);
        reap(pid);
    }
    if (observed) {
        auto expected = denial_stream_state::starting;
        (void)self.current.compare_exchange_strong(expected, denial_stream_state::live);
        if (self.current.load() == denial_stream_state::live) {
            return {};
        }
    }
    if (!failure.empty()) {
        return std::unexpected(std::move(failure));
    }
    if (inactive()) {
        return std::unexpected(std::string{"denial stream degraded"});
    }
    return std::unexpected(std::string{"denial canary not observed"});
}

} // namespace glove::container::macos_detail
