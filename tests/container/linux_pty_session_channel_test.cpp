#include "pty_session_channel.hpp"
#include "resource_monitor.hpp"

#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto write_all(int descriptor, std::string_view bytes) -> bool {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

auto read_exact(int descriptor, std::size_t count) -> std::string {
    std::string bytes(count, '\0');
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto received = ::read(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return {};
        }
        offset += static_cast<std::size_t>(received);
    }
    return bytes;
}

auto run() -> int {
    using glove::container::detail::wall_output_monitor;
    using glove::container::linux_detail::pty_session_channel;

    auto pair = glove::container::linux_detail::open_pty_pair();
    REQUIRE(pair.has_value());

    struct termios raw{};

    REQUIRE(::tcgetattr(pair->slave_fd(), &raw) == 0);
    ::cfmakeraw(&raw);
    REQUIRE(::tcsetattr(pair->slave_fd(), TCSANOW, &raw) == 0);

    std::atomic_uint termination_calls = 0;
    auto monitor =
        wall_output_monitor::create(30'000, 1'024, [&](auto) { termination_calls.fetch_add(1); });
    REQUIRE(monitor.has_value());
    auto channel = pty_session_channel::create({
        .master_fd = pair->release_master(),
        .transcript_bytes = 8,
        .max_read_bytes = 8,
        .max_input_frame_bytes = 4,
        .input_timeout_ms = 1'000,
        .monitor = *monitor,
        .refinement_evaluator = nullptr,
    });
    REQUIRE(channel.has_value());

    REQUIRE(write_all(pair->slave_fd(), "abcdefghijkl"));
    auto tail = (*channel)->wait_read(0, 8, 1'000);
    REQUIRE(tail.has_value());
    REQUIRE(tail->truncated);
    REQUIRE(tail->oldest_cursor == 4);
    REQUIRE(tail->next_cursor == 12);
    REQUIRE(tail->bytes == "efghijkl");
    REQUIRE(!tail->eof);
    auto caught_up = (*channel)->read(tail->next_cursor, 8);
    REQUIRE(caught_up.has_value());
    REQUIRE(caught_up->bytes.empty());
    REQUIRE(!caught_up->truncated);

    REQUIRE((*channel)->write_input("ping").has_value());
    REQUIRE(read_exact(pair->slave_fd(), 4) == "ping");
    REQUIRE(!(*channel)->write_input("oversized").has_value());

    REQUIRE((*channel)->resize(42, 120).has_value());

    struct winsize size{};

    REQUIRE(::ioctl(pair->slave_fd(), TIOCGWINSZ, &size) == 0);
    REQUIRE(size.ws_row == 42);
    REQUIRE(size.ws_col == 120);
    REQUIRE(!(*channel)->resize(0, 120).has_value());
    REQUIRE(!(*channel)->resize(42, 0).has_value());

    auto timed_out = (*channel)->wait_read(tail->next_cursor, 8, 1);
    REQUIRE(!timed_out.has_value());
    pair->close_slave();
    auto eof = (*channel)->wait_read(tail->next_cursor, 8, 1'000);
    REQUIRE(eof.has_value());
    REQUIRE(eof->bytes.empty());
    REQUIRE(eof->eof);
    REQUIRE((*channel)->finish_draining().has_value());
    auto transcript = (*channel)->transcript_commitment();
    REQUIRE(transcript.has_value());
    REQUIRE(transcript->schema == glove::container::raw_pty_transcript_schema);
    REQUIRE(transcript->byte_count == 12);
    REQUIRE(transcript->complete);
    REQUIRE(
        transcript->digest == "d682ed4ca4d989c134ec94f1551e1ec580dd6d5a6ecde9f3d35e6e4a717fbde4"
    );
    REQUIRE(termination_calls.load() == 0);

    auto quota_pair = glove::container::linux_detail::open_pty_pair();
    REQUIRE(quota_pair.has_value());
    REQUIRE(::tcgetattr(quota_pair->slave_fd(), &raw) == 0);
    ::cfmakeraw(&raw);
    REQUIRE(::tcsetattr(quota_pair->slave_fd(), TCSANOW, &raw) == 0);
    auto quota_monitor =
        wall_output_monitor::create(30'000, 4, [&](auto) { termination_calls.fetch_add(1); });
    REQUIRE(quota_monitor.has_value());
    auto quota_channel = pty_session_channel::create({
        .master_fd = quota_pair->release_master(),
        .transcript_bytes = 8,
        .max_read_bytes = 8,
        .max_input_frame_bytes = 4,
        .input_timeout_ms = 1'000,
        .monitor = *quota_monitor,
        .refinement_evaluator = nullptr,
    });
    REQUIRE(quota_channel.has_value());
    REQUIRE(write_all(quota_pair->slave_fd(), "12345"));
    auto limited = (*quota_channel)->wait_read(0, 8, 1'000);
    REQUIRE(!limited.has_value());
    REQUIRE((*quota_channel)->finish_draining().has_value());
    auto limited_transcript = (*quota_channel)->transcript_commitment();
    REQUIRE(limited_transcript.has_value());
    REQUIRE(limited_transcript->byte_count == 5);
    REQUIRE(!limited_transcript->complete);
    REQUIRE(
        limited_transcript->digest ==
        "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    );
    REQUIRE(termination_calls.load() == 1);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
