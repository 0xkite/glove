// The supervised log-stream child: liveness only after an observed canary
// denial, measured canary latency, and degradation (never a hang) when the
// log exits, emits garbage, floods, ignores SIGTERM, or a callback throws.

#include "macos/denial_stream.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::detail::denial_class;
using glove::container::detail::denial_event;
using glove::container::macos_detail::denial_stream;
using glove::container::macos_detail::denial_stream_options;
using glove::container::macos_detail::denial_stream_state;
using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

std::string corpus_dir;

auto group_has_live_members(::pid_t group) -> bool {
    std::array<struct kinfo_proc, 256> processes{};
    std::size_t bytes = sizeof(processes);
    std::array<int, 4> mib{CTL_KERN, KERN_PROC, KERN_PROC_PGRP, group};
    if (::sysctl(mib.data(), mib.size(), processes.data(), &bytes, nullptr, 0) != 0) {
        return true; // Unknown is never "empty".
    }
    for (std::size_t index = 0; index != bytes / sizeof(struct kinfo_proc); ++index) {
        if (processes.at(index).kp_proc.p_stat != SZOMB) {
            return true;
        }
    }
    return false;
}

auto make_nonce() -> std::string {
    std::array<unsigned char, 16> bytes{};
    ::arc4random_buf(bytes.data(), bytes.size());
    constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (const unsigned char byte : bytes) {
        out.push_back(hex.at(byte >> 4U));
        out.push_back(hex.at(byte & 0x0FU));
    }
    return out;
}

// The same canary the class spawns, owned (unreaped) by the test.
auto spawn_canary(const std::string& nonce) -> ::pid_t {
    const std::string profile =
        R"((version 1)(deny default)(import "system.sb")(allow process-exec*)(allow file-read* (subpath "/usr") (subpath "/System")))";
    std::string target = "/private/tmp/glove-denial-canary-" + nonce;
    std::vector<std::string> argv{"/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/touch", target};
    std::vector<char*> args;
    for (auto& arg : argv) {
        args.push_back(arg.data());
    }
    args.push_back(nullptr);
    ::posix_spawn_file_actions_t actions{};
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    ::posix_spawnattr_t attr{};
    ::posix_spawnattr_init(&attr);
    ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    std::string path = "PATH=/usr/bin:/bin";
    std::array<char*, 2> env{path.data(), nullptr};
    ::pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, argv[0].c_str(), &actions, &attr, args.data(), env.data());
    ::posix_spawn_file_actions_destroy(&actions);
    ::posix_spawnattr_destroy(&attr);
    return rc == 0 ? pid : -1;
}

void kill_and_reap(::pid_t pid) {
    if (pid <= 0) {
        return;
    }
    (void)::kill(pid, SIGKILL);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

// Shared between on_event (reader thread) and the test thread.
struct watcher {
    std::mutex mutex;
    std::condition_variable seen;
    ::pid_t want_pid = -1;
    std::string want_nonce;
    bool hit = false;
    std::vector<std::int32_t> pids;
    std::atomic<int> degraded_calls{0};
    std::string degraded_reason;

    void on_event(const denial_event& event) {
        const std::lock_guard lock{mutex};
        if (!event.readings.empty() && pids.size() < 64) {
            pids.push_back(event.readings.front().pid);
        }
        if (event.readings.size() == 1 && event.readings[0].pid == want_pid &&
            !want_nonce.empty() && event.readings[0].target.ends_with(want_nonce)) {
            hit = true;
            seen.notify_all();
        }
    }

    void on_degraded(std::string_view reason) {
        {
            const std::lock_guard lock{mutex};
            degraded_reason = std::string{reason};
        }
        degraded_calls.fetch_add(1);
    }

    auto options(std::vector<std::string> argv = {}) -> denial_stream_options {
        return {
            .argv = std::move(argv),
            .on_event = [this](const denial_event& event) { on_event(event); },
            .on_degraded = [this](std::string_view reason) { on_degraded(reason); },
        };
    }
};

auto wait_for(const auto& condition, milliseconds limit) -> bool {
    const auto deadline = clock_type::now() + limit;
    while (clock_type::now() < deadline) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(milliseconds{10});
    }
    return condition();
}

auto elapsed_ms(clock_type::time_point since) -> long long {
    return std::chrono::duration_cast<milliseconds>(clock_type::now() - since).count();
}

auto live_and_latency() -> int {
    watcher watch;
    auto started = denial_stream::start(watch.options());
    REQUIRE(started.has_value());
    auto& stream = **started;
    // T0: a user who may not read the log gets a stream that degrades at once.
    if (wait_for(
            [&] { return stream.state() == denial_stream_state::degraded; }, milliseconds{2000}
        )) {
        std::printf("SKIP log stream unavailable\n");
        return 77;
    }

    REQUIRE(stream.prove_live(milliseconds{10000}).has_value());
    REQUIRE(stream.state() == denial_stream_state::live);
    REQUIRE(stream.counters().events >= 1);
    std::printf("T1 ok\n");

    int missed = 0;
    const auto t2_start = clock_type::now();
    for (int trial = 1; trial <= 20; ++trial) {
        const std::string nonce = make_nonce();
        ::pid_t pid = -1;
        {
            const std::lock_guard lock{watch.mutex};
            watch.hit = false;
            watch.want_nonce = nonce;
            pid = spawn_canary(nonce);
            watch.want_pid = pid;
        }
        const auto spawned = clock_type::now();
        REQUIRE(pid > 0);
        bool hit = false;
        {
            std::unique_lock lock{watch.mutex};
            hit = watch.seen.wait_for(lock, milliseconds{10000}, [&] { return watch.hit; });
        }
        if (hit) {
            std::printf("T2 trial %d latency_ms %lld\n", trial, elapsed_ms(spawned));
        } else {
            std::printf("T2 trial %d missed\n", trial);
            ++missed;
        }
        {
            const std::lock_guard lock{watch.mutex};
            watch.want_pid = -1;
            watch.want_nonce.clear();
        }
        kill_and_reap(pid);
    }
    const auto seconds = std::max<long long>(
        1, std::chrono::duration_cast<std::chrono::seconds>(clock_type::now() - t2_start).count()
    );
    std::printf(
        "T2 host_events_per_s %lld\n", static_cast<long long>(stream.counters().lines) / seconds
    );
    REQUIRE(missed == 0);
    return 0;
}

auto exited_child() -> int {
    watcher watch;
    auto started = denial_stream::start(watch.options({"/usr/bin/false"}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(wait_for(
        [&] { return stream->state() == denial_stream_state::degraded; }, milliseconds{2000}
    ));
    REQUIRE(watch.degraded_calls.load() == 1);
    REQUIRE(!stream->prove_live(milliseconds{1000}).has_value());
    const auto destroying = clock_type::now();
    stream.reset();
    REQUIRE(elapsed_ms(destroying) < 4000);
    REQUIRE(watch.degraded_calls.load() == 1);
    std::printf("T3 ok\n");
    return 0;
}

auto spawn_failure() -> int {
    watcher watch;
    auto missing = denial_stream::start(watch.options({"/nonexistent/glove-log"}));
    REQUIRE(!missing.has_value());
    REQUIRE(missing.error().find("errno") != std::string::npos);
    auto relative = denial_stream::start(watch.options({"log"}));
    REQUIRE(!relative.has_value());
    std::printf("T4 ok\n");
    return 0;
}

auto garbage_and_flood() -> int {
    watcher watch;
    const std::string script =
        R"(i=0; while [ $i -lt 10000 ]; do echo garbage; i=$((i+1)); done; head -c 100000 /dev/zero | tr '\0' A; echo; cat "$1/valid-mach-lookup.json"; echo; exec sleep 30)";
    auto started = denial_stream::start(watch.options({"/bin/sh", "-c", script, "sh", corpus_dir}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(wait_for([&] { return stream->counters().events == 1; }, milliseconds{10000}));
    const auto counted = stream->counters();
    REQUIRE(counted.rejected_not_json == 10000);
    REQUIRE(counted.oversized_lines == 1);
    REQUIRE(counted.events == 1);
    REQUIRE(counted.lines == 10001);
    {
        const std::lock_guard lock{watch.mutex};
        REQUIRE(watch.pids.size() == 1 && watch.pids.front() == 60708);
    }
    const auto destroying = clock_type::now();
    stream.reset();
    REQUIRE(elapsed_ms(destroying) < 4000);
    std::printf("T5 ok\n");
    return 0;
}

auto term_ignoring_child() -> int {
    watcher watch;
    auto started =
        denial_stream::start(watch.options({"/bin/sh", "-c", "trap '' TERM; sleep 30 & wait"}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    const ::pid_t group = stream->child_pid_for_test();
    REQUIRE(group > 0);
    std::this_thread::sleep_for(milliseconds{200});
    const auto destroying = clock_type::now();
    stream.reset();
    const auto took = elapsed_ms(destroying);
    std::fprintf(stderr, "T6 destructor_ms %lld\n", took);
    REQUIRE(took >= 1900 && took < 4500);
    REQUIRE(!group_has_live_members(group));
    std::printf("T6 ok\n");
    return 0;
}

auto callback_throws() -> int {
    watcher watch;
    auto options = watch.options();
    options.on_event = [](const denial_event&) { throw std::runtime_error{"test callback"}; };
    auto started = denial_stream::start(std::move(options));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    const ::pid_t canary = spawn_canary(make_nonce());
    REQUIRE(canary > 0);
    const bool degraded = wait_for(
        [&] { return stream->state() == denial_stream_state::degraded; }, milliseconds{10000}
    );
    kill_and_reap(canary);
    REQUIRE(degraded);
    REQUIRE(watch.degraded_calls.load() == 1);
    {
        const std::lock_guard lock{watch.mutex};
        REQUIRE(watch.degraded_reason == "denial callback failed");
    }
    std::printf("T7 ok\n");
    return 0;
}

auto replayed_denial_is_not_a_canary() -> int {
    watcher watch;
    const std::string script =
        R"(i=0; while [ $i -lt 60 ]; do cat "$1/valid-mach-lookup.json"; echo; sleep 0.05; i=$((i+1)); done; exec sleep 30)";
    auto started = denial_stream::start(watch.options({"/bin/sh", "-c", script, "sh", corpus_dir}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(!stream->prove_live(milliseconds{2000}).has_value());
    REQUIRE(stream->state() != denial_stream_state::live);
    std::printf("T8 ok\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: container_macos_denial_stream_test <corpus-dir>\n");
        return 2;
    }
    corpus_dir = argv[1];
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (const int failed = live_and_latency(); failed != 0) {
        return failed;
    }
    for (auto* step :
         {exited_child,
          spawn_failure,
          garbage_and_flood,
          term_ignoring_child,
          callback_throws,
          replayed_denial_is_not_a_canary}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    return 0;
}
