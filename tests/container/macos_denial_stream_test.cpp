// The supervised log-stream child: liveness only after an observed canary
// denial, measured canary latency, and degradation (never a hang) when the
// log exits, emits garbage, floods, ignores SIGTERM, or a callback throws.

#include "macos/denial_stream.hpp"
#include "macos/denial_tag.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
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
#include <string_view>
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
using glove::container::macos_detail::make_denial_tag;
using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

std::string corpus_dir;

// The fixed tag of the tagged corpus seeds, and the foreign tag inside one.
constexpr std::string_view seed_tag = "00112233445566778899aabbccddeeff";
constexpr std::string_view foreign_tag = "ffeeddccbbaa99887766554433221100";

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

// A denied touch of TARGET under a profile tagged TAG, owned (unreaped) by
// the test.
auto spawn_touch(std::string target, std::string_view tag) -> ::pid_t {
    const std::string profile =
        R"((version 1)(deny default (with message ")" + std::string{tag} +
        R"("))(import "system.sb")(allow process-exec*)(allow file-read* (subpath "/usr") (subpath "/System")))";
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

// The same canary the class spawns, but tagged TAG.
auto spawn_canary(const std::string& nonce, std::string_view tag) -> ::pid_t {
    return spawn_touch("/private/tmp/glove-denial-canary-" + nonce, tag);
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
    std::vector<std::string> targets;
    std::atomic<int> degraded_calls{0};
    std::string degraded_reason;

    void on_event(const denial_event& event) {
        const std::lock_guard lock{mutex};
        if (!event.readings.empty() && pids.size() < 64) {
            pids.push_back(event.readings.front().pid);
        }
        if (event.readings.size() == 1 && targets.size() < 256) {
            targets.push_back(event.readings.front().target);
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

    auto options(std::string_view tag, std::vector<std::string> argv = {})
        -> denial_stream_options {
        return {
            .tag = std::string{tag},
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
    const std::string tag = make_denial_tag();
    auto started = denial_stream::start(watch.options(tag));
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
    REQUIRE(stream.counters().canary_events >= 1);
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
            pid = spawn_canary(nonce, tag);
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
    auto started = denial_stream::start(watch.options(seed_tag, {"/usr/bin/false"}));
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
    auto missing = denial_stream::start(watch.options(seed_tag, {"/nonexistent/glove-log"}));
    REQUIRE(!missing.has_value());
    REQUIRE(missing.error().find("errno") != std::string::npos);
    auto relative = denial_stream::start(watch.options(seed_tag, {"log"}));
    REQUIRE(!relative.has_value());
    std::printf("T4 ok\n");
    return 0;
}

auto garbage_and_flood() -> int {
    watcher watch;
    const std::string script =
        R"(i=0; while [ $i -lt 10000 ]; do echo garbage; i=$((i+1)); done; head -c 100000 /dev/zero | tr '\0' A; echo; cat "$1/tagged-mach-lookup.json"; exec sleep 30)";
    auto started =
        denial_stream::start(watch.options(seed_tag, {"/bin/sh", "-c", script, "sh", corpus_dir}));
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
    auto started = denial_stream::start(
        watch.options(seed_tag, {"/bin/sh", "-c", "trap '' TERM; sleep 30 & wait"})
    );
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
    const std::string tag = make_denial_tag();
    auto options = watch.options(tag);
    options.on_event = [](const denial_event&) { throw std::runtime_error{"test callback"}; };
    auto started = denial_stream::start(std::move(options));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    const ::pid_t canary = spawn_canary(make_nonce(), tag);
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
        R"(i=0; while [ $i -lt 60 ]; do cat "$1/tagged-mach-lookup.json"; echo; sleep 0.05; i=$((i+1)); done; exec sleep 30)";
    auto started =
        denial_stream::start(watch.options(seed_tag, {"/bin/sh", "-c", script, "sh", corpus_dir}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(!stream->prove_live(milliseconds{2000}).has_value());
    REQUIRE(stream->state() != denial_stream_state::live);
    std::printf("T8 ok\n");
    return 0;
}

// T9: a child reaped by someone else is no longer this object's to signal.
// The orphaned sleep in its group must survive the destructor.
auto lost_child_is_not_signalled() -> int {
    watcher watch;
    auto started =
        denial_stream::start(watch.options(seed_tag, {"/bin/sh", "-c", "sleep 30 & wait"}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    const ::pid_t pid = stream->child_pid_for_test();
    REQUIRE(pid > 0);
    std::this_thread::sleep_for(milliseconds{300});
    REQUIRE(group_has_live_members(pid));
    (void)::kill(pid, SIGKILL);
    int status = 0;
    ::pid_t reaped = -1;
    do {
        reaped = ::waitpid(pid, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    REQUIRE(reaped == pid);
    REQUIRE(group_has_live_members(pid));
    const auto destroying = clock_type::now();
    stream.reset();
    const auto took = elapsed_ms(destroying);
    const bool survived = group_has_live_members(pid);
    // The sleep keeps group pid alive, so the number cannot have been reused.
    (void)::kill(-pid, SIGKILL);
    (void)wait_for([&] { return !group_has_live_members(pid); }, milliseconds{2000});
    REQUIRE(took < 1000);
    REQUIRE(survived);
    std::printf("T9 ok\n");
    return 0;
}

// T10: a denial under another tag never reaches this stream's callback.
auto other_tag_is_not_delivered() -> int {
    watcher watch;
    const std::string tag = make_denial_tag();
    auto started = denial_stream::start(watch.options(tag));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(stream->prove_live(milliseconds{10000}).has_value());
    const std::string other_nonce = make_nonce();
    const std::string mine_nonce = make_nonce();
    const ::pid_t other =
        spawn_touch("/private/tmp/glove-denial-other-" + other_nonce, make_denial_tag());
    const ::pid_t mine = spawn_touch("/private/tmp/glove-denial-mine-" + mine_nonce, tag);
    const auto has_target = [&](std::string_view needle, bool suffix) {
        const std::lock_guard lock{watch.mutex};
        return std::ranges::any_of(watch.targets, [&](const std::string& target) {
            return suffix ? target.ends_with(needle) : target.contains(needle);
        });
    };
    const bool arrived =
        wait_for([&] { return has_target(mine_nonce, true); }, milliseconds{10000});
    const bool carries_tag = has_target(tag, false);
    std::this_thread::sleep_for(milliseconds{500});
    const bool foreign = has_target(other_nonce, false);
    kill_and_reap(other);
    kill_and_reap(mine);
    REQUIRE(other > 0 && mine > 0);
    REQUIRE(arrived);
    REQUIRE(!carries_tag);
    REQUIRE(!foreign);
    std::printf("T10 ok\n");
    return 0;
}

// T11: the stream's own canaries prove liveness but are never delivered.
auto canary_is_not_delivered() -> int {
    watcher watch;
    auto started = denial_stream::start(watch.options(make_denial_tag()));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    REQUIRE(stream->prove_live(milliseconds{10000}).has_value());
    std::this_thread::sleep_for(milliseconds{500});
    {
        const std::lock_guard lock{watch.mutex};
        REQUIRE(std::ranges::none_of(watch.targets, [](const std::string& target) {
            return target.contains("glove-denial-canary-");
        }));
    }
    REQUIRE(stream->counters().canary_events >= 1);
    std::printf("T11 ok\n");
    return 0;
}

// T12: only lines ending with the session tag are delivered, in order.
auto untagged_replay_is_dropped() -> int {
    watcher watch;
    const std::string script =
        R"(cat "$1/valid-mach-lookup.json"; echo; cat "$1/hostile-system-policy-tag-tail.json"; echo; cat "$1/tagged-foreign-tag-inside.json"; echo; cat "$1/tagged-mach-lookup.json"; echo; exec sleep 30)";
    auto started =
        denial_stream::start(watch.options(seed_tag, {"/bin/sh", "-c", script, "sh", corpus_dir}));
    REQUIRE(started.has_value());
    auto stream = std::move(*started);
    (void)wait_for([&] { return stream->counters().events == 2; }, milliseconds{5000});
    const auto counted = stream->counters();
    REQUIRE(counted.events == 2);
    REQUIRE(counted.rejected_untagged >= 1);
    REQUIRE(counted.rejected_not_a_denial >= 1);
    REQUIRE(counted.canary_events == 0);
    {
        const std::lock_guard lock{watch.mutex};
        REQUIRE(watch.targets.size() == 2);
        REQUIRE(watch.targets[0] == "/private/tmp/forge\n" + std::string{foreign_tag});
        REQUIRE(watch.targets[1] == "glove.probe.plain");
    }
    std::printf("T12 ok\n");
    return 0;
}

// T13: a tag that is not 32 lowercase hex characters is refused.
auto bad_tag_is_refused() -> int {
    watcher watch;
    REQUIRE(!denial_stream::start(watch.options("")).has_value());
    REQUIRE(!denial_stream::start(watch.options(seed_tag.substr(0, 31))).has_value());
    REQUIRE(!denial_stream::start(watch.options("00112233445566778899AABBCCDDEEFF")).has_value());
    std::printf("T13 ok\n");
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
          replayed_denial_is_not_a_canary,
          lost_child_is_not_signalled,
          other_tag_is_not_delivered,
          canary_is_not_delivered,
          untagged_replay_is_dropped,
          bad_tag_is_refused}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    return 0;
}
