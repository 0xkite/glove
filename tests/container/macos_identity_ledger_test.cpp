// Attribution of real kernel denials to an unreaped leader's process group:
// leader and live members are attributed; outsiders, ambiguous events and
// events after retirement never are; short-lived children are recorded.

#include "macos/denial_stream.hpp"
#include "macos/identity_ledger.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
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
using glove::container::detail::denial_reading;
using glove::container::macos_detail::attribution;
using glove::container::macos_detail::denial_stream;
using glove::container::macos_detail::denial_stream_options;
using glove::container::macos_detail::denial_stream_state;
using glove::container::macos_detail::identity_ledger;
using glove::container::macos_detail::ledger_options;
using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

constexpr int trials = 20;
constexpr std::size_t max_copied_events = 4096;

const std::string profile =
    R"((version 1)(deny default)(import "system.sb")(allow process-exec*)(allow process-fork)(allow sysctl-read)(allow file-read* (subpath "/usr") (subpath "/bin") (subpath "/System") (subpath "/private/var/select")))";

auto make_nonce() -> std::string {
    std::array<unsigned char, 16> bytes{};
    ::arc4random_buf(bytes.data(), bytes.size());
    constexpr std::string_view hex = "0123456789abcdef";
    std::string out = "/private/tmp/glove-ledger-";
    for (const unsigned char byte : bytes) {
        out.push_back(hex.at(byte >> 4U));
        out.push_back(hex.at(byte & 0x0FU));
    }
    return out;
}

auto now_micros() -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch()
    )
        .count();
}

auto name_of(attribution how) -> const char* {
    switch (how) {
    case attribution::leader:
        return "leader";
    case attribution::member:
        return "member";
    case attribution::unattributed:
        return "unattributed";
    case attribution::ambiguous:
        return "ambiguous";
    case attribution::after_retirement:
        return "after_retirement";
    }
    return "?";
}

// A sandboxed group: its own process group, leader kept unreaped by the test.
auto spawn_group(const std::string& script) -> ::pid_t {
    std::vector<std::string> argv{"/usr/bin/sandbox-exec", "-p", profile, "/bin/sh", "-c", script};
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
    ::posix_spawnattr_setpgroup(&attr, 0);
    ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
    std::string path = "PATH=/usr/bin:/bin";
    std::array<char*, 2> env{path.data(), nullptr};
    ::pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, argv[0].c_str(), &actions, &attr, args.data(), env.data());
    ::posix_spawn_file_actions_destroy(&actions);
    ::posix_spawnattr_destroy(&attr);
    return rc == 0 ? pid : -1;
}

// Signals only a group whose leader this test still holds unreaped.
void kill_group(::pid_t leader) {
    if (leader <= 0) {
        return;
    }
    (void)::kill(-leader, SIGKILL);
    (void)::kill(leader, SIGKILL);
    int status = 0;
    while (::waitpid(leader, &status, 0) < 0 && errno == EINTR) {}
}

struct event_log {
    std::mutex mutex;
    std::deque<denial_event> events;

    void on_event(const denial_event& event) {
        if (event.readings.size() != 1) {
            return;
        }
        const std::lock_guard lock{mutex};
        if (events.size() == max_copied_events) {
            events.pop_front();
        }
        events.push_back(event);
    }

    auto wait_for_nonce(const std::string& nonce) -> std::optional<denial_event> {
        const auto deadline = clock_type::now() + milliseconds{10000};
        while (clock_type::now() < deadline) {
            {
                const std::lock_guard lock{mutex};
                for (const auto& event : events) {
                    if (event.readings.front().target.ends_with(nonce)) {
                        return event;
                    }
                }
            }
            std::this_thread::sleep_for(milliseconds{5});
        }
        return std::nullopt;
    }
};

struct trial_counts {
    int leader = 0;
    int member = 0;
    int unattributed = 0;
    int ambiguous = 0;
    int after_retirement = 0;
    int missed = 0;
    bool member_pid_was_leader = false;
};

void count(trial_counts& counts, attribution how) {
    switch (how) {
    case attribution::leader:
        ++counts.leader;
        break;
    case attribution::member:
        ++counts.member;
        break;
    case attribution::unattributed:
        ++counts.unattributed;
        break;
    case attribution::ambiguous:
        ++counts.ambiguous;
        break;
    case attribution::after_retirement:
        ++counts.after_retirement;
        break;
    }
}

// One group running script (NONCE substituted); its own event is attributed
// with a ledger on its own leader.
auto own_group_trials(event_log& log, const char* label, const std::string& shape)
    -> std::optional<trial_counts> {
    trial_counts counts;
    for (int trial = 1; trial <= trials; ++trial) {
        const std::string nonce = make_nonce();
        std::string script = shape;
        for (auto at = script.find("NONCE"); at != std::string::npos; at = script.find("NONCE")) {
            script.replace(at, 5, nonce);
        }
        const ::pid_t leader = spawn_group(script);
        if (leader <= 0) {
            return std::nullopt;
        }
        auto ledger = identity_ledger::start(leader);
        if (!ledger) {
            kill_group(leader);
            return std::nullopt;
        }
        const auto event = log.wait_for_nonce(nonce);
        if (!event) {
            std::printf("%s trial %d missed\n", label, trial);
            ++counts.missed;
        } else {
            const auto result = (*ledger)->attribute(*event);
            std::printf("%s trial %d %s\n", label, trial, name_of(result.how));
            count(counts, result.how);
            if (result.how == attribution::member && result.pid == leader) {
                counts.member_pid_was_leader = true;
            }
        }
        (*ledger)->retire();
        kill_group(leader);
    }
    return counts;
}

auto outsider_trials(event_log& log) -> std::optional<trial_counts> {
    trial_counts counts;
    for (int trial = 1; trial <= trials; ++trial) {
        const std::string own = make_nonce();
        const std::string other = make_nonce();
        const ::pid_t first = spawn_group("echo x > " + own + "; sleep 2");
        const ::pid_t second = spawn_group("echo x > " + other + "; sleep 2");
        if (first <= 0 || second <= 0) {
            kill_group(first);
            kill_group(second);
            return std::nullopt;
        }
        auto ledger = identity_ledger::start(first);
        if (!ledger) {
            kill_group(first);
            kill_group(second);
            return std::nullopt;
        }
        const auto event = log.wait_for_nonce(other);
        if (!event) {
            std::printf("Ld trial %d missed\n", trial);
            ++counts.missed;
        } else {
            const auto result = (*ledger)->attribute(*event);
            std::printf("Ld trial %d %s\n", trial, name_of(result.how));
            count(counts, result.how);
        }
        (*ledger)->retire();
        kill_group(first);
        kill_group(second);
    }
    return counts;
}

auto single_event(std::int32_t pid, std::int64_t micros) -> denial_event {
    denial_event event;
    event.readings.push_back(
        denial_reading{
            .pid = pid,
            .code = 1,
            .untrusted_comm = "bash",
            .operation = "file-write-create",
            .kind = denial_class::file_write,
            .target = "/private/tmp/glove-ledger-synthetic",
            .target_truncated = false,
        }
    );
    event.unix_micros = micros;
    return event;
}

auto ambiguous_case() -> int {
    const ::pid_t leader = spawn_group("sleep 2");
    REQUIRE(leader > 0);
    auto ledger = identity_ledger::start(leader);
    REQUIRE(ledger.has_value());
    auto event = single_event(leader, now_micros());
    event.readings.push_back(event.readings.front());
    event.readings.back().pid = leader + 1;
    const auto result = (*ledger)->attribute(event);
    (*ledger)->retire();
    kill_group(leader);
    REQUIRE(result.how == attribution::ambiguous && result.pid == 0);
    std::printf("Le ok\n");
    return 0;
}

auto time_bounds_case() -> int {
    const ::pid_t leader = spawn_group("sleep 2");
    REQUIRE(leader > 0);
    const auto before_start = now_micros();
    auto ledger = identity_ledger::start(leader);
    REQUIRE(ledger.has_value());
    std::this_thread::sleep_for(milliseconds{50});
    const auto middle = now_micros();
    std::this_thread::sleep_for(milliseconds{50});
    (*ledger)->retire();
    kill_group(leader);
    const auto late = (*ledger)->attribute(single_event(leader, middle));
    REQUIRE(late.how == attribution::leader && late.pid == leader);
    const auto after = (*ledger)->attribute(single_event(leader, now_micros() + 1'000'000));
    REQUIRE(after.how == attribution::after_retirement && after.pid == 0);
    const auto early = (*ledger)->attribute(single_event(leader, before_start - 10'000'000));
    REQUIRE(early.how == attribution::unattributed && early.pid == 0);
    std::printf("Lf ok\n");
    return 0;
}

auto bound_case() -> int {
    const ::pid_t leader =
        spawn_group("i=0; while [ $i -lt 100 ]; do sleep 5 & i=$((i+1)); done; wait");
    REQUIRE(leader > 0);
    auto ledger = identity_ledger::start(leader, ledger_options{.max_members = 16});
    REQUIRE(ledger.has_value());
    bool evicted = false;
    bool bounded = true;
    const auto deadline = clock_type::now() + milliseconds{5000};
    while (clock_type::now() < deadline) {
        const auto counted = (*ledger)->counters();
        bounded = bounded && counted.table_size <= 16;
        if (counted.members_evicted > 0) {
            evicted = true;
            break;
        }
        std::this_thread::sleep_for(milliseconds{20});
    }
    const auto zero = identity_ledger::start(leader, ledger_options{.max_members = 0});
    const auto over = identity_ledger::start(leader, ledger_options{.max_members = 4097});
    const auto no_leader = identity_ledger::start(0);
    (*ledger)->retire();
    kill_group(leader);
    REQUIRE(bounded);
    REQUIRE(evicted);
    REQUIRE(!zero.has_value() && !over.has_value() && !no_leader.has_value());
    std::printf("Lg ok\n");
    return 0;
}

auto run() -> int {
    event_log log;
    denial_stream_options options{
        .argv = {},
        .on_event = [&log](const denial_event& event) { log.on_event(event); },
        .on_degraded = {},
    };
    auto started = denial_stream::start(std::move(options));
    REQUIRE(started.has_value());
    auto& stream = **started;
    const auto deadline = clock_type::now() + milliseconds{2000};
    while (clock_type::now() < deadline) {
        if (stream.state() == denial_stream_state::degraded) {
            std::printf("SKIP log stream unavailable\n");
            return 77;
        }
        std::this_thread::sleep_for(milliseconds{20});
    }
    REQUIRE(stream.prove_live(milliseconds{10000}).has_value());

    const auto la = own_group_trials(log, "La", "echo x > NONCE; sleep 2");
    REQUIRE(la.has_value());
    const auto lb = own_group_trials(log, "Lb", R"(/bin/sh -c "echo x > NONCE; sleep 2" & wait)");
    REQUIRE(lb.has_value());
    const auto lc = own_group_trials(log, "Lc", "/usr/bin/touch NONCE; sleep 1");
    REQUIRE(lc.has_value());
    const auto ld = outsider_trials(log);
    REQUIRE(ld.has_value());

    REQUIRE(la->missed == 0 && lb->missed == 0 && lc->missed == 0 && ld->missed == 0);
    REQUIRE(la->leader == trials);
    REQUIRE(lb->member == trials && !lb->member_pid_was_leader);
    REQUIRE(lc->leader == 0 && lc->ambiguous == 0 && lc->after_retirement == 0);
    REQUIRE(ld->unattributed == trials);

    for (auto* step : {ambiguous_case, time_bounds_case, bound_case}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    std::printf("ledger ok\n");
    return 0;
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    return run();
}
