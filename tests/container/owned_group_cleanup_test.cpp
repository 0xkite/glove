#include "owned_group_cleanup.hpp"

#include <cerrno>
#include <cstdio>
#include <optional>
#include <vector>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using glove::container::detail::drain_owned_group;
using glove::container::detail::group_cleanup_failure;

struct fixture {
    std::vector<std::optional<int>> signals;
    std::vector<std::optional<bool>> inspections;
    std::size_t signal_calls = 0;
    std::size_t inspect_calls = 0;
    std::size_t pause_calls = 0;
    std::size_t expire_after = 99;
    bool pause_ok = true;

    auto run() {
        return drain_owned_group(
            [&]() -> std::optional<int> {
                ++signal_calls;
                return signal_calls <= signals.size() ? signals[signal_calls - 1] : std::nullopt;
            },
            [&]() -> std::optional<bool> {
                ++inspect_calls;
                return inspect_calls <= inspections.size() ? inspections[inspect_calls - 1]
                                                           : std::nullopt;
            },
            [&]() { return inspect_calls >= expire_after; },
            [&]() {
                ++pause_calls;
                return pause_ok;
            }
        );
    }
};

auto run() -> int {
    // Observed sequence: accepted KILL, transitional EPERM with non-zombie
    // member, then complete zero-live proof. No exit flag implies death here.
    fixture transition{{0, EPERM, EPERM}, {true, true, false}};
    REQUIRE(transition.run());
    REQUIRE(
        transition.signal_calls == 3 && transition.inspect_calls == 3 && transition.pause_calls == 2
    );
    fixture empty_denial{{EPERM}, {false}};
    REQUIRE(empty_denial.run());
    fixture gone_but_live{{ESRCH, 0}, {true, false}};
    REQUIRE(gone_but_live.run());
    fixture exact_deadline_quiescent{{EPERM}, {false}};
    exact_deadline_quiescent.expire_after = 1;
    REQUIRE(exact_deadline_quiescent.run());

    fixture persistent{{EPERM, EPERM}, {true, true}};
    persistent.expire_after = 2;
    auto timed_out = persistent.run();
    REQUIRE(!timed_out && timed_out.error().reason == group_cleanup_failure::deadline);
    REQUIRE(timed_out.error().deferred_error == EPERM && persistent.signal_calls == 2);
    fixture unavailable{{EPERM}, {std::nullopt}};
    auto unknown = unavailable.run();
    REQUIRE(!unknown && unknown.error().reason == group_cleanup_failure::inspection);
    REQUIRE(unknown.error().deferred_error == EPERM && unavailable.pause_calls == 0);
    // A truncated query is unavailable, never a partial zero-live proof.
    fixture truncated{{0}, {std::nullopt}};
    REQUIRE(!truncated.run());
    fixture denied_pause{{EPERM}, {true}};
    denied_pause.pause_ok = false;
    auto paused = denied_pause.run();
    REQUIRE(!paused && paused.error().reason == group_cleanup_failure::pause);
    REQUIRE(paused.error().deferred_error == EPERM);
    fixture unexpected_signal{{EINVAL}, {false}};
    auto bad_signal = unexpected_signal.run();
    REQUIRE(!bad_signal && bad_signal.error().reason == group_cleanup_failure::signal);
    REQUIRE(bad_signal.error().signal_error == EINVAL && unexpected_signal.inspect_calls == 0);
    fixture denial_then_error{{EPERM, EINVAL}, {true}};
    auto retained_errors = denial_then_error.run();
    REQUIRE(!retained_errors && retained_errors.error().reason == group_cleanup_failure::signal);
    REQUIRE(
        retained_errors.error().deferred_error == EPERM &&
        retained_errors.error().signal_error == EINVAL
    );
    REQUIRE(denial_then_error.signal_calls == 2 && denial_then_error.inspect_calls == 1);
    // Callback must verify the unreaped leader before every group signal.
    fixture competing_reaper{{0, std::nullopt}, {true}};
    auto lost_owner = competing_reaper.run();
    REQUIRE(!lost_owner && lost_owner.error().reason == group_cleanup_failure::ownership);
    REQUIRE(competing_reaper.inspect_calls == 1 && competing_reaper.signal_calls == 2);
    fixture denial_then_lost_owner{{EPERM, std::nullopt}, {true}};
    auto retained_denial = denial_then_lost_owner.run();
    REQUIRE(!retained_denial && retained_denial.error().reason == group_cleanup_failure::ownership);
    REQUIRE(retained_denial.error().deferred_error == EPERM);
    return 0;
}
} // namespace

int main() {
    return run();
}
