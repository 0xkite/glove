#pragma once

#include <cerrno>
#include <expected>
#include <optional>

namespace glove::container::detail {

enum class group_cleanup_failure { ownership, signal, inspection, deadline, pause };

struct group_cleanup_error {
    group_cleanup_failure reason;
    int deferred_error = 0;
    int signal_error = 0;
};

// Signal must revalidate the observed, unreaped leader before targeting its
// original PGID; nullopt means ownership lost, never permission to signal again.
// Inspect must provide a complete bounded zero-live proof, not an exit flag or
// partial enumeration. Expired/pause preserve the caller's existing deadline.
// Darwin may reject a KILL while an exiting member remains non-zombie. EPERM
// stays pending until zero-live proof; every unresolved path retains it.
template<typename Signal, typename Inspect, typename Expired, typename Pause>
auto drain_owned_group(Signal signal, Inspect inspect, Expired expired, Pause pause) noexcept
    -> std::expected<void, group_cleanup_error> {
    int deferred = 0;
    for (;;) {
        const std::optional<int> signalled = signal();
        if (!signalled) {
            return std::unexpected(group_cleanup_error{group_cleanup_failure::ownership, deferred});
        }
        if (*signalled == EPERM) {
            deferred = EPERM;
        } else if (*signalled != 0 && *signalled != ESRCH) {
            return std::unexpected(
                group_cleanup_error{group_cleanup_failure::signal, deferred, *signalled}
            );
        }
        const std::optional<bool> live = inspect();
        if (!live) {
            return std::unexpected(
                group_cleanup_error{group_cleanup_failure::inspection, deferred}
            );
        }
        if (!*live) {
            return {};
        }
        if (expired()) {
            return std::unexpected(group_cleanup_error{group_cleanup_failure::deadline, deferred});
        }
        if (!pause()) {
            return std::unexpected(group_cleanup_error{group_cleanup_failure::pause, deferred});
        }
    }
}

} // namespace glove::container::detail
