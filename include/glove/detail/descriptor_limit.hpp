#pragma once

#include <sys/resource.h>

namespace glove::detail {

// Bounded descriptor-relative walks hold a few descriptors per directory
// level, so a tree at the depth bound needs more than the 256 that launchd
// gives a login shell by default. The soft limit is not a boundary: any
// process may raise it to its hard limit, so raising it here changes no
// guarantee. Failure is ignored; a walk that still runs out of descriptors
// fails closed with EMFILE.
inline constexpr rlim_t wanted_descriptor_soft_limit = 8192;

inline auto raise_descriptor_soft_limit() noexcept -> void {
    struct rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return;
    }
    rlim_t target = wanted_descriptor_soft_limit;
    if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < target) {
        target = limit.rlim_max;
    }
    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= target) {
        return;
    }
    limit.rlim_cur = target;
    (void)::setrlimit(RLIMIT_NOFILE, &limit);
}

} // namespace glove::detail
