#pragma once

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <expected>
#include <span>

namespace glove::container::macos_detail {

// Inspection only: never signal the enumerated PIDs, whose identities are not
// pinned. Callers may rely on the answer only while their own unreaped leader
// reserves the PGID numerically. Fixed enumeration capacity is a cleanup
// diagnostic bound, not a PID limit: a truncated listing is an error, never
// "no live members". The error is an errno value, reported numerically.
inline auto group_has_live_members(::pid_t group) noexcept -> std::expected<bool, int> {
    std::array<struct kinfo_proc, 256> processes{};
    std::size_t bytes = sizeof(processes);
    std::array<int, 4> mib{CTL_KERN, KERN_PROC, KERN_PROC_PGRP, group};
    if (::sysctl(mib.data(), mib.size(), processes.data(), &bytes, nullptr, 0) != 0) {
        return std::unexpected(errno);
    }
    if (bytes >= sizeof(processes) || bytes % sizeof(struct kinfo_proc) != 0) {
        return std::unexpected(EOVERFLOW);
    }
    const auto listed = std::span{processes}.first(bytes / sizeof(struct kinfo_proc));
    return std::ranges::any_of(listed, [](const struct kinfo_proc& process) noexcept {
        return process.kp_proc.p_stat != SZOMB;
    });
}

} // namespace glove::container::macos_detail
