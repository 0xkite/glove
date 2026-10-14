#pragma once

#include "glove/container/profile.hpp"

#include <chrono>
#include <expected>
#include <stop_token>
#include <string>
#include <vector>

namespace glove::container {

// Native macOS passthrough; other platforms return an unsupported error. Owns
// the child through reap, not the caller's endpoint. Only stdio is inherited.
// Grace is clamped to [1ms, 3s]; signal exits are reported as 128 + signal.
// Cancellation that otherwise exits successfully is reported as nonzero.
//
// Temporarily owns process-wide INT/QUIT/TERM/HUP/CHLD dispositions exclusively.
// The caller must not concurrently change those dispositions, reap this child,
// or replace stdio/terminal state. Unrelated SIGCHLD handlers are suppressed,
// not replayed; the caller must arrange collection of unrelated children.
// A foreground controlling terminal on stdin is handed to the child and
// restored, including its saved termios state, before returning.
//
// Cleanup covers the original ordinary process group and a drifting direct
// child, not descendants that escape that group. SIGKILL/reap and kernel calls
// have no hard wall-clock bound. Unresolved cleanup is returned as an error;
// this API adds no resource-enforcement or receipt capability.
[[nodiscard]] auto exec_contained_owned(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::stop_token stop = {},
    std::chrono::milliseconds termination_grace = std::chrono::milliseconds{1500}
) -> std::expected<int, std::string>;

} // namespace glove::container
