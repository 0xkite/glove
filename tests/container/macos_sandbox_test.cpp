// Stage 1 integration test (macOS): the spawner must contain an ARBITRARY,
// non-glove-aware binary via an SBPL profile applied through sandbox-exec —
// not rely on the agent self-sandboxing. We spawn /bin/sh with a probe that
// reports whether it can write inside the configured workspace (must) and
// outside it, in $HOME (must not), and read a benign file outside it (must
// not). Reaching any result at all also proves
// the system.sb import lets a dynamically linked binary start under the
// sandbox.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

// True while any non-zombie process still belongs to group. Must be asked
// only after wait(): the handle owes the caller an empty group on return.
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

// Descendants that outlive the leader are killed and proven gone before
// wait() releases the leader's PGID, and the leader's exit code survives.
auto descendants_drained_before_reap() -> int {
    glove::container::profile prof;
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or =
        spawner->spawn(prof, {"/bin/sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $$; exit 7"});
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);
    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    const auto leader = static_cast<::pid_t>(std::stol(*line));
    REQUIRE(leader > 0);
    REQUIRE(!handle->reaped_exit_code());
    auto code = handle->wait();
    REQUIRE(code.has_value());
    REQUIRE(*code == 7);
    REQUIRE(handle->reaped_exit_code() == 7);
    REQUIRE(!group_has_live_members(leader));
    auto again = handle->wait();
    REQUIRE(again.has_value() && *again == 7);
    return 0;
}

// A group that ignores SIGTERM is escalated to SIGKILL within the bounded
// grace periods, and a signal death is reported as -1, not as an exit code.
auto term_ignoring_group_escalates() -> int {
    glove::container::profile prof;
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or = spawner->spawn(
        prof, {"/bin/sh", "-c", "trap '' TERM; echo $$; sleep 30 >/dev/null 2>&1; exit 0"}
    );
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);
    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    const auto leader = static_cast<::pid_t>(std::stol(*line));
    const auto started = std::chrono::steady_clock::now();
    auto code = handle->wait();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    REQUIRE(code.has_value());
    REQUIRE(*code == -1);
    REQUIRE(elapsed < std::chrono::seconds{10});
    REQUIRE(!group_has_live_members(leader));
    return 0;
}

// A group too large for one bounded listing is still killed and proven empty,
// and the leader's exit code survives the truncated inspections.
auto large_group_is_drained() -> int {
    glove::container::profile prof;
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or = spawner->spawn(
        prof,
        {"/bin/sh",
         "-c",
         "i=0; while [ $i -lt 300 ]; do sleep 30 >/dev/null 2>&1 & i=$((i+1)); done; echo $$; exit "
         "7"}
    );
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);
    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    const auto leader = static_cast<::pid_t>(std::stol(*line));
    REQUIRE(leader > 0);
    auto code = handle->wait();
    REQUIRE(code.has_value());
    REQUIRE(*code == 7);
    REQUIRE(!group_has_live_members(leader));
    return 0;
}

// Once another waiter has consumed the leader, the PID and PGID are no longer
// pinned: wait() must fail, keep failing identically, and signal nothing.
auto lost_ownership_sends_no_signal() -> int {
    glove::container::profile prof;
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or =
        spawner->spawn(prof, {"/bin/sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $$ $!; exit 0"});
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);
    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    int leader_value = 0;
    int sleeper_value = 0;
    REQUIRE(std::sscanf(line->c_str(), "%d %d", &leader_value, &sleeper_value) == 2);
    const auto leader = static_cast<::pid_t>(leader_value);
    const auto sleeper = static_cast<::pid_t>(sleeper_value);
    REQUIRE(leader > 0 && sleeper > 0);
    int status = 0;
    ::pid_t reaped = -1;
    do {
        reaped = ::waitpid(leader, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    REQUIRE(reaped == leader);
    auto code = handle->wait();
    REQUIRE(!code.has_value());
    auto again = handle->wait();
    REQUIRE(!again.has_value());
    REQUIRE(again.error() == code.error());
    REQUIRE(::kill(sleeper, 0) == 0);
    (void)::kill(sleeper, SIGKILL);
    return 0;
}

auto run() -> int {
    const char* home = std::getenv("HOME");
    REQUIRE(home != nullptr && *home != '\0');

    // A writable workspace under $HOME, so the "allow workspace / deny the rest
    // of $HOME" distinction is meaningful (a /tmp workspace would be covered by
    // the default scratch-dir allowance and prove nothing).
    std::string ws = std::string{home} + "/.glove_ws_test_" + std::to_string(::getpid());
    std::error_code ec;
    std::filesystem::create_directories(ws, ec);
    REQUIRE(!ec);

    std::string evil = std::string{home} + "/.glove_evil_" + std::to_string(::getpid());

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws, .writable = true});

    // Probe: report deny/allow for a write outside the workspace and inside it,
    // plus a read outside the workspace. The executable itself is an implicit
    // runtime grant; unrelated host files are not.
    std::string script = "if touch '" + evil + "' 2>/dev/null; then h=WRITE; else h=DENY; fi; ";
    script += "if touch '" + ws + "/ok' 2>/dev/null; then w=WRITE; else w=DENY; fi; ";
    script += "if head -c1 '" + std::string{__FILE__} +
              "' >/dev/null 2>&1; then r=READ; else r=DENY; fi; ";
    script += "echo \"home=$h ws=$w outside_read=$r\"";

    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or = spawner->spawn(prof, {"/bin/sh", "-c", script});
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);

    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    std::fprintf(stderr, "probe: %s\n", line->c_str());

    const bool home_denied = line->find("home=DENY") != std::string::npos;
    const bool ws_allowed = line->find("ws=WRITE") != std::string::npos;
    const bool outside_read_denied = line->find("outside_read=DENY") != std::string::npos;

    std::filesystem::remove_all(ws, ec);
    std::filesystem::remove(evil, ec);

    REQUIRE(home_denied);
    REQUIRE(ws_allowed);
    REQUIRE(outside_read_denied);

    // The grant holder must not be able to replace the grant root itself. With
    // no root guard an agent can unlink an empty root and plant a symlink; the
    // next launch canonicalizes that path and silently grants the link target.
    std::filesystem::create_directories(ws, ec);
    REQUIRE(!ec);
    std::string outside = std::string{home} + "/.glove_evil_root_" + std::to_string(::getpid());
    std::filesystem::create_directories(outside, ec);
    REQUIRE(!ec);

    std::string replace = "if rmdir '" + ws + "' 2>/dev/null; then r=UNLINKED; ";
    replace +=
        "if ln -s '" + outside + "' '" + ws + "' 2>/dev/null; then l=REPLACED; else l=FAILED; fi; ";
    replace += "else r=DENY; l=SKIPPED; fi; echo \"root_rmdir=$r root_link=$l\"";

    auto replaced_or = spawner->spawn(prof, {"/bin/sh", "-c", replace});
    REQUIRE(replaced_or.has_value());
    auto replaced = std::move(*replaced_or);
    auto replaced_line = replaced->transport().recv();
    REQUIRE(replaced_line.has_value());
    std::fprintf(stderr, "probe: %s\n", replaced_line->c_str());
    const bool root_unlinked = replaced_line->find("root_rmdir=UNLINKED") != std::string::npos;
    const bool root_replaced = replaced_line->find("root_link=REPLACED") != std::string::npos;
    const bool still_directory =
        std::filesystem::is_directory(ws, ec) && !std::filesystem::is_symlink(ws, ec);

    std::filesystem::remove_all(ws, ec);
    std::filesystem::remove_all(outside, ec);

    REQUIRE(!root_unlinked);
    REQUIRE(!root_replaced);
    REQUIRE(still_directory);
    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = run(); failed != 0) {
        return failed;
    }
    if (const int failed = descendants_drained_before_reap(); failed != 0) {
        return failed;
    }
    if (const int failed = term_ignoring_group_escalates(); failed != 0) {
        return failed;
    }
    if (const int failed = large_group_is_drained(); failed != 0) {
        return failed;
    }
    return lost_ownership_sends_no_signal();
}
