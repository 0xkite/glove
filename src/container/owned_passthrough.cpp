#include "glove/container/owned_passthrough.hpp"

#if defined(__APPLE__)
#    include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX
#    include "macos/launch_command.hpp"
#    include "owned_group_cleanup.hpp"
#    include "signal_mailbox.hpp"
#    include "stdio_admission.hpp"

#    include <fcntl.h>
#    include <pthread.h>
#    include <signal.h>
#    include <spawn.h>
#    include <sys/proc.h>
#    include <sys/sysctl.h>
#    include <sys/wait.h>
#    include <termios.h>
#    include <time.h>
#    include <unistd.h>

#    include <algorithm>
#    include <array>
#    include <atomic>
#    include <cerrno>
#    include <cstddef>
#    include <cstring>
#    include <exception>
#    include <optional>
#    include <utility>

#    if defined(POSIX_SPAWN_CLOEXEC_DEFAULT) && defined(WNOWAIT)
#        include "owned_launch_resources.hpp"
#    endif
#endif

namespace glove::container {

#if defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX &&                               \
    defined(POSIX_SPAWN_CLOEXEC_DEFAULT) && defined(WNOWAIT)
namespace {

using clock_type = std::chrono::steady_clock;
constexpr std::size_t aggregate_limit = 192U * 1024U;
constexpr std::array broker_signals{SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGCHLD};

// Handlers never hold a PID or touch per-invocation storage. Only the owning
// thread sends signals, so handler teardown cannot race a reap into PID reuse.
std::atomic_flag broker_exclusive = ATOMIC_FLAG_INIT;
detail::signal_mailbox broker_events;

void record_signal(int signal) noexcept {
    const auto captured = broker_events.capture();
    const int saved_errno = errno;
    unsigned bit = 0;
    switch (signal) {
    case SIGINT:
        bit = 1U;
        break;
    case SIGQUIT:
        bit = 2U;
        break;
    case SIGTERM:
        bit = 4U;
        break;
    case SIGHUP:
        bit = 8U;
        break;
    default:
        break;
    }
    (void)broker_events.publish(captured, bit);
    errno = saved_errno;
}

using owned_detail::check;
using owned_detail::check_syscall;
using owned_detail::failures;
using owned_detail::spawn_state;
using owned_detail::stdio_snapshot;

class signal_state {
public:
    explicit signal_state(failures& errors) noexcept : errors_{errors} {}

    signal_state(const signal_state&) = delete;
    auto operator=(const signal_state&) -> signal_state& = delete;
    signal_state(signal_state&&) = delete;
    auto operator=(signal_state&&) -> signal_state& = delete;

    ~signal_state() noexcept {
        if (!exclusive_) {
            return;
        }
        broker_events.disarm();
        bool restored = true;
        if (mask_saved_) {
            restored = check(
                ::pthread_sigmask(SIG_BLOCK, &blocked_, nullptr),
                "block signals for restoration (cleanup unresolved on failure)",
                errors_
            );
        }
        while (installed_ != 0) {
            --installed_;
            if (!check_syscall(
                    ::sigaction(broker_signals[installed_], &previous_[installed_], nullptr),
                    "restore signal disposition (cleanup unresolved on failure)",
                    errors_
                )) {
                restored = false;
            }
        }
        if (mask_saved_ && !check(
                               ::pthread_sigmask(SIG_SETMASK, &old_mask_, nullptr),
                               "restore signal mask (cleanup unresolved on failure)",
                               errors_
                           )) {
            restored = false;
        }
        // Failed restoration poisons the process-wide broker rather than
        // allowing another invocation to overwrite partially restored state.
        if (restored) {
            broker_exclusive.clear(std::memory_order_release);
        }
    }

    auto acquire() noexcept -> bool {
        if (broker_exclusive.test_and_set(std::memory_order_acquire)) {
            errors_.add("owned passthrough signal broker is busy or poisoned", EBUSY);
            return false;
        }
        exclusive_ = true;
        if (!check_syscall((::sigemptyset)(&blocked_), "broker sigemptyset", errors_)) {
            return false;
        }
        for (const int signal : broker_signals) {
            if (!check_syscall((::sigaddset)(&blocked_, signal), "broker sigaddset", errors_)) {
                return false;
            }
        }
        if (!check_syscall((::sigaddset)(&blocked_, SIGTTOU), "broker block TTOU", errors_)) {
            return false;
        }
        mask_saved_ = check(
            ::pthread_sigmask(SIG_BLOCK, &blocked_, &old_mask_), "broker pthread_sigmask", errors_
        );
        if (!mask_saved_) {
            return false;
        }
        for (std::size_t index = 0; index != broker_signals.size(); ++index) {
            if (!check_syscall(
                    ::sigaction(broker_signals[index], nullptr, &previous_[index]),
                    "read signal disposition",
                    errors_
                )) {
                return false;
            }
        }
        const auto& child_action = previous_.back();
        if (child_action.sa_handler == SIG_IGN || (child_action.sa_flags & SA_NOCLDWAIT) != 0) {
            errors_.add("SIGCHLD disposition does not preserve owned child identity", EINVAL);
            return false;
        }
        struct sigaction action{};
        action.sa_handler = record_signal;
        if (!check_syscall((::sigfillset)(&action.sa_mask), "broker handler sigfillset", errors_)) {
            return false;
        }
        if (!broker_events.arm()) {
            errors_.add("signal broker generation exhausted", EOVERFLOW);
            return false;
        }
        for (const int signal : broker_signals) {
            if (!check_syscall(
                    ::sigaction(signal, &action, nullptr), "install signal broker", errors_
                )) {
                return false;
            }
            ++installed_;
        }
        // Block TTOU throughout terminal ownership and restoration. The child's
        // checked empty mask and default dispositions do not inherit this mask.
        auto running_mask = old_mask_;
        for (const int signal : broker_signals) {
            if (!check_syscall(
                    (::sigdelset)(&running_mask, signal), "broker unblock signal", errors_
                )) {
                return false;
            }
        }
        if (!check_syscall((::sigaddset)(&running_mask, SIGTTOU), "broker mask TTOU", errors_)) {
            return false;
        }
        return check(
            ::pthread_sigmask(SIG_SETMASK, &running_mask, nullptr),
            "activate signal broker",
            errors_
        );
    }

private:
    failures& errors_;
    std::array<struct sigaction, broker_signals.size()> previous_{};
    sigset_t old_mask_{};
    sigset_t blocked_{};
    std::size_t installed_ = 0;
    bool exclusive_ = false;
    bool mask_saved_ = false;
};

class terminal_state {
public:
    terminal_state(int fd, failures& errors) noexcept : fd_{fd}, errors_{errors} {}

    terminal_state(const terminal_state&) = delete;
    auto operator=(const terminal_state&) -> terminal_state& = delete;
    terminal_state(terminal_state&&) = delete;
    auto operator=(terminal_state&&) -> terminal_state& = delete;

    ~terminal_state() noexcept {
        if (saved_) {
            // signal_state outlives this owner and still has TTOU blocked.
            check_syscall(
                ::tcsetpgrp(fd_, foreground_),
                "restore terminal foreground (cleanup unresolved on failure)",
                errors_
            );
            check_syscall(
                ::tcsetattr(fd_, TCSANOW, &settings_),
                "restore termios (cleanup unresolved on failure)",
                errors_
            );
        }
    }

    auto prepare() noexcept -> bool {
        if (::isatty(fd_) == 0) {
            if (errno == ENOTTY) {
                return true;
            }
            errors_.add("isatty stdin snapshot", errno);
            return false;
        }
        foreground_ = ::tcgetpgrp(fd_);
        if (foreground_ < 0) {
            errors_.add("tcgetpgrp stdin controlling terminal", errno);
            return false;
        }
        if (foreground_ != ::getpgrp()) {
            errors_.add("refusing to steal a background terminal", EPERM);
            return false;
        }
        saved_ = check_syscall(::tcgetattr(fd_, &settings_), "save termios", errors_);
        return saved_;
    }

    auto hand_to(::pid_t pid) noexcept -> bool {
        return !saved_ || check_syscall(::tcsetpgrp(fd_, pid), "tcsetpgrp child", errors_);
    }

    [[nodiscard]] auto active() const noexcept -> bool { return saved_; }

private:
    int fd_;
    failures& errors_;
    ::pid_t foreground_ = -1;
    struct termios settings_{};
    bool saved_ = false;
};

auto pause_tick(failures& errors) noexcept -> bool {
    struct timespec delay{};
    delay.tv_nsec = 5'000'000;
    if (::nanosleep(&delay, nullptr) == 0 || errno == EINTR) {
        return true;
    }
    errors.add("nanosleep", errno);
    return false;
}

// Inspection only: never signal the enumerated PIDs, whose identities are not
// pinned. The original PGID stays numerically reserved by the unreaped leader.
// Fixed enumeration capacity is a cleanup diagnostic bound, not a PID limit.
auto group_has_live_members(::pid_t group, failures& errors) noexcept -> std::optional<bool> {
    std::array<struct kinfo_proc, 256> processes{};
    std::size_t bytes = sizeof(processes);
    int mib[]{CTL_KERN, KERN_PROC, KERN_PROC_PGRP, group};
    if (::sysctl(mib, 4, processes.data(), &bytes, nullptr, 0) != 0) {
        errors.add("ordinary group inspection unavailable (cleanup unresolved)", errno);
        return std::nullopt;
    }
    if (bytes >= sizeof(processes) || bytes % sizeof(struct kinfo_proc) != 0) {
        errors.add("ordinary group inspection truncated (cleanup unresolved)", EOVERFLOW);
        return std::nullopt;
    }
    const auto count = bytes / sizeof(struct kinfo_proc);
    for (std::size_t index = 0; index != count; ++index) {
        if (processes[index].kp_proc.p_stat != SZOMB) {
            return true;
        }
    }
    return false;
}

class owned_child {
public:
    explicit owned_child(failures& errors) noexcept : errors_{errors} {}

    owned_child(const owned_child&) = delete;
    auto operator=(const owned_child&) -> owned_child& = delete;
    owned_child(owned_child&&) = delete;
    auto operator=(owned_child&&) -> owned_child& = delete;

    ~owned_child() noexcept {
        if (pid_ <= 0) {
            return;
        }
        if (!observed_) {
            const bool kill_accepted = signal(SIGKILL);
            // A denied KILL must not turn cleanup into an unbounded wait on a
            // still-running child. Successful KILL/reap can still block in the
            // kernel; it is deliberately not advertised as a hard time bound.
            if (observe(!kill_accepted) != observation::exited) {
                errors_.add("owned child exit/reap unresolved", EIO);
                return;
            }
        }
        // Never consume the leader first: its unreaped identity reserves the
        // original PGID even if it has moved to another process group.
        const auto deadline = clock_type::now() + std::chrono::seconds{3};
        const auto drained = detail::drain_owned_group(
            [&]() noexcept -> std::optional<int> {
                // A competing reaper must disable all further PGID operations,
                // including when teardown follows an earlier exit observation.
                if (observe(true) != observation::exited) {
                    return std::nullopt;
                }
                return ::kill(-pid_, SIGKILL) == 0 ? 0 : errno;
            },
            [&]() noexcept { return group_has_live_members(pid_, errors_); },
            [&]() noexcept { return clock_type::now() >= deadline; },
            [&]() noexcept { return pause_tick(errors_); }
        );
        if (!drained) {
            const auto& error = drained.error();
            if (error.deferred_error != 0) {
                errors_.add("signal original owned process group", error.deferred_error);
            }
            if (error.signal_error != 0) {
                errors_.add("signal original owned process group", error.signal_error);
            }
            if (error.reason == detail::group_cleanup_failure::deadline) {
                errors_.add(
                    "ordinary descendants still live after SIGKILL (cleanup unresolved)", ETIMEDOUT
                );
            } else {
                errors_.add("ordinary descendant cleanup unresolved", EIO);
            }
        }
        if (pid_ <= 0) {
            return; // Never turn lost leader ownership into waitpid(-1).
        }
        int status = 0;
        ::pid_t waited = -1;
        do {
            waited = ::waitpid(pid_, &status, 0);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid_) {
            pid_ = -1;
            // No PID or group operations are permitted beyond this point.
            if ((!WIFEXITED(status) && !WIFSIGNALED(status)) ||
                (WIFEXITED(status) && code_ != WEXITSTATUS(status)) ||
                (WIFSIGNALED(status) && code_ != 128 + WTERMSIG(status))) {
                errors_.add("waitpid disagrees with WNOWAIT exit observation", EIO);
            }
        } else {
            const int error = waited < 0 ? errno : EIO;
            if (error == ECHILD) {
                pid_ = -1;
            }
            errors_.add("waitpid consume (owned child reap unresolved)", error);
        }
    }

    enum class observation { running, exited, failed };

    auto spawn(spawn_state& state, std::vector<char*>& argv, std::vector<char*>& env) noexcept
        -> bool {
        ::pid_t spawned = -1;
        const int rc = ::posix_spawn(
            &spawned,
            "/usr/bin/sandbox-exec",
            &state.actions,
            &state.attributes,
            argv.data(),
            env.data()
        );
        if (!check(rc, "posix_spawn /usr/bin/sandbox-exec", errors_)) {
            return false;
        }
        pid_ = spawned;
        if (pid_ <= 0) {
            errors_.add("posix_spawn did not return an owned child", EIO);
            return false;
        }
        return true;
    }

    auto observe(bool nonblocking) noexcept -> observation {
        if (pid_ <= 0) {
            return observation::failed;
        }
        siginfo_t information{};
        int rc = -1;
        do {
            rc = ::waitid(
                P_PID,
                static_cast<id_t>(pid_),
                &information,
                WEXITED | WNOWAIT | (nonblocking ? WNOHANG : 0)
            );
        } while (rc < 0 && errno == EINTR);
        if (rc != 0) {
            const int error = errno;
            if (error == ECHILD) {
                // A competing reaper broke the caller contract. Do not signal
                // a possibly reused PID/PGID, including from the destructor.
                pid_ = -1;
            }
            errors_.add("waitid WNOWAIT (owned identity/cleanup unresolved)", error);
            return observation::failed;
        }
        if (information.si_pid == 0 && nonblocking) {
            return observation::running;
        }
        if (information.si_pid != pid_ ||
            (information.si_code != CLD_EXITED && information.si_code != CLD_KILLED &&
             information.si_code != CLD_DUMPED)) {
            errors_.add("waitid WNOWAIT returned an invalid exit observation", EIO);
            return observation::failed;
        }
        observed_ = true;
        code_ =
            information.si_code == CLD_EXITED ? information.si_status : 128 + information.si_status;
        return observation::exited;
    }

    auto signal(int number) noexcept -> bool {
        if (pid_ <= 0) {
            return false;
        }
        signal_group(number);
        const auto group = ::getpgid(pid_);
        if (group < 0 && errno != ESRCH) {
            errors_.add("getpgid owned leader", errno);
        }
        if (group != pid_ || number == SIGKILL) {
            // Never signal the drifted group. Always target the owned leader
            // directly for KILL as well: it can move after getpgid, and a
            // single escalation must not leave a drifting child alive.
            if (::kill(pid_, number) != 0 && errno != ESRCH) {
                errors_.add("signal direct owned child", errno);
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto pid() const noexcept -> ::pid_t { return pid_; }

    [[nodiscard]] auto code() const noexcept -> int { return code_; }

private:
    void signal_group(int number) noexcept {
        if (pid_ > 0 && ::kill(-pid_, number) != 0 && errno != ESRCH) {
            const int error = errno;
            // Darwin can return EPERM when the reserved group consists only
            // of zombies. Suppress it only after proving no live member remains.
            if (error == EPERM) {
                const auto live = group_has_live_members(pid_, errors_);
                if (live && !*live) {
                    return;
                }
            }
            errors_.add("signal original owned process group", error);
        }
    }

    failures& errors_;
    ::pid_t pid_ = -1;
    bool observed_ = false;
    int code_ = 0;
};

auto bounded_strings(const std::vector<std::string>& strings, std::size_t& bytes) noexcept -> bool {
    for (const auto& value : strings) {
        if (value.find('\0') != std::string::npos ||
            value.size() > aggregate_limit - 1 - sizeof(char*) ||
            bytes > aggregate_limit - value.size() - 1 - sizeof(char*)) {
            return false;
        }
        bytes += value.size() + 1 + sizeof(char*);
    }
    return true;
}

auto execute(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::stop_token stop,
    std::chrono::milliseconds grace,
    failures& errors
) -> std::expected<int, std::string> {
    if (argv.empty() || argv.size() > 128) {
        return std::unexpected(std::string{"owned passthrough: argv must contain 1..128 entries"});
    }
    for (const auto& argument : argv) {
        if (argument.size() > 16U * 1024U || argument.find('\0') != std::string::npos) {
            return std::unexpected(
                std::string{"owned passthrough: invalid or oversized user argument"}
            );
        }
    }
    std::size_t input_bytes = 2 * sizeof(char*);
    if (!bounded_strings(argv, input_bytes) || !bounded_strings(prof.environment, input_bytes)) {
        return std::unexpected(
            std::string{"owned passthrough: input aggregate exceeds 192 KiB or has NUL"}
        );
    }
    stdio_snapshot stdio{errors};
    if (!stdio.capture()) {
        return 1;
    }
    const bool terminal_stdio = ::isatty(stdio.descriptor(0)) == 1;
    auto prepared = macos_detail::prepare_launch_command(prof, argv, terminal_stdio);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    if (prepared->arguments.empty() || prepared->arguments.front() != "/usr/bin/sandbox-exec" ||
        prepared->arguments.size() > 131) {
        return std::unexpected(std::string{"owned passthrough: invalid prepared launch command"});
    }
    std::size_t prepared_bytes = 2 * sizeof(char*);
    if (!bounded_strings(prepared->arguments, prepared_bytes) ||
        !bounded_strings(prepared->environment, prepared_bytes)) {
        return std::unexpected(
            std::string{"owned passthrough: prepared argv/environment exceeds 192 KiB or has NUL"}
        );
    }
    if (prepared->start_directory &&
        (prepared->start_directory->empty() ||
         prepared->start_directory->find('\0') != std::string::npos ||
         prepared->start_directory->size() >= aggregate_limit ||
         prepared_bytes > aggregate_limit - prepared->start_directory->size() - 1)) {
        return std::unexpected(
            std::string{"owned passthrough: invalid or oversized prepared directory"}
        );
    }
    std::vector<char*> arguments;
    std::vector<char*> environment;
    arguments.reserve(prepared->arguments.size() + 1);
    environment.reserve(prepared->environment.size() + 1);
    for (auto& value : prepared->arguments) {
        arguments.push_back(value.data());
    }
    for (auto& value : prepared->environment) {
        environment.push_back(value.data());
    }
    arguments.push_back(nullptr);
    environment.push_back(nullptr);

    spawn_state spawn{errors};
    if (!spawn.prepare(stdio, prepared->start_directory)) {
        return 1;
    }
    signal_state signals{errors};
    if (!signals.acquire()) {
        return 1;
    }
    // Detect unsupported ownership/inspection primitives before there is a
    // child. Never degrade to a PID-only spawn or consume-before-cleanup wait.
    siginfo_t probe{};
    int probe_rc = 0;
    do {
        probe_rc =
            ::waitid(P_PID, static_cast<id_t>(::getpid()), &probe, WEXITED | WNOWAIT | WNOHANG);
    } while (probe_rc < 0 && errno == EINTR);
    if (probe_rc != -1 || errno != ECHILD) {
        errors.add("waitid WNOWAIT ownership primitive unavailable", ENOTSUP);
        return 1;
    }
    if (!group_has_live_members(::getpgrp(), errors).has_value()) {
        return 1;
    }
    terminal_state terminal{stdio.descriptor(0), errors};
    if (!terminal.prepare()) {
        return 1;
    }
    if (stop.stop_requested()) {
        return 128 + SIGTERM;
    }
    owned_child child{errors};
    if (!child.spawn(spawn, arguments, environment)) {
        return 1;
    }
    if (!terminal.hand_to(child.pid())) {
        return 1;
    }
    if (terminal.active()) {
        // A child can reach a terminal read between spawn and tcsetpgrp. Resume
        // a possible SIGTTIN stop only after the foreground transfer succeeded.
        child.signal(SIGCONT);
    }
    std::optional<clock_type::time_point> deadline;
    int requested_signal = 0;
    bool killed = false;
    for (;;) {
        const auto pending = broker_events.take();
        for (std::size_t index = 0; index != 4; ++index) {
            if ((pending & (1U << index)) != 0) {
                child.signal(broker_signals[index]);
                if (!deadline) {
                    requested_signal = broker_signals[index];
                    deadline = clock_type::now() + grace;
                }
            }
        }
        if (stop.stop_requested() && !deadline) {
            requested_signal = SIGTERM;
            child.signal(SIGTERM);
            deadline = clock_type::now() + grace;
        }
        const auto observed = child.observe(true);
        if (observed == owned_child::observation::exited) {
            return child.code() == 0 && requested_signal != 0 ? 128 + requested_signal
                                                              : child.code();
        }
        if (observed == owned_child::observation::failed) {
            return 1;
        }
        if (deadline && !killed && clock_type::now() >= *deadline) {
            child.signal(SIGKILL);
            killed = true;
        }
        if (!errors.empty() || !pause_tick(errors)) {
            return 1;
        }
    }
}

} // namespace
#endif

auto exec_contained_owned(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::stop_token stop,
    std::chrono::milliseconds termination_grace
) -> std::expected<int, std::string> {
#if defined(__APPLE__) && defined(TARGET_OS_OSX) && TARGET_OS_OSX &&                               \
    defined(POSIX_SPAWN_CLOEXEC_DEFAULT) && defined(WNOWAIT)
    failures errors;
    std::expected<int, std::string> result;
    try {
        result = execute(
            prof,
            argv,
            stop,
            std::clamp(
                termination_grace, std::chrono::milliseconds{1}, std::chrono::milliseconds{3000}
            ),
            errors
        );
    } catch (const std::exception& exception) {
        result = std::unexpected(std::string{"owned passthrough: "} + exception.what());
    } catch (...) {
        result = std::unexpected(std::string{"owned passthrough: unexpected exception"});
    }
    if (!errors.empty()) {
        std::string diagnostic = "owned passthrough: ";
        if (!result) {
            diagnostic += result.error();
            diagnostic += "; ";
        }
        diagnostic += errors.describe();
        return std::unexpected(std::move(diagnostic));
    }
    return result;
#else
    (void)prof;
    (void)argv;
    (void)stop;
    (void)termination_grace;
    return std::unexpected(
        std::string{"owned passthrough unsupported: native macOS CLOEXEC_DEFAULT and waitid "
                    "WNOWAIT are required"}
    );
#endif
}

} // namespace glove::container
