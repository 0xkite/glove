#include "dependency_command.hpp"

#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>

#if defined(__APPLE__)
#    include <libproc.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>

extern char** environ;

namespace glove::host::detail {
namespace {

constexpr std::size_t max_output_bytes = std::size_t{1024} * 1024U;
constexpr auto poll_interval = std::chrono::milliseconds{25};

auto system_error(std::string_view operation, int code = errno) -> std::string {
    return std::string{operation} + ": " + std::error_code{code, std::generic_category()}.message();
}

class unique_fd {
public:
    explicit unique_fd(int descriptor) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;
    unique_fd(unique_fd&&) = delete;
    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() { reset(); }

    void reset() noexcept {
        if (const int descriptor = std::exchange(descriptor_, -1); descriptor >= 0) {
            (void)::close(descriptor);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_;
};

struct spawn_configuration {
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};
    int actions_error = ::posix_spawn_file_actions_init(&actions);
    int attributes_error = actions_error == 0 ? ::posix_spawnattr_init(&attributes) : actions_error;

    spawn_configuration() = default;
    spawn_configuration(const spawn_configuration&) = delete;
    auto operator=(const spawn_configuration&) -> spawn_configuration& = delete;
    spawn_configuration(spawn_configuration&&) = delete;
    auto operator=(spawn_configuration&&) -> spawn_configuration& = delete;

    ~spawn_configuration() {
        if (attributes_error == 0) {
            (void)::posix_spawnattr_destroy(&attributes);
        }
        if (actions_error == 0) {
            (void)::posix_spawn_file_actions_destroy(&actions);
        }
    }
};

auto child_is_terminal(pid_t process) noexcept -> bool {
    siginfo_t observation{};
    return ::waitid(P_PID, static_cast<id_t>(process), &observation, WEXITED | WNOHANG | WNOWAIT) ==
               0 &&
           observation.si_pid == process;
}

auto sole_exited_group_leader(pid_t process) noexcept -> bool {
#if defined(__APPLE__)
    // Darwin killpg reports EPERM for a zombie-only group. Accept that case
    // only when our unreaped child is terminal and the entire bounded group
    // listing contains that child alone. Unknown/live members remain errors.
    if (!child_is_terminal(process)) {
        return false;
    }
    std::array<pid_t, 2> members{};
    const int bytes = ::proc_listpids(
        PROC_PGRP_ONLY, static_cast<std::uint32_t>(process), members.data(), sizeof(members)
    );
    return bytes == static_cast<int>(sizeof(pid_t)) && members.front() == process;
#else
    (void)process;
    return false;
#endif
}

struct stopped_command {
    int status = 0;
    int group_error = 0;
    int leader_error = 0;
    int wait_error = 0;
};

class owned_child {
public:
    explicit owned_child(pid_t process) noexcept : process_{process} {}

    owned_child(const owned_child&) = delete;
    auto operator=(const owned_child&) -> owned_child& = delete;
    owned_child(owned_child&&) = delete;
    auto operator=(owned_child&&) -> owned_child& = delete;

    ~owned_child() {
        if (process_ > 0) {
            (void)stop();
        }
    }

    auto stop() noexcept -> stopped_command {
        // Retain the unreaped leader through both signals: neither its PID
        // nor the original PGID can be recycled while we own this child wait.
        stopped_command result;
        if (::kill(-process_, SIGKILL) != 0) {
            const int error = errno;
            if (error != ESRCH && (error != EPERM || !sole_exited_group_leader(process_))) {
                result.group_error = error;
            }
        }
        // A leader can leave its original group. Signal the still-owned
        // child directly as well; group ESRCH alone does not prove its death.
        if (::kill(process_, SIGKILL) != 0) {
            const int error = errno;
            if (!child_is_terminal(process_)) {
                result.leader_error = error;
            }
        }
        pid_t waited = -1;
        do {
            waited = ::waitpid(process_, &result.status, result.leader_error == 0 ? 0 : WNOHANG);
        } while (waited < 0 && errno == EINTR);
        result.wait_error = waited < 0 ? errno : (waited == 0 ? EAGAIN : 0);
        if (waited > 0 || result.wait_error == ECHILD) {
            process_ = -1;
        }
        // Error formatting stays outside this no-throw emergency cleanup path.
        // A genuine permission failure is reported, never waited indefinitely
        // or misrepresented as successful termination.
        return result;
    }

private:
    pid_t process_;
};

auto configure_spawn(spawn_configuration& configuration, int reader, int writer)
    -> std::expected<void, std::string> {
    if (configuration.actions_error != 0 || configuration.attributes_error != 0) {
        return std::unexpected(std::string{"initialize dependency command spawn state"});
    }
    sigset_t empty_mask{};
    sigset_t default_signals{};
    if (sigemptyset(&empty_mask) != 0 || sigemptyset(&default_signals) != 0) {
        return std::unexpected(system_error("initialize dependency command signals"));
    }
    for (const int signal : {SIGPIPE, SIGINT, SIGTERM, SIGHUP}) {
        if (sigaddset(&default_signals, signal) != 0) {
            return std::unexpected(system_error("configure dependency command signals"));
        }
    }
    short flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
#if defined(__APPLE__)
    flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
    const std::array results{
        ::posix_spawn_file_actions_adddup2(&configuration.actions, writer, STDOUT_FILENO),
        ::posix_spawn_file_actions_addclose(&configuration.actions, reader),
        ::posix_spawn_file_actions_addclose(&configuration.actions, writer),
        ::posix_spawn_file_actions_addopen(
            &configuration.actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0
        ),
        ::posix_spawn_file_actions_addopen(
            &configuration.actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0
        ),
        ::posix_spawnattr_setpgroup(&configuration.attributes, 0),
        ::posix_spawnattr_setsigmask(&configuration.attributes, &empty_mask),
        ::posix_spawnattr_setsigdefault(&configuration.attributes, &default_signals),
        ::posix_spawnattr_setflags(&configuration.attributes, flags),
    };
    if (const auto failed = std::ranges::find_if(results, [](int result) { return result != 0; });
        failed != results.end()) {
        return std::unexpected(system_error("configure dependency command", *failed));
    }
    return {};
}

auto collect_output(int reader, pid_t process, std::chrono::steady_clock::time_point deadline)
    -> std::expected<std::string, std::string> {
    std::string output;
    std::array<char, 4096> buffer{};
    bool eof = false;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!eof) {
            const auto count = ::read(reader, buffer.data(), buffer.size());
            if (count > 0) {
                const auto bytes = static_cast<std::size_t>(count);
                if (bytes > max_output_bytes - output.size()) {
                    return std::unexpected(std::string{"dependency command exceeded output limit"});
                }
                output.append(buffer.data(), bytes);
                // Check the absolute deadline between reads even when a
                // continuously writing child keeps the pipe ready.
                continue;
            }
            if (count == 0) {
                eof = true;
            } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                return std::unexpected(system_error("read dependency command"));
            }
        }
        siginfo_t observation{};
        if (::waitid(
                P_PID, static_cast<id_t>(process), &observation, WEXITED | WNOHANG | WNOWAIT
            ) != 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error("observe dependency command"));
        }
        if (eof && observation.si_pid == process) {
            return output;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()
        );
        const auto wait = std::clamp(remaining, std::chrono::milliseconds{0}, poll_interval);
        pollfd event{.fd = reader, .events = POLLIN, .revents = 0};
        if (::poll(eof ? nullptr : &event, eof ? 0U : 1U, static_cast<int>(wait.count())) < 0 &&
            errno != EINTR) {
            return std::unexpected(system_error("poll dependency command"));
        }
        if ((event.revents & POLLNVAL) != 0) {
            return std::unexpected(std::string{"dependency command pipe became invalid"});
        }
    }
    return std::unexpected(std::string{"dependency command timed out"});
}

} // namespace

auto capture_dependency_command(
    const std::filesystem::path& executable,
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout
) -> std::expected<std::string, std::string> {
    if (timeout <= std::chrono::milliseconds{0} || timeout > std::chrono::seconds{30}) {
        return std::unexpected(std::string{"dependency command deadline must be 1 ms to 30 s"});
    }
    if (!executable.is_absolute() || executable.native().size() > 4096U ||
        executable.native().contains('\0') || arguments.size() > 16U ||
        std::ranges::any_of(arguments, [](const auto& argument) {
            return argument.size() > 4096U || argument.contains('\0');
        })) {
        return std::unexpected(std::string{"invalid dependency command arguments"});
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<int, 2> pipe{-1, -1};
    if (::pipe(pipe.data()) != 0) {
        return std::unexpected(system_error("create dependency command pipe"));
    }
    unique_fd original_reader{pipe.front()};
    unique_fd original_writer{pipe.back()};
    // Closed standard descriptors must not alias a spawn action's pipe FD.
    const int read_copy = ::fcntl(original_reader.get(), F_DUPFD_CLOEXEC, 3);
    if (read_copy < 0) {
        return std::unexpected(system_error("protect dependency command reader"));
    }
    const unique_fd reader{read_copy};
    const int write_copy = ::fcntl(original_writer.get(), F_DUPFD_CLOEXEC, 3);
    if (write_copy < 0) {
        return std::unexpected(system_error("protect dependency command writer"));
    }
    unique_fd writer{write_copy};
    original_reader.reset();
    original_writer.reset();
    if (::fcntl(reader.get(), F_SETFL, O_NONBLOCK) < 0) {
        return std::unexpected(system_error("protect dependency command reader"));
    }
    spawn_configuration configuration;
    if (auto configured = configure_spawn(configuration, reader.get(), writer.get()); !configured) {
        return std::unexpected(configured.error());
    }
    std::vector<std::string> owned_argv{executable.string()};
    owned_argv.insert(owned_argv.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(owned_argv.size() + 1U);
    for (auto& argument : owned_argv) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);
    pid_t process = -1;
    const int spawned = ::posix_spawn(
        &process,
        executable.c_str(),
        &configuration.actions,
        &configuration.attributes,
        argv.data(),
        environ
    );
    if (spawned != 0) {
        return std::unexpected(system_error("launch dependency command", spawned));
    }
    owned_child child{process};
    writer.reset();
    auto output = collect_output(reader.get(), process, deadline);
    auto stopped = child.stop();
    if (stopped.leader_error != 0) {
        return std::unexpected(
            system_error("terminate dependency command leader", stopped.leader_error)
        );
    }
    if (stopped.group_error != 0) {
        return std::unexpected(
            system_error("terminate dependency command group", stopped.group_error)
        );
    }
    if (stopped.wait_error != 0) {
        return std::unexpected(system_error("reap dependency command", stopped.wait_error));
    }
    if (!output) {
        return std::unexpected(output.error());
    }
    if (!WIFEXITED(stopped.status) || WEXITSTATUS(stopped.status) != 0) {
        return std::unexpected(std::string{"dependency command failed"});
    }
    return output;
}

} // namespace glove::host::detail
