#pragma once

#include "stdio_admission.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace glove::container::owned_detail {

// Fixed storage permits checked, nonthrowing disposal during stack unwinding.
// Error strings are assembled only after all owners have left scope.
class failures {
public:
    void add(const char* operation, int code) noexcept {
        if (used_ < entries_.size()) {
            entries_[used_++] = {operation, code};
        } else {
            overflow_ = true;
        }
    }

    [[nodiscard]] auto empty() const noexcept -> bool { return used_ == 0 && !overflow_; }

    [[nodiscard]] auto describe() const -> std::string {
        std::string result;
        for (std::size_t i = 0; i < used_; ++i) {
            if (!result.empty()) {
                result += "; ";
            }
            result += entries_[i].operation;
            result += ": ";
            result += std::strerror(entries_[i].code);
        }
        if (overflow_) {
            result += "; additional cleanup failures (diagnostic capacity exceeded)";
        }
        return result;
    }

private:
    struct entry {
        const char* operation = nullptr;
        int code = 0;
    };

    std::array<entry, 32> entries_{};
    std::size_t used_ = 0;
    bool overflow_ = false;
};

inline auto check(int rc, const char* operation, failures& errors) noexcept -> bool {
    if (rc != 0) {
        errors.add(operation, rc);
        return false;
    }
    return true;
}

inline auto check_syscall(int rc, const char* operation, failures& errors) noexcept -> bool {
    return rc == 0 || check(errno, operation, errors);
}

class stdio_snapshot {
public:
    explicit stdio_snapshot(failures& errors) noexcept : errors_{errors} {}

    stdio_snapshot(const stdio_snapshot&) = delete;
    auto operator=(const stdio_snapshot&) -> stdio_snapshot& = delete;
    stdio_snapshot(stdio_snapshot&&) = delete;
    auto operator=(stdio_snapshot&&) -> stdio_snapshot& = delete;

    ~stdio_snapshot() noexcept {
        for (auto& fd : descriptors_) {
            if (fd >= 0) {
                // Do not retry close: EINTR must not close a subsequently reused fd.
                check_syscall(::close(std::exchange(fd, -1)), "close stdio snapshot", errors_);
            }
        }
    }

    auto capture() noexcept -> bool {
        // This precedes policy preparation, which can open descriptors. A closed
        // stdio slot must never be filled by a policy FD and then inherited.
        if (const int error = detail::stdio_admission_error(); error != 0) {
            errors_.add(detail::stdio_admission_message, error);
            return false;
        }
        for (int fd = 0; fd != 3; ++fd) {
            descriptors_[static_cast<std::size_t>(fd)] = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
            if (descriptors_[static_cast<std::size_t>(fd)] < 0) {
                errors_.add("F_DUPFD_CLOEXEC stdio snapshot", errno);
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto descriptor(std::size_t index) const noexcept -> int {
        return descriptors_[index];
    }

private:
    failures& errors_;
    std::array<int, 3> descriptors_{-1, -1, -1};
};

class spawn_state {
public:
    explicit spawn_state(failures& errors) noexcept : errors_{errors} {}

    spawn_state(const spawn_state&) = delete;
    auto operator=(const spawn_state&) -> spawn_state& = delete;
    spawn_state(spawn_state&&) = delete;
    auto operator=(spawn_state&&) -> spawn_state& = delete;

    ~spawn_state() noexcept {
        if (attributes_ready_) {
            check(::posix_spawnattr_destroy(&attributes), "spawnattr_destroy", errors_);
        }
        if (actions_ready_) {
            check(::posix_spawn_file_actions_destroy(&actions), "file_actions_destroy", errors_);
        }
    }

    auto prepare(const stdio_snapshot& stdio, const std::optional<std::string>& directory) noexcept
        -> bool {
        actions_ready_ =
            check(::posix_spawn_file_actions_init(&actions), "file_actions_init", errors_);
        if (!actions_ready_) {
            return false;
        }
        attributes_ready_ = check(::posix_spawnattr_init(&attributes), "spawnattr_init", errors_);
        if (!attributes_ready_) {
            return false;
        }
        for (std::size_t index = 0; index != 3; ++index) {
            const int target = static_cast<int>(index);
            if (!check(
                    ::posix_spawn_file_actions_adddup2(&actions, stdio.descriptor(index), target),
                    "file_actions_adddup2 stdio",
                    errors_
                ) ||
                !check(
                    ::posix_spawn_file_actions_addinherit_np(&actions, target),
                    "file_actions_addinherit_np stdio",
                    errors_
                ) ||
                !check(
                    ::posix_spawn_file_actions_addclose(&actions, stdio.descriptor(index)),
                    "file_actions_addclose stdio snapshot",
                    errors_
                )) {
                return false;
            }
        }
        if (directory) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            const int rc = ::posix_spawn_file_actions_addchdir_np(&actions, directory->c_str());
#pragma clang diagnostic pop
            if (!check(rc, "file_actions_addchdir_np", errors_)) {
                return false;
            }
        }
        sigset_t mask{};
        sigset_t defaults{};
        if (!check_syscall((::sigemptyset)(&mask), "child sigemptyset", errors_) ||
            !check_syscall((::sigfillset)(&defaults), "child sigfillset", errors_) ||
            !check_syscall((::sigdelset)(&defaults, SIGKILL), "child sigdelset KILL", errors_) ||
            !check_syscall((::sigdelset)(&defaults, SIGSTOP), "child sigdelset STOP", errors_)) {
            return false;
        }
        constexpr short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP |
                                POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
        return check(::posix_spawnattr_setpgroup(&attributes, 0), "spawnattr_setpgroup", errors_) &&
               check(
                   ::posix_spawnattr_setsigmask(&attributes, &mask), "spawnattr_setsigmask", errors_
               ) &&
               check(
                   ::posix_spawnattr_setsigdefault(&attributes, &defaults),
                   "spawnattr_setsigdefault",
                   errors_
               ) &&
               check(::posix_spawnattr_setflags(&attributes, flags), "spawnattr_setflags", errors_);
    }

    ::posix_spawn_file_actions_t actions{};
    ::posix_spawnattr_t attributes{};

private:
    failures& errors_;
    bool actions_ready_ = false;
    bool attributes_ready_ = false;
};

} // namespace glove::container::owned_detail
