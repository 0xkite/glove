#include "glove/container/owned_passthrough.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

extern char** environ;

namespace {
auto checked(int error, const char* operation) -> bool {
    if (error == 0) {
        return true;
    }
    std::fprintf(stderr, "%s failed: %d\n", operation, error);
    return false;
}

class spawn_setup {
public:
    explicit spawn_setup(bool& cleanup_ok) noexcept : cleanup_ok_{cleanup_ok} {}

    spawn_setup(const spawn_setup&) = delete;
    auto operator=(const spawn_setup&) -> spawn_setup& = delete;

    ~spawn_setup() { destroy(); }

    auto initialize() -> bool {
        actions_live_ = checked(::posix_spawn_file_actions_init(&actions), "file_actions_init");
        if (!actions_live_) {
            return false;
        }
        attributes_live_ = checked(::posix_spawnattr_init(&attributes), "spawnattr_init");
        return attributes_live_;
    }

    void destroy() noexcept {
        if (attributes_live_) {
            if (!checked(::posix_spawnattr_destroy(&attributes), "spawnattr_destroy")) {
                cleanup_ok_ = false;
            }
            attributes_live_ = false;
        }
        if (actions_live_) {
            if (!checked(::posix_spawn_file_actions_destroy(&actions), "file_actions_destroy")) {
                cleanup_ok_ = false;
            }
            actions_live_ = false;
        }
    }

    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};

private:
    bool& cleanup_ok_;
    bool actions_live_{false};
    bool attributes_live_{false};
};

// Covers only the direct child and its original process group, not escaped descendants.
class child_owner {
public:
    child_owner(pid_t pid, bool& cleanup_ok) noexcept : pid_{pid}, cleanup_ok_{cleanup_ok} {}

    child_owner(const child_owner&) = delete;
    auto operator=(const child_owner&) -> child_owner& = delete;

    ~child_owner() {
        if (pid_ <= 0) {
            return;
        }
        // Signal while the unreaped direct child still reserves this PID/PGID.
        signal(-pid_);
        signal(pid_);
        int status{};
        pid_t reaped{};
        do {
            reaped = ::waitpid(pid_, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        if (reaped != pid_) {
            checked(errno, "cleanup waitpid");
            cleanup_ok_ = false;
        }
        pid_ = -1;
    }

    void release() noexcept { pid_ = -1; }

private:
    void signal(pid_t target) noexcept {
        if (::kill(target, SIGKILL) != 0 && errno != ESRCH) {
            checked(errno, "cleanup kill");
            cleanup_ok_ = false;
        }
    }

    pid_t pid_;
    bool& cleanup_ok_;
};

auto run_mask(const std::string& self, const std::string& probe, int mask, bool& cleanup_ok)
    -> bool {
    auto mask_text = std::to_string(mask);
    std::string mode{"--closed"};
    std::array<char*, 5> arguments{
        const_cast<char*>(self.c_str()),
        mode.data(),
        mask_text.data(),
        const_cast<char*>(probe.c_str()),
        nullptr
    };
    spawn_setup setup{cleanup_ok};
    if (!setup.initialize()) {
        return false;
    }
    for (int fd = 0; fd < 3; ++fd) {
        if (::fcntl(fd, F_GETFD) < 0) {
            checked(errno, "parent stdio F_GETFD");
            return false;
        }
        const int error = (mask & (1 << fd)) != 0
                              ? ::posix_spawn_file_actions_addclose(&setup.actions, fd)
                              : ::posix_spawn_file_actions_addinherit_np(&setup.actions, fd);
        if (!checked(error, "stdio file action")) {
            return false;
        }
    }
    constexpr short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP;
    if (!checked(::posix_spawnattr_setflags(&setup.attributes, flags), "spawnattr_setflags") ||
        !checked(::posix_spawnattr_setpgroup(&setup.attributes, 0), "spawnattr_setpgroup")) {
        return false;
    }
    pid_t pid{-1};
    if (!checked(
            ::posix_spawn(
                &pid, self.c_str(), &setup.actions, &setup.attributes, arguments.data(), environ
            ),
            "posix_spawn"
        )) {
        return false;
    }
    child_owner child{pid, cleanup_ok};
    setup.destroy();
    if (!cleanup_ok) {
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::fprintf(stderr, "closed stdio mask %d timed out\n", mask);
            return false;
        }
        int status{};
        const auto reaped = ::waitpid(pid, &status, WNOHANG);
        if (reaped == pid) {
            child.release();
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                std::fprintf(stderr, "closed stdio mask %d failed: status %d\n", mask, status);
                return false;
            }
            return true;
        }
        if (reaped < 0 && errno != EINTR) {
            const int error = errno;
            // ECHILD means ownership has already been lost; never signal a reused PID.
            if (error == ECHILD) {
                child.release();
            }
            checked(error, "waitpid");
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 4 && std::string_view{argv[1]} == "--closed") {
        const std::string_view mask{argv[2]};
        if (mask.size() != 1 || mask[0] < '1' || mask[0] > '7') {
            return 2;
        }
        const int closed = mask[0] - '0';
        for (int fd = 0; fd < 3; ++fd) {
            const int result = ::fcntl(fd, F_GETFD);
            if ((closed & (1 << fd)) != 0) {
                if (result != -1 || errno != EBADF) {
                    return 3;
                }
            } else if (result < 0) {
                return 3;
            }
        }
        const auto result = glove::container::exec_contained_owned(
            glove::container::profile{}, {argv[3], "exit", "0"}
        );
        return !result && result.error().find("stdio must be open before launch preparation") !=
                              std::string::npos
                   ? 0
                   : 1;
    }
    if (argc != 2) {
        return 2;
    }
    std::error_code error;
    const auto self = std::filesystem::canonical(argv[0], error);
    if (error || !self.is_absolute()) {
        std::fprintf(stderr, "cannot resolve absolute self path\n");
        return 1;
    }
    for (int mask = 1; mask <= 7; ++mask) {
        bool cleanup_ok{true};
        const bool passed = run_mask(self.string(), argv[1], mask, cleanup_ok);
        if (!passed || !cleanup_ok) {
            return 1;
        }
    }
    return 0;
}
