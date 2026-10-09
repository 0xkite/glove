#include "glove/container/owned_passthrough.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern char** environ;

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class descriptor {
public:
    explicit descriptor(int fd) noexcept : fd_{fd} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    ~descriptor() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    auto get() const noexcept -> int { return fd_; }

private:
    int fd_;
};

class child_owner {
public:
    explicit child_owner(pid_t pid) noexcept : pid_{pid} {}

    ~child_owner() {
        if (pid_ > 0) {
            ::kill(pid_, SIGKILL);
            int status{};
            while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        }
    }

    auto reap(int& status) -> bool {
        pid_t result{};
        do {
            result = ::waitpid(pid_, &status, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result == pid_) {
            pid_ = -1;
            return true;
        }
        return false;
    }

private:
    pid_t pid_;
};

class spawn_setup {
public:
    spawn_setup()
        : actions_ready_{::posix_spawn_file_actions_init(&actions) == 0},
          attributes_ready_{::posix_spawnattr_init(&attributes) == 0} {}

    ~spawn_setup() {
        if (attributes_ready_) {
            ::posix_spawnattr_destroy(&attributes);
        }
        if (actions_ready_) {
            ::posix_spawn_file_actions_destroy(&actions);
        }
    }

    auto ready() const -> bool { return actions_ready_ && attributes_ready_; }

    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};

private:
    bool actions_ready_;
    bool attributes_ready_;
};

auto inside(const std::string& probe, const std::string& denied_terminal) -> int {
    REQUIRE(::ioctl(0, TIOCSCTTY, 0) == 0);
    REQUIRE(::tcsetpgrp(0, ::getpgrp()) == 0);
    REQUIRE(::ioctl(0, TIOCEXCL) == 0);
    REQUIRE(::ioctl(0, TIOCNXCL) == 0);
    termios before{};
    REQUIRE(::tcgetattr(0, &before) == 0);
    descriptor admission{::open(denied_terminal.c_str(), O_RDWR | O_NOCTTY | O_CLOEXEC)};
    REQUIRE(admission.get() >= 0);
    auto result = glove::container::exec_contained_owned({}, {probe, "tty", denied_terminal});
    if (!result) {
        std::fprintf(stderr, "%s\n", result.error().c_str());
    }
    if (result && *result != 0) {
        std::fprintf(stderr, "TTY probe exit code: %d\n", *result);
    }
    REQUIRE(result && *result == 0);
    REQUIRE(::tcgetpgrp(0) == ::getpgrp());
    termios after{};
    REQUIRE(::tcgetattr(0, &after) == 0);
    REQUIRE(
        before.c_iflag == after.c_iflag && before.c_oflag == after.c_oflag &&
        before.c_cflag == after.c_cflag && before.c_lflag == after.c_lflag &&
        before.c_ispeed == after.c_ispeed && before.c_ospeed == after.c_ospeed &&
        std::memcmp(before.c_cc, after.c_cc, sizeof(before.c_cc)) == 0
    );
    return 0;
}

auto outside(char* executable, char* probe) -> int {
    descriptor master{::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)};
    REQUIRE(master.get() >= 0);
    REQUIRE(::grantpt(master.get()) == 0 && ::unlockpt(master.get()) == 0);
    const auto* path = ::ptsname(master.get());
    REQUIRE(path != nullptr);
    descriptor slave{::open(path, O_RDWR | O_NOCTTY | O_CLOEXEC)};
    REQUIRE(slave.get() >= 0);
    spawn_setup setup;
    REQUIRE(setup.ready());
    for (int target = 0; target != 3; ++target) {
        REQUIRE(::posix_spawn_file_actions_adddup2(&setup.actions, slave.get(), target) == 0);
        REQUIRE(::posix_spawn_file_actions_addinherit_np(&setup.actions, target) == 0);
    }
    REQUIRE(
        ::posix_spawnattr_setflags(
            &setup.attributes, POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT
        ) == 0
    );
    descriptor other_master{::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)};
    REQUIRE(other_master.get() >= 0);
    REQUIRE(::grantpt(other_master.get()) == 0 && ::unlockpt(other_master.get()) == 0);
    const auto* other_name = ::ptsname(other_master.get());
    REQUIRE(other_name != nullptr);
    std::string denied_terminal{other_name};
    char mode[] = "--inside";
    char* arguments[]{executable, mode, probe, denied_terminal.data(), nullptr};
    pid_t pid = -1;
    REQUIRE(
        ::posix_spawn(&pid, executable, &setup.actions, &setup.attributes, arguments, environ) == 0
    );
    child_owner child{pid};
    bool supplied = false;
    std::string output;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd input{.fd = master.get(), .events = POLLIN, .revents = 0};
        if (::poll(&input, 1, 20) > 0 && (input.revents & POLLIN) != 0) {
            char buffer[256]{};
            const auto count = ::read(master.get(), buffer, sizeof(buffer));
            if (count > 0) {
                output.append(buffer, static_cast<std::size_t>(count));
                REQUIRE(output.size() <= 16384);
            }
        }
        if (!supplied && output.find("READY") != std::string::npos) {
            REQUIRE(::write(master.get(), "ok\n", 3) == 3);
            supplied = true;
        }
        int status{};
        if (child.reap(status)) {
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                std::fprintf(stderr, "%s\n", output.c_str());
            }
            REQUIRE(supplied && WIFEXITED(status) && WEXITSTATUS(status) == 0);
            return 0;
        }
    }
    std::fprintf(stderr, "PTY timeout: %s\n", output.c_str());
    return 1;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 4 && std::string{argv[1]} == "--inside") {
        return inside(argv[2], argv[3]);
    }
    if (argc != 2) {
        return 2;
    }
    return outside(argv[0], argv[1]);
}
