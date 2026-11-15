#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace {
auto ready(const char* path) -> bool {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    const bool written = ::write(fd, "ready", 5) == 5;
    return ::close(fd) == 0 && written;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        return 2;
    }
    const std::string_view mode{argv[1]};
    if (mode == "tty" && argc == 3) {
        const auto foreground = ::tcgetpgrp(0);
        if (foreground < 0) {
            return errno == EPERM || errno == EACCES ? 31 : 32;
        }
        if (foreground != ::getpgrp()) {
            return 33;
        }
        errno = 0;
        if (::ioctl(0, TIOCEXCL) == 0 || (errno != EPERM && errno != EACCES)) {
            return 34;
        }
        const int unrelated = ::open(argv[2], O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (unrelated >= 0) {
            ::close(unrelated);
            return 35;
        }
        if (errno != EPERM && errno != EACCES) {
            return 36;
        }
        termios settings{};
        if (::tcgetattr(0, &settings) != 0) {
            return 4;
        }
        settings.c_lflag ^= ECHO;
        if (::tcsetattr(0, TCSANOW, &settings) != 0 || ::write(1, "READY\n", 6) != 6) {
            return 5;
        }
        pollfd input{.fd = 0, .events = POLLIN, .revents = 0};
        if (::poll(&input, 1, 2000) != 1) {
            return 6;
        }
        char bytes[32]{};
        const auto count = ::read(0, bytes, sizeof(bytes));
        return count >= 2 && bytes[0] == 'o' && bytes[1] == 'k' ? 0 : 7;
    }
    if (argc != 3 && argc != 4) {
        return 2;
    }
    if (mode == "drift") {
        if (argc != 4) {
            return 2;
        }
        int group = 0;
        const auto end = argv[3] + ::strnlen(argv[3], 16);
        const auto parsed = std::from_chars(argv[3], end, group);
        if (parsed.ec != std::errc{} || parsed.ptr != end || group <= 0 ||
            ::setpgid(0, group) != 0) {
            return 8;
        }
    } else if (mode != "stubborn" && mode != "signal" && mode != "descendant") {
        return 2;
    }
    if (mode != "signal") {
        struct sigaction ignore{};
        ignore.sa_handler = SIG_IGN;
        if ((::sigemptyset)(&ignore.sa_mask) != 0 || ::sigaction(SIGTERM, &ignore, nullptr) != 0 ||
            ::sigaction(SIGINT, &ignore, nullptr) != 0 ||
            ::sigaction(SIGHUP, &ignore, nullptr) != 0) {
            return 9;
        }
    }
    if (mode == "descendant") {
        const auto child = ::fork();
        if (child < 0) {
            return 10;
        }
        if (child > 0) {
            return ready(argv[2]) ? 0 : 11;
        }
    } else if (!ready(argv[2])) {
        return 11;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline) {
        ::poll(nullptr, 0, 10);
    }
    return 42;
}
