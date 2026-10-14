#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string_view>

namespace {
auto number(const char* text, std::uint64_t& value) -> bool {
    const auto length = ::strnlen(text, 32);
    if (length == 0 || length == 32) {
        return false;
    }
    const auto result = std::from_chars(text, text + length, value);
    return result.ec == std::errc{} && result.ptr == text + length;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2 || argc > 5) {
        return 2;
    }
    const std::string_view mode{argv[1]};
    if (mode == "exit" && argc == 3) {
        std::uint64_t value = 0;
        return number(argv[2], value) && value < 128 ? static_cast<int>(value) : 2;
    }
    if (mode == "fd" && argc == 5) {
        std::uint64_t fd = 0, device = 0, inode = 0;
        if (!number(argv[2], fd) || fd > 1024 || !number(argv[3], device) ||
            !number(argv[4], inode)) {
            return 2;
        }
        struct stat metadata{};
        if (::fstat(static_cast<int>(fd), &metadata) != 0) {
            return errno == EBADF ? 0 : 3;
        }
        return static_cast<std::uint64_t>(metadata.st_dev) == device &&
                       static_cast<std::uint64_t>(metadata.st_ino) == inode
                   ? 4
                   : 0;
    }
    if (mode == "tty" && argc == 2) {
        if (!::isatty(STDIN_FILENO) || ::tcgetpgrp(STDIN_FILENO) != ::getpgrp()) {
            return 5;
        }
        pollfd input{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0};
        if (::poll(&input, 1, 2000) != 1) {
            return 6;
        }
        char bytes[16]{};
        const auto count = ::read(STDIN_FILENO, bytes, sizeof(bytes));
        return count >= 2 && bytes[0] == 'o' && bytes[1] == 'k' ? 0 : 7;
    }
    if ((mode == "stubborn" && argc == 2) || (mode == "drift" && argc == 3)) {
        if (mode == "drift") {
            std::uint64_t group = 0;
            if (!number(argv[2], group) || group == 0 || group > 2147483647 ||
                ::setpgid(0, static_cast<pid_t>(group)) != 0) {
                return 8;
            }
        }
        struct sigaction ignored{};
        ignored.sa_handler = SIG_IGN;
        if ((::sigemptyset)(&ignored.sa_mask) != 0) {
            return 9;
        }
        for (const int signal : {SIGINT, SIGTERM, SIGHUP}) {
            if (::sigaction(signal, &ignored, nullptr) != 0) {
                return 9;
            }
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (std::chrono::steady_clock::now() < deadline) {
            ::poll(nullptr, 0, 20);
        }
        return 42;
    }
    return 2;
}
