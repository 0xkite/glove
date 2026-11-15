// Regression guard for profile::allow_loopback_listen on Linux:
// - When false (default), AF_INET socket creation fails with EPERM.
// - When true, private-loopback socket/bind/listen/getsockname on 127.0.0.1:0
//   succeeds inside CLONE_NEWNET while higher address families remain denied.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto child_check_denied() -> int {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        ::close(fd);
        std::fprintf(stderr, "expected AF_INET socket to fail when allow_loopback_listen=false\n");
        return 2;
    }
    REQUIRE(errno == EPERM);
    return 0;
}

auto child_check_allowed() -> int {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);

    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(fd, 4) == 0);

    ::sockaddr_in bound{};
    ::socklen_t len = sizeof(bound);
    REQUIRE(::getsockname(fd, reinterpret_cast<::sockaddr*>(&bound), &len) == 0);
    REQUIRE(ntohs(bound.sin_port) != 0);
    ::close(fd);

    const int inet6_fd = ::socket(AF_INET6, SOCK_STREAM, 0);
    if (inet6_fd >= 0) {
        ::close(inet6_fd);
        std::fprintf(stderr, "expected AF_INET6 socket to remain denied\n");
        return 3;
    }
    REQUIRE(errno == EPERM);
    return 0;
}

auto run_contained_mode(const std::string& self_exe, const char* mode, bool allow_loopback) -> int {
    const auto temp_base =
        std::filesystem::temp_directory_path() / ("glove_loopback_test_" + std::string{mode});
    std::error_code ec;
    std::filesystem::remove_all(temp_base, ec);
    std::filesystem::create_directories(temp_base / "home", ec);
    std::filesystem::create_directories(temp_base / "tmp", ec);

    glove::container::profile prof;
    prof.filesystem.push_back({.path = temp_base.string(), .writable = true});
    prof.filesystem.push_back(
        {.path = std::filesystem::path{self_exe}.parent_path().string(), .writable = false}
    );
    prof.home_dir = (temp_base / "home").string();
    prof.temp_dir = (temp_base / "tmp").string();
    prof.work_dir = temp_base.string();
    prof.allow_loopback_listen = allow_loopback;

    auto validated = glove::container::validate(prof);
    REQUIRE(validated.has_value());

    const std::vector<std::string> argv = {self_exe, mode};
    auto rc = glove::container::exec_contained(*validated, argv);
    std::filesystem::remove_all(temp_base, ec);
    REQUIRE(rc.has_value());
    REQUIRE(*rc == 0);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc >= 2) {
        std::string_view mode{argv[1]};
        if (mode == "--child-denied") {
            return child_check_denied();
        }
        if (mode == "--child-allowed") {
            return child_check_allowed();
        }
    }

    const auto self = std::filesystem::canonical("/proc/self/exe").string();
    if (run_contained_mode(self, "--child-denied", false) != 0) {
        return 1;
    }
    if (run_contained_mode(self, "--child-allowed", true) != 0) {
        return 1;
    }
    return 0;
}
