#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <string_view>

namespace {

constexpr int inherited_socket_fd = 3;
constexpr std::string_view expected_fd_map = R"({"status":3})";

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        return 200;
    }
    int undeclared = -1;
    const std::string_view undeclared_value{argv[1]};
    const auto [end, error] = std::from_chars(
        undeclared_value.data(), undeclared_value.data() + undeclared_value.size(), undeclared
    );
    const char* fd_map = std::getenv("GLOVE_LOCAL_SERVICE_FDS_V1");
    if (error != std::errc{} || end != undeclared_value.data() + undeclared_value.size() ||
        undeclared < inherited_socket_fd || fd_map == nullptr || fd_map != expected_fd_map) {
        return 201;
    }

    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    if (::getsockname(inherited_socket_fd, reinterpret_cast<sockaddr*>(&address), &address_size) !=
            0 ||
        address.ss_family != AF_UNIX) {
        return 202;
    }
    int socket_type = 0;
    socklen_t socket_type_size = sizeof(socket_type);
    if (::getsockopt(inherited_socket_fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_size) !=
            0 ||
        socket_type != SOCK_STREAM || socket_type_size != sizeof(socket_type)) {
        return 203;
    }
    errno = 0;
    if (::fcntl(undeclared, F_GETFD) != -1 || errno != EBADF) {
        return 204;
    }
    errno = 0;
    if (::socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM) {
        return 205;
    }
    int unsupported = 0;
    socklen_t unsupported_size = sizeof(unsupported);
    errno = 0;
    if (::getsockopt(inherited_socket_fd, SOL_SOCKET, SO_ERROR, &unsupported, &unsupported_size) !=
            -1 ||
        errno != EPERM) {
        return 206;
    }
    int local_pair[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, local_pair) != 0) {
        return 207;
    }
    sockaddr_storage local_address{};
    socklen_t local_address_size = sizeof(local_address);
    errno = 0;
    const bool outside_rejected =
        ::getsockname(
            local_pair[0], reinterpret_cast<sockaddr*>(&local_address), &local_address_size
        ) == -1 &&
        errno == EPERM;
    static_cast<void>(::close(local_pair[0]));
    static_cast<void>(::close(local_pair[1]));
    if (!outside_rejected) {
        return 208;
    }
    if (::send(inherited_socket_fd, "ping", 4, MSG_NOSIGNAL) != 4) {
        return 209;
    }
    pollfd readiness{.fd = inherited_socket_fd, .events = POLLIN, .revents = 0};
    std::array<char, 4> response{};
    if (::poll(&readiness, 1, 3'000) <= 0 ||
        ::recv(inherited_socket_fd, response.data(), response.size(), MSG_WAITALL) != 4 ||
        std::string_view{response.data(), response.size()} != "pong") {
        return 210;
    }
    return 0;
}
