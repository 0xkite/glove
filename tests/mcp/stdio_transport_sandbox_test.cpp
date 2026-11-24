#if defined(__linux__)
#    include "glove/mcp/stdio_transport.hpp"

#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <poll.h>
#    include <sys/socket.h>
#    include <unistd.h>

#    include <atomic>
#    include <cstdint>
#    include <cstdio>
#    include <string>
#    include <string_view>
#    include <thread>
#    include <vector>

namespace {

// The product refuses to build a sandbox as host root and depends on a kernel
// that permits unprivileged user namespaces. Neither is a product defect, so a
// host without that capability reports a skip instead of a failure. Anything
// else - including a partial sandbox or a prctl() refusal - is a regression and
// must fail.
auto environment_skip(std::string_view error) -> bool {
    constexpr std::string_view unsupported[] = {
        "stdio_transport sandbox refuses to run as host root",
        "unshare:",
        "sandboxed spawn: write /proc/self/setgroups failed",
        "sandboxed spawn: write /proc/self/uid_map failed",
        "sandboxed spawn: write /proc/self/gid_map failed",
    };
    for (const auto prefix : unsupported) {
        if (error.starts_with(prefix)) {
            return true;
        }
    }
    return false;
}

} // namespace

// NDEBUG builds compile assert() out, so this test never relies on it.
// Dereferencing an errored expected<T> is undefined behaviour, which is how
// this test previously "passed" as a UBSan misaligned-call report.
#    define REQUIRE(cond)                                                                          \
        do {                                                                                       \
            if (!(cond)) {                                                                         \
                std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);   \
                return 1;                                                                          \
            }                                                                                      \
        } while (0)

int main() {
    glove::mcp::stdio_child_options opts{
        .program = "/bin/sh",
        .args =
            {"/bin/sh",
             "-c",
             "grep '^NoNewPrivs:' /proc/self/status; readlink /proc/self/ns/net; id -u"},
        .environment = {"PATH=/usr/bin:/bin"},
        .sandbox = {.enabled = true, .allow_network = false},
    };
    auto transport = glove::mcp::make_stdio_transport(opts);
    if (!transport) {
        const auto& error = transport.error();
        if (environment_skip(error)) {
            std::fprintf(
                stderr, "SKIP: sandboxed stdio transport unavailable: %s\n", error.c_str()
            );
            return 77;
        }
        std::fprintf(
            stderr, "FAIL: unexpected sandboxed stdio transport error: %s\n", error.c_str()
        );
        return 1;
    }

    auto nnp_line = (*transport)->recv();
    REQUIRE(nnp_line.has_value());
    REQUIRE(nnp_line->find("NoNewPrivs:\t1") != std::string::npos);

    auto ns_line = (*transport)->recv();
    REQUIRE(ns_line.has_value());
    REQUIRE(ns_line->find("net:[") != std::string::npos);

    auto uid_line = (*transport)->recv();
    REQUIRE(uid_line.has_value());
    REQUIRE(*uid_line == std::to_string(::geteuid()));

    // Refusals: port 0 and >16 service ports must fail closed.
    {
        glove::mcp::stdio_child_options zero_port = opts;
        zero_port.sandbox.service_ports = {0};
        REQUIRE(!glove::mcp::make_stdio_transport(zero_port).has_value());

        glove::mcp::stdio_child_options too_many = opts;
        too_many.sandbox.service_ports.clear();
        for (std::uint16_t p = 18000; p < 18017; ++p) {
            too_many.sandbox.service_ports.push_back(p);
        }
        REQUIRE(!glove::mcp::make_stdio_transport(too_many).has_value());
    }

    // Forwarded service_ports inside CLONE_NEWNET: allowed port reachable,
    // unlisted host loopback port refused.
    auto start_listener = [](int& out_fd, std::uint16_t& out_port) -> bool {
        out_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (out_fd < 0) {
            return false;
        }
        ::sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::socklen_t len = sizeof(addr);
        if (::bind(out_fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(out_fd, 4) != 0 ||
            ::getsockname(out_fd, reinterpret_cast<::sockaddr*>(&addr), &len) != 0) {
            ::close(out_fd);
            out_fd = -1;
            return false;
        }
        out_port = ntohs(addr.sin_port);
        return true;
    };

    int allowed_fd = -1;
    int blocked_fd = -1;
    std::uint16_t allowed_port = 0;
    std::uint16_t blocked_port = 0;
    REQUIRE(start_listener(allowed_fd, allowed_port));
    REQUIRE(start_listener(blocked_fd, blocked_port));

    std::atomic<bool> stop_server{false};
    std::thread server([&] {
        while (!stop_server.load(std::memory_order_relaxed)) {
            ::pollfd pfd{.fd = allowed_fd, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 50) <= 0 || (pfd.revents & POLLIN) == 0) {
                continue;
            }
            const int client = ::accept4(allowed_fd, nullptr, nullptr, SOCK_CLOEXEC);
            if (client >= 0) {
                static constexpr char kMsg[] = "UPSTREAM_OK\n";
                (void)::send(client, kMsg, sizeof(kMsg) - 1U, MSG_NOSIGNAL);
                (void)::shutdown(client, SHUT_RDWR);
                ::close(client);
            }
        }
    });

    const std::string py_probe = "import socket, sys\n"
                                 "def check(p):\n"
                                 "  s = socket.socket()\n"
                                 "  s.settimeout(2)\n"
                                 "  try:\n"
                                 "    s.connect(('127.0.0.1', p))\n"
                                 "    return s.recv(64).decode().strip()\n"
                                 "  except OSError:\n"
                                 "    return 'REFUSED'\n"
                                 "  finally:\n"
                                 "    s.close()\n"
                                 "print(check(" +
                                 std::to_string(allowed_port) + ") + '|' + check(" +
                                 std::to_string(blocked_port) + "))\n";

    glove::mcp::stdio_child_options svc_opts{
        .program = "/usr/bin/python3",
        .args = {"/usr/bin/python3", "-c", py_probe},
        .environment = {"PATH=/usr/bin:/bin"},
        .sandbox = {.enabled = true, .allow_network = false, .service_ports = {allowed_port}},
    };
    auto svc_transport = glove::mcp::make_stdio_transport(svc_opts);
    REQUIRE(svc_transport.has_value());
    auto svc_line = (*svc_transport)->recv();
    stop_server.store(true, std::memory_order_relaxed);
    (void)::shutdown(allowed_fd, SHUT_RDWR);
    server.join();
    ::close(allowed_fd);
    ::close(blocked_fd);
    REQUIRE(svc_line.has_value());
    REQUIRE(*svc_line == "UPSTREAM_OK|REFUSED");
    return 0;
}
#else
int main() {
    return 0;
}
#endif
