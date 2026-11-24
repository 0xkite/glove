// Plain host-loopback service ports on Linux (CLONE_NEWNET):
// verifies repeatable service_ports forwarding, coexistence with an egress
// proxy port, and fail-closed isolation against unlisted host loopback ports.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// LeakSanitizer cannot trace the nested exec into an isolated PID namespace;
// keep ASan/UBSan active in the child while disabling only child leak tracing.
#if defined(__has_feature)
#    if __has_feature(address_sanitizer)
#        define GLOVE_TEST_ADDRESS_SANITIZER 1
#    endif
#endif
#if defined(__SANITIZE_ADDRESS__) && !defined(GLOVE_TEST_ADDRESS_SANITIZER)
#    define GLOVE_TEST_ADDRESS_SANITIZER 1
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class echo_server final {
public:
    explicit echo_server(std::string banner) : banner_{std::move(banner)} {
        fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd_ < 0) {
            return;
        }
        ::sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::socklen_t len = sizeof(addr);
        if (::bind(fd_, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(fd_, 8) != 0 ||
            ::getsockname(fd_, reinterpret_cast<::sockaddr*>(&addr), &len) != 0) {
            ::close(fd_);
            fd_ = -1;
            return;
        }
        port_ = ntohs(addr.sin_port);
        worker_ = std::thread{[this] { serve(); }};
    }

    echo_server(const echo_server&) = delete;
    auto operator=(const echo_server&) -> echo_server& = delete;

    ~echo_server() {
        stop_.store(true, std::memory_order_relaxed);
        if (fd_ >= 0) {
            (void)::shutdown(fd_, SHUT_RDWR);
        }
        if (worker_.joinable()) {
            worker_.join();
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return port_; }

private:
    void serve() {
        while (!stop_.load(std::memory_order_relaxed)) {
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 50) <= 0 || (pfd.revents & POLLIN) == 0) {
                continue;
            }
            const int client = ::accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) {
                continue;
            }
            (void)::send(client, banner_.data(), banner_.size(), MSG_NOSIGNAL);
            (void)::shutdown(client, SHUT_RDWR);
            ::close(client);
        }
    }

    std::string banner_;
    int fd_ = -1;
    std::uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread worker_;
};

// Child-mode probe: connects to 127.0.0.1:<port>, checks optional banner prefix.
auto run_probe_child(std::uint16_t port, std::string_view expected_banner) -> int {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 10;
    }
    ::sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return 11;
    }
    char buf[64]{};
    const ::ssize_t got = ::recv(fd, buf, sizeof(buf) - 1U, 0);
    ::close(fd);
    if (got <= 0) {
        return 12;
    }
    const std::string_view received{buf, static_cast<std::size_t>(got)};
    if (!expected_banner.empty() && received != expected_banner) {
        return 13;
    }
    return 0;
}

auto probe_in_sandbox(
    const char* self_exe,
    glove::container::profile prof,
    std::uint16_t port,
    std::string_view expected_banner
) -> int {
#if defined(GLOVE_TEST_ADDRESS_SANITIZER)
    prof.environment.emplace_back("ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0");
#endif
    auto code = glove::container::exec_contained(
        prof, {self_exe, "--probe", std::to_string(port), std::string{expected_banner}}
    );
    if (!code) {
        std::fprintf(stderr, "exec_contained failed: %s\n", code.error().c_str());
        return -1;
    }
    return *code;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc >= 4 && std::string_view{argv[1]} == "--probe") {
        const auto port = static_cast<std::uint16_t>(std::stoi(argv[2]));
        return run_probe_child(port, argv[3]);
    }

    echo_server first{"SERVICE_ONE\n"};
    echo_server second{"SERVICE_TWO\n"};
    echo_server proxy_stub{"PROXY_STUB\n"};
    echo_server unlisted{"UNLISTED\n"};
    REQUIRE(
        first.port() != 0 && second.port() != 0 && proxy_stub.port() != 0 && unlisted.port() != 0
    );

    // 1. Single service port: reaches listed port, fails closed on unlisted ports.
    {
        glove::container::profile one;
        one.service_ports = {first.port()};
        REQUIRE(probe_in_sandbox(argv[0], one, first.port(), "SERVICE_ONE\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], one, second.port(), "SERVICE_TWO\n") != 0);
        REQUIRE(probe_in_sandbox(argv[0], one, unlisted.port(), "UNLISTED\n") != 0);
    }

    // 2. Multiple repeatable service ports: reaches both, fails closed on unlisted.
    {
        glove::container::profile both;
        both.service_ports = {second.port(), first.port()};
        REQUIRE(probe_in_sandbox(argv[0], both, first.port(), "SERVICE_ONE\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], both, second.port(), "SERVICE_TWO\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], both, unlisted.port(), "UNLISTED\n") != 0);
    }

    // 3. Coexistence with egress proxy port: reaches proxy and service ports, not unlisted.
    {
        glove::container::profile with_proxy;
        with_proxy.proxy = glove::container::proxy_settings{
            .port = proxy_stub.port(),
            .url = "http://127.0.0.1:" + std::to_string(proxy_stub.port()),
        };
        with_proxy.service_ports = {first.port(), second.port()};
        REQUIRE(probe_in_sandbox(argv[0], with_proxy, proxy_stub.port(), "PROXY_STUB\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], with_proxy, first.port(), "SERVICE_ONE\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], with_proxy, second.port(), "SERVICE_TWO\n") == 0);
        REQUIRE(probe_in_sandbox(argv[0], with_proxy, unlisted.port(), "UNLISTED\n") != 0);
    }

    // 4. Empty service_ports: offline sandbox cannot reach any host loopback port.
    {
        glove::container::profile offline;
        REQUIRE(probe_in_sandbox(argv[0], offline, first.port(), "SERVICE_ONE\n") != 0);
    }

    return 0;
}
