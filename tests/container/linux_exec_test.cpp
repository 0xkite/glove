// Stage 3 + Step A (Linux): `glove exec` contains a real agent via clone3 +
// namespaces + a strict allow-list rootfs, with stdio inherited. We run
// /usr/bin/sh through exec_contained and assert the whole posture in one shot,
// writing the results into the workspace for the host to read back. Requires the
// privileged Docker environment the other Linux spawner tests use.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/net/egress_proxy.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto contains(const std::string& hay, std::string_view needle) -> bool {
    return hay.find(needle) != std::string::npos;
}

auto egress_probe(
    const std::filesystem::path& result, std::uint16_t origin_port, std::string_view authorization
) -> int {
    const char* proxy_url = std::getenv("HTTPS_PROXY");
    if (proxy_url == nullptr) {
        return 20;
    }
    const std::string_view url{proxy_url};
    const auto colon = url.rfind(':');
    if (colon == std::string_view::npos) {
        return 21;
    }
    const auto proxy_port = static_cast<std::uint16_t>(
        std::strtoul(std::string{url.substr(colon + 1)}.c_str(), nullptr, 10)
    );
    const int connection = ::socket(AF_INET, SOCK_STREAM, 0);
    if (connection < 0) {
        return 22;
    }
    ::sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(proxy_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(connection, reinterpret_cast<const ::sockaddr*>(&address), sizeof(address)) < 0) {
        ::close(connection);
        return 23;
    }
    const std::string request =
        "CONNECT localhost:" + std::to_string(origin_port) +
        " HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: " + std::string{authorization} +
        "\r\n\r\n";
    if (::send(connection, request.data(), request.size(), MSG_NOSIGNAL) !=
        static_cast<ssize_t>(request.size())) {
        ::close(connection);
        return 24;
    }
    std::array<char, 4096> buffer{};
    const auto header_size = ::recv(connection, buffer.data(), buffer.size(), 0);
    if (header_size <= 0 ||
        std::string_view{buffer.data(), static_cast<std::size_t>(header_size)}.find(" 200 ") ==
            std::string_view::npos) {
        if (header_size > 0) {
            std::fprintf(
                stderr,
                "egress probe response: %.*s\n",
                static_cast<int>(header_size),
                buffer.data()
            );
        } else {
            std::fprintf(stderr, "egress probe recv=%zd errno=%d\n", header_size, errno);
        }
        ::close(connection);
        return 25;
    }
    constexpr std::string_view payload = "private-loopback-broker";
    if (::send(connection, payload.data(), payload.size(), MSG_NOSIGNAL) !=
        static_cast<ssize_t>(payload.size())) {
        ::close(connection);
        return 26;
    }
    const auto echoed = ::recv(connection, buffer.data(), buffer.size(), 0);
    ::close(connection);
    if (echoed != static_cast<ssize_t>(payload.size()) ||
        std::string_view{buffer.data(), static_cast<std::size_t>(echoed)} != payload) {
        return 27;
    }
    std::ofstream out{result};
    out << "egress=audited-private-loopback\n";
    return out.good() ? 0 : 28;
}

struct echo_origin {
    int listener = -1;
    std::uint16_t port = 0;
    std::thread worker;

    echo_origin() = default;
    echo_origin(const echo_origin&) = delete;
    auto operator=(const echo_origin&) -> echo_origin& = delete;

    echo_origin(echo_origin&& other) noexcept
        : listener{std::exchange(other.listener, -1)},
          port{other.port},
          worker{std::move(other.worker)} {}

    ~echo_origin() {
        if (listener >= 0) {
            ::shutdown(listener, SHUT_RDWR);
            ::close(listener);
        }
        if (worker.joinable()) {
            worker.join();
        }
    }
};

auto start_echo_origin() -> echo_origin {
    echo_origin origin;
    origin.listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (origin.listener < 0) {
        return origin;
    }
    ::sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(origin.listener, reinterpret_cast<const ::sockaddr*>(&address), sizeof(address)) <
            0 ||
        ::listen(origin.listener, 1) < 0) {
        ::close(origin.listener);
        origin.listener = -1;
        return origin;
    }
    socklen_t size = sizeof(address);
    if (::getsockname(origin.listener, reinterpret_cast<::sockaddr*>(&address), &size) < 0) {
        ::close(origin.listener);
        origin.listener = -1;
        return origin;
    }
    origin.port = ntohs(address.sin_port);
    origin.worker = std::thread{[listener = origin.listener] {
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            return;
        }
        std::array<char, 4096> buffer{};
        const auto count = ::recv(client, buffer.data(), buffer.size(), 0);
        if (count > 0) {
            static_cast<void>(::send(client, buffer.data(), static_cast<std::size_t>(count), 0));
        }
        ::close(client);
    }};
    return origin;
}

auto run(const std::filesystem::path& self) -> int {
    const std::string id = std::to_string(::getpid());
    // Keep the fixture outside /tmp, which the container shadows with a fresh
    // tmpfs, but inside CTest's runner-owned working directory. A neighboring
    // file proves non-granted paths are absent rather than merely read-only.
    const auto base = std::filesystem::current_path();
    const auto ws = base / ("glove_ws_" + id);
    const auto home = ws / "home";
    const auto outside = base / ("glove_outside_" + id);
    std::error_code filesystem_error;
    REQUIRE(std::filesystem::create_directories(home, filesystem_error));
    REQUIRE(!filesystem_error);
    {
        std::ofstream marker{outside};
        marker << "OUTSIDE_PROBE_VALUE";
        REQUIRE(marker.good());
    }
    REQUIRE(::setenv("GLOVE_TEST_HOST_SECRET", "must-not-cross", 1) == 0);

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws.string(), .writable = true});
    prof.home_dir = home.string();
    prof.work_dir = ws.string();
    prof.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin"};

    // One agent invocation probes the whole perimeter and writes a result line.
    std::string script;
    script += "{ ";
    script += "echo pid=$$; ";     // PID namespace
    script += "echo cwd=$PWD; ";   // work_dir
    script += "echo home=$HOME; "; // scratch HOME
    script += "head -c4 '" + outside.string() +
              "' >/dev/null 2>&1 && echo outside=BAD || echo outside=denied; ";
    script += "touch /etc/glove_evil 2>/dev/null && echo writeetc=BAD || echo writeetc=denied; ";
    script += "touch ./wok 2>/dev/null && echo writews=ok || echo writews=no; ";
    script += "test -s /proc/net/route && echo network=BAD || echo network=denied; ";
    script +=
        "env | grep '^GLOVE_TEST_HOST_SECRET=' >/dev/null && echo env=BAD || echo env=scrubbed; ";
    script += "} > '" + (ws / "result").string() + "'";

    auto code = glove::container::exec_contained(prof, {"/usr/bin/sh", "-c", script});
    REQUIRE(code.has_value());
    REQUIRE(*code == 0);

    std::ifstream in{ws / "result"};
    REQUIRE(in.good());
    std::string out((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::fprintf(
        stderr, "--- agent perimeter probe ---\n%s-----------------------------\n", out.c_str()
    );

    REQUIRE(contains(out, "pid=1"));                 // contained: PID 1 of its own ns
    REQUIRE(contains(out, "cwd=" + ws.string()));    // started in the workspace
    REQUIRE(contains(out, "home=" + home.string())); // HOME is the scratch home
    REQUIRE(contains(out, "outside=denied"));        // unrelated host file is absent
    REQUIRE(contains(out, "writeetc=denied"));       // write-narrow: /etc not writable
    REQUIRE(contains(out, "writews=ok"));            // workspace writable
    REQUIRE(contains(out, "network=denied"));        // no route leaves the network namespace
    REQUIRE(contains(out, "env=scrubbed"));          // host credentials are not inherited

    auto origin = start_echo_origin();
    REQUIRE(origin.listener >= 0);
    glove::net::egress_options egress_options;
    egress_options.allow = {{.host = "localhost", .port = origin.port, .allow_private = true}};
    bool audited_allow = false;
    egress_options.on_event = [&audited_allow](
                                  const glove::net::egress_event& event
                              ) -> std::expected<void, std::string> {
        audited_allow = event.allowed && event.host == "localhost";
        return {};
    };
    auto proxy = glove::net::start_egress_proxy(std::move(egress_options));
    REQUIRE(proxy.has_value());
    glove::container::profile online = prof;
    // LeakSanitizer cannot trace the nested exec after it enters the isolated
    // PID namespace. Keep ASan/UBSan active and disable only child leak tracing.
    online.environment.emplace_back("ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0");
    online.proxy = glove::container::proxy_settings{
        .port = (*proxy)->port(),
        .url = (*proxy)->proxy_url(),
    };
    const auto egress_result = ws / "egress-result";
    auto egress_code = glove::container::exec_contained(
        online,
        {
            self.string(),
            "--egress-probe",
            egress_result.string(),
            std::to_string(origin.port),
            (*proxy)->proxy_authorization(),
        }
    );
    REQUIRE(egress_code.has_value());
    if (*egress_code != 0) {
        std::fprintf(stderr, "egress probe exit=%d\n", *egress_code);
    }
    REQUIRE(*egress_code == 0);
    std::ifstream egress_in{egress_result};
    REQUIRE(egress_in.good());
    const std::string egress_out{
        std::istreambuf_iterator<char>{egress_in}, std::istreambuf_iterator<char>{}
    };
    REQUIRE(contains(egress_out, "egress=audited-private-loopback"));
    REQUIRE(audited_allow);

    REQUIRE(std::filesystem::remove_all(ws, filesystem_error) > 0);
    REQUIRE(!filesystem_error);
    REQUIRE(std::filesystem::remove(outside, filesystem_error));
    REQUIRE(!filesystem_error);
    REQUIRE(::unsetenv("GLOVE_TEST_HOST_SECRET") == 0);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 5 && std::string_view{argv[1]} == "--egress-probe") {
        return egress_probe(
            argv[2], static_cast<std::uint16_t>(std::strtoul(argv[3], nullptr, 10)), argv[4]
        );
    }
    std::error_code error;
    const auto self = std::filesystem::canonical(argv[0], error);
    REQUIRE(!error);
    return run(self);
}
