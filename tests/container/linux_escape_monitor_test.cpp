// Adversarial invariant verification for Linux container hardening:
//   1. Explicit PR_SET_NO_NEW_PRIVS and full capability drop inside CLONE_NEWUSER.
//   2. Kernel-enforced Landlock filesystem bounds on read-only paths and /dev/null.
//   3. Rootless SECCOMP_RET_USER_NOTIF escape detection, audit observer firing,
//      and immediate process-namespace shutdown (including forked descendants).
//   4. End-to-end CLI `glove exec` audit trail (`seccomp_escape_detected`).
//   5. Zero-allocation CONNECT parser & authentication boundary invariants.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include "net/egress_connect_parser.hpp"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#ifndef GLOVE_BIN
#    error "GLOVE_BIN must point at the glove executable"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto read_all(const std::filesystem::path& path) -> std::string {
    std::ifstream in{path};
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

auto check_posture_and_landlock(
    const std::filesystem::path& ws, const std::filesystem::path& ro_dir
) -> int {
    const std::string status = read_all("/proc/self/status");
    const std::filesystem::path out_file = ws / "posture.txt";
    std::ofstream out{out_file};
    out << status;
    out.flush();
    if (!out.good()) {
        return 10;
    }

    // Attempt forbidden writes against /etc and an explicit read-only grant.
    errno = 0;
    const int ro_fd = ::open((ro_dir / "forbidden.txt").c_str(), O_WRONLY | O_CREAT, 0600);
    if (ro_fd >= 0) {
        ::close(ro_fd);
        return 11;
    }

    errno = 0;
    const int etc_fd = ::open("/etc/glove-landlock-probe", O_WRONLY | O_CREAT, 0600);
    if (etc_fd >= 0) {
        ::close(etc_fd);
        return 12;
    }

    // Writing to /dev/null with O_TRUNC and writing into the workspace must succeed.
    const int dev_null = ::open("/dev/null", O_WRONLY | O_TRUNC);
    if (dev_null < 0) {
        return 13;
    }
    ::close(dev_null);

    const std::filesystem::path allowed_file = ws / "allowed.txt";
    std::ofstream allowed{allowed_file};
    allowed << "ok\n";
    allowed.flush();
    return allowed.good() ? 0 : 14;
}

[[noreturn]] auto run_escape_probe(std::string_view mode, const std::filesystem::path& marker)
    -> int {
    auto touch_marker = [&]() {
        std::ofstream m{marker};
        m << "survived\n";
        m.flush();
    };

    if (mode == "setns") {
#ifdef SYS_setns
        (void)::syscall(SYS_setns, -1L, 0L);
#endif
        touch_marker();
        for (;;) {
            ::pause();
        }
    }
    if (mode == "bpf") {
#ifdef SYS_bpf
        (void)::syscall(SYS_bpf, 0L, 0L, 0L);
#endif
        touch_marker();
        for (;;) {
            ::pause();
        }
    }
    if (mode == "fsopen") {
#ifdef SYS_fsopen
        (void)::syscall(SYS_fsopen, 0L, 0L);
#endif
        touch_marker();
        for (;;) {
            ::pause();
        }
    }
    if (mode == "open_by_handle_at") {
#ifdef SYS_open_by_handle_at
        (void)::syscall(SYS_open_by_handle_at, -1L, 0L, 0L);
#endif
        touch_marker();
        for (;;) {
            ::pause();
        }
    }
    if (mode == "tiocsti") {
#ifdef TIOCSTI
        char c = 'a';
        (void)::ioctl(-1, TIOCSTI, &c);
#endif
        touch_marker();
        for (;;) {
            ::pause();
        }
    }
    if (mode == "forked_unshare") {
        const ::pid_t child = ::fork();
        if (child == 0) {
#ifdef SYS_unshare
            (void)::syscall(SYS_unshare, 0L);
#endif
            touch_marker();
            ::_Exit(42);
        }
        // Parent sleeps; monitor must kill PID 1 and the entire namespace.
        for (;;) {
            ::pause();
        }
    }
    ::_Exit(99);
}

auto run_cli_with_xdg_state(
    const std::vector<std::string>& argv_owned, const std::filesystem::path& state_home
) -> int {
    std::vector<char*> argv;
    argv.reserve(argv_owned.size() + 1);
    for (const auto& value : argv_owned) {
        argv.push_back(const_cast<char*>(value.c_str()));
    }
    argv.push_back(nullptr);

    const ::pid_t child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        ::setenv("XDG_STATE_HOME", state_home.c_str(), 1);
        ::execv(GLOVE_BIN, argv.data());
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

auto test_connect_parser() -> int {
    std::string host;
    std::uint16_t port = 0;
    REQUIRE(
        glove::net::detail::parse_connect(
            "CONNECT api.EXAMPLE.com:443 HTTP/1.1\r\n\r\n", host, port
        )
    );
    REQUIRE(host == "api.example.com");
    REQUIRE(port == 443);

    REQUIRE(glove::net::detail::parse_connect("CONNECT [::1]:8443 HTTP/1.1\r\n\r\n", host, port));
    REQUIRE(host == "::1");
    REQUIRE(port == 8443);

    REQUIRE(!glove::net::detail::parse_connect("CONNECT evil.com:0 HTTP/1.1\r\n\r\n", host, port));
    REQUIRE(
        !glove::net::detail::parse_connect("CONNECT evil.com:70000 HTTP/1.1\r\n\r\n", host, port)
    );
    REQUIRE(!glove::net::detail::parse_connect("GET / HTTP/1.1\r\n\r\n", host, port));
    REQUIRE(!glove::net::detail::parse_connect("CONNECT ../evil:443 HTTP/1.1\r\n\r\n", host, port));

    REQUIRE(
        glove::net::detail::authenticated(
            "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\npRoXy-AuThOrIzAtIoN: "
            "\tBasic abc=\r\n\r\n",
            "Basic abc="
        )
    );
    REQUIRE(!glove::net::detail::authenticated(
        "CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic wrong\r\n\r\n",
        "Basic abc="
    ));
    return 0;
}

auto run(const std::filesystem::path& self) -> int {
    REQUIRE(test_connect_parser() == 0);

    std::error_code ec;
    const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("glove_escape_monitor_" + std::to_string(::getpid()));
    const auto ws = base / "ws";
    const auto ro_dir = base / "ro";
    const auto state_home = base / "state";
    REQUIRE(std::filesystem::create_directories(ws, ec));
    REQUIRE(std::filesystem::create_directories(ro_dir, ec));
    REQUIRE(std::filesystem::create_directories(state_home, ec));

    struct cleanup_guard final {
        std::filesystem::path root;

        ~cleanup_guard() {
            std::error_code ignored;
            std::filesystem::remove_all(root, ignored);
        }
    } cleanup{base};

    // 1. Verify capability drop + NoNewPrivs + Landlock inside default container.
    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws.string(), .writable = true});
    prof.filesystem.push_back({.path = ro_dir.string(), .writable = false});
    prof.home_dir = ws.string();
    prof.work_dir = ws.string();
    prof.environment = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0",
    };

    auto posture_rc = glove::container::exec_contained(
        prof, {self.string(), "--child-posture", ws.string(), ro_dir.string()}
    );
    REQUIRE(posture_rc.has_value());
    REQUIRE(*posture_rc == 0);

    const std::string status = read_all(ws / "posture.txt");
    REQUIRE(status.find("NoNewPrivs:\t1") != std::string::npos);
    REQUIRE(status.find("CapInh:\t0000000000000000") != std::string::npos);
    REQUIRE(status.find("CapPrm:\t0000000000000000") != std::string::npos);
    REQUIRE(status.find("CapEff:\t0000000000000000") != std::string::npos);
    REQUIRE(status.find("CapBnd:\t0000000000000000") != std::string::npos);
    REQUIRE(status.find("CapAmb:\t0000000000000000") != std::string::npos);
    REQUIRE(std::filesystem::exists(ws / "allowed.txt", ec));
    REQUIRE(!std::filesystem::exists(ro_dir / "forbidden.txt", ec));

    // 2. Verify SECCOMP_RET_USER_NOTIF traps and kills escape attempts cleanly.
    struct case_spec {
        const char* mode;
        const char* expected_syscall;
    };

    const std::vector<case_spec> cases = {
        {"setns", "setns"},
        {"bpf", "bpf"},
        {"fsopen", "fsopen"},
        {"open_by_handle_at", "open_by_handle_at"},
        {"tiocsti", "ioctl(TIOCSTI)"},
        {"forked_unshare", "unshare"},
    };
    for (std::size_t idx = 0; idx < cases.size(); ++idx) {
        const auto marker = ws / ("survived_" + std::to_string(idx));
        std::mutex mu;
        std::vector<glove::container::containment_escape_event> events;
        auto observer = [&](const glove::container::containment_escape_event& evt) {
            const std::lock_guard lock{mu};
            events.push_back(evt);
        };
        auto rc = glove::container::exec_contained(
            prof, {self.string(), "--child-escape", cases[idx].mode, marker.string()}, observer
        );
        REQUIRE(rc.has_value());
        REQUIRE(*rc != 0);
        REQUIRE(!std::filesystem::exists(marker, ec));
        REQUIRE(!events.empty());
        REQUIRE(events.front().mechanism == "seccomp_user_notif");
        REQUIRE(events.front().detail == cases[idx].expected_syscall);
    }

    // 3. End-to-end CLI verification: `glove exec` records seccomp_escape_detected
    //    into session.jsonl and aborts the container.
    const auto cli_marker = ws / "cli_survived";
    std::vector<std::string> cli_argv = {
        GLOVE_BIN,
        "exec",
        "--workspace",
        ws.string(),
    };
    if (const char* asan_opts = std::getenv("ASAN_OPTIONS");
        asan_opts != nullptr && *asan_opts != '\0') {
        cli_argv.emplace_back("--env");
        cli_argv.emplace_back("ASAN_OPTIONS");
    }
    cli_argv.insert(
        cli_argv.end(), {"--", self.string(), "--child-escape", "setns", cli_marker.string()}
    );
    const int cli_rc = run_cli_with_xdg_state(cli_argv, state_home);
    REQUIRE(cli_rc != 0);
    REQUIRE(!std::filesystem::exists(cli_marker, ec));
    const std::string journal = read_all(state_home / "glove" / "logs" / "session.jsonl");
    REQUIRE(journal.find("seccomp_escape_detected") != std::string::npos);
    REQUIRE(journal.find("seccomp_user_notif:setns") != std::string::npos);

    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 4 && std::string_view{argv[1]} == "--child-posture") {
        return check_posture_and_landlock(argv[2], argv[3]);
    }
    if (argc == 4 && std::string_view{argv[1]} == "--child-escape") {
        return run_escape_probe(argv[2], argv[3]);
    }
    const std::filesystem::path self = std::filesystem::canonical("/proc/self/exe");
    return run(self);
}
