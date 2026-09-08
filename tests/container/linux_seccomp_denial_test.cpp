// Regression guard for the seccomp escape-surface deny list in setup_seccomp
// (src/container/linux/clone_spawner.cpp). The test binary re-execs itself
// inside exec_contained; the contained instance attempts each syscall the
// filter is supposed to deny and asserts every one returns EPERM. This locks
// in the fix for the mount-API bypass (mount(2) was denied but fsopen/
// move_mount/open_tree/mount_setattr were reachable) and the io_uring / handle
// / pidfd_getfd gaps, so a future edit that drops one is caught.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
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

struct denied_syscall {
    const char* name;
    long number;
};

// Syscalls the hardened filter must block. Guarded so the test still compiles
// on a libc that lacks a given SYS_ macro (it simply omits that probe).
auto denied_syscalls() -> std::vector<denied_syscall> {
    std::vector<denied_syscall> out;
#ifdef SYS_io_uring_setup
    out.push_back({"io_uring_setup", SYS_io_uring_setup});
#endif
#ifdef SYS_fsopen
    out.push_back({"fsopen", SYS_fsopen});
#endif
#ifdef SYS_fsconfig
    out.push_back({"fsconfig", SYS_fsconfig});
#endif
#ifdef SYS_fsmount
    out.push_back({"fsmount", SYS_fsmount});
#endif
#ifdef SYS_fspick
    out.push_back({"fspick", SYS_fspick});
#endif
#ifdef SYS_move_mount
    out.push_back({"move_mount", SYS_move_mount});
#endif
#ifdef SYS_open_tree
    out.push_back({"open_tree", SYS_open_tree});
#endif
#ifdef SYS_mount_setattr
    out.push_back({"mount_setattr", SYS_mount_setattr});
#endif
#ifdef SYS_open_by_handle_at
    out.push_back({"open_by_handle_at", SYS_open_by_handle_at});
#endif
#ifdef SYS_pidfd_getfd
    out.push_back({"pidfd_getfd", SYS_pidfd_getfd});
#endif
#ifdef SYS_fanotify_init
    out.push_back({"fanotify_init", SYS_fanotify_init});
#endif
    // Controls: these were already denied before the fix. If they are ever
    // reachable the filter did not load at all, which this test should catch.
#ifdef SYS_mount
    out.push_back({"mount", SYS_mount});
#endif
#ifdef SYS_setns
    out.push_back({"setns", SYS_setns});
#endif
    return out;
}

// Run inside the sandbox: probe each syscall and write BLOCKED/REACHABLE lines.
// Under SCMP_ACT_ERRNO(EPERM) a blocked syscall returns -1/EPERM; any other
// outcome (success, EFAULT, EINVAL, ...) means it was reached. Exit 0 iff all
// are blocked.
auto seccomp_probe(const std::filesystem::path& result) -> int {
    std::ofstream out{result};
    if (!out.good()) {
        return 2;
    }
    int reachable = 0;
    for (const auto& probe : denied_syscalls()) {
        errno = 0;
        const long rc = ::syscall(probe.number, 0L, 0L, 0L, 0L, 0L, 0L);
        const bool blocked = rc < 0 && errno == EPERM;
        out << probe.name << (blocked ? " BLOCKED" : " REACHABLE") << '\n';
        if (!blocked) {
            ++reachable;
        }
    }
    out.flush();
    return reachable == 0 ? 0 : 3;
}

auto run(const std::filesystem::path& self) -> int {
    const auto base = std::filesystem::current_path();
    const auto ws = base / ("glove_seccomp_ws_" + std::to_string(::getpid()));
    std::error_code ec;
    REQUIRE(std::filesystem::create_directories(ws, ec));
    REQUIRE(!ec);

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws.string(), .writable = true});
    prof.home_dir = ws.string();
    prof.work_dir = ws.string();
    prof.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin"};
    // LeakSanitizer cannot trace the nested exec into the isolated PID
    // namespace; keep ASan/UBSan active and disable only child leak tracing.
    prof.environment.emplace_back("ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0");

    const auto result = ws / "seccomp-result";
    auto code =
        glove::container::exec_contained(prof, {self.string(), "--seccomp-probe", result.string()});
    REQUIRE(code.has_value());

    std::ifstream in{result};
    REQUIRE(in.good());
    const std::string report{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    std::fprintf(
        stderr,
        "--- contained seccomp probe ---\n%s-------------------------------\n",
        report.c_str()
    );

    REQUIRE(*code == 0);
    REQUIRE(report.find("REACHABLE") == std::string::npos);
    // Spot-check the two that defined the vulnerability and its control.
    REQUIRE(report.find("move_mount BLOCKED") != std::string::npos);
    REQUIRE(report.find("io_uring_setup BLOCKED") != std::string::npos);
    REQUIRE(report.find("mount BLOCKED") != std::string::npos);

    REQUIRE(std::filesystem::remove_all(ws, ec) > 0);
    REQUIRE(!ec);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 3 && std::string_view{argv[1]} == "--seccomp-probe") {
        return seccomp_probe(argv[2]);
    }
    std::error_code error;
    const auto self = std::filesystem::canonical(argv[0], error);
    REQUIRE(!error);
    return run(self);
}
