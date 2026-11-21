// End-to-end Phase 4 acceptance: invoke the freshly-built `glove` binary as
// a child process with `--upstream yams=...` and the synthetic agent in
// client mode. The synthetic agent inside the container drives an MCP
// session through glove's kernel against yams; success means the entire
// stack — spawner, kernel, registry, mcp_extension, policy, audit — works
// end-to-end against a real upstream.

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

extern char** environ;

// LeakSanitizer cannot inspect the contained fixture after Glove installs its Linux sandbox.
// Keep LSan on the parent while the child retains ASan/UBSan with leak detection disabled.
#if defined(__has_feature)
#    if __has_feature(address_sanitizer)
#        define GLOVE_TEST_ADDRESS_SANITIZER 1
#    endif
#endif
#if defined(__SANITIZE_ADDRESS__) && !defined(GLOVE_TEST_ADDRESS_SANITIZER)
#    define GLOVE_TEST_ADDRESS_SANITIZER 1
#endif

#ifndef GLOVE_BIN
#    error "GLOVE_BIN must be defined"
#endif
#ifndef GLOVE_SYNTHETIC_AGENT_BIN
#    error "GLOVE_SYNTHETIC_AGENT_BIN must be defined"
#endif
#ifndef GLOVE_YAMS_BIN
#    error "GLOVE_YAMS_BIN must be defined"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

// A private audit log: the default journal is shared by every launch of this
// user and held under an exclusive lock, so a concurrent test run would fail
// this one.
auto private_audit_log() -> std::string {
    const auto directory =
        std::filesystem::temp_directory_path() / ("glove_run_yams_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    return (directory / "audit.jsonl").string();
}

auto run() -> int {
    std::vector<std::string> argv_owned{
        GLOVE_BIN,
        "run",
        "--audit-log",
        private_audit_log(),
#if defined(GLOVE_TEST_ADDRESS_SANITIZER)
        "--read",
        GLOVE_SYNTHETIC_AGENT_BIN,
#endif
        "--upstream",
        std::string{"yams="} + GLOVE_YAMS_BIN + ",serve,--quiet",
        "--allow",
        "yams.mcp.echo",
        "--",
#if defined(GLOVE_TEST_ADDRESS_SANITIZER)
        "/usr/bin/env",
        "ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0",
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
#endif
        GLOVE_SYNTHETIC_AGENT_BIN,
        "--mode=client",
    };

    std::vector<char*> argv;
    argv.reserve(argv_owned.size() + 1);
    for (auto& s : argv_owned) {
        argv.push_back(s.data());
    }
    argv.push_back(nullptr);

    ::pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, GLOVE_BIN, nullptr, nullptr, argv.data(), environ);
    if (rc != 0) {
        std::fprintf(stderr, "posix_spawn: %s\n", std::strerror(rc));
        return 1;
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        std::fprintf(stderr, "waitpid: %s\n", std::strerror(errno));
        return 1;
    }
    REQUIRE(WIFEXITED(status));
    const int exit_code = WEXITSTATUS(status);
    if (exit_code != 0) {
        std::fprintf(stderr, "glove run exited with %d\n", exit_code);
        return 1;
    }
    return 0;
}

} // namespace

auto main() -> int {
    const int code = run();
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path{private_audit_log()}.parent_path(), ec);
    return code;
}
