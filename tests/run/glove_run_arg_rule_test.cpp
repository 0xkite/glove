// F1.1 acceptance: drives the freshly-built `glove` binary with both a
// passing and a denying `--allow-arg` rule against yams. Verifies the
// argument-level policy is wired all the way from CLI flag through the
// jsonpath_engine through the kernel into the contained agent.

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
    const auto directory = std::filesystem::temp_directory_path() /
                           ("glove_run_arg_rule_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    return (directory / "audit.jsonl").string();
}

auto run_glove(const std::string& allow_arg) -> int {
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
        "--allow-arg",
        allow_arg,
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
    if (::posix_spawn(&pid, GLOVE_BIN, nullptr, nullptr, argv.data(), environ) != 0) {
        return -1;
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto run() -> int {
    // Passing prefix: synthetic agent sends text="glove-says-hi", rule says
    // it must start with "glove-says-". Allowed; agent exits 0.
    {
        const int code = run_glove("yams.mcp.echo:text=glove-says-");
        if (code != 0) {
            std::fprintf(stderr, "expected allow-path exit 0, got %d\n", code);
            return 1;
        }
    }
    // Denying prefix: rule requires text to start with "does-not-match-",
    // which the agent's call ("glove-says-hi") fails. Policy denies. The
    // synthetic agent in client mode reads the denied response, finds no
    // "glove-says-hi" in the content, exits 15.
    {
        const int code = run_glove("yams.mcp.echo:text=does-not-match-");
        if (code != 15) {
            std::fprintf(stderr, "expected deny-path exit 15, got %d\n", code);
            return 1;
        }
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
