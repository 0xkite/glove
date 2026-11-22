// A termination signal sent to `glove exec` or `glove shell` on macOS reaches
// the agent, and glove still finishes its own work: it writes the exit record,
// leaves no agent process behind, and exits 128 + the signal. An agent that
// ignores the signal is killed after the grace period.

#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <thread>

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

using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto start_glove(
    const char* subcommand,
    const std::filesystem::path& workspace,
    const std::filesystem::path& audit,
    const std::string& script
) -> ::pid_t {
    const ::pid_t child = ::fork();
    if (child == 0) {
        if (std::freopen("/dev/null", "r", stdin) == nullptr ||
            std::freopen("/dev/null", "w", stderr) == nullptr) {
            std::_Exit(126);
        }
        ::execl(
            GLOVE_BIN,
            GLOVE_BIN,
            subcommand,
            "--workspace",
            workspace.c_str(),
            "--audit-log",
            audit.c_str(),
            "--",
            "/bin/sh",
            "-c",
            script.c_str(),
            static_cast<char*>(nullptr)
        );
        std::_Exit(127);
    }
    return child;
}

// Reads the pid the agent wrote once it was running, or 0 on timeout.
auto agent_pid(const std::filesystem::path& file) -> ::pid_t {
    const auto deadline = clock_type::now() + milliseconds{10000};
    while (clock_type::now() < deadline) {
        const auto text = read_file(file);
        if (!text.empty() && text.back() == '\n') {
            return static_cast<::pid_t>(std::strtol(text.c_str(), nullptr, 10));
        }
        std::this_thread::sleep_for(milliseconds{20});
    }
    return 0;
}

auto gone(::pid_t pid) -> bool {
    const auto deadline = clock_type::now() + milliseconds{2000};
    while (clock_type::now() < deadline) {
        if (::kill(pid, 0) != 0 && errno == ESRCH) {
            return true;
        }
        std::this_thread::sleep_for(milliseconds{20});
    }
    return false;
}

struct outcome {
    int status = -1;
    long long took_ms = 0;
    std::string audit;
    bool agent_gone = false;
};

auto signalled(const char* subcommand, int signal_number, const std::string& body, int number)
    -> outcome {
    std::error_code ec;
    const auto base =
        std::filesystem::canonical(std::filesystem::temp_directory_path()) /
        ("glove_exec_signal_" + std::to_string(::getpid()) + "_" + std::to_string(number));
    const auto workspace = base / "workspace";
    std::filesystem::create_directories(workspace, ec);
    const auto pid_file = workspace / "agent.pid";
    const auto audit = base / "audit.jsonl";
    const ::pid_t glove =
        start_glove(subcommand, workspace, audit, "echo $$ > '" + pid_file.string() + "'; " + body);
    outcome result;
    const ::pid_t agent = glove > 0 ? agent_pid(pid_file) : 0;
    if (agent <= 0) {
        if (glove > 0) {
            ::kill(glove, SIGKILL);
            ::waitpid(glove, &result.status, 0);
            result.status = -1;
        }
        std::filesystem::remove_all(base, ec);
        return result;
    }
    const auto sent = clock_type::now();
    ::kill(glove, signal_number);
    if (::waitpid(glove, &result.status, 0) != glove) {
        result.status = -1;
    }
    result.took_ms = std::chrono::duration_cast<milliseconds>(clock_type::now() - sent).count();
    result.agent_gone = gone(agent);
    result.audit = read_file(audit);
    std::filesystem::remove_all(base, ec);
    return result;
}

auto has_exit_record(const std::string& audit, int code) -> bool {
    return audit.contains(R"("action":"agent_exit","tool":")" + std::to_string(code) + R"(")");
}

auto run() -> int {
    int number = 0;
    // The agent is the sleep itself, so its exit is the signal's default
    // action and not one shell's idea of an interrupted `wait`.
    const std::string cooperative = "exec /bin/sleep 30";
    for (const char* subcommand : {"exec", "shell"}) {
        for (const int signal_number : {SIGTERM, SIGHUP, SIGINT}) {
            const auto result = signalled(subcommand, signal_number, cooperative, ++number);
            std::fprintf(
                stderr,
                "%s signal %d: status %d, %lld ms\n",
                subcommand,
                signal_number,
                result.status,
                result.took_ms
            );
            REQUIRE(result.status >= 0 && WIFEXITED(result.status));
            REQUIRE(WEXITSTATUS(result.status) == 128 + signal_number);
            REQUIRE(result.took_ms < 1400);
            REQUIRE(result.agent_gone);
            REQUIRE(result.audit.contains(R"("action":"agent_launch")"));
            REQUIRE(has_exit_record(result.audit, 128 + signal_number));
        }
    }
    // A shell agent waiting on a child: the shell handles the signal and exits.
    const auto shell = signalled("exec", SIGTERM, "/bin/sleep 30 & wait", ++number);
    REQUIRE(shell.status >= 0 && WIFEXITED(shell.status));
    REQUIRE(WEXITSTATUS(shell.status) == 128 + SIGTERM);
    REQUIRE(shell.agent_gone);
    REQUIRE(has_exit_record(shell.audit, 128 + SIGTERM));
    // An agent that ignores SIGTERM is killed after the grace period (1.5 s).
    const auto stubborn =
        signalled("exec", SIGTERM, "trap '' TERM; /bin/sleep 30 & wait", ++number);
    std::fprintf(stderr, "ignoring agent: status %d, %lld ms\n", stubborn.status, stubborn.took_ms);
    REQUIRE(stubborn.status >= 0 && WIFEXITED(stubborn.status));
    REQUIRE(WEXITSTATUS(stubborn.status) == 128 + SIGKILL);
    REQUIRE(stubborn.took_ms >= 1400 && stubborn.took_ms < 4500);
    REQUIRE(stubborn.agent_gone);
    REQUIRE(has_exit_record(stubborn.audit, 128 + SIGKILL));
    std::printf("exec signal ok\n");
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
