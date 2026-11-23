// A termination signal sent to `glove exec` or `glove shell` reaches the
// agent, and glove still finishes its own work: it writes the exit record,
// leaves no agent process behind, and exits 128 + the signal. An agent that
// does not act on the signal is killed after the grace period.
//
// On Linux the agent is the init process of its own pid namespace. The kernel
// drops a signal such a process has no handler for, so the cooperative agent
// traps the signal, and an agent that merely has the default disposition is
// the one that gets killed. A pid from inside the namespace says nothing to
// the test, so liveness is a file the agent's child keeps appending to.

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
    const std::string& script,
    const char* stop_grace = nullptr
) -> ::pid_t {
    const ::pid_t child = ::fork();
    if (child == 0) {
        if (std::freopen("/dev/null", "r", stdin) == nullptr ||
            std::freopen("/dev/null", "w", stderr) == nullptr) {
            std::_Exit(126);
        }
        if (stop_grace != nullptr) {
            ::execl(
                GLOVE_BIN,
                GLOVE_BIN,
                subcommand,
                "--stop-grace",
                stop_grace,
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

// True once FILE has stopped growing: nothing of the agent is still running.
[[maybe_unused]] auto quiet(const std::filesystem::path& file) -> bool {
    std::error_code ec;
    const auto deadline = clock_type::now() + milliseconds{3000};
    while (clock_type::now() < deadline) {
        const auto before = std::filesystem::file_size(file, ec);
        std::this_thread::sleep_for(milliseconds{400});
        if (std::filesystem::file_size(file, ec) == before) {
            return true;
        }
    }
    return false;
}

[[maybe_unused]] auto gone(::pid_t pid) -> bool {
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

auto signalled(
    const char* subcommand,
    int signal_number,
    const std::string& body,
    int number,
    const char* stop_grace = nullptr
) -> outcome {
    std::error_code ec;
    const auto base =
        std::filesystem::canonical(std::filesystem::temp_directory_path()) /
        ("glove_exec_signal_" + std::to_string(::getpid()) + "_" + std::to_string(number));
    const auto workspace = base / "workspace";
    std::filesystem::create_directories(workspace, ec);
    const auto pid_file = workspace / "agent.pid";
    const auto heartbeat = workspace / "heartbeat";
    const auto audit = base / "audit.jsonl";
    // A child of the agent that must not outlive it.
    const std::string beat =
        "(while :; do echo . >> '" + heartbeat.string() + "'; /bin/sleep 0.05; done) & ";
    const ::pid_t glove = start_glove(
        subcommand,
        workspace,
        audit,
        beat + "echo $$ > '" + pid_file.string() + "'; " + body,
        stop_grace
    );
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
#if defined(__linux__)
    result.agent_gone = quiet(heartbeat);
#else
    result.agent_gone = gone(agent) && quiet(heartbeat);
#endif
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
#if defined(__linux__)
    const std::string cooperative = "trap 'exit 0' TERM HUP INT; /bin/sleep 30 & wait";
    const std::string stubborn_body = "/bin/sleep 30 & wait";
#else
    const std::string cooperative = "exec /bin/sleep 30";
    const std::string stubborn_body = "trap '' TERM; /bin/sleep 30 & wait";
#endif
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
#if !defined(__linux__)
    // A shell agent waiting on a child: the shell handles the signal and exits.
    const auto shell = signalled("exec", SIGTERM, "/bin/sleep 30 & wait", ++number);
    REQUIRE(shell.status >= 0 && WIFEXITED(shell.status));
    REQUIRE(WEXITSTATUS(shell.status) == 128 + SIGTERM);
    REQUIRE(shell.agent_gone);
    REQUIRE(has_exit_record(shell.audit, 128 + SIGTERM));
#endif
    // An agent that does not act on SIGTERM is killed after the grace period (1.5 s).
    const auto stubborn = signalled("exec", SIGTERM, stubborn_body, ++number);
    std::fprintf(stderr, "ignoring agent: status %d, %lld ms\n", stubborn.status, stubborn.took_ms);
    REQUIRE(stubborn.status >= 0 && WIFEXITED(stubborn.status));
    REQUIRE(WEXITSTATUS(stubborn.status) == 128 + SIGKILL);
    REQUIRE(stubborn.took_ms >= 1400 && stubborn.took_ms < 4500);
    REQUIRE(stubborn.agent_gone);
    REQUIRE(has_exit_record(stubborn.audit, 128 + SIGKILL));
    // --stop-grace sets the grace: short and long, on both subcommands.
    const auto quick = signalled("exec", SIGTERM, stubborn_body, ++number, "0.3");
    std::fprintf(stderr, "stop-grace 0.3: status %d, %lld ms\n", quick.status, quick.took_ms);
    REQUIRE(quick.status >= 0 && WIFEXITED(quick.status));
    REQUIRE(WEXITSTATUS(quick.status) == 128 + SIGKILL);
    REQUIRE(quick.took_ms >= 250 && quick.took_ms < 1300);
    REQUIRE(quick.agent_gone);
    const auto slow = signalled("shell", SIGTERM, stubborn_body, ++number, "4");
    std::fprintf(stderr, "stop-grace 4: status %d, %lld ms\n", slow.status, slow.took_ms);
    REQUIRE(slow.status >= 0 && WIFEXITED(slow.status));
    REQUIRE(WEXITSTATUS(slow.status) == 128 + SIGKILL);
    REQUIRE(slow.took_ms >= 3900 && slow.took_ms < 7000);
    REQUIRE(slow.agent_gone);
    REQUIRE(has_exit_record(slow.audit, 128 + SIGKILL));
    std::printf("exec signal ok\n");
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
