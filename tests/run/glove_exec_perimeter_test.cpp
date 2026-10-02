// Direct-agent defaults must not silently expose the caller's current
// directory, place glove-managed state in the selected workspace, or let an
// agent tamper with its own audit trail.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
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

auto run_glove(std::vector<std::string> argv_owned) -> int {
    std::vector<char*> argv;
    argv.reserve(argv_owned.size() + 1);
    for (auto& value : argv_owned) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);

    const ::pid_t child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        ::execv(GLOVE_BIN, argv.data());
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto run() -> int {
    std::error_code ec;
    const auto base =
        std::filesystem::temp_directory_path() / ("glove_perimeter_" + std::to_string(::getpid()));
    const auto workspace = base / "workspace";
    const auto marker =
        std::filesystem::current_path() / ("glove-caller-secret-" + std::to_string(::getpid()));
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    {
        std::ofstream out{marker};
        out << "not for the agent\n";
        REQUIRE(out.good());
    }

    // With no --workspace or --read, even an absolute path passed in argv is
    // not readable. The command exits 42 if the boundary is too broad.
    REQUIRE(
        run_glove(
            {GLOVE_BIN,
             "exec",
             "--",
             "/bin/sh",
             "-c",
             "test ! -r \"$1\" || exit 42",
             "glove-test",
             marker.string()}
        ) == 0
    );

    // HOME/TMPDIR are private runtime state, not hidden mutations inside the
    // user's project tree.
    REQUIRE(
        run_glove(
            {GLOVE_BIN,
             "exec",
             "--workspace",
             workspace.string(),
             "--",
             "/bin/sh",
             "-c",
             "case \"$HOME\" in \"$1\"/*) exit 42;; esac",
             "glove-test",
             workspace.string()}
        ) == 0
    );
    REQUIRE(!std::filesystem::exists(workspace / ".glove-home"));

    // An append-only audit destination cannot sit below any path granted to
    // the agent, even if the operator names it explicitly.
    const auto exposed_audit = workspace / "audit.jsonl";
    REQUIRE(
        run_glove(
            {GLOVE_BIN,
             "exec",
             "--workspace",
             workspace.string(),
             "--audit-log",
             exposed_audit.string(),
             "--",
             "/usr/bin/true"}
        ) == 1
    );
    REQUIRE(!std::filesystem::exists(exposed_audit));

    // --herdr fails closed when HERDR_ENV is not present.
    ::unsetenv("HERDR_ENV");
    ::unsetenv("HERDR_PANE_ID");
    REQUIRE(run_glove({GLOVE_BIN, "exec", "--herdr", "--", "/usr/bin/true"}) == 1);

    // --herdr succeeds and records host-side lifecycle transitions when HERDR_ENV=1,
    // HERDR_PANE_ID, and HERDR_BIN_PATH are provided.
    const auto mock_herdr = base / "mock_herdr.sh";
    const auto herdr_log = base / "herdr_calls.log";
    {
        std::ofstream script{mock_herdr};
        script << "#!/bin/sh\n";
        script << "echo \"$@\" >> \"" << herdr_log.string() << "\"\n";
        script << "exit 0\n";
    }
    std::filesystem::permissions(mock_herdr, std::filesystem::perms::owner_all);

    ::setenv("HERDR_ENV", "1", 1);
    ::setenv("HERDR_PANE_ID", "w1:p1", 1);
    ::setenv("HERDR_BIN_PATH", mock_herdr.c_str(), 1);
    REQUIRE(run_glove({GLOVE_BIN, "exec", "--herdr", "--", "/usr/bin/true"}) == 0);
    ::unsetenv("HERDR_ENV");
    ::unsetenv("HERDR_PANE_ID");
    ::unsetenv("HERDR_BIN_PATH");

    std::ifstream log_in{herdr_log};
    REQUIRE(log_in.good());
    std::string log_contents{
        std::istreambuf_iterator<char>{log_in}, std::istreambuf_iterator<char>{}
    };
    REQUIRE(
        log_contents.find(
            "pane report-agent w1:p1 --source glove:sandbox --agent true --state working"
        ) != std::string::npos
    );
    REQUIRE(
        log_contents.find(
            "pane report-agent w1:p1 --source glove:sandbox --agent true --state done"
        ) != std::string::npos
    );
    REQUIRE(
        log_contents.find("pane release-agent w1:p1 --source glove:sandbox --agent true") !=
        std::string::npos
    );

    // --agent fails closed when the host provider credential is absent.
    ::unsetenv("ANTHROPIC_API_KEY");
    REQUIRE(run_glove({GLOVE_BIN, "exec", "--agent", "claude-code", "--", "/usr/bin/true"}) == 1);

    // --agent must never put the host credential in the child environment. The
    // sandbox sees only an ephemeral session nonce and a loopback base URL.
    const auto preset_dir = base / "preset";
    std::filesystem::create_directories(preset_dir, ec);
    REQUIRE(!ec);
    const auto observed = preset_dir / "observed.txt";
    ::setenv("ANTHROPIC_API_KEY", "sk-ant-host-credential-must-not-leak", 1);
    REQUIRE(
        run_glove(
            {GLOVE_BIN,
             "exec",
             "--agent",
             "claude-code",
             "--workspace",
             preset_dir.string(),
             "--",
             "/bin/sh",
             "-c",
             "printf 'key=%s\\nbase=%s\\n' \"$ANTHROPIC_API_KEY\" \"$ANTHROPIC_BASE_URL\" > \"$1\"",
             "glove-test",
             observed.string()}
        ) == 0
    );
    ::unsetenv("ANTHROPIC_API_KEY");
    {
        std::ifstream obs{observed};
        REQUIRE(obs.good());
        const std::string contents{
            std::istreambuf_iterator<char>{obs}, std::istreambuf_iterator<char>{}
        };
        REQUIRE(contents.find("sk-ant-host-credential-must-not-leak") == std::string::npos);
        REQUIRE(contents.find("key=glove-session-") != std::string::npos);
        REQUIRE(contents.find("base=http://127.0.0.1:") != std::string::npos);
    }

    std::filesystem::remove(marker, ec);
    std::filesystem::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
