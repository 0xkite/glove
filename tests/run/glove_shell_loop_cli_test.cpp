// End-to-end invariants for `glove shell` and `glove loop`:
// 1. `glove shell` without `--workspace` creates an ephemeral private runtime dir.
// 2. `glove shell --workspace <missing>` fails closed without auto-creating it.
// 3. `glove loop` reads `@prompt`, runs `--verify` offline inside the sandbox,
//    feeds verification failure output into the next turn, and exits 0 when
//    verification passes.
// 4. `glove loop` exits non-zero when `--max-iterations` is exhausted.

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
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
        std::filesystem::temp_directory_path() / ("glove_shell_loop_" + std::to_string(::getpid()));
    const auto workspace = base / "workspace";
    std::filesystem::remove_all(base, ec);
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);

    // 1. `glove shell` without `--workspace` uses an ephemeral private runtime dir.
    REQUIRE(
        run_glove({GLOVE_BIN, "shell", "--", "/bin/sh", "-c", "test \"$GLOVE_SANDBOXED\" = 1"}) == 0
    );

    // 2. Explicit missing `--workspace` must fail closed (never auto-create).
    const auto missing_ws = base / "does-not-exist";
    REQUIRE(
        run_glove({GLOVE_BIN, "shell", "--workspace", missing_ws.string(), "--", "/bin/true"}) != 0
    );
    REQUIRE(!std::filesystem::exists(missing_ws, ec));

    // 3. `glove loop` with `@prompt` file and `--verify` feedback across 2 turns.
    const auto prompt_file = base / "prompt.txt";
    {
        std::ofstream out(prompt_file);
        out << "Initial RE prompt";
    }
    const auto mock_agent = workspace / "mock_agent.sh";
    {
        std::ofstream out(mock_agent);
        out << "#!/bin/sh\n"
               "set -e\n"
               "prompt=\"$1\"\n"
               "printf '%s\\n' \"$prompt\" > last_prompt.txt\n"
               "case \"$prompt\" in\n"
               "  *\"Previous verification failed\"*)\n"
               "    echo 'second' > state.txt\n"
               "    ;;\n"
               "  *)\n"
               "    echo 'first' > state.txt\n"
               "    ;;\n"
               "esac\n";
    }
    REQUIRE(::chmod(mock_agent.c_str(), 0755) == 0);

    REQUIRE(
        run_glove({
            GLOVE_BIN,
            "loop",
            "--workspace",
            workspace.string(),
            "--agent",
            "agy",
            "--cmd",
            mock_agent.string(),
            "--prompt",
            "@" + prompt_file.string(),
            "--verify",
            "grep -q '^second$' state.txt || { echo 'missing second'; exit 1; }",
            "--max-iterations",
            "3",
        }) == 0
    );

    {
        std::ifstream in(workspace / "last_prompt.txt");
        std::string last_prompt((std::istreambuf_iterator<char>(in)), {});
        REQUIRE(last_prompt.find("Previous verification failed (exit 1)") != std::string::npos);
        REQUIRE(last_prompt.find("missing second") != std::string::npos);
        REQUIRE(last_prompt.find("Initial RE prompt") != std::string::npos);
    }

    // 4. Exhausting `--max-iterations` returns non-zero.
    REQUIRE(
        run_glove({
            GLOVE_BIN,
            "loop",
            "--workspace",
            workspace.string(),
            "--agent",
            "agy",
            "--cmd",
            mock_agent.string(),
            "--prompt",
            "Always fail",
            "--verify",
            "exit 1",
            "--max-iterations",
            "2",
        }) == 1
    );

    std::filesystem::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
