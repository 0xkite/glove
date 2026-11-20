// Stage 3 (macOS): `glove exec` runs a real, self-driving agent contained with
// stdio inherited and no MCP kernel. We exercise the platform entry point
// exec_contained directly and assert the two containment guarantees that matter
// for an agent like pi: (1) HOME is redirected into the writable workspace so
// the agent's state writes land inside the sandbox; (2) a write outside the
// workspace is denied; (3) host credential-bearing environment variables are
// not inherited.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    REQUIRE(::setenv("GLOVE_TEST_HOST_SECRET", "must-not-cross", 1) == 0);
    std::error_code ec;
    auto base =
        std::filesystem::temp_directory_path() / ("glove_exec_test_" + std::to_string(::getpid()));
    auto workspace = base / "ws";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    // A path OUTSIDE the workspace that must be denied. It has to be somewhere
    // the profile does NOT allow — the host $HOME, not /var/folders (which is a
    // permitted scratch dir). The test cleans it up if it somehow appears.
    const char* host_home = std::getenv("HOME");
    REQUIRE(host_home != nullptr && *host_home != '\0');
    std::filesystem::path forbidden =
        std::filesystem::path{host_home} / (".glove_exec_forbidden_" + std::to_string(::getpid()));

    glove::container::profile prof;
    prof.filesystem.push_back({.path = workspace.string(), .writable = true});
    // HOME is the scratch-home the runner would set; point it at the workspace.
    prof.home_dir = workspace.string();

    // The agent: record its $HOME (which glove should have pointed at the
    // workspace), and attempt a write outside it.
    std::string script = "printf '%s' \"$HOME\" > \"$HOME/home_marker\"; ";
    script += "if env | grep '^GLOVE_TEST_HOST_SECRET=' >/dev/null; then ";
    script += "printf inherited > \"$HOME/env_marker\"; else ";
    script += "printf scrubbed > \"$HOME/env_marker\"; fi; ";
    script += "touch '" + forbidden.string() + "' 2>/dev/null || true";

    auto code = glove::container::exec_contained(prof, {"/bin/sh", "-c", script});
    REQUIRE(code.has_value());
    REQUIRE(*code == 0);

    // (1) HOME was the workspace, and the agent wrote its marker there.
    auto marker = workspace / "home_marker";
    REQUIRE(std::filesystem::exists(marker));
    std::ifstream in{marker};
    std::string home_seen;
    std::getline(in, home_seen);
    std::fprintf(stderr, "agent $HOME = %s\n", home_seen.c_str());
    REQUIRE(std::filesystem::equivalent(home_seen, workspace, ec));
    REQUIRE(!ec);

    std::ifstream env_in{workspace / "env_marker"};
    std::string env_seen;
    std::getline(env_in, env_seen);
    REQUIRE(env_seen == "scrubbed");

    // (2) the write outside the workspace was denied.
    const bool escaped = std::filesystem::exists(forbidden);
    std::filesystem::remove_all(base, ec);
    REQUIRE(!escaped);
    REQUIRE(::unsetenv("GLOVE_TEST_HOST_SECRET") == 0);
    return 0;
}

// A regular file inherited as stdout must be stat-able by the contained agent
// (Node and others fstat/stat their stdio path).
auto regular_file_stdout_metadata() -> int {
    std::error_code ec;
    auto base = std::filesystem::temp_directory_path() /
                ("glove_exec_stdio_test_" + std::to_string(::getpid()));
    auto workspace = base / "ws";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    const auto out_file = base / "stdout.txt";

    glove::container::profile prof;
    prof.filesystem.push_back({.path = workspace.string(), .writable = true});
    prof.home_dir = workspace.string();

    const int out_fd = ::open(out_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(out_fd >= 0);
    const int saved = ::dup(STDOUT_FILENO);
    REQUIRE(saved >= 0);
    REQUIRE(::dup2(out_fd, STDOUT_FILENO) >= 0);
    ::close(out_fd);
    const std::string script = "if /usr/bin/stat -q \"" + out_file.string() +
                               "\" >/dev/null; then echo meta=OK; else echo meta=DENY; fi";
    auto code = glove::container::exec_contained(prof, {"/bin/sh", "-c", script});
    ::dup2(saved, STDOUT_FILENO);
    ::close(saved);

    std::ifstream in{out_file};
    std::string seen;
    std::getline(in, seen);
    std::fprintf(stderr, "stdout file: %s\n", seen.c_str());
    std::filesystem::remove_all(base, ec);
    REQUIRE(code.has_value());
    REQUIRE(seen == "meta=OK");
    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = regular_file_stdout_metadata(); failed != 0) {
        return failed;
    }
    return run();
}
