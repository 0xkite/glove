// `glove exec --denial-trace` on macOS records a short-lived child's denial
// to a new trace file that parses back and replays into features. A trace
// path the agent could reach, or an existing file, stops the launch before
// the agent runs.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_trace.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
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

constexpr int skip_code = 77;
constexpr int trials = 3;

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

// Runs glove exec with stdin from /dev/null and stderr to a file; returns the
// wait status, or -1.
auto glove_exec(
    const std::filesystem::path& workspace,
    const std::filesystem::path& trace,
    const std::filesystem::path& audit,
    const std::string& script,
    const std::filesystem::path& stderr_path
) -> int {
    const ::pid_t child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        if (std::freopen("/dev/null", "r", stdin) == nullptr ||
            std::freopen(stderr_path.c_str(), "w", stderr) == nullptr) {
            std::_Exit(126);
        }
        ::execl(
            GLOVE_BIN,
            GLOVE_BIN,
            "exec",
            "--workspace",
            workspace.c_str(),
            "--denial-trace",
            trace.c_str(),
            // Private, so a concurrent launch holding the default journal
            // cannot fail this one.
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
    int status = 0;
    return ::waitpid(child, &status, 0) == child ? status : -1;
}

auto records(int number, const std::filesystem::path& home) -> int {
    std::error_code ec;
    const auto base =
        std::filesystem::canonical(std::filesystem::temp_directory_path()) /
        ("glove_exec_trace_" + std::to_string(::getpid()) + "_" + std::to_string(number));
    const auto workspace = base / "workspace";
    const auto trace_path = base / "trace.jsonl";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    const std::string marker =
        ".glove_trace_e2e_" + std::to_string(::getpid()) + "_" + std::to_string(number);
    const auto forbidden = home / marker;
    const int status = glove_exec(
        workspace,
        trace_path,
        base / "audit.jsonl",
        "/usr/bin/touch '" + forbidden.string() + "'; exit 0",
        base / "stderr.txt"
    );
    if (std::filesystem::exists(forbidden, ec)) {
        std::filesystem::remove(forbidden, ec);
        std::fprintf(stderr, "sandbox did not hold: %s exists\n", forbidden.c_str());
        return 1;
    }
    REQUIRE(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    const auto trace = glove::container::parse_denial_trace(read_file(trace_path));
    REQUIRE(trace.has_value());
    REQUIRE(trace->end.has_value());
    if (number == 1 && trace->end->state == glove::container::denial_telemetry_state::unavailable) {
        std::printf("SKIP denial telemetry unavailable\n");
        std::filesystem::remove_all(base, ec);
        return skip_code;
    }
    REQUIRE(trace->end->state == glove::container::denial_telemetry_state::live);
    REQUIRE(trace->end->end_proof);
    REQUIRE(!trace->truncated);
    REQUIRE(trace->context.home == home.string());
    REQUIRE(
        std::ranges::find(trace->context.workspace_roots, workspace.string()) !=
        trace->context.workspace_roots.end()
    );
    const auto hit = std::ranges::find_if(trace->events, [&](const auto& event) {
        return event.denial.kind == "file_write" && event.denial.comm == "touch" &&
               event.denial.target.ends_with(marker);
    });
    REQUIRE(hit != trace->events.end());

    // The recorded trace replays into features: the denied file is in home.
    glove::container::denial_feature_builder builder{trace->context};
    for (const auto& event : trace->events) {
        builder.observe(event.denial, event.at);
    }
    const auto features = builder.features(trace->end->at);
    const auto names = glove::container::denial_feature_names();
    const auto at = static_cast<std::size_t>(
        std::ranges::find(names, std::string_view{"write_outside_workspace"}) - names.begin()
    );
    REQUIRE(features.at(at) >= static_cast<float>(std::log1p(1.0)));
    std::printf("T trial %d ok (%zu events)\n", number, trace->events.size());
    std::filesystem::remove_all(base, ec);
    return 0;
}

auto refuses(const std::filesystem::path&) -> int {
    std::error_code ec;
    const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                      ("glove_exec_trace_refuse_" + std::to_string(::getpid()));
    const auto workspace = base / "workspace";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    const auto ran = workspace / "agent-ran";
    const std::string script = "/usr/bin/touch '" + ran.string() + "'";

    // Inside the workspace: the agent could rewrite its own trace.
    const auto inside = workspace / "trace.jsonl";
    int status = glove_exec(workspace, inside, base / "audit.jsonl", script, base / "stderr1.txt");
    REQUIRE(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0);
    REQUIRE(!std::filesystem::exists(ran, ec));
    REQUIRE(!std::filesystem::exists(inside, ec));
    REQUIRE(read_file(base / "stderr1.txt").contains("denial trace destination is exposed"));

    // An existing file is never overwritten or appended to.
    const auto existing = base / "existing.jsonl";
    std::ofstream{existing} << "keep\n";
    status = glove_exec(workspace, existing, base / "audit.jsonl", script, base / "stderr2.txt");
    REQUIRE(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) != 0);
    REQUIRE(!std::filesystem::exists(ran, ec));
    REQUIRE(read_file(existing) == "keep\n");
    std::printf("R ok\n");
    std::filesystem::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    const char* home_env = std::getenv("HOME");
    REQUIRE(home_env != nullptr && *home_env == '/');
    std::error_code ec;
    const auto home = std::filesystem::canonical(home_env, ec);
    REQUIRE(!ec);
    for (int number = 1; number <= trials; ++number) {
        if (const int failed = records(number, home); failed != 0) {
            return failed;
        }
    }
    if (const int failed = refuses(home); failed != 0) {
        return failed;
    }
    std::printf("exec denial trace ok\n");
    return 0;
}
