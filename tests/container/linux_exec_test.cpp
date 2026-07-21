// Stage 3 + Step A (Linux): `glove exec` contains a real agent via clone3 +
// namespaces + a strict allow-list rootfs, with stdio inherited. We run
// /usr/bin/sh through exec_contained and assert the whole posture in one shot,
// writing the results into the workspace for the host to read back. Requires the
// privileged Docker environment the other Linux spawner tests use.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto contains(const std::string& hay, std::string_view needle) -> bool {
    return hay.find(needle) != std::string::npos;
}

auto run() -> int {
    const std::string id = std::to_string(::getpid());
    // Keep the fixture outside /tmp, which the container shadows with a fresh
    // tmpfs, but inside CTest's runner-owned working directory. A neighboring
    // file proves non-granted paths are absent rather than merely read-only.
    const auto base = std::filesystem::current_path();
    const auto ws = base / ("glove_ws_" + id);
    const auto home = ws / "home";
    const auto outside = base / ("glove_outside_" + id);
    std::error_code filesystem_error;
    REQUIRE(std::filesystem::create_directories(home, filesystem_error));
    REQUIRE(!filesystem_error);
    {
        std::ofstream marker{outside};
        marker << "OUTSIDE_PROBE_VALUE";
        REQUIRE(marker.good());
    }
    REQUIRE(::setenv("GLOVE_TEST_HOST_SECRET", "must-not-cross", 1) == 0);

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws.string(), .writable = true});
    prof.home_dir = home.string();
    prof.work_dir = ws.string();
    prof.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin"};

    // One agent invocation probes the whole perimeter and writes a result line.
    std::string script;
    script += "{ ";
    script += "echo pid=$$; ";     // PID namespace
    script += "echo cwd=$PWD; ";   // work_dir
    script += "echo home=$HOME; "; // scratch HOME
    script += "head -c4 '" + outside.string() +
              "' >/dev/null 2>&1 && echo outside=BAD || echo outside=denied; ";
    script += "touch /etc/glove_evil 2>/dev/null && echo writeetc=BAD || echo writeetc=denied; ";
    script += "touch ./wok 2>/dev/null && echo writews=ok || echo writews=no; ";
    script +=
        "env | grep '^GLOVE_TEST_HOST_SECRET=' >/dev/null && echo env=BAD || echo env=scrubbed; ";
    script += "} > '" + (ws / "result").string() + "'";

    auto code = glove::container::exec_contained(prof, {"/usr/bin/sh", "-c", script});
    REQUIRE(code.has_value());
    REQUIRE(*code == 0);

    std::ifstream in{ws / "result"};
    REQUIRE(in.good());
    std::string out((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::fprintf(
        stderr, "--- agent perimeter probe ---\n%s-----------------------------\n", out.c_str()
    );

    REQUIRE(contains(out, "pid=1"));                 // contained: PID 1 of its own ns
    REQUIRE(contains(out, "cwd=" + ws.string()));    // started in the workspace
    REQUIRE(contains(out, "home=" + home.string())); // HOME is the scratch home
    REQUIRE(contains(out, "outside=denied"));        // unrelated host file is absent
    REQUIRE(contains(out, "writeetc=denied"));       // write-narrow: /etc not writable
    REQUIRE(contains(out, "writews=ok"));            // workspace writable
    REQUIRE(contains(out, "env=scrubbed"));          // host credentials are not inherited

    REQUIRE(std::filesystem::remove_all(ws, filesystem_error) > 0);
    REQUIRE(!filesystem_error);
    REQUIRE(std::filesystem::remove(outside, filesystem_error));
    REQUIRE(!filesystem_error);
    REQUIRE(::unsetenv("GLOVE_TEST_HOST_SECRET") == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
