// Stage 1 integration test (macOS): the spawner must contain an ARBITRARY,
// non-glove-aware binary via an SBPL profile applied through sandbox-exec —
// not rely on the agent self-sandboxing. We spawn /bin/sh with a probe that
// reports whether it can write inside the configured workspace (must) and
// outside it, in $HOME (must not), and read a benign file outside it (must
// not). Reaching any result at all also proves
// the system.sb import lets a dynamically linked binary start under the
// sandbox.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
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
    const char* home = std::getenv("HOME");
    REQUIRE(home != nullptr && *home != '\0');

    // A writable workspace under $HOME, so the "allow workspace / deny the rest
    // of $HOME" distinction is meaningful (a /tmp workspace would be covered by
    // the default scratch-dir allowance and prove nothing).
    std::string ws = std::string{home} + "/.glove_ws_test_" + std::to_string(::getpid());
    std::error_code ec;
    std::filesystem::create_directories(ws, ec);
    REQUIRE(!ec);

    std::string evil = std::string{home} + "/.glove_evil_" + std::to_string(::getpid());

    glove::container::profile prof;
    prof.filesystem.push_back({.path = ws, .writable = true});

    // Probe: report deny/allow for a write outside the workspace and inside it,
    // plus a read outside the workspace. The executable itself is an implicit
    // runtime grant; unrelated host files are not.
    std::string script = "if touch '" + evil + "' 2>/dev/null; then h=WRITE; else h=DENY; fi; ";
    script += "if touch '" + ws + "/ok' 2>/dev/null; then w=WRITE; else w=DENY; fi; ";
    script += "if head -c1 '" + std::string{__FILE__} +
              "' >/dev/null 2>&1; then r=READ; else r=DENY; fi; ";
    script += "echo \"home=$h ws=$w outside_read=$r\"";

    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    auto handle_or = spawner->spawn(prof, {"/bin/sh", "-c", script});
    REQUIRE(handle_or.has_value());
    auto handle = std::move(*handle_or);

    auto line = handle->transport().recv();
    REQUIRE(line.has_value());
    std::fprintf(stderr, "probe: %s\n", line->c_str());

    const bool home_denied = line->find("home=DENY") != std::string::npos;
    const bool ws_allowed = line->find("ws=WRITE") != std::string::npos;
    const bool outside_read_denied = line->find("outside_read=DENY") != std::string::npos;

    std::filesystem::remove_all(ws, ec);
    std::filesystem::remove(evil, ec);

    REQUIRE(home_denied);
    REQUIRE(ws_allowed);
    REQUIRE(outside_read_denied);

    // The grant holder must not be able to replace the grant root itself. With
    // no root guard an agent can unlink an empty root and plant a symlink; the
    // next launch canonicalizes that path and silently grants the link target.
    std::filesystem::create_directories(ws, ec);
    REQUIRE(!ec);
    std::string outside = std::string{home} + "/.glove_evil_root_" + std::to_string(::getpid());
    std::filesystem::create_directories(outside, ec);
    REQUIRE(!ec);

    std::string replace = "if rmdir '" + ws + "' 2>/dev/null; then r=UNLINKED; ";
    replace +=
        "if ln -s '" + outside + "' '" + ws + "' 2>/dev/null; then l=REPLACED; else l=FAILED; fi; ";
    replace += "else r=DENY; l=SKIPPED; fi; echo \"root_rmdir=$r root_link=$l\"";

    auto replaced_or = spawner->spawn(prof, {"/bin/sh", "-c", replace});
    REQUIRE(replaced_or.has_value());
    auto replaced = std::move(*replaced_or);
    auto replaced_line = replaced->transport().recv();
    REQUIRE(replaced_line.has_value());
    std::fprintf(stderr, "probe: %s\n", replaced_line->c_str());
    const bool root_unlinked = replaced_line->find("root_rmdir=UNLINKED") != std::string::npos;
    const bool root_replaced = replaced_line->find("root_link=REPLACED") != std::string::npos;
    const bool still_directory =
        std::filesystem::is_directory(ws, ec) && !std::filesystem::is_symlink(ws, ec);

    std::filesystem::remove_all(ws, ec);
    std::filesystem::remove_all(outside, ec);

    REQUIRE(!root_unlinked);
    REQUIRE(!root_replaced);
    REQUIRE(still_directory);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
