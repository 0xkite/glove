// Spawns /bin/cat -u as an echo "server" and round-trips a few frames through
// the stdio transport. The point is to exercise the spawn/pipe/cleanup path
// under sanitizers; the codec is irrelevant here.
//
// macOS-only for now: BSD cat supports `-u` (unbuffered). When Linux CI lands
// we will switch to `stdbuf -o0 cat` or equivalent.

#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <cstdlib>
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
    glove::mcp::stdio_child_options opts{
        .program = "/bin/cat",
        .args = {"cat", "-u"},
    };

    auto t_or = glove::mcp::make_stdio_transport(opts);
    REQUIRE(t_or.has_value());
    std::unique_ptr<glove::mcp::transport> t = std::move(*t_or);

    for (int i = 0; i < 8; ++i) {
        std::string frame = "hello-";
        frame.append(std::to_string(i));

        auto sent = t->send(frame);
        REQUIRE(sent.has_value());

        auto got = t->recv();
        REQUIRE(got.has_value());
        REQUIRE(*got == frame);
    }

    REQUIRE(!t->send("two\nframes").has_value());

    REQUIRE(::setenv("GLOVE_TEST_HOST_SECRET", "must-not-cross", 1) == 0);
    glove::mcp::stdio_child_options environment_probe{
        .program = "/bin/sh",
        .args = {"sh", "-c", "env | grep GLOVE_TEST_HOST_SECRET || echo scrubbed"},
    };
    auto probe_or = glove::mcp::make_stdio_transport(environment_probe);
    REQUIRE(probe_or.has_value());
    auto probe = std::move(*probe_or);
    auto environment_result = probe->recv();
    REQUIRE(environment_result.has_value());
    REQUIRE(*environment_result == "scrubbed");
    REQUIRE(::unsetenv("GLOVE_TEST_HOST_SECRET") == 0);

    // Unexpected EOF reports the child's exit status when available.
    glove::mcp::stdio_child_options failing_child{
        .program = "/bin/sh",
        .args = {"sh", "-c", "exit 42"},
    };
    auto failing_or = glove::mcp::make_stdio_transport(failing_child);
    REQUIRE(failing_or.has_value());
    auto failing_recv = (*failing_or)->recv();
    REQUIRE(!failing_recv.has_value());
    REQUIRE(failing_recv.error().find("unexpected eof from child") != std::string::npos);
    REQUIRE(failing_recv.error().find("exit status 42") != std::string::npos);

    // Destruction signals the child and reaps it; sanitizers will catch leaks
    // or use-after-close on the pipes.
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
