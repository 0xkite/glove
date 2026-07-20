// Regression test for F1: the parent-side ends of an upstream's pipes must be
// close-on-exec so they do NOT survive into a subsequently spawned process.
// If they leaked, a contained agent could read/write upstream MCP servers
// directly, bypassing the kernel's policy and audit.
//
// Strategy: hold several upstreams open (each contributes two parent-side pipe
// fds), then spawn one more process that reports how many file descriptors it
// inherited. With FD_CLOEXEC the count is constant (just stdio + the listing's
// own handle); without it, the count grows by two per held upstream.

#include "glove/mcp/stdio_transport.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto inherited_descriptor_count() -> int {
    glove::mcp::stdio_child_options counter{
        .program = "/bin/sh",
        .args = {"sh", "-c", "ls /dev/fd | wc -l"},
    };
    auto transport = glove::mcp::make_stdio_transport(counter);
    if (!transport) {
        return -1;
    }
    auto line = (*transport)->recv();
    return line ? std::atoi(line->c_str()) : -1;
}

auto run() -> int {
    const int baseline_count = inherited_descriptor_count();
    REQUIRE(baseline_count > 0);

    // Hold several upstreams open. Each is a plain `cat` that we never talk to;
    // we only care about the parent-side fds make_stdio_transport keeps.
    std::vector<std::unique_ptr<glove::mcp::transport>> held;
    for (int i = 0; i < 4; ++i) {
        glove::mcp::stdio_child_options opts{
            .program = "/bin/cat",
            .args = {"cat"},
        };
        auto t_or = glove::mcp::make_stdio_transport(opts);
        REQUIRE(t_or.has_value());
        held.push_back(std::move(*t_or));
    }

    // Count again while the upstreams are held. Sanitizers may reserve their
    // own descriptors, so the invariant is no growth rather than a platform-
    // specific absolute count.
    const int loaded_count = inherited_descriptor_count();
    REQUIRE(loaded_count > 0);

    // Without CLOEXEC, four held upstreams add eight inherited pipe ends.
    std::fprintf(
        stderr, "inherited fd count: baseline=%d loaded=%d\n", baseline_count, loaded_count
    );
    REQUIRE(loaded_count == baseline_count);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
