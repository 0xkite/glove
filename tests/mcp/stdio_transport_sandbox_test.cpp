#include "glove/mcp/stdio_transport.hpp"

#include <cassert>
#include <string>

int main() {
#if defined(__linux__)
    glove::mcp::stdio_child_options opts{
        .program = "/bin/sh",
        .args =
            {"/bin/sh", "-c", "grep '^NoNewPrivs:' /proc/self/status; readlink /proc/self/ns/net"},
        .environment = {"PATH=/usr/bin:/bin"},
        .sandbox = {.enabled = true, .allow_network = false},
    };
    auto transport = glove::mcp::make_stdio_transport(opts);
    if (!transport) {
        // Skip gracefully if the host kernel/AppArmor forbids unprivileged userns.
        if (transport.error().find("unshare:") != std::string::npos) {
            return 77;
        }
        assert(false && "unexpected sandboxed stdio_transport failure");
    }

    auto nnp_line = (*transport)->recv();
    assert(nnp_line.has_value());
    assert(nnp_line->find("NoNewPrivs:\t1") != std::string::npos);

    auto ns_line = (*transport)->recv();
    assert(ns_line.has_value());
    assert(ns_line->find("net:[") != std::string::npos);
#endif
    return 0;
}
