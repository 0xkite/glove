#if defined(__linux__)
#    include "glove/mcp/stdio_transport.hpp"

#    include <unistd.h>

#    include <cstdio>
#    include <string>
#    include <string_view>

namespace {

// The product refuses to build a sandbox as host root and depends on a kernel
// that permits unprivileged user namespaces. Neither is a product defect, so a
// host without that capability reports a skip instead of a failure. Anything
// else - including a partial sandbox or a prctl() refusal - is a regression and
// must fail.
auto environment_skip(std::string_view error) -> bool {
    constexpr std::string_view unsupported[] = {
        "stdio_transport sandbox refuses to run as host root",
        "unshare:",
        "sandboxed spawn: write /proc/self/setgroups failed",
        "sandboxed spawn: write /proc/self/uid_map failed",
        "sandboxed spawn: write /proc/self/gid_map failed",
    };
    for (const auto prefix : unsupported) {
        if (error.starts_with(prefix)) {
            return true;
        }
    }
    return false;
}

} // namespace

// NDEBUG builds compile assert() out, so this test never relies on it.
// Dereferencing an errored expected<T> is undefined behaviour, which is how
// this test previously "passed" as a UBSan misaligned-call report.
#    define REQUIRE(cond)                                                                          \
        do {                                                                                       \
            if (!(cond)) {                                                                         \
                std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);   \
                return 1;                                                                          \
            }                                                                                      \
        } while (0)

int main() {
    glove::mcp::stdio_child_options opts{
        .program = "/bin/sh",
        .args =
            {"/bin/sh",
             "-c",
             "grep '^NoNewPrivs:' /proc/self/status; readlink /proc/self/ns/net; id -u"},
        .environment = {"PATH=/usr/bin:/bin"},
        .sandbox = {.enabled = true, .allow_network = false},
    };
    auto transport = glove::mcp::make_stdio_transport(opts);
    if (!transport) {
        const auto& error = transport.error();
        if (environment_skip(error)) {
            std::fprintf(
                stderr, "SKIP: sandboxed stdio transport unavailable: %s\n", error.c_str()
            );
            return 77;
        }
        std::fprintf(
            stderr, "FAIL: unexpected sandboxed stdio transport error: %s\n", error.c_str()
        );
        return 1;
    }

    auto nnp_line = (*transport)->recv();
    REQUIRE(nnp_line.has_value());
    REQUIRE(nnp_line->find("NoNewPrivs:\t1") != std::string::npos);

    auto ns_line = (*transport)->recv();
    REQUIRE(ns_line.has_value());
    REQUIRE(ns_line->find("net:[") != std::string::npos);

    auto uid_line = (*transport)->recv();
    REQUIRE(uid_line.has_value());
    REQUIRE(*uid_line == std::to_string(::geteuid()));
    return 0;
}
#else
int main() {
    return 0;
}
#endif
