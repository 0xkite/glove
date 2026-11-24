// Container spawner round-trip — runs on macOS (sandbox-exec spawner) and
// Linux (clone_spawner baseline). Spawns the synthetic agent in server mode,
// drives initialize / tools/list / tools/call through the inherited stdio
// pipes, drops the handle, lets the dtor reap.
//
// On macOS, sandbox-exec applies SBPL before the synthetic agent starts. On
// Linux the clone3 child builds its namespace/rootfs/seccomp perimeter before
// exec. The round trip therefore also proves the contained process can retain
// only its intended stdio channel.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdio>
#include <memory>
#include <string>
#include <utility>

#ifndef GLOVE_SYNTHETIC_AGENT_BIN
#    error "GLOVE_SYNTHETIC_AGENT_BIN must point at the synthetic agent binary"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    glove::container::profile p;
    p.filesystem.push_back({.path = "/usr/lib", .writable = false});
    auto vp = glove::container::validate(p);
    REQUIRE(vp.has_value());

    auto sp = glove::container::make_default_spawner();
    REQUIRE(sp != nullptr);

    auto os_tier = glove::container::make_spawner(glove::container::isolation_tier::os_primitives);
    REQUIRE(os_tier.has_value() && *os_tier != nullptr);

    auto vm_tier = glove::container::make_spawner(glove::container::isolation_tier::microvm);
    REQUIRE(!vm_tier.has_value());
    REQUIRE(vm_tier.error().find("not constructed") != std::string::npos);

    glove::container::profile limited;
    limited.required_limits = glove::container::resource_limits{
        .cpu_time_ms = 60'000,
        .memory_bytes = 512 * 1024 * 1024,
        .pids = 128,
        .wall_time_ms = 120'000,
        .disk_bytes = 1024 * 1024 * 1024,
        .terminal_output_bytes = 16 * 1024 * 1024,
    };
    REQUIRE(!sp->resource_capabilities().complete());
    auto rejected_spawn = sp->spawn(limited, {GLOVE_SYNTHETIC_AGENT_BIN});
    REQUIRE(!rejected_spawn.has_value());
    REQUIRE(
        rejected_spawn.error().find("mandatory resource enforcement unavailable") !=
        std::string::npos
    );
    auto rejected_exec = glove::container::exec_contained(limited, {GLOVE_SYNTHETIC_AGENT_BIN});
    REQUIRE(!rejected_exec.has_value());
    REQUIRE(
        rejected_exec.error().find("mandatory resource enforcement unavailable") !=
        std::string::npos
    );

    auto handle = sp->spawn(*vp, {GLOVE_SYNTHETIC_AGENT_BIN});
    if (!handle) {
        std::fprintf(stderr, "spawn failed: %s\n", handle.error().c_str());
        return 1;
    }
    auto& t = (*handle)->transport();

    auto sent = t.send(
        R"({"jsonrpc":"2.0","id":1,"method":"initialize",)"
        R"("params":{"protocolVersion":"2025-06-18",)"
        R"("capabilities":{},)"
        R"("clientInfo":{"name":"test","version":"0"}}})"
    );
    REQUIRE(sent.has_value());
    auto reply = t.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":1") != std::string::npos);
    REQUIRE(reply->find("glove-synthetic-agent") != std::string::npos);
    REQUIRE(reply->find("\"protocolVersion\":\"2025-06-18\"") != std::string::npos);

    sent = t.send(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    REQUIRE(sent.has_value());
    reply = t.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":2") != std::string::npos);
    REQUIRE(reply->find("\"name\":\"noop\"") != std::string::npos);

    sent = t.send(
        R"({"jsonrpc":"2.0","id":3,"method":"tools/call",)"
        R"("params":{"name":"noop","arguments":{}}})"
    );
    REQUIRE(sent.has_value());
    reply = t.recv();
    REQUIRE(reply.has_value());
    REQUIRE(reply->find("\"id\":3") != std::string::npos);
    REQUIRE(reply->find("noop ok") != std::string::npos);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
