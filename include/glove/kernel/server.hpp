#pragma once

#include "glove/audit/sink.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/policy/engine.hpp"
#include "glove/version.hpp"

#include <expected>
#include <memory>
#include <string>

namespace glove::kernel {

// Identifying info the kernel returns from `initialize`. Kept here (vs.
// hard-coded in server.cpp) so callers can override per-deployment.
struct server_identity {
    std::string name = "glove";
    std::string version{glove::version};
};

// MCP server loop driven by a transport. Reads frames from the agent,
// dispatches into the registry (with optional policy + audit interception),
// writes responses back. Returns when recv() reports EOF.
//
// The same transport carries both directions (agent→kernel requests come in
// via recv; kernel→agent responses go out via send). The agent_handle
// produced by the container spawner satisfies this contract.
class server {
public:
    struct options {
        server_identity identity;
        // Optional. Each tool call is gated by this policy before dispatch.
        std::shared_ptr<glove::policy::engine> policy;
        // Optional. Every dispatch (allowed or denied) is recorded here.
        std::shared_ptr<glove::audit::sink> audit;
    };

    server(glove::mcp::transport& transport, registry& reg, options opts);

    server(const server&) = delete;
    server& operator=(const server&) = delete;
    server(server&&) = delete;
    server& operator=(server&&) = delete;

    // Run until the agent disconnects (recv returns eof) or a fatal codec
    // error makes continuing unsafe. Returns nothing on clean shutdown.
    auto run() -> std::expected<void, std::string>;

private:
    glove::mcp::transport* transport_;
    registry* registry_;
    options opts_;
};

} // namespace glove::kernel
