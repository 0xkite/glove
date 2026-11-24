#pragma once

#include "glove/mcp/transport.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace glove::mcp {

struct stdio_sandbox_options {
    bool enabled = false;
    bool allow_network = false;
    // Plain host 127.0.0.1 TCP ports forwarded into CLONE_NEWNET (Linux).
    std::vector<std::uint16_t> service_ports{};
};

// Options for spawning an MCP server (or any line-framed peer) as a child
// process. The child's stdin/stdout become the wire; its stderr is inherited
// by the caller for log surfacing.
struct stdio_child_options {
    // argv[0] — the program path. Looked up via PATH (posix_spawnp).
    std::string program;
    // Full argv. Conventionally argv[0] equals `program`. May be empty, in
    // which case argv = { program, nullptr } is used.
    std::vector<std::string> args;
    // Complete child environment as NAME=VALUE. Empty selects a minimal PATH,
    // never the host process environment.
    std::vector<std::string> environment{};
    // Optional Linux namespace + NoNewPrivs containment for upstream MCP tools.
    stdio_sandbox_options sandbox{};
};

// Spawn `opts.program` and return a transport that talks to it via newline-
// delimited frames over the child's stdin/stdout. The child is signalled and
// reaped when the transport is destroyed.
//
// Frames must not contain '\n'; the line is the framing unit until the JSON-
// RPC codec layer lands. Frame content is arbitrary bytes otherwise.
auto make_stdio_transport(const stdio_child_options& opts)
    -> std::expected<std::unique_ptr<transport>, std::string>;

} // namespace glove::mcp
