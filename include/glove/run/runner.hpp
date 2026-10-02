#pragma once

#include "glove/net/egress_proxy.hpp"
#include "glove/policy/engine.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace glove::run {

// One upstream MCP server description. `argv` is forwarded to
// `mcp::stdio_transport`; `name` becomes the registry namespace prefix.
struct upstream_spec {
    std::string name;
    std::vector<std::string> argv;
};

// Top-level options for the `glove run` subcommand. Built from CLI flags
// (today) or config (Phase 6).
struct options {
    // The contained agent's argv (program path + args). Required.
    std::vector<std::string> agent_argv;
    // Zero or more upstream MCP servers, exposed as extensions.
    std::vector<upstream_spec> upstreams;
    // Allow-list of qualified tool names (e.g. "yams.mcp.echo"). Empty
    // means default-deny-all (no tool calls succeed).
    std::vector<std::string> allow;
    // Argument-level prefix constraints. A rule whose `tool_name` is also
    // in `allow` tightens what arguments that tool will accept. See
    // `glove::policy::argument_prefix_rule`.
    std::vector<glove::policy::argument_prefix_rule> prefix_rules;
    // Optional JSONL audit destination. When unset, an in-memory sink is
    // used (events drop on exit; only useful in tests).
    std::optional<std::filesystem::path> audit_log;
    // Optional read-write workspace path exposed to the agent. When unset,
    // both modes use only a per-run private empty working directory.
    std::optional<std::filesystem::path> workspace;
    // Extra explicit filesystem capabilities.
    std::vector<std::string> readable;
    std::vector<std::string> writable;
    // Names copied from the host environment. Values are looked up only after
    // explicit selection; no host variable is inherited by default.
    std::vector<std::string> environment_names;
    // Exact host+port grants through the authenticated egress proxy.
    std::vector<glove::net::egress_rule> egress;
    // Report lifecycle (working/done) to host Herdr supervisor when running
    // inside a Herdr pane.
    bool herdr = false;
    // Preset agent profile (e.g. "claude-code", "codex", "pi") that selects a
    // credentialed reverse endpoint and generates the matching environment.
    std::optional<std::string> agent_preset;
};

// Run the contained agent end-to-end: build the profile, spawn the agent,
// wire the kernel server with a registry of MCP extensions, run until the
// agent disconnects, return its exit code.
auto execute(const options& opts) -> std::expected<int, std::string>;

// Run a real, self-driving agent contained but NOT as an MCP client: the agent
// keeps its own stdio (terminal / --print output) and, on supported platforms,
// reaches its LLM through the egress proxy. Builds the profile + proxy, then blocks in
// `exec_contained` until the agent exits. `upstreams`/`allow`/`prefix_rules`
// are ignored (no kernel). This is the `glove exec` path for agents like pi.
auto exec(const options& opts) -> std::expected<int, std::string>;

} // namespace glove::run
