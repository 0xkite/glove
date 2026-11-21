#pragma once

#include "glove/net/egress_proxy.hpp"
#include "glove/policy/engine.hpp"
#include "glove/run/secret_reference.hpp"

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

// One literal environment variable set in the sandbox.
struct environment_value {
    std::string name;
    std::string value;
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
    // Optional new file for this launch's raw sandbox denials (macOS only),
    // collected to train and evaluate denial deciders. Never inside a path
    // the agent can reach.
    std::optional<std::filesystem::path> denial_trace;
    // Optional read-write workspace path exposed to the agent. When unset,
    // both modes use only a per-run private empty working directory.
    std::optional<std::filesystem::path> workspace;
    // Extra explicit filesystem capabilities.
    std::vector<std::string> readable;
    std::vector<std::string> writable;
    // Names copied from the host environment. Values are looked up only after
    // explicit selection; no host variable is inherited by default.
    std::vector<std::string> environment_names;
    // Literal variables from a launch profile. The same names are reserved
    // as for environment_names.
    std::vector<environment_value> environment_values;
    // Exact host+port grants through the authenticated egress proxy.
    std::vector<glove::net::egress_rule> egress;
    // Report lifecycle (working/done) to host Herdr supervisor when running
    // inside a Herdr pane.
    bool herdr = false;
    // Preset agent profile (e.g. "claude-code", "codex", "pi") that selects a
    // credentialed reverse endpoint and generates the matching environment.
    std::optional<std::string> agent_preset;
    // `--share-credential <provider>` (shell, Pi only): mediate one host
    // provider key through the credentialed endpoint. The sandbox receives a
    // session nonce and a loopback base URL, never the key itself.
    std::optional<std::string> share_credential;
    // `--share-credential-origin <host>`: required when the host models.json
    // sends a catalog provider to a host Pi's catalog does not name.
    std::optional<std::string> share_credential_origin;
    // Where the preset's provider credential comes from. Unset: the preset's
    // host environment variable (e.g. ANTHROPIC_API_KEY).
    std::optional<secret_reference> provider_secret;
    // Absolute host paths for canary decoys planted for this launch only;
    // "{nonce}" becomes a per-launch value. See src/run/decoys.hpp.
    std::vector<std::string> decoys;
    // Opt-in host system services by catalog name (container/system_services.hpp);
    // empty by default. Feeds profile::system_services, which validate() checks.
    std::vector<std::string> system_services;
    // Permit private-loopback socket binding/listening inside the sandbox's
    // isolated network namespace (required by runtimes like agy).
    bool allow_loopback_listen = false;
    // Extra directories prepended to PATH inside the sandbox (used when
    // mounting an agent harness closure for `glove shell` / `glove loop`).
    std::vector<std::string> extra_path_dirs;
    // Optional plain host-loopback TCP port bridged into the sandbox's private
    // 127.0.0.1 (e.g. 8080 for a local llama.cpp server in Pi's models.json).
    std::optional<std::uint16_t> bridge_port;
    // Plain host-loopback TCP service ports (declaration only in the red commit).
    std::vector<std::uint16_t> service_ports;
    // Materialize guest agent configuration (e.g. ~/.pi/agent/models.json and
    // settings.json) into the private sandbox HOME directory.
    bool seed_guest_agent_home = false;
    // The seeded harness is Pi: its local packages were offered for exposure,
    // so report each one the sandbox still cannot load.
    bool report_pi_packages = false;
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
