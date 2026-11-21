#include "glove/detail/descriptor_limit.hpp"
#include "glove/host/config.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/policy/engine.hpp"
#include "glove/reflect/json_codec.hpp"
#include "glove/run/launch_profile.hpp"
#include "glove/run/pi_host_config.hpp"
#include "glove/run/pi_provider_share.hpp"
#include "glove/run/runner.hpp"
#include "glove/term/terminal.hpp"
#include "glove/version.hpp"

#include "host/cli.hpp"
#include "run/pi_cli.hpp"
#include "run/profile_cli.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void print_banner() {
    auto term = glove::term::make_default_terminal();
    std::string banner = "glove ";
    banner.append(glove::version);
    banner.append(" — lightweight LLM-agent container.\n");
    term->write(banner);
    term->flush();
}

void print_run_usage() {
    std::fprintf(
        stderr,
        "usage: glove run [options] -- <agent argv>...\n"
        "\n"
        "options:\n"
        "  --profile <name>                     start from launch profile <name>\n"
        "                                       (see `glove profile`); flags add to it\n"
        "  --upstream <name>=<cmd>[,<arg>...]   register one upstream MCP server\n"
        "                                       (may be repeated)\n"
        "  --allow <qualified.tool>             permit one tool name through policy\n"
        "                                       (may be repeated; default deny)\n"
        "  --allow-arg <tool>:<field>=<prefix>  argument-level constraint: the tool's\n"
        "                                       <field> argument must be a string starting\n"
        "                                       with <prefix> (may be repeated; multiple\n"
        "                                       rules for the same tool ALL must pass)\n"
        "  --audit-log <path>                   JSONL audit destination\n"
        "                                       (default: in-memory)\n"
        "  --denial-trace <path>                record this launch's sandbox denials to a\n"
        "                                       new file (macOS; for training deciders)\n"
        "  --workspace <path>                   read-write workspace bound for the agent\n"
        "                                       (default: none)\n"
        "  --read <path>                        expose one additional path read-only\n"
        "  --write <path>                       expose one additional path read-write\n"
        "  --env <name>                         copy one named host environment variable\n"
        "  --egress-allow <host>[:port]         permit outbound HTTPS through the\n"
        "                                       audited egress proxy (may be repeated; a\n"
        "                                       leading '.' matches subdomains; port defaults\n"
        "                                       to 443). Without any,\n"
        "                                       the agent has no network.\n"
        "  --system-service <name>              opt in to a host system service from the\n"
        "                                       catalog (network-config, tls-config; may be\n"
        "                                       repeated; default none)\n"
        "  -h, --help                           show this help and exit\n"
    );
}

// Split a `--allow-arg` value of the form `<tool>:<field>=<prefix>`.
auto parse_allow_arg(std::string_view spec)
    -> std::expected<glove::policy::argument_prefix_rule, std::string> {
    auto colon = spec.find(':');
    if (colon == std::string_view::npos) {
        return std::unexpected(std::string{"--allow-arg needs tool:field=prefix"});
    }
    auto eq = spec.find('=', colon + 1);
    if (eq == std::string_view::npos) {
        return std::unexpected(std::string{"--allow-arg needs tool:field=prefix"});
    }
    glove::policy::argument_prefix_rule out{
        .tool_name = std::string{spec.substr(0, colon)},
        .field = std::string{spec.substr(colon + 1, eq - colon - 1)},
        .required_prefix = std::string{spec.substr(eq + 1)},
    };
    if (out.tool_name.empty() || out.field.empty()) {
        return std::unexpected(std::string{"--allow-arg tool and field cannot be empty"});
    }
    return out;
}

auto parse_egress(std::string_view spec) -> std::expected<glove::net::egress_rule, std::string> {
    glove::net::egress_rule rule;
    std::string_view host = spec;
    std::string_view port;
    const auto colon = spec.rfind(':');
    if (colon != std::string_view::npos && spec.find(':') == colon) {
        host = spec.substr(0, colon);
        port = spec.substr(colon + 1);
    }
    if (host.empty()) {
        return std::unexpected(std::string{"--egress-allow host cannot be empty"});
    }
    rule.host = std::string{host};
    if (!port.empty()) {
        unsigned parsed = 0;
        for (const char c : port) {
            if (c < '0' || c > '9') {
                return std::unexpected(std::string{"--egress-allow port must be numeric"});
            }
            parsed = parsed * 10U + static_cast<unsigned>(c - '0');
            if (parsed > 65535U) {
                return std::unexpected(std::string{"--egress-allow port is out of range"});
            }
        }
        if (parsed == 0) {
            return std::unexpected(std::string{"--egress-allow port must be non-zero"});
        }
        rule.port = static_cast<std::uint16_t>(parsed);
    }
    return rule;
}

// Split a `--upstream` / `--mcp` value of the form `<name>=<cmd>[,<arg>...]`
// or shorthand `<name>` (e.g. `yams` -> `yams=/usr/local/bin/yams,serve,--quiet`).
auto parse_upstream(std::string_view spec)
    -> std::expected<glove::run::upstream_spec, std::string> {
    auto eq = spec.find('=');
    if (eq == std::string_view::npos) {
        if (spec == "yams") {
            std::string bin = "/usr/local/bin/yams";
            if (!std::filesystem::exists(bin) && std::filesystem::exists("/usr/bin/yams")) {
                bin = "/usr/bin/yams";
            }
            return glove::run::upstream_spec{
                .name = "yams",
                .argv = {std::move(bin), "serve", "--quiet"},
            };
        }
        return std::unexpected(std::string{"--upstream needs name=cmd[,arg...] (or 'yams')"});
    }
    glove::run::upstream_spec out;
    out.name = std::string{spec.substr(0, eq)};
    if (out.name.empty()) {
        return std::unexpected(std::string{"--upstream name is empty"});
    }

    std::string_view rest = spec.substr(eq + 1);
    while (!rest.empty()) {
        auto comma = rest.find(',');
        if (comma == std::string_view::npos) {
            out.argv.emplace_back(rest);
            break;
        }
        out.argv.emplace_back(rest.substr(0, comma));
        rest = rest.substr(comma + 1);
    }
    if (out.argv.empty() || out.argv.front().empty()) {
        return std::unexpected(std::string{"--upstream cmd is empty"});
    }
    return out;
}

void print_exec_usage() {
    std::fprintf(
        stderr,
        "usage: glove exec [options] -- <agent argv>...\n"
        "\n"
        "Run a real, self-driving agent (e.g. pi) contained: it keeps its own\n"
        "stdio and reaches its LLM only through the audited egress proxy. No MCP\n"
        "kernel is wired (use `glove run` for an MCP-client agent).\n"
        "\n"
        "options:\n"
        "  --profile <name>        start from launch profile <name> (see `glove profile`);\n"
        "                          the flags below add to it\n"
        "  --workspace <path>      read-write workspace for the agent\n"
        "                          (omitted: private empty working directory)\n"
        "  --read <path>           expose one additional path read-only\n"
        "  --write <path>          expose one additional path read-write\n"
        "  --env <name>            copy one named host environment variable\n"
        "  --mcp, --upstream <spec>\n"
        "                          attach an MCP server (`yams` or `<name>=<cmd>[,<arg>...]`);\n"
        "                          all tools are allowed unless `--allow` is specified\n"
        "  --allow <qualified.tool>\n"
        "                          restrict MCP to an explicit allow-list of tools\n"
        "  --allow-arg <tool>:<field>=<prefix>\n"
        "                          argument prefix constraint on an allowed tool\n"
        "  --bridge-port <port>    bridge a host 127.0.0.1 TCP port into the sandbox\n"
        "  --service-port <port>   allow a plain host 127.0.0.1 TCP service (repeatable;\n"
        "                          works with --share-credential; no credential)\n"
        "  --system-service <name> opt in to a host system service from the catalog\n"
        "                          (network-config, tls-config; repeatable; default none)\n"
        "  --audit-log <path>      append launch, exit, and egress events as JSONL\n"
        "  --denial-trace <path>   record this launch's sandbox denials to a new file\n"
        "                          (macOS; for training denial deciders)\n"
        "  --egress-allow <host>[:port]\n"
        "                          permit outbound HTTPS (repeatable; leading '.'\n"
        "                          matches subdomains; port defaults to 443). Without any,\n"
        "                          the agent has no network.\n"
        "  --allow-loopback-listen allow private-loopback bind/listen inside the\n"
        "                          sandbox network namespace (e.g. for agy)\n"
        "  --herdr                 report lifecycle (working/done) to host Herdr when\n"
        "                          running inside a Herdr pane\n"
        "  --agent <preset>        mediate provider credentials for a built-in client\n"
        "                          (claude-code, codex, or pi). Reads the provider key\n"
        "                          from the host environment, bridges a local reverse\n"
        "                          endpoint into the sandbox, and injects the real key\n"
        "                          on the host side; the sandbox sees only an ephemeral\n"
        "                          session nonce.\n"
        "  -h, --help              show this help and exit\n"
    );
}

void print_shell_usage() {
    std::fprintf(
        stderr,
        "usage: glove shell [<env-name>] [options] [-- <agent args or command>...]\n"
        "\n"
        "Launch an interactive agent harness prompt TUI (pi, agy, claude, or codex)\n"
        "directly inside the workspace (auto-creating --workspace if needed).\n"
        "\n"
        "saved environments (<XDG_CONFIG_HOME>/glove/envs/<name>.json):\n"
        "  --save <name>           save this environment configuration for quick launch\n"
        "  --load <name>           load a saved environment (or pass <name> positionally)\n"
        "  --last                  launch the most recently used environment\n"
        "  --list                  list saved and currently running environments\n"
        "\n"
        "options:\n"
        "  --profile <name>        start from launch profile <name> (see `glove profile`)\n"
        "  --workspace <path>      read-write workspace (auto-created if missing;\n"
        "                          omitted: ephemeral private workspace)\n"
        "  --agent <name>          agent harness to launch: pi, agy, claude, or codex\n"
        "                          (omitted: auto-detects installed harness)\n"
        "  --read <path>           expose one additional path read-only\n"
        "  --write <path>          expose one additional path read-write\n"
        "  --env <name>            copy one named host environment variable\n"
        "  --mcp, --upstream <spec>\n"
        "                          attach an MCP server (`yams` or `<name>=<cmd>[,<arg>...]`);\n"
        "                          all tools are allowed unless `--allow` is specified\n"
        "  --allow <qualified.tool>\n"
        "                          restrict MCP to an explicit allow-list of tools\n"
        "  --allow-arg <tool>:<field>=<prefix>\n"
        "                          argument prefix constraint on an allowed tool\n"
        "  --bridge-port <port>    bridge a host 127.0.0.1 TCP port into the sandbox\n"
        "  --service-port <port>   allow a plain host 127.0.0.1 TCP service (repeatable;\n"
        "                          works with --share-credential; no credential)\n"
        "  --system-service <name> opt in to a host system service from the catalog\n"
        "                          (network-config, tls-config; repeatable; default none)\n"
        "  --audit-log <path>      append launch, exit, and egress events as JSONL\n"
        "  --share-credential <pi-provider>\n"
        "                          with --agent pi: mediate the host API key for one Pi\n"
        "                          provider; the sandbox gets a session nonce, never the key\n"
        "  --share-credential-origin <host>\n"
        "                          confirm the host when ~/.pi/agent/models.json redirects\n"
        "                          a catalog provider\n"
        "  --egress-allow <host>[:port]\n"
        "                          permit outbound HTTPS through the egress proxy\n"
        "  --allow-loopback-listen allow private-loopback bind/listen inside the\n"
        "                          sandbox network namespace (enabled by default)\n"
        "  --herdr                 report lifecycle to host Herdr\n"
        "  -h, --help              show this help and exit\n"
    );
}

void print_loop_usage() {
    std::fprintf(
        stderr,
        "usage: glove loop --prompt <text|@file> [options]\n"
        "\n"
        "Run a seeded agent feedback loop inside the sandbox. After each agent turn,\n"
        "if --verify is set, runs the verification command inside the sandbox (offline)\n"
        "and feeds failure output back into the next turn until it passes or\n"
        "--max-iterations is reached.\n"
        "\n"
        "options:\n"
        "  --prompt <text|@file>   initial task prompt or @path to prompt file (required)\n"
        "  --agent <name>          agent driver: pi (default), claude, codex, or agy\n"
        "  --cmd <path>            override agent executable path\n"
        "  --verify <cmd>          sandboxed shell command to verify each iteration\n"
        "  --verify-timeout <sec>  kill the verifier after this many seconds (default: 600)\n"
        "  --max-iterations <N>    maximum loop iterations, 1-1000 (default: 5)\n"
        "  --workspace <path>      read-write workspace for the agent\n"
        "  --read <path>           expose one additional path read-only\n"
        "  --write <path>          expose one additional path read-write\n"
        "  --env <name>            copy one named host environment variable\n"
        "  --mcp, --upstream <spec>\n"
        "                          attach an MCP server (`yams` or `<name>=<cmd>[,<arg>...]`);\n"
        "                          all tools are allowed unless `--allow` is specified\n"
        "  --allow <qualified.tool>\n"
        "                          restrict MCP to an explicit allow-list of tools\n"
        "  --allow-arg <tool>:<field>=<prefix>\n"
        "                          argument prefix constraint on an allowed tool\n"
        "  --bridge-port <port>    bridge a host 127.0.0.1 TCP port into the sandbox\n"
        "  --service-port <port>   allow a plain host 127.0.0.1 TCP service (repeatable;\n"
        "                          works with --share-credential; no credential)\n"
        "  --system-service <name> opt in to a host system service from the catalog\n"
        "                          (network-config, tls-config; repeatable; default none)\n"
        "  --audit-log <path>      append launch, exit, and egress events as JSONL\n"
        "  --egress-allow <host>[:port]\n"
        "                          permit outbound HTTPS through the egress proxy\n"
        "  --allow-loopback-listen allow private-loopback bind/listen inside the sandbox\n"
        "  --herdr                 report lifecycle to host Herdr\n"
        "  -h, --help              show this help and exit\n"
    );
}

// Parse flags shared across `exec`, `shell`, and `loop`.
// Returns std::nullopt if args[i] is not a shared sandbox flag, 0 if consumed,
// or 2 on parse error.
auto parse_sandbox_flag(
    std::span<char* const> args,
    std::size_t& i,
    glove::run::options& opts,
    std::string_view cmd_name
) -> std::optional<int> {
    std::string_view a{args[i]};
    if (a == "--workspace") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --workspace needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        opts.workspace = std::filesystem::path{args[i + 1]};
        i += 2;
        return 0;
    }
    if (a == "--herdr") {
        opts.herdr = true;
        ++i;
        return 0;
    }
    if (a == "--allow-loopback-listen") {
        opts.allow_loopback_listen = true;
        ++i;
        return 0;
    }
    if (a == "--share-credential" || a == "--share-credential-origin") {
        if (cmd_name != "shell") {
            std::fprintf(
                stderr,
                "glove %.*s: %.*s is supported only by glove shell --agent pi\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                static_cast<int>(a.size()),
                a.data()
            );
            return 2;
        }
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: %.*s needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                static_cast<int>(a.size()),
                a.data()
            );
            return 2;
        }
        auto& target =
            a == "--share-credential" ? opts.share_credential : opts.share_credential_origin;
        target = std::string{args[i + 1]};
        i += 2;
        return 0;
    }
    if (a == "--agent") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --agent needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        opts.agent_preset = std::string{args[i + 1]};
        i += 2;
        return 0;
    }
    if (a == "--read" || a == "--write" || a == "--env" || a == "--audit-log") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: %.*s needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                static_cast<int>(a.size()),
                a.data()
            );
            return 2;
        }
        if (a == "--read") {
            opts.readable.emplace_back(args[i + 1]);
        } else if (a == "--write") {
            opts.writable.emplace_back(args[i + 1]);
        } else if (a == "--env") {
            opts.environment_names.emplace_back(args[i + 1]);
        } else {
            opts.audit_log = std::filesystem::path{args[i + 1]};
        }
        i += 2;
        return 0;
    }
    if (a == "--system-service") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --system-service needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        // The catalog decides which names exist; validate() refuses the rest at launch.
        opts.system_services.emplace_back(args[i + 1]);
        i += 2;
        return 0;
    }
    if (a == "--egress-allow") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --egress-allow needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        auto rule = parse_egress(args[i + 1]);
        if (!rule) {
            std::fprintf(
                stderr,
                "glove %.*s: %s\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                rule.error().c_str()
            );
            return 2;
        }
        opts.egress.push_back(std::move(*rule));
        i += 2;
        return 0;
    }
    if (a == "--upstream" || a == "--mcp") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: %.*s needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                static_cast<int>(a.size()),
                a.data()
            );
            return 2;
        }
        auto spec = parse_upstream(args[i + 1]);
        if (!spec) {
            std::fprintf(
                stderr,
                "glove %.*s: %s\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                spec.error().c_str()
            );
            return 2;
        }
        opts.upstreams.push_back(std::move(*spec));
        i += 2;
        return 0;
    }
    if (a == "--allow") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --allow needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        opts.allow.emplace_back(args[i + 1]);
        i += 2;
        return 0;
    }
    if (a == "--allow-arg") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --allow-arg needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        auto rule = parse_allow_arg(args[i + 1]);
        if (!rule) {
            std::fprintf(
                stderr,
                "glove %.*s: %s\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data(),
                rule.error().c_str()
            );
            return 2;
        }
        opts.prefix_rules.push_back(std::move(*rule));
        i += 2;
        return 0;
    }
    if (a == "--bridge-port") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --bridge-port needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        int port_val = 0;
        const std::string_view pstr{args[i + 1]};
        const auto [ptr, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), port_val);
        if (pstr.empty() || ec != std::errc{} || ptr != pstr.data() + pstr.size() || port_val < 1 ||
            port_val > 65535) {
            std::fprintf(
                stderr,
                "glove %.*s: --bridge-port must be an integer in [1, 65535]\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        opts.bridge_port = static_cast<std::uint16_t>(port_val);
        i += 2;
        return 0;
    }
    if (a == "--service-port") {
        if (i + 1 >= args.size()) {
            std::fprintf(
                stderr,
                "glove %.*s: --service-port needs an argument\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        int port_val = 0;
        const std::string_view pstr{args[i + 1]};
        const auto [ptr, ec] = std::from_chars(pstr.data(), pstr.data() + pstr.size(), port_val);
        if (pstr.empty() || ec != std::errc{} || ptr != pstr.data() + pstr.size() || port_val < 1 ||
            port_val > 65535) {
            std::fprintf(
                stderr,
                "glove %.*s: --service-port must be an integer in [1, 65535]\n",
                static_cast<int>(cmd_name.size()),
                cmd_name.data()
            );
            return 2;
        }
        opts.service_ports.push_back(static_cast<std::uint16_t>(port_val));
        i += 2;
        return 0;
    }
    return std::nullopt;
}

// Loads launch profile NAME and layers the command-line options OPTS on top.
auto apply_profile_flag(
    const std::optional<std::string>& name, glove::run::options& opts, std::string_view cmd_name
) -> bool {
    if (!name) {
        return true;
    }
    auto profile = glove::run::load_launch_profile(*name);
    if (!profile) {
        std::fprintf(
            stderr,
            "glove %.*s: %s\n",
            static_cast<int>(cmd_name.size()),
            cmd_name.data(),
            profile.error().c_str()
        );
        return false;
    }
    auto applied =
        glove::run::apply_launch_profile(*profile, opts, glove::run::invoking_user_home());
    if (!applied) {
        std::fprintf(
            stderr,
            "glove %.*s: profile %s: %s\n",
            static_cast<int>(cmd_name.size()),
            cmd_name.data(),
            name->c_str(),
            applied.error().c_str()
        );
        return false;
    }
    opts = std::move(*applied);
    return true;
}

// `--profile <name>`: returns 0 when consumed, 2 on a missing argument, or
// nullopt when ARGS[I] is another flag.
auto parse_profile_flag(
    std::span<char* const> args,
    std::size_t& i,
    std::optional<std::string>& name,
    std::string_view cmd_name
) -> std::optional<int> {
    if (std::string_view{args[i]} != "--profile") {
        return std::nullopt;
    }
    if (i + 1 >= args.size() || name) {
        std::fprintf(
            stderr,
            "glove %.*s: --profile needs one argument and may be given once\n",
            static_cast<int>(cmd_name.size()),
            cmd_name.data()
        );
        return 2;
    }
    name = std::string{args[i + 1]};
    i += 2;
    return 0;
}

auto exec_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
    std::optional<std::string> profile_name;
    std::size_t i = 0;
    bool dashdash_seen = false;
    while (i < args.size()) {
        std::string_view a{args[i]};
        if (a == "--") {
            dashdash_seen = true;
            ++i;
            break;
        }
        if (a == "-h" || a == "--help") {
            print_exec_usage();
            return 0;
        }
        if (a == "--denial-trace") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove exec: --denial-trace needs an argument\n");
                return 2;
            }
            opts.denial_trace = std::filesystem::path{args[i + 1]};
            i += 2;
            continue;
        }
        if (const auto handled = parse_profile_flag(args, i, profile_name, "exec")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        if (const auto handled = parse_sandbox_flag(args, i, opts, "exec")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        std::fprintf(
            stderr, "glove exec: unknown flag '%.*s'\n", static_cast<int>(a.size()), a.data()
        );
        print_exec_usage();
        return 2;
    }
    if (!dashdash_seen) {
        std::fprintf(stderr, "glove exec: missing `-- <agent argv>...`\n");
        print_exec_usage();
        return 2;
    }
    while (i < args.size()) {
        opts.agent_argv.emplace_back(args[i]);
        ++i;
    }
    if (opts.agent_argv.empty()) {
        std::fprintf(stderr, "glove exec: agent argv is empty after `--`\n");
        return 2;
    }
    if (!apply_profile_flag(profile_name, opts, "exec")) {
        return 1;
    }

    auto code = glove::run::exec(opts);
    if (!code) {
        std::fprintf(stderr, "glove exec: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

auto paths_overlap(const std::filesystem::path& a, const std::filesystem::path& b) -> bool {
    const auto na = a.lexically_normal();
    const auto nb = b.lexically_normal();
    const auto [ma, _] = std::mismatch(na.begin(), na.end(), nb.begin(), nb.end());
    if (ma == na.end()) {
        return true;
    }
    const auto [mb, __] = std::mismatch(nb.begin(), nb.end(), na.begin(), na.end());
    return mb == nb.end();
}

auto is_subpath_of(const std::filesystem::path& path, const std::filesystem::path& base) -> bool {
    const auto np = path.lexically_normal();
    const auto nb = base.lexically_normal();
    const auto [mb, mp] = std::ranges::mismatch(nb, np);
    return mb == nb.end();
}

void add_non_overlapping_read_dir(glove::run::options& opts, const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || ec) {
        return;
    }
    const auto abs = std::filesystem::weakly_canonical(dir, ec);
    if (ec || abs.empty() || abs == abs.root_path()) {
        return;
    }
    // Never expose the whole user home or sensitive credential dotfiles.
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        const std::filesystem::path home_path{home};
        std::error_code home_ec;
        const auto canon_home = std::filesystem::canonical(home_path, home_ec);
        if (home_ec || canon_home.empty()) {
            return;
        }
        if (abs == canon_home || paths_overlap(abs, canon_home / ".ssh") ||
            paths_overlap(abs, canon_home / ".gnupg") || paths_overlap(abs, canon_home / ".aws")) {
            return;
        }
    }
    // System directories (/usr, /bin, /lib, /etc) are already mounted by the spawner.
    for (const char* sys_root : {"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}) {
        if (paths_overlap(abs, std::filesystem::path{sys_root})) {
            return;
        }
    }
    if (opts.workspace) {
        const auto ws_abs = std::filesystem::weakly_canonical(*opts.workspace, ec);
        if (!ec && paths_overlap(abs, ws_abs)) {
            return;
        }
    }
    for (const auto& existing : opts.writable) {
        const auto ex_abs = std::filesystem::weakly_canonical(existing, ec);
        if (!ec && paths_overlap(abs, ex_abs)) {
            return;
        }
    }
    for (const auto& existing : opts.readable) {
        const auto ex_abs = std::filesystem::weakly_canonical(existing, ec);
        if (!ec && paths_overlap(abs, ex_abs)) {
            return;
        }
    }
    opts.readable.push_back(abs.string());
}

void add_verified_agent_read_dir(
    glove::run::options& opts,
    const std::filesystem::path& dir,
    std::span<const std::filesystem::path> approved_roots
) {
    struct ::stat st{};
    if (::lstat(dir.c_str(), &st) != 0 || st.st_uid != ::geteuid()) {
        return;
    }
    std::error_code ec;
    const auto canon = std::filesystem::canonical(dir, ec);
    if (ec || canon.empty()) {
        return;
    }
    struct ::stat cst{};
    if (::stat(canon.c_str(), &cst) != 0 || !S_ISDIR(cst.st_mode) || cst.st_uid != ::geteuid()) {
        return;
    }
    const std::string canon_str = canon.string();
    for (std::string_view sensitive : {".ssh", ".gnupg", ".aws", ".azure", ".kube", "auth.json"}) {
        if (canon_str.find(sensitive) != std::string::npos) {
            return;
        }
    }
    bool inside_approved = false;
    for (const auto& root : approved_roots) {
        if (is_subpath_of(canon, root)) {
            inside_approved = true;
            break;
        }
    }
    if (!inside_approved) {
        return;
    }
    add_non_overlapping_read_dir(opts, canon);
}

// Expose the local packages and resources named in host Pi settings read-only,
// so one kept outside the approved roots (for example a source checkout) still
// loads. The runner drops any that end up unreadable from the guest settings,
// so a refused package degrades to "not loaded" with a warning.
void add_pi_local_packages(
    glove::run::options& opts,
    const std::filesystem::path& home_dir,
    const std::filesystem::path& pi_agent_dir
) {
    std::vector<std::filesystem::path> agent_writable{opts.writable.begin(), opts.writable.end()};
    if (opts.workspace) {
        agent_writable.push_back(*opts.workspace);
    }
    auto text = glove::run::read_host_pi_settings(pi_agent_dir, home_dir, agent_writable);
    if (!text) {
        return;
    }
    auto packages = glove::run::pi_local_package_sources(*text, pi_agent_dir, home_dir);
    if (!packages) {
        return;
    }
    const std::array<std::filesystem::path, 2> dotfiles_roots{
        home_dir / "Documents" / "depend" / "dotfiles", home_dir / ".dotfiles"
    };
    for (const auto& package : *packages) {
        if (is_subpath_of(package.resolved, pi_agent_dir)) {
            continue;
        }
        auto canonical = glove::run::pi_package_exposure(package.resolved, home_dir, pi_agent_dir);
        if (!canonical) {
            continue;
        }
        const bool approved = std::ranges::any_of(dotfiles_roots, [&](const auto& root) {
            std::error_code ec;
            const auto canonical_root = std::filesystem::weakly_canonical(root, ec);
            return !ec && is_subpath_of(*canonical, canonical_root);
        });
        const auto before = opts.readable.size();
        add_non_overlapping_read_dir(opts, *canonical);
        if (!approved && opts.readable.size() > before) {
            // A package outside the approved roots is visible on every launch,
            // so name it: settings.json is the only thing that put it there.
            std::fprintf(
                stderr,
                "glove: exposing Pi package '%s' read-only (from %s)\n",
                glove::run::printable(canonical->string()).c_str(),
                glove::run::printable((pi_agent_dir / "settings.json").string()).c_str()
            );
        }
    }
}

void add_unique_path_dir(glove::run::options& opts, const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec) || ec) {
        return;
    }
    const std::string s = dir.lexically_normal().string();
    for (const auto& existing : opts.extra_path_dirs) {
        if (existing == s) {
            return;
        }
    }
    opts.extra_path_dirs.push_back(s);
}

auto resolve_harness_executable(std::string_view name) -> std::optional<std::filesystem::path> {
    const std::string bin_name{name == "claude-code" ? "claude" : name};
    auto is_usable_executable = [](const std::filesystem::path& candidate) -> bool {
        std::error_code ec;
        return std::filesystem::is_regular_file(candidate, ec) && !ec &&
               ::access(candidate.c_str(), X_OK) == 0;
    };
    std::error_code ec;
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        const std::filesystem::path home_dir{home};
        for (const auto& candidate : {
                 home_dir / ".local" / "bin" / bin_name,
                 home_dir / ".pi" / "agent" / "bin" / bin_name,
             }) {
            if (is_usable_executable(candidate)) {
                return std::filesystem::absolute(candidate, ec);
            }
        }
        const auto nvm_nodes = home_dir / ".nvm" / "versions" / "node";
        if (std::filesystem::is_directory(nvm_nodes, ec) && !ec) {
            for (const auto& entry : std::filesystem::directory_iterator(nvm_nodes, ec)) {
                const auto candidate = entry.path() / "bin" / bin_name;
                if (is_usable_executable(candidate)) {
                    return std::filesystem::absolute(candidate, ec);
                }
            }
        }
    }
    if (const char* path_env = std::getenv("PATH"); path_env != nullptr) {
        std::string_view rest{path_env};
        while (!rest.empty()) {
            const auto colon = rest.find(':');
            const std::string_view dir =
                colon == std::string_view::npos ? rest : rest.substr(0, colon);
            if (!dir.empty()) {
                const auto candidate = std::filesystem::path{dir} / bin_name;
                if (is_usable_executable(candidate)) {
                    return std::filesystem::absolute(candidate, ec);
                }
            }
            if (colon == std::string_view::npos) {
                break;
            }
            rest.remove_prefix(colon + 1);
        }
    }
    return std::nullopt;
}

// Mounts the agent harness binary + its symlink/runtime closure (~/.local/bin,
// non-credential ~/.pi/agent subdirs, ~/.nvm/versions/node/<ver>, etc.)
// read-only into `opts` and prepends their `bin` directories to `extra_path_dirs`.
auto attach_agent_harness_closure(
    glove::run::options& opts, std::string_view driver, std::optional<std::string_view> cmd_override
) -> std::string {
    opts.seed_guest_agent_home = true;
    std::error_code ec;
    std::string resolved_bin;
    if (cmd_override && !cmd_override->empty()) {
        resolved_bin = std::string{*cmd_override};
        const std::filesystem::path p{resolved_bin};
        if (p.is_absolute() && p.has_parent_path()) {
            add_non_overlapping_read_dir(opts, p.parent_path());
            add_unique_path_dir(opts, p.parent_path());
        }
    } else if (auto found = resolve_harness_executable(driver)) {
        resolved_bin = found->string();
        add_non_overlapping_read_dir(opts, found->parent_path());
        add_unique_path_dir(opts, found->parent_path());
        const auto canon = std::filesystem::weakly_canonical(*found, ec);
        if (!ec && canon.has_parent_path()) {
            // If canonical path is `<root>/bin/<exe>` (e.g. ~/.nvm/.../bin/pi),
            // expose `<root>` unless `<root>` is `~/.pi/agent` (which contains
            // host credentials/sessions and is mounted selectively below).
            const auto parent = canon.parent_path();
            const auto root = parent.parent_path();
            const bool is_pi_agent_root =
                root.filename() == "agent" && root.parent_path().filename() == ".pi";
            if (parent.filename() == "bin" && parent.has_parent_path() && !is_pi_agent_root) {
                add_non_overlapping_read_dir(opts, root);
            } else {
                add_non_overlapping_read_dir(opts, parent);
            }
            add_unique_path_dir(opts, parent);
        }
    } else {
        resolved_bin = driver == "claude-code" ? std::string{"claude"} : std::string{driver};
    }

    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        const std::filesystem::path home_dir{home};
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "bin");
        add_unique_path_dir(opts, home_dir / ".local" / "bin");
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "opt");
        add_unique_path_dir(opts, home_dir / ".local" / "opt" / "clice" / "bin");
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "share" / "uv");
        add_non_overlapping_read_dir(opts, home_dir / ".cargo" / "bin");
        add_unique_path_dir(opts, home_dir / ".cargo" / "bin");
        add_non_overlapping_read_dir(opts, home_dir / ".rustup");
        add_non_overlapping_read_dir(opts, home_dir / "go" / "bin");
        add_unique_path_dir(opts, home_dir / "go" / "bin");
        add_unique_path_dir(opts, std::filesystem::path{"/usr/local/bin"});
        const auto pi_agent_dir = home_dir / ".pi" / "agent";
        const std::filesystem::path dotfiles_dir = home_dir / "Documents" / "depend" / "dotfiles";
        const std::filesystem::path alt_dotfiles_dir = home_dir / ".dotfiles";
        const std::array<std::filesystem::path, 3> approved_pi_roots{
            pi_agent_dir, dotfiles_dir, alt_dotfiles_dir
        };
        for (const char* sub :
             {"bin", "install", "npm", "skills", "pi-subagents", "pi-web-access", "missions"}) {
            add_verified_agent_read_dir(opts, pi_agent_dir / sub, approved_pi_roots);
        }
        add_unique_path_dir(opts, pi_agent_dir / "bin");
        add_verified_agent_read_dir(
            opts, dotfiles_dir / "pi" / ".pi" / "agent" / "packages", approved_pi_roots
        );
        if (driver == "pi") {
            add_pi_local_packages(opts, home_dir, pi_agent_dir);
            opts.report_pi_packages = true;
        }
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "share" / "antigravity-cli");
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "share" / "claude");
        add_non_overlapping_read_dir(opts, home_dir / ".local" / "share" / "pi-node");
        add_unique_path_dir(opts, home_dir / ".local" / "share" / "pi-node" / "current" / "bin");

        const std::array<std::filesystem::path, 3> approved_sage_config_roots{
            home_dir / ".config" / "sage", dotfiles_dir, alt_dotfiles_dir
        };
        add_verified_agent_read_dir(
            opts, home_dir / ".config" / "sage", approved_sage_config_roots
        );
        const std::array<std::filesystem::path, 1> approved_sage_share_roots{
            home_dir / ".local" / "share" / "sage"
        };
        add_verified_agent_read_dir(
            opts, home_dir / ".local" / "share" / "sage", approved_sage_share_roots
        );

        const auto nvm_nodes = home_dir / ".nvm" / "versions" / "node";
        if (std::filesystem::is_directory(nvm_nodes, ec) && !ec) {
            std::filesystem::path chosen_node;
            for (const auto& entry : std::filesystem::directory_iterator(nvm_nodes, ec)) {
                if (entry.is_directory(ec) && entry.path() > chosen_node) {
                    chosen_node = entry.path();
                }
            }
            if (!chosen_node.empty()) {
                add_non_overlapping_read_dir(opts, chosen_node);
                add_unique_path_dir(opts, chosen_node / "bin");
            }
        }
    }

    // When launching an interactive agent harness without a mediated preset or
    // explicit egress list, allow standard LLM provider endpoints through the
    // audited egress proxy so configured cloud models (DeepSeek, Anthropic,
    // OpenAI, Gemini, RunInfra, Mistral, OpenRouter) can connect.
    if (opts.egress.empty() && !opts.agent_preset.has_value()) {
        for (const char* host : {
                 "api.deepseek.com",
                 "api.runinfra.ai",
                 "api.anthropic.com",
                 "api.openai.com",
                 "api.mistral.ai",
                 "api.kimi.com",
                 "openrouter.ai",
                 "generativelanguage.googleapis.com",
                 "api.individual.githubcopilot.com",
             }) {
            opts.egress.push_back(glove::net::egress_rule{.host = host, .port = 443});
        }
    }
    return resolved_bin;
}

auto ensure_workspace_directory(const std::optional<std::filesystem::path>& workspace)
    -> std::expected<void, std::string> {
    if (!workspace) {
        return {};
    }
    std::error_code ec;
    if (!std::filesystem::exists(*workspace, ec)) {
        std::filesystem::create_directories(*workspace, ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot create workspace directory '"} + workspace->string() +
                "': " + ec.message()
            );
        }
        std::filesystem::permissions(
            *workspace,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec
        );
        if (ec) {
            return std::unexpected(
                std::string{"cannot set permissions on workspace directory '"} +
                workspace->string() + "': " + ec.message()
            );
        }
    }
    return {};
}

auto resolve_envs_directory() -> std::optional<std::filesystem::path> {
    if (auto dirs = glove::host::resolve_directories(glove::host::current_environment())) {
        return dirs->config / "envs";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        return std::filesystem::path{home} / ".config" / "glove" / "envs";
    }
    return std::nullopt;
}

auto json_escape(std::string_view text) -> std::string {
    std::string out = "\"";
    for (const char raw : text) {
        const auto ch = static_cast<unsigned char>(raw);
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (ch < 0x20U) {
                char hex[7]{};
                std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned int>(ch));
                out += hex;
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    out.push_back('"');
    return out;
}

auto json_string_array(const std::vector<std::string>& items) -> std::string {
    std::string out = "[";
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            out += ", ";
        }
        out += json_escape(items[i]);
    }
    out.push_back(']');
    return out;
}

auto read_proc_starttime(long pid) noexcept -> std::int64_t {
    if (pid <= 0) {
        return 0;
    }
    const std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream in(stat_path, std::ios::binary);
    if (!in) {
        return 0;
    }
    std::string line;
    std::getline(in, line);
    const auto rparen = line.rfind(')');
    if (rparen == std::string::npos || rparen + 2 >= line.size()) {
        return 0;
    }
    std::istringstream iss(line.substr(rparen + 2));
    std::string token;
    // Field 3 is state (1st token after ')'); field 22 is starttime (20th token after ')').
    for (int field = 3; field <= 22; ++field) {
        if (!(iss >> token)) {
            return 0;
        }
    }
    std::int64_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
    if (ec != std::errc{} || ptr != token.data() + token.size() || value <= 0) {
        return 0;
    }
    return value;
}

void save_env_profile(
    std::string_view name, const glove::run::options& opts, std::string_view driver, long active_pid
) noexcept {
    if (!glove::host::is_valid_policy_name(name)) {
        return;
    }
    const auto envs_dir = resolve_envs_directory();
    if (!envs_dir) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(*envs_dir, ec);
    if (ec) {
        return;
    }
    std::filesystem::permissions(
        *envs_dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec
    );
    if (ec) {
        return;
    }

    std::vector<std::string> upstreams;
    for (const auto& u : opts.upstreams) {
        std::string spec = u.name + "=";
        for (std::size_t j = 0; j < u.argv.size(); ++j) {
            if (j > 0) {
                spec.push_back(',');
            }
            spec += u.argv[j];
        }
        upstreams.push_back(std::move(spec));
    }
    std::vector<std::string> egress;
    for (const auto& e : opts.egress) {
        egress.push_back(e.host + ":" + std::to_string(e.port));
    }
    std::vector<std::string> allow_arg;
    for (const auto& r : opts.prefix_rules) {
        allow_arg.push_back(r.tool_name + ":" + r.field + "=" + r.required_prefix);
    }

    auto to_abs_string = [](const std::filesystem::path& p) -> std::string {
        if (p.empty()) {
            return {};
        }
        std::error_code abs_ec;
        auto canon = std::filesystem::weakly_canonical(p, abs_ec);
        if (!abs_ec && !canon.empty()) {
            return canon.string();
        }
        abs_ec.clear();
        auto abs = std::filesystem::absolute(p, abs_ec);
        return (!abs_ec && !abs.empty()) ? abs.lexically_normal().string() : p.string();
    };
    const std::string abs_workspace =
        opts.workspace ? to_abs_string(*opts.workspace) : std::string{};
    std::vector<std::string> abs_readable;
    for (const auto& r : opts.readable) {
        auto s = to_abs_string(std::filesystem::path{r});
        if (!s.empty() && std::ranges::find(abs_readable, s) == abs_readable.end()) {
            abs_readable.push_back(std::move(s));
        }
    }
    std::vector<std::string> abs_writable;
    for (const auto& w : opts.writable) {
        auto s = to_abs_string(std::filesystem::path{w});
        if (!s.empty() && std::ranges::find(abs_writable, s) == abs_writable.end()) {
            abs_writable.push_back(std::move(s));
        }
    }

    // The shared reflect JSON codec only reads string arrays, so service ports
    // are stored as decimal strings.
    std::vector<std::string> service_port_strings;
    for (const auto port : opts.service_ports) {
        service_port_strings.push_back(std::to_string(port));
    }

    const std::int64_t starttime = read_proc_starttime(active_pid);
    std::ostringstream out;
    out << "{\n"
        << "  \"name\": " << json_escape(name) << ",\n"
        << "  \"workspace\": " << json_escape(abs_workspace) << ",\n"
        << "  \"agent\": " << json_escape(driver) << ",\n"
        << "  \"readable\": " << json_string_array(abs_readable) << ",\n"
        << "  \"writable\": " << json_string_array(abs_writable) << ",\n"
        << "  \"env\": " << json_string_array(opts.environment_names) << ",\n"
        << "  \"upstreams\": " << json_string_array(upstreams) << ",\n"
        << "  \"allow\": " << json_string_array(opts.allow) << ",\n"
        << "  \"allow_arg\": " << json_string_array(allow_arg) << ",\n"
        << "  \"egress\": " << json_string_array(egress) << ",\n"
        << "  \"bridge_port\": " << (opts.bridge_port ? static_cast<long>(*opts.bridge_port) : 0L)
        << ",\n"
        << "  \"service_ports\": " << json_string_array(service_port_strings) << ",\n"
        << "  \"active_pid\": " << active_pid << ",\n"
        << "  \"active_starttime\": " << starttime << "\n"
        << "}\n";
    const std::string serialized = out.str();
    const auto path = *envs_dir / (std::string{name} + ".json");
    const int fd =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    (void)::fchmod(fd, 0600);
    std::size_t off = 0;
    while (off < serialized.size()) {
        const ssize_t n = ::write(fd, serialized.data() + off, serialized.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    (void)::close(fd);
}

auto load_env_profile(std::string_view name, glove::run::options& opts)
    -> std::expected<void, std::string> {
    if (!glove::host::is_valid_policy_name(name)) {
        return std::unexpected("invalid saved environment name '" + std::string{name} + "'");
    }
    const auto envs_dir = resolve_envs_directory();
    if (!envs_dir) {
        return std::unexpected(std::string{"cannot resolve XDG config directory"});
    }
    const auto path = *envs_dir / (std::string{name} + ".json");
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(
            "saved environment '" + std::string{name} + "' not found at " + path.string()
        );
    }
    std::string content;
    std::array<char, 4096> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)::close(fd);
            return std::unexpected("failed reading saved environment '" + std::string{name} + "'");
        }
        if (n == 0) {
            break;
        }
        content.append(buf.data(), static_cast<std::size_t>(n));
    }
    (void)::close(fd);
    auto parsed = glove::reflect::detail::parse_json_object(content);
    if (!parsed) {
        return std::unexpected(
            "invalid saved environment '" + std::string{name} + "': " + parsed.error()
        );
    }
    if (auto it = parsed->find("workspace"); it != parsed->end()) {
        const auto* s = std::get_if<std::string>(&it->second);
        if (s == nullptr) {
            return std::unexpected(
                "invalid 'workspace' in saved environment '" + std::string{name} + "'"
            );
        }
        if (!s->empty()) {
            opts.workspace = std::filesystem::path{*s};
        }
    }
    if (auto it = parsed->find("agent"); it != parsed->end()) {
        const auto* s = std::get_if<std::string>(&it->second);
        if (s == nullptr) {
            return std::unexpected(
                "invalid 'agent' in saved environment '" + std::string{name} + "'"
            );
        }
        if (!s->empty()) {
            opts.agent_preset = *s;
        }
    }
    if (auto it = parsed->find("readable"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'readable' in saved environment '" + std::string{name} + "'"
            );
        }
        opts.readable.insert(opts.readable.end(), arr->begin(), arr->end());
    }
    if (auto it = parsed->find("writable"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'writable' in saved environment '" + std::string{name} + "'"
            );
        }
        opts.writable.insert(opts.writable.end(), arr->begin(), arr->end());
    }
    if (auto it = parsed->find("env"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'env' in saved environment '" + std::string{name} + "'"
            );
        }
        opts.environment_names.insert(opts.environment_names.end(), arr->begin(), arr->end());
    }
    if (auto it = parsed->find("upstreams"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'upstreams' in saved environment '" + std::string{name} + "'"
            );
        }
        for (const auto& spec : *arr) {
            auto u = parse_upstream(spec);
            if (!u) {
                return std::unexpected(
                    "invalid upstream in saved environment '" + std::string{name} +
                    "': " + u.error()
                );
            }
            opts.upstreams.push_back(std::move(*u));
        }
    }
    if (auto it = parsed->find("allow"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'allow' in saved environment '" + std::string{name} + "'"
            );
        }
        opts.allow.insert(opts.allow.end(), arr->begin(), arr->end());
    }
    if (auto it = parsed->find("allow_arg"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'allow_arg' in saved environment '" + std::string{name} + "'"
            );
        }
        for (const auto& spec : *arr) {
            auto r = parse_allow_arg(spec);
            if (!r) {
                return std::unexpected(
                    "invalid allow_arg in saved environment '" + std::string{name} +
                    "': " + r.error()
                );
            }
            opts.prefix_rules.push_back(std::move(*r));
        }
    }
    if (auto it = parsed->find("egress"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'egress' in saved environment '" + std::string{name} + "'"
            );
        }
        for (const auto& spec : *arr) {
            auto e = parse_egress(spec);
            if (!e) {
                return std::unexpected(
                    "invalid egress in saved environment '" + std::string{name} + "': " + e.error()
                );
            }
            opts.egress.push_back(std::move(*e));
        }
    }
    if (auto it = parsed->find("system_services"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'system_services' in saved environment '" + std::string{name} + "'"
            );
        }
        opts.system_services.insert(opts.system_services.end(), arr->begin(), arr->end());
    }
    if (auto it = parsed->find("service_ports"); it != parsed->end()) {
        const auto* arr = std::get_if<std::vector<std::string>>(&it->second);
        if (arr == nullptr) {
            return std::unexpected(
                "invalid 'service_ports' in saved environment '" + std::string{name} + "'"
            );
        }
        for (const auto& text : *arr) {
            unsigned port = 0;
            const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), port);
            const bool digits = !text.empty() && std::ranges::all_of(text, [](char ch) {
                return ch >= '0' && ch <= '9';
            });
            if (!digits || ec != std::errc{} || ptr != text.data() + text.size() || port < 1 ||
                port > 65535) {
                return std::unexpected(
                    "invalid service port '" + text + "' in saved environment '" +
                    std::string{name} + "'"
                );
            }
            opts.service_ports.push_back(static_cast<std::uint16_t>(port));
        }
    }
    if (auto it = parsed->find("bridge_port"); it != parsed->end()) {
        const auto* n = std::get_if<std::int64_t>(&it->second);
        if (n == nullptr || (*n != 0 && (*n < 1 || *n > 65535))) {
            return std::unexpected(
                "invalid 'bridge_port' in saved environment '" + std::string{name} + "'"
            );
        }
        if (*n >= 1 && *n <= 65535) {
            opts.bridge_port = static_cast<std::uint16_t>(*n);
        }
    }
    return {};
}

auto list_env_profiles() -> int {
    const auto envs_dir = resolve_envs_directory();
    if (!envs_dir) {
        std::fprintf(stderr, "glove shell: cannot resolve XDG config directory\n");
        return 1;
    }
    std::printf("Saved environments (%s):\n", envs_dir->c_str());
    std::error_code ec;
    if (!std::filesystem::is_directory(*envs_dir, ec)) {
        std::printf("  (none saved)\n");
        return 0;
    }
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(*envs_dir, ec)) {
        if (entry.path().extension() != ".json") {
            continue;
        }
        std::ifstream in(entry.path(), std::ios::binary);
        if (!in) {
            continue;
        }
        const std::string content((std::istreambuf_iterator<char>(in)), {});
        auto parsed = glove::reflect::detail::parse_json_object(content);
        if (!parsed) {
            continue;
        }
        ++count;
        const std::string name = entry.path().stem().string();
        std::string ws;
        if (auto it = parsed->find("workspace"); it != parsed->end()) {
            if (const auto* s = std::get_if<std::string>(&it->second)) {
                ws = *s;
            }
        }
        std::string agent;
        if (auto it = parsed->find("agent"); it != parsed->end()) {
            if (const auto* s = std::get_if<std::string>(&it->second)) {
                agent = *s;
            }
        }
        long pid = 0;
        if (auto it = parsed->find("active_pid"); it != parsed->end()) {
            if (const auto* n = std::get_if<std::int64_t>(&it->second)) {
                pid = static_cast<long>(*n);
            }
        }
        std::int64_t saved_starttime = 0;
        if (auto it = parsed->find("active_starttime"); it != parsed->end()) {
            if (const auto* n = std::get_if<std::int64_t>(&it->second)) {
                saved_starttime = *n;
            }
        }
        const bool pid_alive = pid > 0 && ::kill(static_cast<::pid_t>(pid), 0) == 0;
        const std::int64_t live_starttime = pid_alive ? read_proc_starttime(pid) : 0;
        const bool running =
            pid_alive && (saved_starttime == 0 || live_starttime == saved_starttime);
        std::size_t read_count = 0;
        if (auto it = parsed->find("readable"); it != parsed->end()) {
            if (const auto* arr = std::get_if<std::vector<std::string>>(&it->second)) {
                read_count = arr->size();
            }
        }
        std::size_t mcp_count = 0;
        if (auto it = parsed->find("upstreams"); it != parsed->end()) {
            if (const auto* arr = std::get_if<std::vector<std::string>>(&it->second)) {
                mcp_count = arr->size();
            }
        }
        std::printf(
            "  %c %-14s %-16s agent=%-6s mcp=%zu reads=%zu workspace=%s\n"
            "      launch: glove shell %s   |   update: glove shell %s --save %s [--read <path> "
            "...]\n",
            running ? '*' : '-',
            name.c_str(),
            running ? ("RUNNING(" + std::to_string(pid) + ")").c_str() : "SAVED",
            agent.empty() ? "auto" : agent.c_str(),
            mcp_count,
            read_count,
            ws.empty() ? "<ephemeral>" : ws.c_str(),
            name.c_str(),
            name.c_str(),
            name.c_str()
        );
    }
    if (count == 0) {
        std::printf("  (none saved)\n");
    }
    return 0;
}

auto shell_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
    opts.allow_loopback_listen = true;
    std::optional<std::string> save_name;
    std::optional<std::string> load_name;
    std::optional<std::string> profile_name;
    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view a{args[i]};
        if (a == "--") {
            ++i;
            break;
        }
        if (a == "-h" || a == "--help") {
            print_shell_usage();
            return 0;
        }
        if (a == "--list") {
            return list_env_profiles();
        }
        if (a == "--last") {
            load_name = "last";
            ++i;
            continue;
        }
        if (a == "--save" || a == "--load" || a == "--env-profile") {
            if (i + 1 >= args.size()) {
                std::fprintf(
                    stderr,
                    "glove shell: %.*s needs an argument\n",
                    static_cast<int>(a.size()),
                    a.data()
                );
                return 2;
            }
            if (a == "--save") {
                save_name = std::string{args[i + 1]};
                if (!glove::host::is_valid_policy_name(*save_name)) {
                    std::fprintf(
                        stderr, "glove shell: invalid environment name '%s'\n", save_name->c_str()
                    );
                    return 2;
                }
            } else {
                load_name = std::string{args[i + 1]};
            }
            i += 2;
            continue;
        }
        if (const auto handled = parse_profile_flag(args, i, profile_name, "shell")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        if (const auto handled = parse_sandbox_flag(args, i, opts, "shell")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        if (i == 0 && !a.starts_with('-')) {
            load_name = std::string{a};
            ++i;
            continue;
        }
        std::fprintf(
            stderr, "glove shell: unknown flag '%.*s'\n", static_cast<int>(a.size()), a.data()
        );
        print_shell_usage();
        return 2;
    }

    if (load_name && profile_name) {
        std::fprintf(
            stderr, "glove shell: use either a saved environment or --profile, not both\n"
        );
        return 2;
    }
    if (!apply_profile_flag(profile_name, opts, "shell")) {
        return 1;
    }
    if (load_name) {
        glove::run::options loaded;
        loaded.allow_loopback_listen = true;
        if (auto ok = load_env_profile(*load_name, loaded); !ok) {
            std::fprintf(stderr, "glove shell: %s\n", ok.error().c_str());
            return 1;
        }
        if (opts.workspace) {
            loaded.workspace = opts.workspace;
        }
        if (opts.agent_preset) {
            loaded.agent_preset = opts.agent_preset;
        }
        if (opts.bridge_port) {
            loaded.bridge_port = opts.bridge_port;
        }
        if (opts.audit_log) {
            loaded.audit_log = opts.audit_log;
        }
        // Not stored in saved environments; a flag given at load time applies.
        loaded.share_credential = opts.share_credential;
        loaded.share_credential_origin = opts.share_credential_origin;
        // A path given both in the profile and on the command line is one rule.
        const auto merge_paths = [](std::vector<std::string>& into,
                                    const std::vector<std::string>& extra) {
            for (const auto& path : extra) {
                if (std::ranges::find(into, path) == into.end()) {
                    into.push_back(path);
                }
            }
        };
        merge_paths(loaded.readable, opts.readable);
        merge_paths(loaded.writable, opts.writable);
        loaded.environment_names.insert(
            loaded.environment_names.end(),
            opts.environment_names.begin(),
            opts.environment_names.end()
        );
        loaded.upstreams.insert(
            loaded.upstreams.end(), opts.upstreams.begin(), opts.upstreams.end()
        );
        loaded.allow.insert(loaded.allow.end(), opts.allow.begin(), opts.allow.end());
        loaded.prefix_rules.insert(
            loaded.prefix_rules.end(), opts.prefix_rules.begin(), opts.prefix_rules.end()
        );
        loaded.egress.insert(loaded.egress.end(), opts.egress.begin(), opts.egress.end());
        loaded.service_ports.insert(
            loaded.service_ports.end(), opts.service_ports.begin(), opts.service_ports.end()
        );
        opts = std::move(loaded);
    }

    if (auto ws_ok = ensure_workspace_directory(opts.workspace); !ws_ok) {
        std::fprintf(stderr, "glove shell: %s\n", ws_ok.error().c_str());
        return 1;
    }

    std::vector<std::string> trailing_args;
    while (i < args.size()) {
        trailing_args.emplace_back(args[i]);
        ++i;
    }

    const bool had_explicit_agent = opts.agent_preset.has_value();
    std::string driver = opts.agent_preset.value_or("");
    if (driver.empty()) {
        for (std::string_view candidate : {"pi", "agy", "claude", "codex"}) {
            if (resolve_harness_executable(candidate).has_value()) {
                driver = std::string{candidate};
                break;
            }
        }
    }

    // An explicitly shared credential is opt-in and fails closed: it never
    // falls back to raw provider egress or to another preset.
    if (opts.share_credential_origin && !opts.share_credential) {
        std::fprintf(
            stderr, "glove shell: --share-credential-origin requires --share-credential\n"
        );
        return 2;
    }
    if (opts.share_credential) {
        const char* refusal = nullptr;
        if (!glove::run::valid_pi_provider_name(*opts.share_credential)) {
            refusal = "--share-credential needs a Pi provider name (for example deepseek)";
        } else if (driver != "pi") {
            refusal = "--share-credential requires --agent pi";
        } else if (!opts.egress.empty()) {
            refusal = "--share-credential cannot be combined with --egress-allow, including "
                      "egress stored in a loaded environment (save it again without egress): "
                      "the provider is reached only through the credentialed endpoint";
        } else {
            // A forwarded key variable would hand the sandbox a real secret
            // beside the mediated one.
            for (const auto& name : opts.environment_names) {
                if (name.find("API_KEY") != std::string::npos || name.ends_with("_TOKEN") ||
                    name.ends_with("_SECRET")) {
                    refusal = "--share-credential cannot be combined with --env of a key, token, "
                              "or secret variable";
                    break;
                }
            }
        }
        if (refusal != nullptr) {
            std::fprintf(stderr, "glove shell: %s\n", refusal);
            return 2;
        }
        opts.agent_preset = "pi-shared";
    } else if (driver == "agy" || !opts.egress.empty()) {
        opts.agent_preset.reset();
    } else if (driver == "pi" || driver == "claude" || driver == "claude-code") {
        const char* key = std::getenv("ANTHROPIC_API_KEY");
        if (opts.provider_secret || (key != nullptr && *key != '\0')) {
            opts.agent_preset = driver;
        } else {
            opts.agent_preset.reset();
        }
    } else if (driver == "codex") {
        const char* key = std::getenv("OPENAI_API_KEY");
        if (opts.provider_secret || (key != nullptr && *key != '\0')) {
            opts.agent_preset = driver;
        } else {
            opts.agent_preset.reset();
        }
    } else {
        opts.agent_preset.reset();
    }

    const auto user_readable = opts.readable;
    // Default provider egress is recomputed at launch; only explicit grants are saved.
    const auto user_egress = opts.egress;
    const bool explicit_cmd = !trailing_args.empty() && !trailing_args.front().starts_with('-');
    const std::string resolved_bin = (driver.empty() || (explicit_cmd && !had_explicit_agent))
                                         ? std::string{}
                                         : attach_agent_harness_closure(opts, driver, std::nullopt);

    if (explicit_cmd) {
        // Explicit command after `--` (e.g. `glove shell -- /bin/sh -c ...`).
        opts.agent_argv = std::move(trailing_args);
    } else if (!resolved_bin.empty() && std::filesystem::path{resolved_bin}.is_absolute()) {
        opts.agent_argv.push_back(resolved_bin);
        opts.agent_argv.insert(opts.agent_argv.end(), trailing_args.begin(), trailing_args.end());
    } else if (had_explicit_agent) {
        std::fprintf(
            stderr, "glove shell: agent '%s' is not installed or not executable\n", driver.c_str()
        );
        return 1;
    } else {
        opts.agent_argv.push_back(std::filesystem::exists("/bin/bash") ? "/bin/bash" : "/bin/sh");
        opts.agent_argv.insert(opts.agent_argv.end(), trailing_args.begin(), trailing_args.end());
    }

    glove::run::options saved_snapshot = opts;
    saved_snapshot.readable = user_readable;
    saved_snapshot.egress = user_egress;
    const long my_pid = static_cast<long>(::getpid());
    if (save_name) {
        save_env_profile(*save_name, saved_snapshot, driver, my_pid);
    }
    if (!explicit_cmd || save_name.has_value() || load_name.has_value()) {
        save_env_profile("last", saved_snapshot, driver, my_pid);
    }

    auto code = glove::run::exec(opts);

    if (save_name) {
        save_env_profile(*save_name, saved_snapshot, driver, 0);
    }
    if (!explicit_cmd || save_name.has_value() || load_name.has_value()) {
        save_env_profile("last", saved_snapshot, driver, 0);
    }
    if (!code) {
        std::fprintf(stderr, "glove shell: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

auto load_prompt_spec(std::string_view spec) -> std::expected<std::string, std::string> {
    if (spec.starts_with('@')) {
        const std::filesystem::path path{spec.substr(1)};
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected(std::string{"cannot open prompt file '"} + path.string() + "'");
        }
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }
    return std::string{spec};
}

// Parse a complete positive decimal integer in [1, max]. Rejects prefixes such
// as "3garbage", signs, empty input, and out-of-range values.
auto parse_positive_int(std::string_view text, int max) -> std::optional<int> {
    int value = 0;
    const auto* first = text.data();
    const auto* last = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (text.empty() || ec != std::errc{} || ptr != last || value < 1 || value > max) {
        return std::nullopt;
    }
    return value;
}

constexpr std::size_t kVerifyFeedbackTailBytes = 4000;

struct verify_outcome {
    int exit_code = 0;
    bool timed_out = false;
    std::string tail;
};

// Run `verify_cmd` offline inside the sandbox. Output is echoed to stderr and
// only a bounded tail is retained. A monotonic deadline bounds the whole
// verifier: on expiry its process group is killed (the contained child dies
// with it through PR_SET_PDEATHSIG and its PID namespace), then it is reaped.
auto run_sandbox_verify(
    const glove::run::options& base_opts, const std::string& verify_cmd, int timeout_seconds
) -> std::expected<verify_outcome, std::string> {
    int pipe_fd[2] = {-1, -1};
#if defined(__linux__)
    if (::pipe2(pipe_fd, O_CLOEXEC) != 0) {
        return std::unexpected(std::string{"pipe failed for --verify"});
    }
#else
    if (::pipe(pipe_fd) != 0) {
        return std::unexpected(std::string{"pipe failed for --verify"});
    }
    for (const int fd : pipe_fd) {
        const int flags = ::fcntl(fd, F_GETFD);
        if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
            (void)::close(pipe_fd[0]);
            (void)::close(pipe_fd[1]);
            return std::unexpected(std::string{"fcntl(FD_CLOEXEC) failed for --verify"});
        }
    }
#endif
    const ::pid_t child = ::fork();
    if (child < 0) {
        ::close(pipe_fd[0]);
        ::close(pipe_fd[1]);
        return std::unexpected(std::string{"fork failed for --verify"});
    }
    if (child == 0) {
        ::setpgid(0, 0);
        const int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
        }
        ::dup2(pipe_fd[1], STDOUT_FILENO);
        ::dup2(pipe_fd[1], STDERR_FILENO);
        glove::run::options verify_opts = base_opts;
        verify_opts.egress.clear();
        verify_opts.agent_preset.reset();
        verify_opts.allow_loopback_listen = false;
        verify_opts.herdr = false;
        verify_opts.agent_argv = {"/bin/sh", "-c", verify_cmd};
        auto rc = glove::run::exec(verify_opts);
        if (!rc) {
            std::fprintf(stderr, "glove loop verify: %s\n", rc.error().c_str());
            std::_Exit(125);
        }
        std::_Exit(*rc);
    }
    ::setpgid(child, child);
    ::close(pipe_fd[1]);

    verify_outcome outcome;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{timeout_seconds};
    std::array<char, 4096> buf{};
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()
        );
        if (remaining.count() <= 0) {
            outcome.timed_out = true;
            break;
        }
        ::pollfd pfd{.fd = pipe_fd[0], .events = POLLIN, .revents = 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(remaining.count()));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            continue;
        }
        const ssize_t n = ::read(pipe_fd[0], buf.data(), buf.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        const auto count = static_cast<std::size_t>(n);
        std::fwrite(buf.data(), 1, count, stderr);
        outcome.tail.append(buf.data(), count);
        if (outcome.tail.size() > kVerifyFeedbackTailBytes) {
            outcome.tail.erase(0, outcome.tail.size() - kVerifyFeedbackTailBytes);
        }
    }
    if (outcome.timed_out) {
        ::kill(-child, SIGKILL);
    }
    ::close(pipe_fd[0]);
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (outcome.timed_out) {
        outcome.exit_code = 124;
    } else {
        outcome.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    }
    return outcome;
}

auto loop_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
    std::optional<std::string> prompt_spec;
    std::optional<std::string> verify_cmd;
    std::optional<std::string> cmd_override;
    int max_iterations = 5;
    int verify_timeout_seconds = 600;

    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view a{args[i]};
        if (a == "-h" || a == "--help") {
            print_loop_usage();
            return 0;
        }
        if (const auto handled = parse_sandbox_flag(args, i, opts, "loop")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        if (a == "--prompt" || a == "--verify" || a == "--cmd" || a == "--max-iterations" ||
            a == "--verify-timeout") {
            if (i + 1 >= args.size()) {
                std::fprintf(
                    stderr,
                    "glove loop: %.*s needs an argument\n",
                    static_cast<int>(a.size()),
                    a.data()
                );
                return 2;
            }
            if (a == "--prompt") {
                prompt_spec = std::string{args[i + 1]};
            } else if (a == "--verify") {
                verify_cmd = std::string{args[i + 1]};
            } else if (a == "--cmd") {
                cmd_override = std::string{args[i + 1]};
            } else if (a == "--max-iterations") {
                const auto parsed = parse_positive_int(args[i + 1], 1000);
                if (!parsed) {
                    std::fprintf(
                        stderr, "glove loop: --max-iterations must be an integer in [1, 1000]\n"
                    );
                    return 2;
                }
                max_iterations = *parsed;
            } else {
                const auto parsed = parse_positive_int(args[i + 1], 86400);
                if (!parsed) {
                    std::fprintf(
                        stderr,
                        "glove loop: --verify-timeout must be an integer number of seconds in "
                        "[1, 86400]\n"
                    );
                    return 2;
                }
                verify_timeout_seconds = *parsed;
            }
            i += 2;
            continue;
        }
        std::fprintf(
            stderr, "glove loop: unknown flag '%.*s'\n", static_cast<int>(a.size()), a.data()
        );
        print_loop_usage();
        return 2;
    }

    if (!prompt_spec) {
        std::fprintf(stderr, "glove loop: --prompt <text|@file> is required\n");
        print_loop_usage();
        return 2;
    }
    auto base_prompt = load_prompt_spec(*prompt_spec);
    if (!base_prompt) {
        std::fprintf(stderr, "glove loop: %s\n", base_prompt.error().c_str());
        return 2;
    }

    const std::string driver = opts.agent_preset.value_or("pi");
    if (driver != "pi" && driver != "claude" && driver != "claude-code" && driver != "codex" &&
        driver != "agy") {
        std::fprintf(
            stderr,
            "glove loop: unsupported --agent '%s' (expected pi, claude, claude-code, codex, or "
            "agy)\n",
            driver.c_str()
        );
        return 2;
    }
    if (driver == "agy") {
        opts.allow_loopback_listen = true;
        opts.agent_preset.reset();
    } else if (!opts.egress.empty()) {
        // Explicit --egress-allow uses the CONNECT proxy rather than the
        // credentialed reverse endpoint.
        opts.agent_preset.reset();
    } else {
        opts.agent_preset = driver;
    }

    if (auto ws_ok = ensure_workspace_directory(opts.workspace); !ws_ok) {
        std::fprintf(stderr, "glove loop: %s\n", ws_ok.error().c_str());
        return 1;
    }

    const std::string bin = attach_agent_harness_closure(
        opts, driver, cmd_override ? std::optional<std::string_view>{*cmd_override} : std::nullopt
    );

    std::string current_prompt = *base_prompt;
    const int total_turns = verify_cmd ? max_iterations : 1;
    for (int iter = 1; iter <= total_turns; ++iter) {
        std::fprintf(
            stderr, "[glove loop] iteration %d/%d (%s)\n", iter, total_turns, driver.c_str()
        );
        glove::run::options turn_opts = opts;
        if (driver == "agy") {
            turn_opts.agent_argv = {bin, current_prompt};
        } else if (driver == "codex") {
            turn_opts.agent_argv = {bin, "exec", current_prompt};
        } else {
            turn_opts.agent_argv = {bin, "-p", current_prompt};
        }
        auto code = glove::run::exec(turn_opts);
        if (!code) {
            std::fprintf(stderr, "glove loop: %s\n", code.error().c_str());
            return 1;
        }
        if (!verify_cmd) {
            return *code;
        }
        auto verify_result = run_sandbox_verify(opts, *verify_cmd, verify_timeout_seconds);
        if (!verify_result) {
            std::fprintf(stderr, "glove loop: %s\n", verify_result.error().c_str());
            return 1;
        }
        if (verify_result->exit_code == 0) {
            std::fprintf(
                stderr, "[glove loop] iteration %d/%d: verification passed\n", iter, total_turns
            );
            return 0;
        }
        std::fprintf(
            stderr,
            "[glove loop] iteration %d/%d: verification %s (exit %d)\n",
            iter,
            total_turns,
            verify_result->timed_out ? "timed out" : "failed",
            verify_result->exit_code
        );
        current_prompt = std::string{"Previous verification "} +
                         (verify_result->timed_out ? "timed out" : "failed") + " (exit " +
                         std::to_string(verify_result->exit_code) + "):\n```\n" +
                         verify_result->tail + "\n```\n\nOriginal task:\n" + *base_prompt;
    }
    std::fprintf(
        stderr,
        "[glove loop] reached max iterations (%d) without passing verification\n",
        total_turns
    );
    return 1;
}

auto run_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
    std::optional<std::string> profile_name;
    std::size_t i = 0;
    bool dashdash_seen = false;
    while (i < args.size()) {
        std::string_view a{args[i]};
        if (a == "--") {
            dashdash_seen = true;
            ++i;
            break;
        }
        if (a == "-h" || a == "--help") {
            print_run_usage();
            return 0;
        }
        if (a == "--upstream") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --upstream needs an argument\n");
                return 2;
            }
            auto spec = parse_upstream(args[i + 1]);
            if (!spec) {
                std::fprintf(stderr, "glove run: %s\n", spec.error().c_str());
                return 2;
            }
            opts.upstreams.push_back(std::move(*spec));
            i += 2;
            continue;
        }
        if (a == "--allow") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --allow needs an argument\n");
                return 2;
            }
            opts.allow.emplace_back(args[i + 1]);
            i += 2;
            continue;
        }
        if (a == "--allow-arg") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --allow-arg needs an argument\n");
                return 2;
            }
            auto rule = parse_allow_arg(args[i + 1]);
            if (!rule) {
                std::fprintf(stderr, "glove run: %s\n", rule.error().c_str());
                return 2;
            }
            opts.prefix_rules.push_back(std::move(*rule));
            i += 2;
            continue;
        }
        if (a == "--audit-log") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --audit-log needs an argument\n");
                return 2;
            }
            opts.audit_log = std::filesystem::path{args[i + 1]};
            i += 2;
            continue;
        }
        if (const auto handled = parse_profile_flag(args, i, profile_name, "run")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        if (a == "--denial-trace") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --denial-trace needs an argument\n");
                return 2;
            }
            opts.denial_trace = std::filesystem::path{args[i + 1]};
            i += 2;
            continue;
        }
        if (a == "--workspace") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --workspace needs an argument\n");
                return 2;
            }
            opts.workspace = std::filesystem::path{args[i + 1]};
            i += 2;
            continue;
        }
        if (a == "--read" || a == "--write" || a == "--env") {
            if (i + 1 >= args.size()) {
                std::fprintf(
                    stderr,
                    "glove run: %.*s needs an argument\n",
                    static_cast<int>(a.size()),
                    a.data()
                );
                return 2;
            }
            if (a == "--read") {
                opts.readable.emplace_back(args[i + 1]);
            } else if (a == "--write") {
                opts.writable.emplace_back(args[i + 1]);
            } else {
                opts.environment_names.emplace_back(args[i + 1]);
            }
            i += 2;
            continue;
        }
        if (a == "--system-service") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --system-service needs an argument\n");
                return 2;
            }
            opts.system_services.emplace_back(args[i + 1]);
            i += 2;
            continue;
        }
        if (a == "--egress-allow") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove run: --egress-allow needs an argument\n");
                return 2;
            }
            auto rule = parse_egress(args[i + 1]);
            if (!rule) {
                std::fprintf(stderr, "glove run: %s\n", rule.error().c_str());
                return 2;
            }
            opts.egress.push_back(std::move(*rule));
            i += 2;
            continue;
        }
        std::fprintf(
            stderr, "glove run: unknown flag '%.*s'\n", static_cast<int>(a.size()), a.data()
        );
        print_run_usage();
        return 2;
    }

    if (!dashdash_seen) {
        std::fprintf(stderr, "glove run: missing `-- <agent argv>...`\n");
        print_run_usage();
        return 2;
    }
    while (i < args.size()) {
        opts.agent_argv.emplace_back(args[i]);
        ++i;
    }
    if (opts.agent_argv.empty()) {
        std::fprintf(stderr, "glove run: agent argv is empty after `--`\n");
        return 2;
    }
    if (!apply_profile_flag(profile_name, opts, "run")) {
        return 1;
    }

    auto code = glove::run::execute(opts);
    if (!code) {
        std::fprintf(stderr, "glove run: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

void print_usage() {
    print_banner();
    std::fprintf(
        stderr,
        "\noptions:\n"
        "  -h, --help      show this help message and exit\n"
        "  -V, --version   print version and exit\n"
        "\nworkspace & agent execution:\n"
        "  shell           drop into an interactive sandboxed workspace shell\n"
        "  loop            run a seeded agent feedback loop (--prompt, --verify)\n"
        "  exec            contain a self-driving agent (-- <argv>...)\n"
        "  run             spawn an MCP-client agent inside the container\n"
        "  profile         create, edit, and check launch profiles (--profile <name>)\n"
        "\nsetup, policy & sessions:\n"
        "  setup           initialize machine-local config, keys, and optional policies\n"
        "  policy          detect harnesses and generate or validate runtime policy\n"
        "  workspace       register and list explicit workspace exposures\n"
        "  session         create or inspect gloved-managed workspace sessions\n"
        "  daemon          install and manage the fixed gloved user service\n"
        "  status          show concise daemon and readiness summary\n"
        "  doctor          diagnose configuration, sandbox prerequisites, and service health\n"
        "  config          inspect or derive trusted machine-local configuration\n"
    );
}

auto mcp_bridge_subcommand(std::span<char* const> args) -> int {
    std::string sock_path;
    if (!args.empty()) {
        sock_path = args[0];
    } else if (const char* env_sock = std::getenv("GLOVE_MCP_SOCKET"); env_sock != nullptr) {
        sock_path = env_sock;
    }
    if (sock_path.empty() || sock_path.size() >= sizeof(::sockaddr_un{}.sun_path)) {
        std::fprintf(stderr, "glove mcp-bridge: missing or invalid socket path\n");
        return 2;
    }
#if defined(SOCK_CLOEXEC)
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if (fd < 0) {
        std::fprintf(stderr, "glove mcp-bridge: socket: %s\n", std::strerror(errno));
        return 1;
    }
    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
    ::sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1U);
    if (::connect(fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::fprintf(
            stderr, "glove mcp-bridge: connect(%s): %s\n", sock_path.c_str(), std::strerror(errno)
        );
        (void)::close(fd);
        return 1;
    }

    std::array<::pollfd, 2> pfds{{
        {.fd = STDIN_FILENO, .events = POLLIN, .revents = 0},
        {.fd = fd, .events = POLLIN, .revents = 0},
    }};
    std::array<char, 4096> buf{};
    for (;;) {
        const int ready = ::poll(pfds.data(), pfds.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pfds[0].fd >= 0 && (pfds[0].revents & (POLLIN | POLLHUP)) != 0) {
            const ::ssize_t n = ::read(STDIN_FILENO, buf.data(), buf.size());
            if (n <= 0) {
                (void)::shutdown(fd, SHUT_WR);
                pfds[0].fd = -1;
                pfds[0].events = 0;
                pfds[0].revents = 0;
            } else {
                std::size_t off = 0;
                while (off < static_cast<std::size_t>(n)) {
                    const ::ssize_t w = ::send(
                        fd, buf.data() + off, static_cast<std::size_t>(n) - off, MSG_NOSIGNAL
                    );
                    if (w <= 0) {
                        (void)::close(fd);
                        return 0;
                    }
                    off += static_cast<std::size_t>(w);
                }
            }
        }
        if ((pfds[1].revents & (POLLIN | POLLHUP)) != 0) {
            const ::ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
            if (n <= 0) {
                break;
            }
            std::size_t off = 0;
            while (off < static_cast<std::size_t>(n)) {
                const ::ssize_t w =
                    ::write(STDOUT_FILENO, buf.data() + off, static_cast<std::size_t>(n) - off);
                if (w <= 0) {
                    (void)::close(fd);
                    return 0;
                }
                off += static_cast<std::size_t>(w);
            }
        }
    }
    (void)::close(fd);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    glove::detail::raise_descriptor_soft_limit();
    if (argc < 2) {
        print_usage();
        return 0;
    }
    std::string_view sub{argv[1]};
    if (sub == "mcp-bridge") {
        return mcp_bridge_subcommand(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "-V" || sub == "--version") {
        std::printf("glove %.*s\n", static_cast<int>(glove::version.size()), glove::version.data());
        return 0;
    }
    if (sub == "pi") {
        return glove::run::pi_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "run") {
        return run_subcommand(std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)});
    }
    if (sub == "exec") {
        return exec_subcommand(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "shell") {
        return shell_subcommand(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "loop") {
        return loop_subcommand(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "profile") {
        return glove::run::profile_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "setup") {
        return glove::host::setup_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "daemon") {
        return glove::host::daemon_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "doctor") {
        return glove::host::doctor_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "status") {
        return glove::host::status_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "config") {
        return glove::host::config_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "policy") {
        return glove::host::policy_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "workspace") {
        return glove::host::workspace_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "session") {
        return glove::host::session_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "init") {
        return glove::host::init_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "-h" || sub == "--help") {
        print_usage();
        return 0;
    }
    std::fprintf(
        stderr, "glove: unknown subcommand '%.*s'\n", static_cast<int>(sub.size()), sub.data()
    );
    return 2;
}
