#include "glove/policy/engine.hpp"
#include "glove/run/runner.hpp"
#include "glove/term/terminal.hpp"
#include "glove/version.hpp"

#include "host/cli.hpp"

#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <span>
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

// Split a `--upstream` value of the form `<name>=<cmd>[,<arg>...]`.
auto parse_upstream(std::string_view spec)
    -> std::expected<glove::run::upstream_spec, std::string> {
    auto eq = spec.find('=');
    if (eq == std::string_view::npos) {
        return std::unexpected(std::string{"--upstream needs name=cmd[,arg...]"});
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
        "  --workspace <path>      read-write workspace for the agent\n"
        "                          (omitted: private empty working directory)\n"
        "  --read <path>           expose one additional path read-only\n"
        "  --write <path>          expose one additional path read-write\n"
        "  --env <name>            copy one named host environment variable\n"
        "  --audit-log <path>      append launch, exit, and egress events as JSONL\n"
        "  --egress-allow <host>[:port]\n"
        "                          permit outbound HTTPS (repeatable; leading '.'\n"
        "                          matches subdomains; port defaults to 443). Without any,\n"
        "                          the agent has no network.\n"
        "  -h, --help              show this help and exit\n"
    );
}

auto exec_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
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
        if (a == "--workspace") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove exec: --workspace needs an argument\n");
                return 2;
            }
            opts.workspace = std::filesystem::path{args[i + 1]};
            i += 2;
            continue;
        }
        if (a == "--read" || a == "--write" || a == "--env" || a == "--audit-log") {
            if (i + 1 >= args.size()) {
                std::fprintf(
                    stderr,
                    "glove exec: %.*s needs an argument\n",
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
            continue;
        }
        if (a == "--egress-allow") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "glove exec: --egress-allow needs an argument\n");
                return 2;
            }
            auto rule = parse_egress(args[i + 1]);
            if (!rule) {
                std::fprintf(stderr, "glove exec: %s\n", rule.error().c_str());
                return 2;
            }
            opts.egress.push_back(std::move(*rule));
            i += 2;
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

    auto code = glove::run::exec(opts);
    if (!code) {
        std::fprintf(stderr, "glove exec: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

auto run_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
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

    auto code = glove::run::execute(opts);
    if (!code) {
        std::fprintf(stderr, "glove run: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        print_banner();
        return 0;
    }
    std::string_view sub{argv[1]};
    if (sub == "run") {
        return run_subcommand(std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)});
    }
    if (sub == "exec") {
        return exec_subcommand(
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
    if (sub == "config") {
        return glove::host::config_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "init") {
        return glove::host::init_command(
            std::span<char* const>{argv + 2, static_cast<std::size_t>(argc - 2)}
        );
    }
    if (sub == "-h" || sub == "--help") {
        print_banner();
        std::fprintf(
            stderr,
            "\nsubcommands:\n"
            "  run     spawn an MCP-client agent inside the container\n"
            "  exec    contain a real self-driving agent (e.g. pi); stdio + egress\n"
            "  setup   create trusted machine-local configuration and state\n"
            "  daemon  install and manage the fixed gloved user service\n"
            "  doctor  verify configuration and local service readiness\n"
            "  config  inspect trusted machine-local configuration\n"
            "  init    enroll a project beneath a setup-approved protected root\n"
        );
        return 0;
    }
    std::fprintf(
        stderr, "glove: unknown subcommand '%.*s'\n", static_cast<int>(sub.size()), sub.data()
    );
    return 2;
}
