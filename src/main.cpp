#include "glove/policy/engine.hpp"
#include "glove/run/runner.hpp"
#include "glove/term/terminal.hpp"
#include "glove/version.hpp"

#include "host/cli.hpp"
#include "run/pi_cli.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
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
        "usage: glove shell [options] [-- <command argv>...]\n"
        "\n"
        "Drop into an interactive sandboxed workspace shell (defaults to /bin/bash\n"
        "or /bin/sh when no command is given).\n"
        "\n"
        "options:\n"
        "  --workspace <path>      read-write workspace for the shell\n"
        "  --read <path>           expose one additional path read-only\n"
        "  --write <path>          expose one additional path read-write\n"
        "  --env <name>            copy one named host environment variable\n"
        "  --audit-log <path>      append launch, exit, and egress events as JSONL\n"
        "  --egress-allow <host>[:port]\n"
        "                          permit outbound HTTPS through the egress proxy\n"
        "  --allow-loopback-listen allow private-loopback bind/listen inside the\n"
        "                          sandbox network namespace\n"
        "  --herdr                 report lifecycle to host Herdr\n"
        "  --agent <preset>        mediate provider credentials (claude-code, codex, pi)\n"
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
    return std::nullopt;
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

    auto code = glove::run::exec(opts);
    if (!code) {
        std::fprintf(stderr, "glove exec: %s\n", code.error().c_str());
        return 1;
    }
    return *code;
}

auto shell_subcommand(std::span<char* const> args) -> int {
    glove::run::options opts;
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
        if (const auto handled = parse_sandbox_flag(args, i, opts, "shell")) {
            if (*handled != 0) {
                return *handled;
            }
            continue;
        }
        std::fprintf(
            stderr, "glove shell: unknown flag '%.*s'\n", static_cast<int>(a.size()), a.data()
        );
        print_shell_usage();
        return 2;
    }
    while (i < args.size()) {
        opts.agent_argv.emplace_back(args[i]);
        ++i;
    }
    if (opts.agent_argv.empty()) {
        if (std::filesystem::exists("/bin/bash")) {
            opts.agent_argv.emplace_back("/bin/bash");
        } else {
            opts.agent_argv.emplace_back("/bin/sh");
        }
    }
    auto code = glove::run::exec(opts);
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
    if (::pipe2(pipe_fd, O_CLOEXEC) != 0) {
        return std::unexpected(std::string{"pipe failed for --verify"});
    }
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

    const std::string bin =
        cmd_override.value_or(driver == "claude-code" ? std::string{"claude"} : driver);

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

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        print_usage();
        return 0;
    }
    std::string_view sub{argv[1]};
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
