#include "glove/run/runner.hpp"

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/kernel/mcp_extension.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/kernel/server.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/lazy_init.hpp"
#include "glove/mcp/stdio_transport.hpp"
#include "glove/net/credentialed_endpoint.hpp"
#include "glove/net/egress_proxy.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <spawn.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

extern "C" char** environ;

namespace glove::run {

namespace {

class private_runtime final {
public:
    private_runtime(const private_runtime&) = delete;
    private_runtime& operator=(const private_runtime&) = delete;

    private_runtime(private_runtime&& other) noexcept : root_{std::move(other.root_)} {
        other.root_.clear();
    }

    private_runtime& operator=(private_runtime&&) = delete;

    ~private_runtime() {
        if (!root_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(root_, ignored);
        }
    }

    static auto create() -> std::expected<private_runtime, std::string> {
        std::error_code ec;
        auto root = std::filesystem::temp_directory_path(ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot locate temporary directory: "} + ec.message()
            );
        }
        std::string pattern = (root / "glove-XXXXXX").string();
        if (::mkdtemp(pattern.data()) == nullptr) {
            return std::unexpected(std::string{"mkdtemp: "} + std::strerror(errno));
        }
        return private_runtime{std::filesystem::path{std::move(pattern)}};
    }

    auto root() const -> const std::filesystem::path& { return root_; }

private:
    explicit private_runtime(std::filesystem::path root) : root_{std::move(root)} {}

    std::filesystem::path root_;
};

auto resolve_absolute(std::filesystem::path path) -> std::expected<std::string, std::string> {
    std::error_code ec;
    auto result = std::filesystem::absolute(std::move(path), ec);
    if (ec) {
        return std::unexpected(std::string{"cannot resolve path: "} + ec.message());
    }
    return result.lexically_normal().string();
}

auto append_selected_environment(
    glove::container::profile& profile, const std::vector<std::string>& names
) -> std::expected<void, std::string> {
    profile.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TERM=xterm-256color"};
    for (const auto& name : names) {
        if (name.empty() || name.find('=') != std::string::npos) {
            return std::unexpected(std::string{"--env requires a variable name, not NAME=VALUE"});
        }
        // Glove-managed variables, plus the outer-harness control variables.
        // The documented invariant is that the sandboxed child never receives
        // Herdr's socket path or binary path; allowing them through `--env`
        // would hand an agent the supervisor's control channel.
        for (const auto* reserved : {
                 "HOME",
                 "TMPDIR",
                 "GLOVE_SANDBOXED",
                 "HTTPS_PROXY",
                 "HTTP_PROXY",
                 "ALL_PROXY",
                 "HERDR_ENV",
                 "HERDR_PANE_ID",
                 "HERDR_BIN_PATH",
                 "HERDR_SOCKET_PATH",
                 "HERDR_AGENT",
             }) {
            if (name == reserved) {
                return std::unexpected(
                    std::string{"--env cannot override glove-managed variable "} + name
                );
            }
        }
        const char* value = std::getenv(name.c_str());
        if (value == nullptr) {
            return std::unexpected(std::string{"selected environment variable is unset: "} + name);
        }
        profile.environment.push_back(name + "=" + value);
    }
    return {};
}

auto build_profile(const options& opts, const std::filesystem::path& runtime_root)
    -> std::expected<glove::container::profile, std::string> {
    glove::container::profile profile;
    if (auto environment = append_selected_environment(profile, opts.environment_names);
        !environment) {
        return std::unexpected(environment.error());
    }

    profile.filesystem.push_back({.path = runtime_root.string(), .writable = true});
    profile.home_dir = (runtime_root / "home").string();
    profile.temp_dir = (runtime_root / "tmp").string();
    profile.work_dir = runtime_root.string();

    if (opts.workspace) {
        auto workspace = resolve_absolute(*opts.workspace);
        if (!workspace) {
            return std::unexpected(workspace.error());
        }
        profile.filesystem.push_back({.path = *workspace, .writable = true});
        profile.work_dir = *workspace;
    }

    for (const auto& path : opts.readable) {
        auto resolved = resolve_absolute(path);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        profile.filesystem.push_back({.path = std::move(*resolved), .writable = false});
    }
    for (const auto& path : opts.writable) {
        auto resolved = resolve_absolute(path);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        profile.filesystem.push_back({.path = std::move(*resolved), .writable = true});
    }
    return profile;
}

auto provision(const glove::container::profile& profile) -> std::expected<void, std::string> {
    for (const auto& path : {profile.home_dir, profile.temp_dir}) {
        if (!path) {
            continue;
        }
        std::error_code ec;
        std::filesystem::create_directories(*path, ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot create private sandbox directory '"} + *path +
                "': " + ec.message()
            );
        }
        std::filesystem::permissions(
            *path, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec
        );
        if (ec) {
            return std::unexpected(
                std::string{"cannot protect private sandbox directory '"} + *path +
                "': " + ec.message()
            );
        }
    }
    for (const auto& rule : profile.filesystem) {
        std::error_code ec;
        if (!std::filesystem::exists(rule.path, ec) || ec) {
            return std::unexpected(
                std::string{"explicit filesystem path does not exist: '"} + rule.path + "'"
            );
        }
    }
    return {};
}

auto prepare_profile(const options& opts, const std::filesystem::path& runtime_root)
    -> std::expected<glove::container::profile, std::string> {
    auto raw = build_profile(opts, runtime_root);
    if (!raw) {
        return std::unexpected(raw.error());
    }
    auto validated = glove::container::validate(*raw);
    if (!validated) {
        return std::unexpected(std::string{"profile: "} + validated.error());
    }
    if (auto prepared = provision(*validated); !prepared) {
        return std::unexpected(prepared.error());
    }
    auto revalidated = glove::container::validate(*validated);
    if (!revalidated) {
        return std::unexpected(
            std::string{"profile changed during provisioning: "} + revalidated.error()
        );
    }
    return revalidated;
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto audit_destination(
    const std::optional<std::filesystem::path>& requested, const glove::container::profile& profile
) -> std::expected<std::optional<std::filesystem::path>, std::string> {
    if (!requested) {
        return std::optional<std::filesystem::path>{};
    }
    auto absolute = resolve_absolute(*requested);
    if (!absolute) {
        return std::unexpected(absolute.error());
    }
    std::error_code ec;
    auto destination = std::filesystem::weakly_canonical(*absolute, ec);
    if (ec) {
        return std::unexpected(std::string{"cannot resolve audit destination: "} + ec.message());
    }
    for (const auto& rule : profile.filesystem) {
        if (path_within(destination, std::filesystem::path{rule.path})) {
            return std::unexpected(
                std::string{"audit destination must be outside every agent-visible path: '"} +
                destination.string() + "'"
            );
        }
    }
    return std::optional<std::filesystem::path>{std::move(destination)};
}

auto build_registry(const std::vector<upstream_spec>& upstreams)
    -> std::expected<std::unique_ptr<glove::kernel::registry>, std::string> {
    auto registry = std::make_unique<glove::kernel::registry>();
    for (const auto& upstream : upstreams) {
        if (upstream.argv.empty()) {
            return std::unexpected(std::string{"upstream '"} + upstream.name + "': empty argv");
        }
        glove::mcp::stdio_child_options child{
            .program = upstream.argv.front(),
            .args = upstream.argv,
            .environment = {},
        };
        auto transport = glove::mcp::make_stdio_transport(child);
        if (!transport) {
            return std::unexpected(
                std::string{"upstream '"} + upstream.name + "': " + transport.error()
            );
        }
        auto client = glove::mcp::make_client(std::move(*transport));
        auto lazy = glove::mcp::make_lazy_init_client(std::move(client), "glove", "0.0.1");
        auto extension = glove::kernel::make_mcp_extension(upstream.name, std::move(lazy));
        if (auto added = registry->add(std::move(extension)); !added) {
            return std::unexpected(added.error());
        }
    }
    return registry;
}

auto build_audit_sink(const std::optional<std::filesystem::path>& path)
    -> std::expected<std::shared_ptr<glove::audit::sink>, std::string> {
    if (!path) {
        return glove::audit::make_memory_sink();
    }
    return glove::audit::make_jsonl_sink(*path);
}

auto record(
    const std::shared_ptr<glove::audit::sink>& sink,
    glove::audit::action action,
    std::string subject,
    glove::mcp::tool_call_status status = glove::mcp::tool_call_status::ok,
    std::string error = {}
) -> std::expected<void, std::string> {
    if (!sink) {
        return {};
    }
    glove::audit::event event{
        .what = action,
        .tool_name = std::move(subject),
        .arguments_json = {},
        .status = status,
        .error_message = std::move(error),
    };
    return sink->record(event);
}

auto start_egress(
    const options& opts,
    glove::container::profile& profile,
    const std::shared_ptr<glove::audit::sink>& sink
) -> std::expected<std::unique_ptr<glove::net::egress_proxy>, std::string> {
    if (opts.egress.empty()) {
        return std::unique_ptr<glove::net::egress_proxy>{};
    }
    glove::net::egress_options proxy_options;
    proxy_options.allow = opts.egress;
    proxy_options.on_event =
        [sink](const glove::net::egress_event& event) -> std::expected<void, std::string> {
        const std::string target = event.host + ":" + std::to_string(event.port);
        const auto status = event.allowed ? glove::mcp::tool_call_status::ok
                                          : glove::mcp::tool_call_status::invalid_arguments;
        if (auto audited = record(sink, glove::audit::action::egress, target, status, event.detail);
            !audited) {
            std::fprintf(stderr, "glove audit: %s\n", audited.error().c_str());
            return std::unexpected(audited.error());
        }
        std::fprintf(
            stderr,
            "glove egress: %s %s%s%s\n",
            event.allowed ? "ALLOW" : "DENY",
            target.c_str(),
            event.detail.empty() ? "" : " — ",
            event.detail.c_str()
        );
        return {};
    };
    auto proxy = glove::net::start_egress_proxy(std::move(proxy_options));
    if (!proxy) {
        return std::unexpected(std::string{"egress proxy: "} + proxy.error());
    }
    profile.proxy = glove::container::proxy_settings{
        .port = (*proxy)->port(),
        .url = (*proxy)->proxy_url(),
    };
    return std::move(*proxy);
}

// One built-in agent preset: the provider endpoint it talks to and the
// environment variable names that steer the client at the mediated proxy.
struct preset_definition {
    glove::net::endpoint_provider provider;
    std::string_view label;
    std::string_view path_prefix;
    std::string_view upstream_host;
    std::string_view base_url_env;
    std::string_view api_key_env;
    std::vector<std::string> allowed_paths;
};

auto preset_definition_for(std::string_view name) -> std::optional<preset_definition> {
    if (name == "claude-code" || name == "claude") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::anthropic,
            .label = "claude-code",
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .base_url_env = "ANTHROPIC_BASE_URL",
            .api_key_env = "ANTHROPIC_API_KEY",
            .allowed_paths = {"/v1/messages", "/v1/messages/count_tokens"},
        };
    }
    if (name == "codex" || name == "openai") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::openai,
            .label = "codex",
            .path_prefix = "/openai",
            .upstream_host = "api.openai.com",
            .base_url_env = "OPENAI_BASE_URL",
            .api_key_env = "OPENAI_API_KEY",
            .allowed_paths = {"/v1/chat/completions", "/v1/responses", "/v1/models"},
        };
    }
    if (name == "pi") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::anthropic,
            .label = "pi",
            .path_prefix = "/anthropic",
            .upstream_host = "api.anthropic.com",
            .base_url_env = "ANTHROPIC_BASE_URL",
            .api_key_env = "ANTHROPIC_API_KEY",
            .allowed_paths = {"/v1/messages", "/v1/messages/count_tokens"},
        };
    }
    return std::nullopt;
}

// An ephemeral, non-actionable session token. The agent presents it as its API
// key; only this session's host proxy accepts it, so a leaked environment or
// transcript exposes nothing usable off-host.
auto random_session_nonce() -> std::expected<std::string, std::string> {
    std::array<unsigned char, 24> bytes{};
    if (::getentropy(bytes.data(), bytes.size()) != 0) {
        return std::unexpected(std::string{"getentropy: "} + std::strerror(errno));
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string nonce = "glove-session-";
    for (const auto byte : bytes) {
        nonce.push_back(hex[byte >> 4U]);
        nonce.push_back(hex[byte & 0x0fU]);
    }
    return nonce;
}

struct preset_startup {
    std::unique_ptr<glove::net::credentialed_endpoint> endpoint;
    std::optional<glove::container::bridge_endpoint_settings> bridge;
    std::vector<std::string> environment;
};

// Start the mediated reverse endpoint for `--agent <preset>` and compute the
// environment that steers the client at it. The real provider secret is read
// only here, on the host, and is never placed in the child environment.
auto start_agent_preset(const options& opts, const std::shared_ptr<glove::audit::sink>& sink)
    -> std::expected<preset_startup, std::string> {
    preset_startup startup;
    if (!opts.agent_preset) {
        return startup;
    }
    auto definition = preset_definition_for(*opts.agent_preset);
    if (!definition) {
        return std::unexpected(
            std::string{"unknown --agent preset '"} + *opts.agent_preset +
            "'; expected claude-code, codex, or pi"
        );
    }
    // The sandbox exposes exactly one loopback bridge destination, so a
    // credentialed endpoint cannot coexist with raw CONNECT egress. Allowing
    // both would also let the agent bypass injection and inspection.
    if (!opts.egress.empty()) {
        return std::unexpected(
            std::string{"--agent "} + std::string{definition->label} +
            " cannot be combined with --egress-allow: the sandbox has one loopback bridge "
            "destination, and a credentialed upstream must not also be reachable over raw "
            "CONNECT egress"
        );
    }
    const std::string api_key_env{definition->api_key_env};
    // Reject host-credential-shaped selections. `--env` cannot smuggle a real
    // provider secret or a base-URL override past the mediated endpoint.
    for (const std::string_view name : opts.environment_names) {
        for (const std::string_view reserved : {
                 std::string_view{"ANTHROPIC_API_KEY"},
                 std::string_view{"ANTHROPIC_AUTH_TOKEN"},
                 std::string_view{"ANTHROPIC_BASE_URL"},
                 std::string_view{"OPENAI_API_KEY"},
                 std::string_view{"OPENAI_BASE_URL"},
             }) {
            if (name == reserved) {
                return std::unexpected(
                    std::string{"--env "} + std::string{name} +
                    " cannot be combined with "
                    "--agent: the mediated endpoint owns provider credentials and base URLs"
                );
            }
        }
    }
    const char* secret = std::getenv(api_key_env.c_str());
    if (secret == nullptr || *secret == '\0') {
        return std::unexpected(
            std::string{"--agent "} + std::string{definition->label} +
            " requires the host environment variable " + api_key_env
        );
    }
    auto nonce = random_session_nonce();
    if (!nonce) {
        return std::unexpected(nonce.error());
    }

    glove::net::credentialed_endpoint_options endpoint_options;
    endpoint_options.endpoints.push_back({
        .provider = definition->provider,
        .path_prefix = std::string{definition->path_prefix},
        .upstream_host = std::string{definition->upstream_host},
        .upstream_port = 443,
        .secret_token = std::string{secret},
        .session_nonce = *nonce,
        .allowed_methods = {"POST"},
        .allowed_paths = definition->allowed_paths,
    });
    endpoint_options.on_event =
        [sink](const glove::net::endpoint_event& event) -> std::expected<void, std::string> {
        const std::string subject = event.method + " " + event.path;
        const auto status = event.allowed ? glove::mcp::tool_call_status::ok
                                          : glove::mcp::tool_call_status::invalid_arguments;
        if (auto audited =
                record(sink, glove::audit::action::egress, subject, status, event.detail);
            !audited) {
            return std::unexpected(audited.error());
        }
        if (!event.allowed) {
            std::fprintf(
                stderr,
                "glove credential proxy: DENY %s — %s\n",
                subject.c_str(),
                event.detail.c_str()
            );
        }
        return {};
    };

    auto endpoint = glove::net::start_credentialed_endpoint(std::move(endpoint_options));
    if (!endpoint) {
        return std::unexpected(std::string{"credentialed endpoint: "} + endpoint.error());
    }
    auto base_url = (*endpoint)->base_url(definition->provider);
    if (!base_url) {
        return std::unexpected(base_url.error());
    }
    // The sandbox loopback bridge advertises the same port number in the
    // child's private network namespace, so one port describes both ends.
    startup.bridge = glove::container::bridge_endpoint_settings{
        .port = (*endpoint)->port(),
    };
    startup.environment.push_back(std::string{definition->base_url_env} + "=" + *base_url);
    startup.environment.push_back(api_key_env + "=" + *nonce);
    startup.endpoint = std::move(*endpoint);
    // Drop the real credential from this process's environment now that the
    // endpoint owns it. Otherwise it lingers and is inherited by every child
    // this process starts, including the optional herdr reporter, which is
    // spawned with ::environ.
    ::unsetenv(api_key_env.c_str());
    return startup;
}

class herdr_reporter final {
public:
    herdr_reporter(const herdr_reporter&) = delete;
    herdr_reporter& operator=(const herdr_reporter&) = delete;
    herdr_reporter(herdr_reporter&&) = delete;
    herdr_reporter& operator=(herdr_reporter&&) = delete;

    static auto create(bool enabled, std::string_view agent_name)
        -> std::expected<std::unique_ptr<herdr_reporter>, std::string> {
        if (!enabled) {
            return std::unique_ptr<herdr_reporter>{};
        }
        const char* herdr_env = std::getenv("HERDR_ENV");
        const char* pane_id = std::getenv("HERDR_PANE_ID");
        if (herdr_env == nullptr || std::string_view{herdr_env} != "1" || pane_id == nullptr ||
            *pane_id == '\0') {
            return std::unexpected(
                std::string{"--herdr requested but HERDR_ENV=1 and HERDR_PANE_ID are not set"}
            );
        }
        std::string bin = "herdr";
        if (const char* bin_path = std::getenv("HERDR_BIN_PATH");
            bin_path != nullptr && *bin_path != '\0') {
            bin = bin_path;
        }
        std::string normalized_name = std::filesystem::path{agent_name}.filename().string();
        if (normalized_name.empty()) {
            normalized_name = "agent";
        }
        auto reporter = std::unique_ptr<herdr_reporter>(
            new herdr_reporter(std::move(bin), pane_id, std::move(normalized_name))
        );
        reporter->report("working");
        return reporter;
    }

    ~herdr_reporter() {
        if (!pane_id_.empty()) {
            report("done");
            release();
        }
    }

    void report(std::string_view state) const {
        run_command({
            "pane",
            "report-agent",
            pane_id_,
            "--source",
            "glove:sandbox",
            "--agent",
            agent_name_,
            "--state",
            std::string{state},
        });
    }

    void release() const {
        run_command({
            "pane",
            "release-agent",
            pane_id_,
            "--source",
            "glove:sandbox",
            "--agent",
            agent_name_,
        });
    }

private:
    herdr_reporter(std::string bin, std::string pane_id, std::string agent_name)
        : bin_{std::move(bin)}, pane_id_{std::move(pane_id)}, agent_name_{std::move(agent_name)} {}

    void run_command(const std::vector<std::string>& args) const {
        std::vector<char*> c_args;
        c_args.reserve(args.size() + 2);
        c_args.push_back(const_cast<char*>(bin_.c_str()));
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        pid_t pid = 0;
        // Its own process group, so a signal aimed at glove (or a terminal
        // hangup) is not also delivered to the reporter.
        ::posix_spawnattr_t attr{};
        if (::posix_spawnattr_init(&attr) != 0) {
            std::fprintf(stderr, "glove: herdr spawn attributes could not be initialized\n");
            return;
        }
        static_cast<void>(::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP));
        static_cast<void>(::posix_spawnattr_setpgroup(&attr, 0));
        const int spawn_rc =
            ::posix_spawnp(&pid, bin_.c_str(), nullptr, &attr, c_args.data(), ::environ);
        ::posix_spawnattr_destroy(&attr);
        if (spawn_rc != 0) {
            std::fprintf(
                stderr, "glove: herdr report failed to spawn: %s\n", std::strerror(spawn_rc)
            );
            return;
        }

        // Report the state, but never block the agent on it. A hung herdr must
        // not hold up launch or teardown, so the wait is bounded and the child
        // is killed by process group if it overruns.
        constexpr auto reporter_timeout = std::chrono::milliseconds{5000};
        const auto deadline = std::chrono::steady_clock::now() + reporter_timeout;
        int status = 0;
        bool reaped = false;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = ::waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                reaped = true;
                break;
            }
            if (result < 0 && errno != EINTR) {
                break;
            }
            ::usleep(10'000);
        }
        if (!reaped) {
            std::fprintf(stderr, "glove: herdr command exceeded its deadline; killing it\n");
            static_cast<void>(::kill(-pid, SIGKILL));
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            std::fprintf(
                stderr, "glove: herdr command returned non-zero exit status (%d)\n", status
            );
        }
    }

    std::string bin_;
    std::string pane_id_;
    std::string agent_name_;
};

} // namespace

auto execute(const options& opts) -> std::expected<int, std::string> {
    if (opts.agent_argv.empty()) {
        return std::unexpected(std::string{"runner: agent_argv is required"});
    }
    auto runtime = private_runtime::create();
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    auto profile = prepare_profile(opts, runtime->root());
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto registry = build_registry(opts.upstreams);
    if (!registry) {
        return std::unexpected(registry.error());
    }
    auto audit_path = audit_destination(opts.audit_log, *profile);
    if (!audit_path) {
        return std::unexpected(audit_path.error());
    }
    auto sink = build_audit_sink(*audit_path);
    if (!sink) {
        return std::unexpected(sink.error());
    }
    std::shared_ptr<glove::policy::engine> policy = glove::policy::make_jsonpath_engine(
        {.allow = opts.allow,
         .deny = {},
         .prefix_rules = opts.prefix_rules,
         .default_decision = glove::policy::decision::deny}
    );
    auto proxy = start_egress(opts, *profile, *sink);
    if (!proxy) {
        return std::unexpected(proxy.error());
    }
    auto spawner = glove::container::make_default_spawner();
    if (!spawner) {
        return std::unexpected(std::string{"no platform spawner available"});
    }
    if (auto audited = record(*sink, glove::audit::action::agent_launch, opts.agent_argv.front());
        !audited) {
        return std::unexpected(std::string{"audit launch: "} + audited.error());
    }
    auto handle = spawner->spawn(*profile, opts.agent_argv);
    if (!handle) {
        return std::unexpected(std::string{"spawn: "} + handle.error());
    }
    glove::kernel::server::options server_options{
        .identity = {.name = "glove", .version = "0.0.1"},
        .policy = std::move(policy),
        .audit = *sink,
    };
    glove::kernel::server server{(*handle)->transport(), **registry, std::move(server_options)};
    if (auto ran = server.run(); !ran) {
        return std::unexpected(std::string{"kernel: "} + ran.error());
    }
    auto exit_code = (*handle)->wait();
    if (!exit_code) {
        return std::unexpected(std::string{"wait: "} + exit_code.error());
    }
    if (auto audited = record(
            *sink,
            glove::audit::action::agent_exit,
            std::to_string(*exit_code),
            *exit_code == 0 ? glove::mcp::tool_call_status::ok
                            : glove::mcp::tool_call_status::execution_error
        );
        !audited) {
        return std::unexpected(std::string{"audit exit: "} + audited.error());
    }
    return *exit_code;
}

auto exec(const options& opts) -> std::expected<int, std::string> {
    if (opts.agent_argv.empty()) {
        return std::unexpected(std::string{"runner: agent_argv is required"});
    }
    auto runtime = private_runtime::create();
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    auto profile = prepare_profile(opts, runtime->root());
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto audit_path = audit_destination(opts.audit_log, *profile);
    if (!audit_path) {
        return std::unexpected(audit_path.error());
    }
    auto sink = build_audit_sink(*audit_path);
    if (!sink) {
        return std::unexpected(sink.error());
    }
    // Resolve the agent preset before starting the egress proxy. This is the
    // step that rejects a preset combined with --egress-allow, so doing it first
    // means a rejected request never briefly binds and then discards a CONNECT
    // listener.
    auto preset = start_agent_preset(opts, *sink);
    if (!preset) {
        return std::unexpected(preset.error());
    }

    auto proxy = start_egress(opts, *profile, *sink);
    if (!proxy) {
        return std::unexpected(proxy.error());
    }

    if (preset->bridge) {
        profile->bridge_endpoint = *preset->bridge;
        profile->environment.insert(
            profile->environment.end(), preset->environment.begin(), preset->environment.end()
        );
        // Re-validate so the credentialed-endpoint/egress mutual exclusion and
        // environment rules are enforced on the exact launch profile.
        auto revalidated = glove::container::validate(*profile);
        if (!revalidated) {
            return std::unexpected(std::string{"profile: "} + revalidated.error());
        }
        *profile = std::move(*revalidated);
    }

    auto reporter = herdr_reporter::create(opts.herdr, opts.agent_argv.front());
    if (!reporter) {
        return std::unexpected(reporter.error());
    }
    std::string readable;
    std::string writable;
    for (const auto& rule : profile->filesystem) {
        auto& output = rule.writable ? writable : readable;
        output += (output.empty() ? "" : ", ") + rule.path;
    }
    std::fprintf(
        stderr,
        "glove: readable=[%s] writable=[%s] environment=%zu selected egress=%zu rule(s)\n",
        readable.c_str(),
        writable.c_str(),
        opts.environment_names.size(),
        opts.egress.size()
    );
    if (auto audited = record(*sink, glove::audit::action::agent_launch, opts.agent_argv.front());
        !audited) {
        return std::unexpected(std::string{"audit launch: "} + audited.error());
    }
    auto exit_code = glove::container::exec_contained(*profile, opts.agent_argv);
    if (!exit_code) {
        return std::unexpected(exit_code.error());
    }
    if (auto audited = record(
            *sink,
            glove::audit::action::agent_exit,
            std::to_string(*exit_code),
            *exit_code == 0 ? glove::mcp::tool_call_status::ok
                            : glove::mcp::tool_call_status::execution_error
        );
        !audited) {
        return std::unexpected(std::string{"audit exit: "} + audited.error());
    }
    return *exit_code;
}

} // namespace glove::run
