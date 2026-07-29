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
#include "glove/mcp/transport.hpp"
#include "glove/net/egress_proxy.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <unistd.h>

#include <algorithm>
#include <cerrno>
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
        for (const auto* reserved :
             {"HOME", "TMPDIR", "GLOVE_SANDBOXED", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"}) {
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
    auto proxy = start_egress(opts, *profile, *sink);
    if (!proxy) {
        return std::unexpected(proxy.error());
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
