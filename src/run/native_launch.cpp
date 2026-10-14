#include "native_launch.hpp"

#include "glove/container/owned_passthrough.hpp"
#include "glove/detail/descriptor_acl.hpp"

#include "../container/stdio_admission.hpp"
#include "../host/runtime_snapshot.hpp"
#include "native_audit.hpp"
#include "native_library_environment.hpp"
#include "native_private_state.hpp"
#include "provider_endpoint.hpp"

#if defined(__APPLE__)
#    include "../container/macos/launch_command.hpp"
#    include "../container/macos/runtime_filesystem.hpp"
#endif

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

namespace glove::run::detail {
namespace fs = std::filesystem;
template<typename T> using result = std::expected<T, std::string>;

auto admit_native_operator_stdio() -> result<void> {
    if (container::detail::stdio_admission_error() != 0) {
        return std::unexpected(std::string{container::detail::stdio_admission_message});
    }
    return {};
}

#if defined(__APPLE__)
namespace {

class workspace_witness {
public:
    // The label is a synchronous borrow from the live launch context, not stored
    // in an endpoint callback or retained beyond this launch.
    workspace_witness(int fd, struct stat identity, std::string_view label) noexcept
        : fd_{fd}, identity_{identity}, label_{label} {}

    workspace_witness(const workspace_witness&) = delete;
    auto operator=(const workspace_witness&) -> workspace_witness& = delete;

    workspace_witness(workspace_witness&& other) noexcept
        : fd_{std::exchange(other.fd_, -1)}, identity_{other.identity_}, label_{other.label_} {}

    auto operator=(workspace_witness&&) -> workspace_witness& = delete;

    ~workspace_witness() {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    auto recheck(const fs::path& path) const -> result<void> {
        struct stat opened{};
        struct stat named{};
        if (::fstat(fd_, &opened) != 0 || ::lstat(path.c_str(), &named) != 0 || !matches(opened) ||
            !matches(named)) {
            return std::unexpected(
                std::string{label_} + " workspace identity or private permissions changed"
            );
        }
        return glove::detail::check_descriptor_acl(fd_, glove::detail::acl_scope::owner_private);
    }

private:
    auto matches(const struct stat& info) const -> bool {
        return S_ISDIR(info.st_mode) && info.st_dev == identity_.st_dev &&
               info.st_ino == identity_.st_ino && info.st_uid == ::geteuid() &&
               info.st_uid == identity_.st_uid && info.st_gid == identity_.st_gid &&
               (info.st_mode & 07777U) == 0700U;
    }

    int fd_;
    struct stat identity_;
    std::string_view label_;
};

auto pin_workspace(const fs::path& path, std::string_view label) -> result<workspace_witness> {
    const int fd =
        ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected("cannot pin private " + std::string{label} + " workspace");
    }
    struct stat identity{};
    if (::fstat(fd, &identity) != 0) {
        (void)::close(fd);
        return std::unexpected("cannot inspect private " + std::string{label} + " workspace");
    }
    workspace_witness witness{fd, identity, label};
    if (auto admitted = witness.recheck(path); !admitted) {
        return std::unexpected(admitted.error());
    }
    return witness;
}

auto bounded_absolute(const fs::path& path) -> bool {
    const auto& text = path.native();
    return path.is_absolute() && path == path.lexically_normal() && text.size() <= 4096 &&
           text.find('\0') == std::string::npos && std::distance(path.begin(), path.end()) <= 128;
}

auto within(const fs::path& candidate, const fs::path& root) -> bool {
    return std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end()).first ==
           root.end();
}

auto disjoint(const fs::path& left, const fs::path& right) -> bool {
    return !within(left, right) && !within(right, left);
}

auto workspace_for(
    const native_launch_context& context, const host::staged_runtime_harness& runtime
) -> result<fs::path> {
    std::error_code error;
    fs::path input = context.workspace ? *context.workspace : fs::current_path(error);
    if (error || input.empty() || input.native().size() > 4096 ||
        input.native().find('\0') != std::string::npos) {
        return std::unexpected("invalid " + context.display_name + " workspace path");
    }
    auto workspace = fs::canonical(input, error);
    if (error || !bounded_absolute(workspace) || !fs::is_directory(workspace, error) || error) {
        return std::unexpected(
            context.display_name + " workspace must be an existing canonical directory"
        );
    }
    if (context.protected_auth_roots.size() > 32) {
        return std::unexpected(
            "too many protected " + context.display_name + " authentication roots"
        );
    }
    const auto& paths = context.directories;
    std::vector<fs::path> forbidden{
        paths.config,
        paths.state,
        paths.data,
        paths.cache,
        paths.runtime,
        runtime.source_executable,
        runtime.canonical_source_executable,
        runtime.source_launch_executable,
        runtime.protected_entry_point,
        runtime.launch_executable
    };
    forbidden.insert(
        forbidden.end(), context.protected_auth_roots.begin(), context.protected_auth_roots.end()
    );
    forbidden.insert(
        forbidden.end(),
        runtime.source_read_only_paths.begin(),
        runtime.source_read_only_paths.end()
    );
    forbidden.insert(
        forbidden.end(), runtime.read_only_paths.begin(), runtime.read_only_paths.end()
    );
    for (const auto& path : forbidden) {
        if (!bounded_absolute(path)) {
            return std::unexpected("invalid protected " + context.display_name + " authority path");
        }
        const auto resolved = fs::weakly_canonical(path, error);
        if (error || !disjoint(workspace, path) || !disjoint(workspace, resolved)) {
            return std::unexpected(
                context.display_name + " workspace overlaps protected host or runtime authority"
            );
        }
    }
    return workspace;
}

auto nonce_for_run(std::string_view label) -> result<std::string> {
    std::array<unsigned char, 24> bytes{};
    if (::getentropy(bytes.data(), bytes.size()) != 0) {
        return std::unexpected("cannot obtain " + std::string{label} + " endpoint entropy");
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string nonce = "glove-session-";
    for (const auto byte : bytes) {
        nonce.push_back(digits[byte >> 4U]);
        nonce.push_back(digits[byte & 15U]);
    }
    return nonce;
}

auto host_credential(net::endpoint_provider provider, std::string_view label)
    -> result<std::string> {
    const char* name =
        provider == net::endpoint_provider::openai ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
    const char* secret = std::getenv(name);
    if (secret == nullptr || *secret == '\0') {
        return std::unexpected(
            std::string{label} + " requires host API-key authentication: export " + name
        );
    }
    const auto length = ::strnlen(secret, 8193);
    if (length > 8192) {
        return std::unexpected(std::string{label} + " host credential exceeds its bound");
    }
    return std::string{secret, length};
}

auto record(
    const std::shared_ptr<audit::sink>& sink,
    std::string_view name,
    audit::action action,
    mcp::tool_call_status status = mcp::tool_call_status::ok
) -> result<void> {
    try {
        return sink->record(
            {.what = action,
             .tool_name = std::string{name},
             .arguments_json = {},
             .status = status,
             .error_message = {}}
        );
    } catch (const std::bad_alloc&) {
        return native_audit_allocation_error();
    }
}

void revoke_before_rollback(void* context) noexcept {
    static_cast<std::unique_ptr<net::credentialed_endpoint>*>(context)->reset();
}

auto profile_for(
    const fs::path& workspace,
    const native_launch_binding& approved,
    const native_private_run_plan& plan,
    const native_startup_recipe& recipe,
    const std::vector<std::string>& libraries,
    std::uint16_t port,
    std::string_view nonce,
    bool materialized = true
) -> result<container::profile> {
    const auto paths = plan.paths();
    container::profile profile;
    profile.filesystem = {
        {.path = workspace.string(), .writable = true},
        {.path = paths.home.string(), .writable = true},
        {.path = (plan.root() / "tmp").string(), .writable = true},
        {.path = paths.agent.string(), .writable = true},
        {.path = paths.sessions.string(), .writable = true}
    };
    for (const auto& path : approved.runtime.read_only_paths) {
        profile.runtime_filesystem.push_back({.path = path.string(), .writable = false});
    }
    if (materialized) {
        for (const auto& file : recipe.configuration) {
            profile.immutable_files.push_back((paths.agent / file.name).string());
        }
    }
    for (const auto& name : recipe.reserved_entries) {
        profile.reserved_entries.push_back({.parent = workspace.string(), .name = name});
    }
    profile.home_dir = paths.home.string();
    profile.temp_dir = (plan.root() / "tmp").string();
    profile.work_dir = workspace.string();
    profile.bridge_endpoint = container::bridge_endpoint_settings{.port = port};
    profile.environment = {"PATH=/usr/bin:/bin"};
    // HOME/TMPDIR are profile-owned; libraries cannot shadow core/adapter names.
    std::set<std::string> names{"PATH", "HOME", "TMPDIR"};
    for (const auto& binding : recipe.environment) {
        if (binding.source != native_environment_source::private_location) {
            std::string value;
            switch (binding.source) {
            case native_environment_source::endpoint_base_url:
                value = recipe.base_url;
                break;
            case native_environment_source::endpoint_nonce:
                value = std::string{nonce};
                break;
            case native_environment_source::literal:
                value = binding.literal;
                break;
            default:
                return std::unexpected("invalid native environment source");
            }
            if (value.empty() || !names.emplace(binding.name).second) {
                return std::unexpected("native environment name collision");
            }
            profile.environment.push_back(binding.name + "=" + value);
            continue;
        }
        fs::path value;
        switch (binding.location) {
        case native_private_location::agent:
            value = paths.agent;
            break;
        case native_private_location::config:
            value = paths.home / ".config";
            break;
        case native_private_location::state:
            value = paths.home / ".local/state";
            break;
        case native_private_location::data:
            value = paths.home / ".local/share";
            break;
        case native_private_location::cache:
            value = paths.home / ".cache";
            break;
        default:
            return std::unexpected("invalid native environment location");
        }
        if (!names.emplace(binding.name).second) {
            return std::unexpected("native environment name collision");
        }
        profile.environment.push_back(binding.name + "=" + value.string());
    }
    for (const auto& entry : libraries) {
        const auto equals = entry.find('=');
        if (equals == std::string::npos || equals == 0 ||
            !names.emplace(entry.substr(0, equals)).second) {
            return std::unexpected(
                "native library environment name collision or malformed binding"
            );
        }
        profile.environment.push_back(entry);
    }
    return container::validate(profile);
}

} // namespace
#endif

auto launch_native_with_context(
    const native_launch_context& context,
    const native_harness_adapter& adapter,
    std::stop_token stop
) -> result<int> {
#if !defined(__APPLE__)
    (void)adapter;
    (void)stop;
    return std::unexpected(
        "glove " + context.policy.runtime_id + " requires the native macOS backend"
    );
#else
    if (context.backend != native_launch_backend::macos) {
        return std::unexpected(
            "glove " + context.policy.runtime_id + " requires the native macOS backend"
        );
    }
    if (auto stdio = admit_native_operator_stdio(); !stdio) {
        return std::unexpected(stdio.error());
    }
    if (stop.stop_requested()) {
        return std::unexpected(context.display_name + " launch cancelled");
    }
    if (auto policy = validate_native_startup_policy(context.policy); !policy) {
        return std::unexpected(policy.error());
    }
    if (context.display_name.empty() || context.display_name.size() > 64 ||
        context.display_name.find('\0') != std::string::npos || !context.admit_runtime ||
        !context.admit_assets || !context.revalidate) {
        return std::unexpected("invalid native host composition");
    }
    const auto& paths = context.directories;
    for (const auto& path : {paths.config, paths.state, paths.data, paths.cache, paths.runtime}) {
        if (!bounded_absolute(path)) {
            return std::unexpected("invalid protected " + context.display_name + " host directory");
        }
    }
    if (!bounded_absolute(context.runs) ||
        context.runs != paths.runtime / context.policy.runtime_id / "runs") {
        return std::unexpected("invalid native private-run namespace");
    }
    auto approved = context.admit_runtime();
    if (!approved) {
        return std::unexpected(approved.error());
    }
    // Admission may block on host work; a cancellation admitted meanwhile
    // ends preparation here, before any endpoint or private state exists.
    if (stop.stop_requested()) {
        return std::unexpected(context.display_name + " launch cancelled");
    }
    if (approved->runtime.runtime_id != context.policy.runtime_id ||
        (approved->provider != net::endpoint_provider::openai &&
         approved->provider != net::endpoint_provider::anthropic)) {
        return std::unexpected("unsupported native runtime or provider binding");
    }
    auto workspace = workspace_for(context, approved->runtime);
    if (!workspace) {
        return std::unexpected(workspace.error());
    }
    auto workspace_identity = pin_workspace(*workspace, context.display_name);
    if (!workspace_identity) {
        return std::unexpected(workspace_identity.error());
    }
    container::profile workspace_only;
    workspace_only.filesystem = {{.path = workspace->string(), .writable = true}};
    for (const auto& name : context.policy.reserved_entries) {
        workspace_only.reserved_entries.push_back({.parent = workspace->string(), .name = name});
    }
    if (auto absent = container::macos_detail::validate_launch_constraints(workspace_only);
        !absent) {
        return std::unexpected(absent.error());
    }
    auto assets = context.admit_assets(*approved);
    if (!assets) {
        return std::unexpected(assets.error());
    }
    if (auto checked =
            validate_native_library_environment(approved->runtime, assets->library_environment);
        !checked) {
        return std::unexpected(checked.error());
    }
    auto nonce = nonce_for_run(context.display_name);
    if (!nonce) {
        return std::unexpected(nonce.error());
    }
    auto plan = prepare_native_private_run(context.runs);
    if (!plan) {
        return std::unexpected(plan.error());
    }
    native_startup_input input{
        .runtime = approved->runtime,
        .policy = context.policy,
        .provider = approved->provider,
        .model = approved->model,
        .arguments = approved->arguments,
        .catalog_json = assets->catalog_json,
        .endpoint_port = 1,
        .nonce = *nonce,
        .paths = plan->paths(),
        .conversation_id = context.conversation_id,
        .resume = context.resume
    };
    // Placeholder port is pure preflight only: no bytes are written or endpoint
    // created until the host has admitted the entire compiled startup projection.
    auto preflight = adapter.encode_startup(input);
    if (!preflight) {
        return std::unexpected(preflight.error());
    }
    if (auto checked = validate_native_startup_recipe(input, *preflight); !checked) {
        return std::unexpected(checked.error());
    }
    if (auto checked = profile_for(
            *workspace, *approved, *plan, *preflight, assets->library_environment, 1, *nonce, false
        );
        !checked) {
        return std::unexpected(checked.error());
    }
    auto secret = context.credential ? context.credential(approved->provider)
                                     : host_credential(approved->provider, context.display_name);
    if (!secret) {
        return std::unexpected(secret.error());
    }
    if (secret->empty() || secret->size() > 8192 || secret->find('\0') != std::string::npos ||
        secret->find_first_of("\r\n") != std::string::npos) {
        return std::unexpected("invalid " + context.display_name + " host credential");
    }
    auto options = make_provider_endpoint_options(
        approved->provider == net::endpoint_provider::openai ? provider_surface::native_openai
                                                             : provider_surface::native_anthropic,
        std::move(*secret),
        *nonce
    );
    if (!options) {
        return std::unexpected(options.error());
    }
    std::shared_ptr<audit::sink> sink = context.audit;
    if (!sink) {
        auto bounded = make_native_audit_sink(
            native_audit_max_events, native_audit_max_bytes, context.display_name
        );
        if (!bounded) {
            return std::unexpected(std::move(bounded.error()));
        }
        sink = std::move(*bounded);
    }
    options->on_event =
        [sink, name = context.policy.runtime_id](const net::endpoint_event& event) -> result<void> {
        return record(
            sink,
            name,
            audit::action::egress,
            event.allowed ? mcp::tool_call_status::ok : mcp::tool_call_status::invalid_arguments
        );
    };
    // Reverse destruction revokes/joins the endpoint before eligible state cleanup,
    // including exception paths. Explicit error paths also revoke before removal.
    std::optional<native_private_state> state;
    auto started = context.start_endpoint ? context.start_endpoint(std::move(*options))
                                          : net::start_credentialed_endpoint(std::move(*options));
    if (!started) {
        return std::unexpected(started.error());
    }
    auto endpoint = std::move(*started);
    if (!endpoint || endpoint->port() == 0) {
        return std::unexpected(context.display_name + " endpoint did not supply a valid port");
    }
    auto endpoint_nonce = endpoint->session_nonce(approved->provider);
    auto endpoint_url = endpoint->base_url(approved->provider);
    if (!endpoint_nonce || !endpoint_url || *endpoint_nonce != *nonce ||
        *endpoint_url !=
            "http://127.0.0.1:" + std::to_string(endpoint->port()) +
                (approved->provider == net::endpoint_provider::openai ? "/openai" : "/anthropic")) {
        return std::unexpected(
            context.display_name + " endpoint binding disagrees with private configuration"
        );
    }
    input.endpoint_port = endpoint->port();
    auto recipe = adapter.encode_startup(input);
    if (!recipe) {
        return std::unexpected(recipe.error());
    }
    if (auto checked = validate_native_startup_recipe(input, *recipe); !checked) {
        return std::unexpected(checked.error());
    }
    if (auto parent = host::snapshot::ensure_protected_directory(paths.runtime, true); !parent) {
        return std::unexpected(parent.error());
    }
    if (auto parent = host::snapshot::ensure_protected_directory(context.runs, true); !parent) {
        return std::unexpected(parent.error());
    }
    auto created = native_private_state::create(
        *plan, recipe->configuration, {&endpoint, &revoke_before_rollback}
    );
    if (!created) {
        return std::unexpected(created.error());
    }
    state.emplace(std::move(*created));
    const auto fail_before_launch = [&](std::string original) -> result<int> {
        endpoint.reset();
        if (auto cleaned = state->cleanup(); !cleaned) {
            original += "; " + context.display_name + " private cleanup failed: " + cleaned.error();
        }
        return std::unexpected(std::move(original));
    };
    const auto planned_paths = plan->paths();
    if (state->root() != plan->root() || state->home() != planned_paths.home ||
        state->agent() != planned_paths.agent || state->sessions() != planned_paths.sessions) {
        return fail_before_launch("native private state differs from its admitted plan");
    }
    auto profile = profile_for(
        *workspace, *approved, *plan, *recipe, assets->library_environment, endpoint->port(), *nonce
    );
    if (!profile) {
        return fail_before_launch(profile.error());
    }
    if (context.materialize) {
        if (auto materialized = context.materialize(*state); !materialized) {
            return fail_before_launch(materialized.error());
        }
    }
    if (auto audited = record(sink, context.policy.runtime_id, audit::action::agent_launch);
        !audited) {
        return fail_before_launch(std::move(audited.error()));
    }
    auto current = context.revalidate();
    if (!current) {
        return fail_before_launch(current.error());
    }
    if (current->binding.provider != approved->provider ||
        current->binding.model != approved->model ||
        current->binding.arguments != approved->arguments ||
        !same_native_runtime_binding(current->binding.runtime, approved->runtime)) {
        return fail_before_launch(
            context.display_name + " runtime selection changed before launch"
        );
    }
    if (auto checked = validate_native_library_environment(
            current->binding.runtime, current->assets.library_environment
        );
        !checked) {
        return fail_before_launch(checked.error());
    }
    if (current->assets.catalog_json != assets->catalog_json ||
        current->assets.library_environment != assets->library_environment) {
        return fail_before_launch(
            context.display_name + " catalog or runtime libraries changed before launch"
        );
    }
    auto current_workspace = workspace_for(context, current->binding.runtime);
    if (!current_workspace || *current_workspace != *workspace) {
        return fail_before_launch(
            context.display_name + " workspace authority changed before launch"
        );
    }
    if (auto bound = workspace_identity->recheck(*workspace); !bound) {
        return fail_before_launch(bound.error());
    }
    auto checked_profile = container::validate(*profile);
    if (!checked_profile) {
        return fail_before_launch(checked_profile.error());
    }
    if (auto prepared =
            container::macos_detail::prepare_launch_command(*checked_profile, recipe->argv, true);
        !prepared) {
        return fail_before_launch(prepared.error());
    }
    if (stop.stop_requested()) {
        return fail_before_launch(context.display_name + " launch cancelled");
    }
    if (auto launching = state->mark_launching(); !launching) {
        endpoint.reset();
        return std::unexpected(
            context.display_name + " launch state uncertain; retained: " + launching.error()
        );
    }
    if (context.on_launching) {
        context.on_launching();
    }
    auto exited = context.execute_owned
                      ? context.execute_owned(*checked_profile, recipe->argv, stop)
                      : container::exec_contained_owned(*checked_profile, recipe->argv, stop);
    endpoint.reset();
    if (!exited) {
        return std::unexpected(
            context.display_name +
            " launch outcome uncertain; private state retained: " + exited.error()
        );
    }
    // Retained finalization: history publication happens here, with the owned
    // process outcome known and the endpoint revoked, before the quiescent
    // marker makes disposable nonce-bearing state eligible for cleanup.
    if (context.finalize) {
        if (auto finalized = context.finalize(*state, *exited); !finalized) {
            return std::unexpected(
                context.display_name +
                " finalization failed; private state retained: " + finalized.error()
            );
        }
    }
    if (auto quiescent = state->mark_quiescent(); !quiescent) {
        return std::unexpected(
            context.display_name +
            " quiescent marker failed; private state retained: " + quiescent.error()
        );
    }
    auto audited = record(sink, context.policy.runtime_id, audit::action::agent_exit);
    auto cleaned = state->cleanup();
    if (!audited) {
        std::string original = std::move(audited.error());
        if (!cleaned) {
            original += "; " + context.display_name + " private cleanup failed: " + cleaned.error();
        }
        return std::unexpected(std::move(original));
    }
    if (!cleaned) {
        return std::unexpected(
            context.display_name + " private cleanup failed: " + cleaned.error()
        );
    }
    return *exited;
#endif
}

} // namespace glove::run::detail
