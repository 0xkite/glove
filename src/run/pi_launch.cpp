#include "glove/run/pi_launch.hpp"

#include "glove/container/owned_passthrough.hpp"
#include "glove/run/pi_runtime.hpp"

#include "../container/stdio_admission.hpp"
#include "../host/runtime_snapshot.hpp"
#include "pi_audit.hpp"
#include "pi_catalog.hpp"
#include "pi_guest_config.hpp"
#include "pi_launch_internal.hpp"
#include "pi_machine_authorities.hpp"
#include "pi_private_state.hpp"
#include "pi_runtime_internal.hpp"
#include "provider_endpoint.hpp"

#if defined(__APPLE__)
#    include "../container/macos/launch_command.hpp"
#    include "../container/macos/runtime_filesystem.hpp"
#endif

#include "glove/detail/descriptor_acl.hpp"

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

namespace glove::run {
namespace fs = std::filesystem;
template<typename T> using result = std::expected<T, std::string>;
#if defined(__APPLE__)
namespace {

auto admit_operator_stdio() -> result<void> {
    if (container::detail::stdio_admission_error() != 0) {
        return std::unexpected(std::string{container::detail::stdio_admission_message});
    }
    return {};
}

class workspace_witness {
public:
    workspace_witness(int fd, struct stat identity) noexcept : fd_{fd}, identity_{identity} {}

    workspace_witness(const workspace_witness&) = delete;
    auto operator=(const workspace_witness&) -> workspace_witness& = delete;

    workspace_witness(workspace_witness&& other) noexcept
        : fd_{std::exchange(other.fd_, -1)}, identity_{other.identity_} {}

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
            return std::unexpected("Pi workspace identity or private permissions changed");
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
};

auto pin_workspace(const fs::path& path) -> result<workspace_witness> {
    const int fd =
        ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected("cannot pin private Pi workspace");
    }
    struct stat identity{};
    if (::fstat(fd, &identity) != 0) {
        (void)::close(fd);
        return std::unexpected("cannot inspect private Pi workspace");
    }
    workspace_witness witness{fd, identity};
    if (auto admitted = witness.recheck(path); !admitted) {
        return std::unexpected(admitted.error());
    }
    return witness;
}

// These comparisons bind record identity by its validated contents; the loader
// independently proves file and snapshot identities around every read.
auto binding(const host::staged_runtime_harness& runtime) {
    return std::tie(
        runtime.runtime_id,
        runtime.executable_name,
        runtime.source_executable,
        runtime.canonical_source_executable,
        runtime.source_launch_executable,
        runtime.source_read_only_paths,
        runtime.protected_entry_point,
        runtime.launch_executable,
        runtime.launch_arguments,
        runtime.read_only_paths,
        runtime.snapshot_digest,
        runtime.adoption_manifest_digest,
        runtime.snapshot_logical_bytes,
        runtime.snapshot_entries
    );
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

auto disjoint(const fs::path& a, const fs::path& b) -> bool {
    return !within(a, b) && !within(b, a);
}

auto workspace_for(
    const pi_launch_request& request,
    const detail::pi_launch_context& context,
    const pi_runtime_selection& runtime
) -> result<fs::path> {
    std::error_code error;
    fs::path input = request.workspace ? *request.workspace : fs::current_path(error);
    if (error || input.empty() || input.native().size() > 4096 ||
        input.native().find('\0') != std::string::npos) {
        return std::unexpected("invalid Pi workspace path");
    }
    auto workspace = fs::canonical(input, error);
    if (error || !bounded_absolute(workspace) || !fs::is_directory(workspace, error) || error) {
        return std::unexpected("Pi workspace must be an existing canonical directory");
    }
    if (context.protected_auth_roots.size() > 32) {
        return std::unexpected("too many protected Pi authentication roots");
    }
    std::vector<fs::path> forbidden{
        context.directories.config,
        context.directories.state,
        context.directories.data,
        context.directories.cache,
        context.directories.runtime,
        runtime.runtime.source_executable,
        runtime.runtime.canonical_source_executable,
        runtime.runtime.source_launch_executable,
        runtime.runtime.protected_entry_point,
        runtime.runtime.launch_executable
    };
    forbidden.insert(
        forbidden.end(), context.protected_auth_roots.begin(), context.protected_auth_roots.end()
    );
    forbidden.insert(
        forbidden.end(),
        runtime.runtime.source_read_only_paths.begin(),
        runtime.runtime.source_read_only_paths.end()
    );
    forbidden.insert(
        forbidden.end(),
        runtime.runtime.read_only_paths.begin(),
        runtime.runtime.read_only_paths.end()
    );
    for (const auto& path : forbidden) {
        if (!bounded_absolute(path)) {
            return std::unexpected("invalid protected Pi authority path");
        }
        const auto resolved = fs::weakly_canonical(path, error);
        if (error || !disjoint(workspace, path) || !disjoint(workspace, resolved)) {
            return std::unexpected("Pi workspace overlaps protected host or runtime authority");
        }
    }
    return workspace;
}

auto nonce_for_run() -> result<std::string> {
    std::array<unsigned char, 24> bytes{};
    if (::getentropy(bytes.data(), bytes.size()) != 0) {
        return std::unexpected("cannot obtain Pi endpoint entropy");
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string nonce = "glove-session-";
    for (const auto byte : bytes) {
        nonce.push_back(digits[byte >> 4U]);
        nonce.push_back(digits[byte & 15U]);
    }
    return nonce;
}

auto host_credential(pi_provider provider) -> result<std::string> {
    const char* name = provider == pi_provider::openai ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
    const char* secret = std::getenv(name);
    if (secret == nullptr || *secret == '\0') {
        return std::unexpected(
            std::string{"Pi requires host API-key authentication: export "} + name
        );
    }
    const auto length = ::strnlen(secret, 8193);
    if (length > 8192) {
        return std::unexpected("Pi host credential exceeds its bound");
    }
    return std::string{secret, length};
}

auto record(
    const std::shared_ptr<audit::sink>& sink,
    audit::action action,
    mcp::tool_call_status status = mcp::tool_call_status::ok
) -> result<void> {
    try {
        return sink->record(
            {.what = action,
             .tool_name = "pi",
             .arguments_json = {},
             .status = status,
             .error_message = {}}
        );
    } catch (const std::bad_alloc&) {
        return detail::pi_audit_allocation_error();
    }
}

auto add_machine_authorities(detail::pi_launch_context& context) -> result<void> {
    auto roots = detail::load_pi_machine_authorities(context.directories);
    if (!roots) {
        return std::unexpected(roots.error());
    }
    context.protected_auth_roots.insert(
        context.protected_auth_roots.end(), roots->begin(), roots->end()
    );
    return {};
}

void revoke_before_rollback(void* context) noexcept {
    static_cast<std::unique_ptr<net::credentialed_endpoint>*>(context)->reset();
}

auto profile_for(
    const fs::path& workspace,
    const pi_runtime_selection& runtime,
    const detail::pi_private_state& state,
    const std::vector<std::string>& library_environment,
    std::uint16_t port
) -> result<container::profile> {
    container::profile profile;
    profile.filesystem = {
        {.path = workspace.string(), .writable = true},
        {.path = state.home().string(), .writable = true},
        {.path = state.tmp().string(), .writable = true},
        {.path = state.agent().string(), .writable = true},
        {.path = state.sessions().string(), .writable = true}
    };
    for (const auto& path : runtime.runtime.read_only_paths) {
        profile.runtime_filesystem.push_back({.path = path.string(), .writable = false});
    }
    profile.immutable_files = {
        state.models().string(), state.settings().string(), state.auth().string()
    };
    profile.reserved_entries = {{.parent = workspace.string(), .name = ".pi"}};
    profile.home_dir = state.home().string();
    profile.temp_dir = state.tmp().string();
    profile.work_dir = workspace.string();
    profile.bridge_endpoint = container::bridge_endpoint_settings{.port = port};
    profile.environment = {
        "PATH=/usr/bin:/bin",
        "PI_CODING_AGENT_DIR=" + state.agent().string(),
        "XDG_CONFIG_HOME=" + (state.home() / ".config").string(),
        "XDG_STATE_HOME=" + (state.home() / ".local/state").string(),
        "XDG_DATA_HOME=" + (state.home() / ".local/share").string(),
        "XDG_CACHE_HOME=" + (state.home() / ".cache").string()
    };
    profile.environment.insert(
        profile.environment.end(), library_environment.begin(), library_environment.end()
    );
    return container::validate(profile);
}

} // namespace
#endif

namespace detail {

auto launch_pi_with_context(
    const pi_launch_request& request, const pi_launch_context& context, std::stop_token stop
) -> result<int> {
#if !defined(__APPLE__)
    (void)request;
    (void)context;
    (void)stop;
    return std::unexpected("glove pi requires the native macOS backend");
#else
    if (auto stdio = admit_operator_stdio(); !stdio) {
        return std::unexpected(stdio.error());
    }
    if (stop.stop_requested()) {
        return std::unexpected("Pi launch cancelled");
    }
    const auto& paths = context.directories;
    for (const auto& path : {paths.config, paths.state, paths.data, paths.cache, paths.runtime}) {
        if (!bounded_absolute(path)) {
            return std::unexpected("invalid protected Pi host directory");
        }
    }
    auto source_authorities = pi_source_authorities(paths, context.protected_auth_roots);
    if (!source_authorities) {
        return std::unexpected(source_authorities.error());
    }
    const auto record_path = paths.config / "pi/selection.json";
    auto runtime = load_pi_runtime_with_exclusions(record_path, *source_authorities);
    if (!runtime) {
        return std::unexpected(
            "Pi runtime selection unavailable; run 'glove pi setup': " + runtime.error()
        );
    }
    if (!*runtime) {
        return std::unexpected("Pi runtime is not configured; run 'glove pi setup'");
    }
    const auto& approved = **runtime;
    auto selection = select_pi_launch(request.selection, approved.model);
    if (!selection) {
        return std::unexpected(selection.error());
    }
    auto workspace = workspace_for(request, context, approved);
    if (!workspace) {
        return std::unexpected(workspace.error());
    }
    auto workspace_identity = pin_workspace(*workspace);
    if (!workspace_identity) {
        return std::unexpected(workspace_identity.error());
    }
    container::profile workspace_only;
    workspace_only.filesystem = {{.path = workspace->string(), .writable = true}};
    workspace_only.reserved_entries = {{.parent = workspace->string(), .name = ".pi"}};
    if (auto absent = container::macos_detail::validate_launch_constraints(workspace_only);
        !absent) {
        return std::unexpected(absent.error());
    }
    auto catalog =
        load_pi_builtin_catalog(approved, selection->model.provider, *source_authorities);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    auto libraries = pi_library_environment_with_exclusions(approved, *source_authorities);
    if (!libraries) {
        return std::unexpected(libraries.error());
    }
    auto secret = context.credential ? context.credential(selection->model.provider)
                                     : host_credential(selection->model.provider);
    if (!secret) {
        return std::unexpected(secret.error());
    }
    if (secret->empty() || secret->size() > 8192 || secret->find('\0') != std::string::npos ||
        secret->find_first_of("\r\n") != std::string::npos) {
        return std::unexpected("invalid Pi host credential");
    }
    auto nonce = nonce_for_run();
    if (!nonce) {
        return std::unexpected(nonce.error());
    }
    auto options = make_provider_endpoint_options(
        selection->model.provider == pi_provider::openai ? provider_surface::pi_openai
                                                         : provider_surface::pi_anthropic,
        std::move(*secret),
        *nonce
    );
    if (!options) {
        return std::unexpected(options.error());
    }
    std::shared_ptr<audit::sink> sink = context.audit;
    if (!sink) {
        auto bounded = make_pi_audit_sink();
        if (!bounded) {
            return std::unexpected(std::move(bounded.error()));
        }
        sink = std::move(*bounded);
    }
    options->on_event = [sink](const net::endpoint_event& event) -> result<void> {
        // No target, headers, payload, nonce or credential enters audit/reporter state.
        return record(
            sink,
            audit::action::egress,
            event.allowed ? mcp::tool_call_status::ok : mcp::tool_call_status::invalid_arguments
        );
    };
    std::optional<pi_private_state> state;
    auto started = context.start_endpoint ? context.start_endpoint(std::move(*options))
                                          : net::start_credentialed_endpoint(std::move(*options));
    if (!started) {
        return std::unexpected(started.error());
    }
    auto endpoint = std::move(*started);
    if (!endpoint || endpoint->port() == 0) {
        return std::unexpected("Pi endpoint did not supply a valid port");
    }
    auto config = make_pi_guest_config(*selection, endpoint->port(), *nonce, *catalog);
    if (!config) {
        return std::unexpected(config.error());
    }
    const auto provider = selection->model.provider == pi_provider::openai
                              ? net::endpoint_provider::openai
                              : net::endpoint_provider::anthropic;
    auto endpoint_nonce = endpoint->session_nonce(provider);
    auto endpoint_url = endpoint->base_url(provider);
    if (!endpoint_nonce || !endpoint_url || *endpoint_nonce != *nonce ||
        *endpoint_url !=
            ("http://127.0.0.1:" + std::to_string(endpoint->port()) +
             (selection->model.provider == pi_provider::openai ? "/openai" : "/anthropic"))) {
        return std::unexpected("Pi endpoint binding disagrees with private configuration");
    }
    const auto runs = paths.runtime / "pi/runs";
    if (auto parent = host::snapshot::ensure_protected_directory(paths.runtime, true); !parent) {
        return std::unexpected(parent.error());
    }
    if (auto parent = host::snapshot::ensure_protected_directory(runs, true); !parent) {
        return std::unexpected(parent.error());
    }
    auto created = pi_private_state::create(runs, *config, {&endpoint, &revoke_before_rollback});
    if (!created) {
        return std::unexpected(created.error());
    }
    state.emplace(std::move(*created));
    const auto fail_before_launch = [&](std::string original) -> result<int> {
        endpoint.reset();
        if (auto cleaned = state->cleanup(); !cleaned) {
            original += "; Pi private cleanup failed: " + cleaned.error();
        }
        return std::unexpected(std::move(original));
    };
    auto profile = profile_for(*workspace, approved, *state, *libraries, endpoint->port());
    if (!profile) {
        return fail_before_launch(profile.error());
    }
    if (approved.runtime.launch_arguments.size() != 1) {
        return fail_before_launch("Pi runtime must supply one approved script");
    }
    std::vector<std::string> argv{
        approved.runtime.launch_executable.string(), approved.runtime.launch_arguments.front()
    };
    if (config->arguments.size() < selection->arguments.size()) {
        return fail_before_launch("Pi argument construction lost its approved suffix");
    }
    const auto closed_count = config->arguments.size() - selection->arguments.size();
    argv.insert(
        argv.end(),
        config->arguments.begin(),
        config->arguments.begin() + static_cast<std::ptrdiff_t>(closed_count)
    );
    argv.push_back("--session-dir");
    argv.push_back(state->sessions().string());
    argv.insert(argv.end(), selection->arguments.begin(), selection->arguments.end());
    if (auto audited = record(sink, audit::action::agent_launch); !audited) {
        return fail_before_launch(std::move(audited.error()));
    }
    // Audit and boundary callbacks precede these checks; no planner/guest input
    // may turn a previously approved record into different launch authority.
    auto current = load_pi_runtime_with_exclusions(record_path, *source_authorities);
    if (!current || !*current || (**current).model != approved.model ||
        binding((**current).runtime) != binding(approved.runtime)) {
        return fail_before_launch("Pi runtime selection changed before launch");
    }
    auto current_catalog =
        load_pi_builtin_catalog(**current, selection->model.provider, *source_authorities);
    auto current_libraries = pi_library_environment_with_exclusions(**current, *source_authorities);
    if (!current_catalog || !current_libraries || *current_catalog != *catalog ||
        *current_libraries != *libraries) {
        return fail_before_launch("Pi catalog or runtime libraries changed before launch");
    }
    auto current_workspace = workspace_for(request, context, **current);
    if (!current_workspace || *current_workspace != *workspace) {
        return fail_before_launch("Pi workspace authority changed before launch");
    }
    if (auto workspace_bound = workspace_identity->recheck(*workspace); !workspace_bound) {
        return fail_before_launch(workspace_bound.error());
    }
    auto checked_profile = container::validate(*profile);
    if (!checked_profile) {
        return fail_before_launch(checked_profile.error());
    }
#    if defined(__APPLE__)
    if (auto prepared =
            container::macos_detail::prepare_launch_command(*checked_profile, argv, true);
        !prepared) {
        return fail_before_launch(prepared.error());
    }
#    endif
    if (stop.stop_requested()) {
        return fail_before_launch("Pi launch cancelled");
    }
    if (auto launching = state->mark_launching(); !launching) {
        endpoint.reset();
        return std::unexpected("Pi launch state uncertain; retained: " + launching.error());
    }
    auto exited = context.execute_owned
                      ? context.execute_owned(*checked_profile, argv, stop)
                      : container::exec_contained_owned(*checked_profile, argv, stop);
    endpoint.reset();
    if (!exited) {
        return std::unexpected(
            "Pi launch outcome uncertain; private state retained: " + exited.error()
        );
    }
    if (auto quiescent = state->mark_quiescent(); !quiescent) {
        return std::unexpected(
            "Pi quiescent marker failed; private state retained: " + quiescent.error()
        );
    }
    auto audited = record(sink, audit::action::agent_exit);
    auto cleaned = state->cleanup();
    if (!audited) {
        std::string original = std::move(audited.error());
        if (!cleaned) {
            original += "; Pi private cleanup failed: " + cleaned.error();
        }
        return std::unexpected(std::move(original));
    }
    if (!cleaned) {
        return std::unexpected("Pi private cleanup failed: " + cleaned.error());
    }
    return *exited;
#endif
}

} // namespace detail

auto launch_pi(const pi_launch_request& request, std::stop_token stop) -> result<int> {
#if !defined(__APPLE__)
    (void)request;
    (void)stop;
    return std::unexpected("glove pi requires the native macOS backend");
#else
    if (auto stdio = admit_operator_stdio(); !stdio) {
        return std::unexpected(stdio.error());
    }
    const auto environment = host::current_environment();
    auto directories = host::resolve_directories(environment);
    if (!directories) {
        return std::unexpected(directories.error());
    }
    detail::pi_launch_context context{
        .directories = std::move(*directories),
        .protected_auth_roots = {},
        .credential = {},
        .start_endpoint = {},
        .execute_owned = {},
        .audit = {}
    };
    if (environment.home && !environment.home->empty()) {
        const fs::path home{*environment.home};
        context.protected_auth_roots = {
            home / ".pi",
            home / ".ssh",
            home / ".aws",
            home / ".config",
            home / ".netrc",
            home / ".npmrc"
        };
    }
    if (auto protected_roots = add_machine_authorities(context); !protected_roots) {
        return std::unexpected(protected_roots.error());
    }
    return detail::launch_pi_with_context(request, context, stop);
#endif
}

} // namespace glove::run
