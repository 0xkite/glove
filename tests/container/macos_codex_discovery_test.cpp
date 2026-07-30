// Live macOS lane: resolve each locally installed, SBPL-vetted native harness
// through Glove's policy-owned discovery path, then launch `--version`.
// This deliberately exercises no credentials, network, or resource claims.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-macos-native-harness-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

struct native_runtime {
    std::string_view id;
    std::string_view executable;
};

// The Linux native-harness image verifies the full adapter set. macOS keeps
// this lane limited to distributions whose complete runtime closure is already
// represented by a narrow SBPL policy; it must not turn a broad Homebrew or
// user-home grant into a compatibility shortcut.
constexpr std::array<native_runtime, 2> native_runtimes{{
    {"codex", "codex"},
    {"copilot", "copilot"},
}};

auto executable_on_service_path(std::string_view executable)
    -> std::optional<std::filesystem::path> {
    const char* path = std::getenv("PATH");
    if (path == nullptr) {
        return std::nullopt;
    }
    std::string_view remaining{path};
    while (true) {
        const auto colon = remaining.find(':');
        const auto entry = remaining.substr(0, colon);
        if (!entry.empty()) {
            const auto candidate = std::filesystem::path{entry} / executable;
            if (::access(candidate.c_str(), X_OK) == 0) {
                return candidate;
            }
        }
        if (colon == std::string_view::npos) {
            return std::nullopt;
        }
        remaining.remove_prefix(colon + 1);
    }
}

auto run_runtime(
    const native_runtime& runtime,
    const std::filesystem::path& executable,
    const std::filesystem::path& workspace,
    const std::filesystem::path& temp_root
) -> int {
    using namespace glove::supervisor;

    std::error_code error;
    // Model production discovery with a dedicated, service-owned runtime
    // directory, never an inherited PATH directory.
    const auto runtime_bin = temp_root / ("operator-runtime-bin-" + std::string{runtime.id});
    REQUIRE(std::filesystem::create_directory(runtime_bin, error));
    REQUIRE(!error);
    std::filesystem::create_symlink(executable, runtime_bin / runtime.executable, error);
    REQUIRE(!error);

    const runtime_launch_template launch{
        .runtime_discovery = std::string{runtime.id},
        .executable_path = "",
        .executable_search_paths = {runtime_bin.string()},
        .arguments = {"--version"},
        .environment = {"PATH=" + runtime_bin.string() + ":/usr/bin:/bin", "TERM=xterm-256color"},
        .read_only_paths = {},
    };
    const auto digest = runtime_launch_template_digest(launch);
    REQUIRE(digest.has_value());
    auto paths = path_alias_registry::build({path_alias_policy{
        .alias = "workspace",
        .host_path = std::filesystem::canonical(workspace).string(),
        .target_path = "/workspace",
        .max_ttl_secs = 60,
        .access = {path_access_policy{
            .access = path_access::ephemeral_write,
            .materialization = path_materialization::copy,
            .create_policy = path_create_policy::empty_directory,
            .cleanup_policy = path_cleanup_policy::remove,
            .max_bytes = 1'048'576,
        }},
    }});
    REQUIRE(paths.has_value());
    auto validator = session_plan_validator::build(
        session_plan_policy{
            .revision = 1,
            .max_plan_ttl_ms = 60'000,
            .runtime_templates = {runtime_template_policy{
                .runtime_template_id = std::string{runtime.id} + "-local",
                .runtime_id = std::string{runtime.id},
                .adapter_command_digest = *digest,
                .backend = sandbox_backend::apple_container,
                .allowed_path_aliases = {"workspace"},
                .allowed_projection_destinations = {"libraries"},
                .launch = launch,
            }},
            .library_projection_destinations = {library_projection_destination_policy{
                .alias = "libraries",
                .target_path = "/opt/sage/library-bundles",
            }},
            .resource_profiles = {resource_limits{
                .cpu_time_ms = 1'000,
                .memory_bytes = 67'108'864,
                .pids = 16,
                .wall_time_ms = 2'000,
                .disk_bytes = 1'048'576,
                .terminal_output_bytes = 1'048'576,
            }},
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles = {},
            .egress_policies = {},
            .secret_mounts = {},
        },
        std::move(*paths)
    );
    REQUIRE(validator.has_value());
    const std::string plan =
        R"({"schema_version":1,"runtime_id":")" + std::string{runtime.id} +
        R"(","runtime_template_id":")" + std::string{runtime.id} +
        R"(-local","adapter_command_digest":")" + *digest +
        R"(","sandbox_backend":"apple_container","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","destination_alias":"libraries"}],"secret_handles":[],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":1048576,"terminal_output_bytes":1048576},"policy_revision":1,"expires_at_ms":61000})";
    auto resolved = validator->resolve_runtime_launch_json(plan, 1'000);
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->backend == sandbox_backend::apple_container);
    REQUIRE(std::filesystem::path{resolved->argv.front()}.is_absolute());
    // Harness distributions may resolve to a versioned Mach-O or an entrypoint
    // script. Assert policy resolution, not packaging-specific basenames.
    REQUIRE(resolved->argv.front() != runtime.executable);
    REQUIRE(::access(resolved->argv.front().c_str(), X_OK) == 0);

    glove::container::profile profile;
    profile.filesystem.push_back({.path = workspace.string(), .writable = true});
    profile.home_dir = workspace.string();
    profile.work_dir = workspace.string();
    profile.environment = resolved->environment;
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(spawner != nullptr);
    REQUIRE(!spawner->resource_capabilities().complete());
    auto handle = spawner->spawn(profile, resolved->argv);
    REQUIRE(handle.has_value());
    auto line = (*handle)->transport().recv();
    const auto exit_code = (*handle)->wait();
    if (!line) {
        std::fprintf(
            stderr,
            "native harness %.*s produced no stdout (exit=%d)\n",
            static_cast<int>(runtime.id.size()),
            runtime.id.data(),
            exit_code ? *exit_code : -1
        );
        return 1;
    }
    REQUIRE(exit_code.has_value());
    REQUIRE(*exit_code == 0);
    REQUIRE(!line->empty());
    std::fprintf(
        stderr,
        "Glove SBPL native harness discovery probe (%.*s): %s\n",
        static_cast<int>(runtime.id.size()),
        runtime.id.data(),
        line->c_str()
    );
    return 0;
}

auto run() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto workspace = temp.root() / "workspace";
    std::error_code error;
    REQUIRE(std::filesystem::create_directories(workspace, error));
    REQUIRE(!error);

    std::size_t installed = 0;
    std::size_t failed = 0;
    for (const auto& runtime : native_runtimes) {
        const auto executable = executable_on_service_path(runtime.executable);
        if (!executable) {
            std::fprintf(
                stderr,
                "SKIP: %.*s is not installed on this service PATH\n",
                static_cast<int>(runtime.id.size()),
                runtime.id.data()
            );
            continue;
        }
        ++installed;
        if (run_runtime(runtime, *executable, workspace, temp.root()) != 0) {
            ++failed;
        }
    }
    if (installed == 0) {
        std::fprintf(
            stderr, "SKIP: no supported native harness is installed on this service PATH\n"
        );
        return 77;
    }
    return failed == 0 ? 0 : 1;
}

} // namespace

auto main() -> int {
    return run();
}
