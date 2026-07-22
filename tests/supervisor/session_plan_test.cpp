#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/path_exposure.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
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
        std::string pattern = "/tmp/glove-session-plan-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto replace_once(std::string input, std::string_view before, std::string_view after)
    -> std::string {
    const auto offset = input.find(before);
    if (offset != std::string::npos) {
        input.replace(offset, before.size(), after);
    }
    return input;
}

auto launch_template() -> glove::supervisor::runtime_launch_template {
    return {
        .executable_path = "/usr/bin/true",
        .arguments = {"--version"},
        .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
    };
}

auto launch_digest() -> std::string {
    auto digest = glove::supervisor::runtime_launch_template_digest(launch_template());
    return digest.value_or("launch-template-digest-failed");
}

auto valid_plan() -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
           launch_digest() +
           R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
}

auto policy_json(const std::filesystem::path& source) -> std::string {
    return R"({"schema_version":1,"revision":7,"max_plan_ttl_ms":120000,"runtime_templates":[{"runtime_template_id":"codex-safe","runtime_id":"codex","adapter_command_digest":")" +
           launch_digest() +
           R"(","sandbox_backend":"linux_production","allowed_path_aliases":["workspace"],"allowed_projection_destinations":["libraries"],"launch":{"executable_path":"/usr/bin/true","arguments":["--version"],"environment":["PATH=/usr/bin:/bin","TERM=xterm-256color"]}}],"path_aliases":[{"alias":"workspace","host_path":")" +
           std::filesystem::canonical(source).string() +
           R"(","target_path":"/workspace","max_ttl_secs":120,"access":[{"access":"ephemeral_write","materialization":"copy","create_policy":"empty_directory","cleanup_policy":"remove","max_bytes":2097152}]}],"library_projection_destinations":[{"alias":"libraries","target_path":"/opt/sage/library-bundles"}],"resource_profiles":[{"profile_id":"small","cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576}],"egress_policy_ids":["no-network"],"tool_policy_ids":["sage-readonly"],"secret_handles":["codex-token"]})";
}

auto validator_for(
    const std::filesystem::path& source,
    bool with_launch = true,
    std::shared_ptr<const glove::supervisor::path_exposure_registry> exposures = {}
) -> glove::supervisor::result<glove::supervisor::session_plan_validator> {
    using namespace glove::supervisor;
    path_alias_policy path{
        .alias = "workspace",
        .host_path = std::filesystem::canonical(source).string(),
        .target_path = "/workspace",
        .max_ttl_secs = 120,
        .access = {
            path_access_policy{
                .access = path_access::ephemeral_write,
                .materialization = path_materialization::copy,
                .create_policy = path_create_policy::empty_directory,
                .cleanup_policy = path_cleanup_policy::remove,
                .max_bytes = 2'097'152,
            },
        },
    };
    auto paths = path_alias_registry::build({std::move(path)});
    if (!paths) {
        return std::unexpected(paths.error());
    }
    return session_plan_validator::build(
        session_plan_policy{
            .revision = 7,
            .max_plan_ttl_ms = 120'000,
            .runtime_templates =
                {
                    runtime_template_policy{
                        .runtime_template_id = "codex-safe",
                        .runtime_id = "codex",
                        .adapter_command_digest = launch_digest(),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = with_launch
                                      ? std::optional<runtime_launch_template>{launch_template()}
                                      : std::nullopt,
                    },
                },
            .library_projection_destinations =
                {
                    library_projection_destination_policy{
                        .alias = "libraries",
                        .target_path = "/opt/sage/library-bundles",
                    },
                },
            .resource_profiles =
                {
                    resource_limits{
                        .cpu_time_ms = 1'000,
                        .memory_bytes = 67'108'864,
                        .pids = 16,
                        .wall_time_ms = 2'000,
                        .disk_bytes = 2'097'152,
                        .terminal_output_bytes = 1'048'576,
                    },
                },
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles = {"codex-token"},
        },
        std::move(*paths),
        std::move(exposures)
    );
}

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    std::ofstream{source / "tracked.txt"} << "immutable source\n";

    auto validator = validator_for(std::filesystem::canonical(source));
    if (!validator) {
        std::fprintf(stderr, "validator build failed: %s\n", validator.error().c_str());
    }
    REQUIRE(validator.has_value());

    // Fixed-size storage exercises the public parser boundary without a
    // trailing std::string sentinel. Malformed plans must fail closed.
    constexpr std::string_view malformed_plan =
        "{\"schema_version\":1,\"runtime_id\":\"codex\",\"runtime_template_id\":\"codex-safe\"";
    std::array<char, malformed_plan.size()> unterminated{};
    std::ranges::copy(malformed_plan, unterminated.begin());
    REQUIRE(!validator
                 ->validate_json(std::string_view{unterminated.data(), unterminated.size()}, 1'000)
                 .has_value());

    REQUIRE(launch_digest().size() == 64U);
    REQUIRE(launch_digest() == "05a49649e7973f6f8d6b119c9d525472517e6021fb38f8b191e0b40c8c4741d0");
    auto changed_launch = launch_template();
    changed_launch.arguments.push_back("changed");
    auto changed_launch_digest = glove::supervisor::runtime_launch_template_digest(changed_launch);
    REQUIRE(changed_launch_digest.has_value());
    REQUIRE(*changed_launch_digest != launch_digest());
    auto relative_launch = launch_template();
    relative_launch.executable_path = "usr/bin/true";
    REQUIRE(!glove::supervisor::runtime_launch_template_digest(relative_launch).has_value());
    auto unsorted_environment = launch_template();
    std::ranges::reverse(unsorted_environment.environment);
    REQUIRE(!glove::supervisor::runtime_launch_template_digest(unsorted_environment).has_value());
    auto duplicate_environment = launch_template();
    duplicate_environment.environment = {"PATH=first", "PATH=second"};
    REQUIRE(!glove::supervisor::runtime_launch_template_digest(duplicate_environment).has_value());

    auto accepted = validator->validate_json(valid_plan(), 1'000);
    REQUIRE(accepted.has_value());
    REQUIRE(accepted->schema_version == 1);
    REQUIRE(accepted->policy_revision == 7);
    auto launch = validator->resolve_runtime_launch_json(valid_plan(), 1'000);
    REQUIRE(launch.has_value());
    REQUIRE(launch->runtime_id == "codex");
    REQUIRE(launch->runtime_template_id == "codex-safe");
    REQUIRE(launch->adapter_command_digest == launch_digest());
    REQUIRE(launch->argv == std::vector<std::string>({"/usr/bin/true", "--version"}));
    REQUIRE(launch->environment == launch_template().environment);
    REQUIRE(launch->limits.cpu_time_ms == 1'000);
    auto libraries = validator->resolve_library_projections_json(valid_plan(), 1'000);
    REQUIRE(libraries.has_value());
    REQUIRE(libraries->size() == 1U);
    REQUIRE(libraries->front().projection_id == "sage-core");
    REQUIRE(
        libraries->front().content_digest ==
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    REQUIRE(libraries->front().destination_alias == "libraries");
    auto library_targets = validator->resolve_library_projection_targets_json(valid_plan(), 1'000);
    REQUIRE(library_targets.has_value());
    REQUIRE(library_targets->size() == 1U);
    REQUIRE(library_targets->front().projection == libraries->front());
    REQUIRE(library_targets->front().target_path == "/opt/sage/library-bundles");

    auto exposure_registry = path_exposure_registry::build({
        path_exposure_root_policy{
            .root_id = "projects",
            .host_root = std::filesystem::canonical(temp.root()).string(),
            .allowed_modes =
                {
                    path_exposure_mode{
                        .access = path_access::ephemeral_write,
                        .materialization = path_materialization::copy,
                        .max_bytes = 2'097'152,
                        .cleanup_policy = path_cleanup_policy::remove,
                    },
                },
            .max_ttl_secs = 120,
            .allowed_runtime_template_ids = {"codex-safe"},
        },
    });
    REQUIRE(exposure_registry.has_value());
    auto shared_exposures = std::make_shared<path_exposure_registry>(std::move(*exposure_registry));
    auto exposure = shared_exposures->create(
        path_exposure_create_request{
            .request_id = "create-worktree",
            .exposure_id = "worktree",
            .root_id = "projects",
            .host_path = std::filesystem::canonical(source).string(),
            .display_label = "Worktree",
            .allowed_modes =
                {
                    path_exposure_mode{
                        .access = path_access::ephemeral_write,
                        .materialization = path_materialization::copy,
                        .max_bytes = 2'097'152,
                        .cleanup_policy = path_cleanup_policy::remove,
                    },
                },
            .ttl_secs = 120,
            .allowed_runtime_template_ids = {"codex-safe"},
        },
        1'000
    );
    REQUIRE(exposure.has_value());
    auto v2_validator = validator_for(source, true, shared_exposures);
    REQUIRE(v2_validator.has_value());
    const auto v2_plan =
        R"({"schema_version":2,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
        launch_digest() +
        R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"exposure_id":"worktree","generation":1,"scope_digest":")" +
        exposure->scope_digest +
        R"(","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
    auto accepted_v2 = v2_validator->validate_json(v2_plan, 1'000);
    REQUIRE(accepted_v2.has_value());
    REQUIRE(accepted_v2->schema_version == 2);
    auto canonical_v2 = v2_validator->canonicalize_json(v2_plan, 1'000);
    REQUIRE(canonical_v2.has_value());
    REQUIRE(canonical_v2->canonical_json == v2_plan);
    auto resolved_v2 = v2_validator->resolve_path_grants_json(v2_plan, 1'000);
    REQUIRE(resolved_v2.has_value());
    REQUIRE(resolved_v2->size() == 1U);
    REQUIRE(resolved_v2->front().alias() == "worktree");
    REQUIRE(resolved_v2->front().target_path() == "/workspace/exposures/worktree");
    REQUIRE(shared_exposures->revoke("revoke-worktree", "worktree", exposure->generation, 2'000)
                .has_value());
    REQUIRE(!v2_validator->validate_json(v2_plan, 2'000).has_value());
    REQUIRE(resolved_v2->front().verify_identity().has_value());

    const auto changed_library = replace_once(valid_plan(), "sage-core", "sage-other");
    auto changed_libraries = validator->resolve_library_projections_json(changed_library, 1'000);
    REQUIRE(changed_libraries.has_value());
    REQUIRE(changed_libraries->front().projection_id == "sage-other");

    auto invalid_destination_policy = session_plan_policy{
        .revision = 7,
        .max_plan_ttl_ms = 120'000,
        .runtime_templates =
            {
                runtime_template_policy{
                    .runtime_template_id = "codex-safe",
                    .runtime_id = "codex",
                    .adapter_command_digest = launch_digest(),
                    .backend = sandbox_backend::linux_production,
                    .allowed_path_aliases = {"workspace"},
                    .allowed_projection_destinations = {"libraries"},
                    .launch = launch_template(),
                },
            },
        .library_projection_destinations =
            {
                library_projection_destination_policy{
                    .alias = "libraries",
                    .target_path = "relative/library-bundles",
                },
            },
        .resource_profiles =
            {
                resource_limits{
                    .cpu_time_ms = 1'000,
                    .memory_bytes = 67'108'864,
                    .pids = 16,
                    .wall_time_ms = 2'000,
                    .disk_bytes = 2'097'152,
                    .terminal_output_bytes = 1'048'576,
                },
            },
        .egress_policy_ids = {"no-network"},
        .tool_policy_ids = {"sage-readonly"},
        .secret_handles = {"codex-token"},
    };
    path_alias_policy invalid_destination_path{
        .alias = "workspace",
        .host_path = std::filesystem::canonical(source).string(),
        .target_path = "/workspace",
        .max_ttl_secs = 120,
        .access = {
            path_access_policy{
                .access = path_access::ephemeral_write,
                .materialization = path_materialization::copy,
                .create_policy = path_create_policy::empty_directory,
                .cleanup_policy = path_cleanup_policy::remove,
                .max_bytes = 2'097'152,
            },
        },
    };
    auto invalid_destination_paths =
        path_alias_registry::build({std::move(invalid_destination_path)});
    REQUIRE(invalid_destination_paths.has_value());
    REQUIRE(!session_plan_validator::build(
                 std::move(invalid_destination_policy), std::move(*invalid_destination_paths)
    )
                 .has_value());

    auto plan_only_validator = validator_for(std::filesystem::canonical(source), false);
    REQUIRE(plan_only_validator.has_value());
    REQUIRE(plan_only_validator->validate_json(valid_plan(), 1'000).has_value());
    REQUIRE(!plan_only_validator->resolve_runtime_launch_json(valid_plan(), 1'000).has_value());

    const auto policy_path = temp.root() / "session-policy.json";
    {
        std::ofstream output{policy_path};
        output << policy_json(source);
    }
    REQUIRE(::chmod(policy_path.c_str(), 0600) == 0);
    auto loaded = glove::supervisor::session_plan_validator::load(policy_path);
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->validate_json(valid_plan(), 1'000).has_value());
    REQUIRE(loaded->resolve_runtime_launch_json(valid_plan(), 1'000).has_value());

    const auto unbound_destination_policy_path = temp.root() / "unbound-destination-policy.json";
    {
        std::ofstream output{unbound_destination_policy_path};
        output << replace_once(
            policy_json(source),
            R"("library_projection_destinations":[{"alias":"libraries","target_path":"/opt/sage/library-bundles"}])",
            R"("library_projection_destinations":[])"
        );
    }
    REQUIRE(::chmod(unbound_destination_policy_path.c_str(), 0600) == 0);
    REQUIRE(!glove::supervisor::session_plan_validator::load(unbound_destination_policy_path)
                 .has_value());

    const auto unnamed_resource_policy_path = temp.root() / "unnamed-resource-policy.json";
    {
        std::ofstream output{unnamed_resource_policy_path};
        output << replace_once(
            policy_json(source), "\"profile_id\":\"small\"", "\"profile_id\":\"\""
        );
    }
    REQUIRE(::chmod(unnamed_resource_policy_path.c_str(), 0600) == 0);
    REQUIRE(
        !glove::supervisor::session_plan_validator::load(unnamed_resource_policy_path).has_value()
    );

    const auto mismatched_policy_path = temp.root() / "mismatched-session-policy.json";
    {
        std::ofstream output{mismatched_policy_path};
        output << replace_once(policy_json(source), "/usr/bin/true", "/usr/bin/false");
    }
    REQUIRE(::chmod(mismatched_policy_path.c_str(), 0600) == 0);
    REQUIRE(!glove::supervisor::session_plan_validator::load(mismatched_policy_path).has_value());
    REQUIRE(::chmod(policy_path.c_str(), 0644) == 0);
    REQUIRE(!glove::supervisor::session_plan_validator::load(policy_path).has_value());
    REQUIRE(::chmod(policy_path.c_str(), 0600) == 0);

    const auto unknown_runtime = replace_once(valid_plan(), "codex-safe", "shell");
    REQUIRE(!validator->validate_json(unknown_runtime, 1'000).has_value());

    const auto stale_policy =
        replace_once(valid_plan(), "\"policy_revision\":7", "\"policy_revision\":6");
    REQUIRE(!validator->validate_json(stale_policy, 1'000).has_value());

    const auto raw_authority = replace_once(
        valid_plan(), "\"expires_at_ms\":61000", "\"expires_at_ms\":61000,\"argv\":[\"/bin/sh\"]"
    );
    REQUIRE(!validator->validate_json(raw_authority, 1'000).has_value());

    const auto excessive_quota =
        replace_once(valid_plan(), "\"max_bytes\":1048576", "\"max_bytes\":4194304");
    REQUIRE(!validator->validate_json(excessive_quota, 1'000).has_value());

    const auto wrong_materialization =
        replace_once(valid_plan(), "\"materialization\":\"copy\"", "\"materialization\":\"bind\"");
    REQUIRE(!validator->validate_json(wrong_materialization, 1'000).has_value());

    const auto receipt_named_cleanup = replace_once(
        valid_plan(), "\"cleanup_policy\":\"remove\"", "\"cleanup_policy\":\"retain_receipt\""
    );
    REQUIRE(!validator->validate_json(receipt_named_cleanup, 1'000).has_value());

    const auto expired =
        replace_once(valid_plan(), "\"expires_at_ms\":61000", "\"expires_at_ms\":1000");
    REQUIRE(!validator->validate_json(expired, 1'000).has_value());

    const auto excessive_ttl =
        replace_once(valid_plan(), "\"expires_at_ms\":61000", "\"expires_at_ms\":200000");
    REQUIRE(!validator->validate_json(excessive_ttl, 1'000).has_value());

    const auto grant_outlives_plan =
        replace_once(valid_plan(), "\"ttl_secs\":60", "\"ttl_secs\":120");
    REQUIRE(!validator->validate_json(grant_outlives_plan, 1'000).has_value());

    const auto unsorted_secrets = replace_once(
        valid_plan(),
        "\"secret_handles\":[\"codex-token\"]",
        "\"secret_handles\":[\"z-token\",\"codex-token\"]"
    );
    REQUIRE(!validator->validate_json(unsorted_secrets, 1'000).has_value());

    return 0;
}

} // namespace

int main() {
    return run();
}
