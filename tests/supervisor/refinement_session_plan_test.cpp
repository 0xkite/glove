#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto plan(std::string_view runtime_template_id) -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":")" +
           std::string{runtime_template_id} +
           R"(","adapter_command_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[],"library_projections":[],"secret_handles":[],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
}

auto run() -> int {
    using namespace glove::supervisor;

    auto paths = path_alias_registry::build({
        path_alias_policy{
            .alias = "workspace",
            .host_path = std::filesystem::canonical(std::filesystem::current_path()).string(),
            .target_path = "/workspace",
            .max_ttl_secs = 120,
            .access = {
                path_access_policy{
                    .access = path_access::read,
                    .materialization = path_materialization::bind,
                    .create_policy = path_create_policy::never,
                    .cleanup_policy = path_cleanup_policy::retain,
                    .max_bytes = 0,
                },
            },
        },
    });
    REQUIRE(paths.has_value());
    auto validator = session_plan_validator::build(
        session_plan_policy{
            .revision = 7,
            .max_plan_ttl_ms = 120'000,
            .runtime_templates =
                {
                    runtime_template_policy{
                        .runtime_template_id = "codex-safe",
                        .runtime_id = "codex",
                        .adapter_command_digest = std::string(64, 'a'),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {},
                        .launch = std::nullopt,
                    },
                    runtime_template_policy{
                        .runtime_template_id = "refinement-eval-v1",
                        .runtime_id = "codex",
                        .adapter_command_digest = std::string(64, 'a'),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {},
                        .launch = std::nullopt,
                    },
                },
            .library_projection_destinations = {},
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
            .secret_handles = {},
            .egress_policies = {},
            .secret_mounts = {},
        },
        std::move(*paths)
    );
    REQUIRE(validator.has_value());
    REQUIRE(validator->validate_json(plan("codex-safe"), 1'000).has_value());
    const auto refinement = validator->validate_json(plan("refinement-eval-v1"), 1'000);
    REQUIRE(!refinement.has_value());
    REQUIRE(
        refinement.error() == "refinement-eval-v1 requires unavailable dedicated result evidence"
    );
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
