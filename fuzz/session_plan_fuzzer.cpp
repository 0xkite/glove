#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr std::size_t maximum_plan_bytes = 1024U * 1024U;

auto constrained_validator() -> const glove::supervisor::session_plan_validator& {
    using namespace glove::supervisor;

    static const session_plan_validator instance = [] {
        auto paths = path_alias_registry::build({
            path_alias_policy{
                .alias = "workspace",
                .host_path = "/private/tmp",
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
            },
        });
        if (!paths) {
            std::abort();
        }
        auto built = session_plan_validator::build(
            session_plan_policy{
                .revision = 7,
                .max_plan_ttl_ms = 120'000,
                .runtime_templates =
                    {
                        runtime_template_policy{
                            .runtime_template_id = "codex-safe",
                            .runtime_id = "codex",
                            .adapter_command_digest = std::string(64U, 'a'),
                            .backend = sandbox_backend::linux_production,
                            .allowed_path_aliases = {"workspace"},
                            .allowed_projection_destinations = {"libraries"},
                            .launch = std::nullopt,
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
            std::move(*paths)
        );
        if (!built) {
            std::abort();
        }
        return std::move(*built);
    }();
    return instance;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_plan_bytes) {
        return 0;
    }

    // The public validator must safely consume arbitrary byte spans and must
    // never turn a malformed plan into launch or path authority.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view plan_json{reinterpret_cast<const char*>(data), size};
    const auto& validator = constrained_validator();
    static_cast<void>(validator.validate_json(plan_json, 1'000));
    static_cast<void>(validator.canonicalize_json(plan_json, 1'000));
    static_cast<void>(validator.resolve_library_projections_json(plan_json, 1'000));
    return 0;
}
