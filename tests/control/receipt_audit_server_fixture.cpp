#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_unix_server.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

auto receipt() -> glove::container::resource_enforcement_receipt {
    using namespace glove::container;
    return {
        .schema_version = 1,
        .profile_digest = std::string(64, 'c'),
        .backend = sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 60'000,
                .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                .pids = 128,
                .wall_time_ms = 120'000,
                .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
            },
        .mechanisms =
            {
                .cpu_time = enforcement_mechanism::cgroup_v2,
                .memory = enforcement_mechanism::cgroup_v2,
                .pids = enforcement_mechanism::cgroup_v2,
                .wall_time = enforcement_mechanism::watchdog,
                .disk = enforcement_mechanism::filesystem_quota,
                .terminal_output = enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 500,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = 1024,
            },
        .termination_cause = resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections =
            {
                library_projection_receipt{
                    .projection_id = "library-main",
                    .destination_alias = "codex-skills",
                    .target_path =
                        "/opt/sage/codex-skills/"
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json",
                    .content_digest =
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
            },
        .retained_changes = {},
    };
}

auto fail(std::string_view operation, std::string_view error) -> int {
    std::fprintf(
        stderr,
        "%.*s: %.*s\n",
        static_cast<int>(operation.size()),
        operation.data(),
        static_cast<int>(error.size()),
        error.data()
    );
    return 1;
}

auto plan_validator_for(const std::filesystem::path& source)
    -> glove::supervisor::result<glove::supervisor::session_plan_validator> {
    using namespace glove::supervisor;
    auto paths = path_alias_registry::build({
        path_alias_policy{
            .alias = "sage-protocol",
            .host_path = std::filesystem::canonical(source).string(),
            .target_path = "/workspace/sage-protocol",
            .max_ttl_secs = 600,
            .access = {
                path_access_policy{
                    .access = path_access::ephemeral_write,
                    .materialization = path_materialization::copy,
                    .create_policy = path_create_policy::empty_directory,
                    .cleanup_policy = path_cleanup_policy::remove,
                    .max_bytes = 1'000'000,
                },
            },
        },
    });
    if (!paths) {
        return std::unexpected(paths.error());
    }
    return session_plan_validator::build(
        session_plan_policy{
            .revision = 1,
            .max_plan_ttl_ms = 180'000,
            .runtime_templates =
                {
                    runtime_template_policy{
                        .runtime_template_id = "codex-headless-v1",
                        .runtime_id = "codex",
                        .adapter_command_digest = std::string(64, 'a'),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"sage-protocol"},
                        .allowed_projection_destinations = {"codex-skills"},
                        .launch = {},
                        .adoption = std::nullopt,
                    },
                },
            .library_projection_destinations =
                {
                    library_projection_destination_policy{
                        .alias = "codex-skills",
                        .target_path = "/opt/sage/codex-skills",
                    },
                },
            .resource_profiles =
                {
                    resource_limits{
                        .cpu_time_ms = 60'000,
                        .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                        .pids = 128,
                        .wall_time_ms = 120'000,
                        .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                        .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
                    },
                },
            .egress_policy_ids = {"deny-all"},
            .tool_policy_ids = {"no-upstream-tools"},
            .secret_handles = {"github-readonly"},
            .egress_policies = {},
            .secret_mounts = {},
        },
        std::move(*paths)
    );
}

auto run(int argc, char** argv) -> int {
    if (argc != 5) {
        return fail("usage", "fixture SOCKET SECRET KEY JOURNAL");
    }
    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = std::filesystem::path{argv[3]},
        .journal_path = std::filesystem::path{argv[4]},
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    if (!producer) {
        return fail("initialize receipt producer", producer.error());
    }
    if (auto reconciled = (*producer)->acknowledge_bootstrap((*producer)->anchor()); !reconciled) {
        return fail("reconcile receipt producer", reconciled.error());
    }
    auto reservation = (*producer)->reserve_terminal();
    if (!reservation) {
        return fail("reserve terminal receipt", reservation.error());
    }
    auto terminal = (*producer)->commit_terminal(
        std::move(*reservation), "session-1", controller_plan_digest, receipt()
    );
    if (!terminal) {
        return fail("commit terminal receipt", terminal.error());
    }
    producer->reset();

    const auto plan_source = std::filesystem::path{argv[4]}.parent_path() / "plan-source";
    std::error_code directory_error;
    if (!std::filesystem::create_directory(plan_source, directory_error) || directory_error) {
        return fail("create plan source", directory_error.message());
    }
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    auto validator = plan_validator_for(plan_source);
    if (!validator) {
        return fail("create plan validator", validator.error());
    }

    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    auto sessions = glove::control::session_registry::open_or_create(
        std::filesystem::path{argv[4]}.parent_path() / "sessions.journal", shared_validator
    );
    if (!sessions) {
        return fail("create session registry", sessions.error().message);
    }
    auto server = glove::control::receipt_audit_unix_server::create({
        .socket_path = std::filesystem::path{argv[1]},
        .bootstrap_secret_path = std::filesystem::path{argv[2]},
        .producer = producer_config,
        .plan_validator = std::move(shared_validator),
        .sessions = std::shared_ptr<glove::control::session_registry>{std::move(*sessions)},
        .runtime = {},
        .local_services = {},
        .path_exposures = {},
        .materialization_root = {},
        .io_timeout_ms = 5'000,
        .control_audit = {},
    });
    if (!server) {
        return fail("create receipt server", server.error());
    }
    for (int request = 0; request < 6; ++request) {
        if (auto served = (*server)->serve_one(); !served) {
            return fail("serve receipt request", served.error());
        }
    }
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    return run(argc, argv);
}
