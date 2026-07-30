#include "glove/container/digest.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "session_reconciliation.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
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

constexpr std::string_view controller_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-session-registry-test-XXXXXX";
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

auto library_bundle_digest() -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(library_bundle.data());
    return glove::container::sha256_hex(std::span{bytes, library_bundle.size()}).value_or("");
}

auto launch_template() -> glove::supervisor::runtime_launch_template {
    return {
        .runtime_discovery = {},
        .executable_path = "/usr/bin/true",
        .executable_search_paths = {},
        .arguments = {"--version"},
        .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
        .read_only_paths = {},
    };
}

auto runtime_digest() -> std::string {
    return glove::supervisor::runtime_launch_template_digest(launch_template()).value_or("");
}

auto valid_plan() -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
           runtime_digest() +
           R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":")" +
           library_bundle_digest() +
           R"(","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
}

auto valid_plan_at(std::uint64_t now_ms) -> std::string {
    auto plan = valid_plan();
    constexpr std::string_view original = R"("expires_at_ms":61000)";
    const auto replacement = std::string{"\"expires_at_ms\":"} + std::to_string(now_ms + 120'000);
    const auto offset = plan.find(original);
    if (offset != std::string::npos) {
        plan.replace(offset, original.size(), replacement);
    }
    return plan;
}

auto managed_plan() -> std::string {
    auto plan = valid_plan();
    const auto offset = plan.find(R"("sandbox_backend":"linux_production")");
    if (offset != std::string::npos) {
        plan.replace(
            offset,
            std::string_view{R"("sandbox_backend":"linux_production")"}.size(),
            R"("sandbox_backend":"apple_container")"
        );
    }
    return plan;
}

auto direct_write_plan() -> std::string {
    auto plan = valid_plan();
    const std::string ephemeral =
        R"("access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove")";
    const std::string direct =
        R"("access":"direct_write","materialization":"bind","max_bytes":0,"ttl_secs":60,"cleanup_policy":"retain")";
    const auto offset = plan.find(ephemeral);
    if (offset != std::string::npos) {
        plan.replace(offset, ephemeral.size(), direct);
    }
    return plan;
}

auto terminal_receipt(
    std::string profile_digest, std::uint64_t started_at_ms, std::uint64_t finished_at_ms
) -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::move(profile_digest),
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 1'000,
                .memory_bytes = 67'108'864,
                .pids = 16,
                .wall_time_ms = 2'000,
                .disk_bytes = 2'097'152,
                .terminal_output_bytes = 1'048'576,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 10,
                .peak_memory_bytes = 1'048'576,
                .peak_pids = 2,
                .wall_time_ms = finished_at_ms - started_at_ms,
                .disk_bytes = 4'096,
                .terminal_output_bytes = 128,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = started_at_ms,
        .finished_at_ms = finished_at_ms,
        .library_projections = {},
        .retained_changes = {},
    };
}

auto process_identity(std::uint32_t pid) -> glove::control::linux_process_identity {
    return {
        .schema_version = 1,
        .pid = pid,
        .boot_id = "12345678-1234-1234-1234-123456789abc",
        .start_time_ticks = 10'000U + pid,
        .cgroup_device = 42,
        .cgroup_inode = 20'000U + pid,
        .cgroup_path_digest = std::string(64, 'd'),
    };
}

auto cgroup_identity(std::uint32_t pid) -> glove::control::linux_cgroup_recovery_identity {
    return {
        .schema_version = 1,
        .device = 42,
        .inode = 20'000U + pid,
    };
}

auto filesystem_identity() -> glove::control::linux_filesystem_recovery_identity {
    return {
        .schema_version = 1,
        .disk_limit_bytes = 2'097'152,
        .partitions = {{.alias = "workspace", .quota_bytes = 1'048'576}},
    };
}

auto validator_for(
    const std::filesystem::path& source,
    glove::supervisor::sandbox_backend backend =
        glove::supervisor::sandbox_backend::linux_production
)
    -> glove::supervisor::result<glove::supervisor::session_plan_validator> {
    using namespace glove::supervisor;
    auto paths = path_alias_registry::build({
        path_alias_policy{
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
                path_access_policy{
                    .access = path_access::direct_write,
                    .materialization = path_materialization::bind,
                    .create_policy = path_create_policy::never,
                    .cleanup_policy = path_cleanup_policy::retain,
                    .max_bytes = 0,
                },
            },
        },
    });
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
                        .adapter_command_digest = runtime_digest(),
                        .backend = backend,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = launch_template(),
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
            .egress_policies = {},
            .secret_mounts =
                {
                    secret_mount_policy{
                        .handle = "codex-token",
                        .runtime_id = "codex",
                        .source_path = (source / "codex-auth.json").string(),
                        .target_path = "/home/agent/.codex/auth.json",
                    },
                },
        },
        std::move(*paths)
    );
}

auto run() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    std::ofstream{source / "tracked.txt"} << "host-owned\n";

    auto validator = validator_for(source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto bundle_root = temp.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(bundle_root));
    REQUIRE(::chmod(bundle_root.c_str(), 0700) == 0);
    const auto bundle_path = bundle_root / (library_bundle_digest() + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary};
        output.write(library_bundle.data(), static_cast<std::streamsize>(library_bundle.size()));
    }
    REQUIRE(::chmod(bundle_path.c_str(), 0600) == 0);
    auto opened_bundle_store = glove::supervisor::library_bundle_store::open(bundle_root);
    REQUIRE(opened_bundle_store.has_value());
    auto shared_bundle_store = std::make_shared<const glove::supervisor::library_bundle_store>(
        std::move(*opened_bundle_store)
    );
    const auto store_path = temp.root() / "sessions.journal";
    auto registry = glove::control::session_registry::open_or_create(
        store_path, shared_validator, shared_bundle_store
    );
    REQUIRE(registry.has_value());
    REQUIRE((*registry)->record_count() == 0);

    auto locked = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(!locked.has_value());

    auto created = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 1'000
    );
    REQUIRE(created.has_value());
    REQUIRE(created->schema_version == 1);
    REQUIRE(created->session_id == "session-1");
    REQUIRE(created->controller_plan_digest == controller_digest);
    REQUIRE(created->plan_content_digest.size() == 64);
    REQUIRE(created->state == glove::control::session_state::created);
    REQUIRE(created->policy_revision == 7);
    REQUIRE(created->expires_at_ms == 61'000);
    REQUIRE(created->created_at_ms == 1'000);
    REQUIRE((*registry)->record_count() == 1);

    auto replay = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 1'001
    );
    REQUIRE(replay.has_value());
    REQUIRE(*replay == *created);
    REQUIRE((*registry)->record_count() == 1);

    auto expired_replay = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 62'000
    );
    REQUIRE(expired_replay.has_value());
    REQUIRE(*expired_replay == *created);
    REQUIRE((*registry)->record_count() == 1);

    auto changed_request = (*registry)->create(
        "session-2", controller_digest, valid_plan(), "create-session-1", 1'001
    );
    REQUIRE(!changed_request.has_value());
    auto changed_session = (*registry)->create(
        "session-1", std::string(64, 'd'), valid_plan(), "create-session-2", 1'001
    );
    REQUIRE(!changed_session.has_value());
    auto invalid_plan = (*registry)->create(
        "session-2", controller_digest, "{\"schema_version\":1}", "create-session-2", 1'001
    );
    REQUIRE(!invalid_plan.has_value());
    REQUIRE((*registry)->record_count() == 1);

    auto status = (*registry)->status("session-1");
    REQUIRE(status.has_value());
    REQUIRE(*status == *created);
    REQUIRE(!(*registry)->status("missing").has_value());
    auto canonical = (*registry)->canonical_plan("session-1");
    REQUIRE(canonical.has_value());
    REQUIRE(*canonical == valid_plan());

    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-1",
        .session_id = "session-1",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = 1'001,
        .expires_at_ms = 2'001,
    };
    auto wrong_authorization = authorization;
    wrong_authorization.plan_content_digest = std::string(64, 'd');
    REQUIRE(!(*registry)
                 ->reserve_start(wrong_authorization, "reserve-session-wrong-digest", 1'002)
                 .has_value());
    auto expired_authorization = authorization;
    expired_authorization.expires_at_ms = 1'002;
    REQUIRE(!(*registry)
                 ->reserve_start(expired_authorization, "reserve-session-expired", 1'002)
                 .has_value());
    REQUIRE((*registry)->record_count() == 1);

    auto reserved = (*registry)->reserve_start(authorization, "reserve-session-1", 1'002);
    if (!reserved) {
        std::fprintf(stderr, "reserve_start failed: %s\n", reserved.error().message.c_str());
    }
    REQUIRE(reserved.has_value());
    REQUIRE(reserved->session.state == glove::control::session_state::preparing);
    REQUIRE(reserved->authorization_id == authorization.authorization_id);
    REQUIRE(reserved->authorization_expires_at_ms == authorization.expires_at_ms);
    REQUIRE(reserved->launch.runtime_template_id == "codex-safe");
    REQUIRE(
        reserved->launch.argv ==
        std::vector<std::string>({
            "/usr/bin/true",
            "--version",
            "--dangerously-bypass-approvals-and-sandbox",
        })
    );
    REQUIRE((*registry)->record_count() == 2);
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-wrong", 1'002).has_value()
    );
    auto start_inputs = (*registry)->resolve_start_inputs("session-1", "approval-session-1", 1'002);
    REQUIRE(start_inputs.has_value());
    REQUIRE(start_inputs->session == reserved->session);
    REQUIRE(start_inputs->launch == reserved->launch);
    REQUIRE(start_inputs->path_grants.size() == 1);
    REQUIRE(start_inputs->path_grants.front().alias() == "workspace");
    REQUIRE(start_inputs->path_grants.front().descriptor_fd() >= 0);
    REQUIRE(start_inputs->path_grants.front().verify_identity().has_value());
    REQUIRE(start_inputs->library_projections.size() == 1U);
    REQUIRE(start_inputs->library_projections.front().projection_id == "sage-core");
    REQUIRE(
        start_inputs->library_projections.front().bundle.content_digest() == library_bundle_digest()
    );
    REQUIRE(start_inputs->library_projections.front().destination_alias == "libraries");
    REQUIRE(
        start_inputs->library_projections.front().target_path ==
        "/opt/sage/library-bundles/" + library_bundle_digest() + ".json"
    );
    REQUIRE(start_inputs->library_projections.front().bundle.verify_identity().has_value());
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-1", 2'001).has_value()
    );
    auto reserved_replay = (*registry)->reserve_start(authorization, "reserve-session-1", 3'000);
    REQUIRE(reserved_replay.has_value());
    REQUIRE(reserved_replay->session == reserved->session);
    REQUIRE(reserved_replay->launch == reserved->launch);
    REQUIRE(reserved_replay->authorization_id == reserved->authorization_id);
    REQUIRE(reserved_replay->authorization_expires_at_ms == reserved->authorization_expires_at_ms);
    REQUIRE((*registry)->record_count() == 2);
    auto changed_reservation = authorization;
    changed_reservation.authorization_id = "approval-session-1-changed";
    REQUIRE(
        !(*registry)->reserve_start(changed_reservation, "reserve-session-1", 1'003).has_value()
    );
    REQUIRE((*registry)->status("session-1")->state == glove::control::session_state::preparing);

    auto duplicate_start = authorization;
    duplicate_start.authorization_id = "approval-session-1-second";
    REQUIRE(!(*registry)->reserve_start(duplicate_start, "reserve-session-2", 1'003).has_value());

    const glove::control::session_execution_binding execution_binding{
        .schema_version = 1,
        .session_id = "session-1",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = "approval-session-1",
        .profile_digest = std::string(64, 'e'),
        .cgroup_identity = cgroup_identity(4242),
        .filesystem_identity = filesystem_identity(),
    };
    const auto audit_key_path = temp.root() / "receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
        output.flush();
        REQUIRE(output.good());
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = temp.root() / "receipts.journal",
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    auto receipt_reservation = (*producer)->reserve_terminal(
        execution_binding.session_id,
        execution_binding.controller_plan_digest,
        execution_binding.profile_digest
    );
    REQUIRE(receipt_reservation.has_value());
    auto malformed_execution = execution_binding;
    malformed_execution.profile_digest = "not-a-digest";
    REQUIRE(!(*registry)
                 ->mark_starting(
                     malformed_execution, *receipt_reservation, "starting-session-malformed", 1'003
                 )
                 .has_value());
    auto malformed_cgroup_execution = execution_binding;
    malformed_cgroup_execution.cgroup_identity.inode = 0;
    REQUIRE(!(*registry)
                 ->mark_starting(
                     malformed_cgroup_execution,
                     *receipt_reservation,
                     "starting-session-malformed-cgroup",
                     1'003
                 )
                 .has_value());
    auto wrong_execution_authorization = execution_binding;
    wrong_execution_authorization.authorization_id = "approval-session-wrong";
    REQUIRE(!(*registry)
                 ->mark_starting(
                     wrong_execution_authorization,
                     *receipt_reservation,
                     "starting-session-wrong-approval",
                     1'003
                 )
                 .has_value());
    REQUIRE(!(*registry)
                 ->mark_starting(
                     execution_binding, *receipt_reservation, "starting-session-expired", 2'001
                 )
                 .has_value());
    REQUIRE((*registry)->record_count() == 2);

    auto starting = (*registry)->mark_starting(
        execution_binding, *receipt_reservation, "starting-session-1", 1'003
    );
    REQUIRE(starting.has_value());
    REQUIRE(starting->session.state == glove::control::session_state::starting);
    REQUIRE(starting->authorization_id == execution_binding.authorization_id);
    REQUIRE(starting->authorization_expires_at_ms == authorization.expires_at_ms);
    REQUIRE(starting->profile_digest == execution_binding.profile_digest);
    REQUIRE(starting->starting_at_ms == 1'003);
    REQUIRE(starting->cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(starting->filesystem_identity == execution_binding.filesystem_identity);
    REQUIRE((*registry)->record_count() == 3);
    REQUIRE((*registry)->status("session-1") == starting->session);
    REQUIRE((*registry)->starting_status("session-1") == starting);
    auto starting_candidates = (*registry)->recovery_candidates();
    REQUIRE(starting_candidates.has_value());
    REQUIRE(starting_candidates->size() == 1);
    REQUIRE(starting_candidates->front().session == starting->session);
    REQUIRE(starting_candidates->front().authorization_id == starting->authorization_id);
    REQUIRE(starting_candidates->front().profile_digest == starting->profile_digest);
    REQUIRE(starting_candidates->front().starting_at_ms == starting->starting_at_ms);
    REQUIRE(starting_candidates->front().cgroup_identity == starting->cgroup_identity);
    REQUIRE(starting_candidates->front().filesystem_identity == starting->filesystem_identity);
    REQUIRE(starting_candidates->front().running_at_ms == 0);
    REQUIRE(!starting_candidates->front().process_identity.has_value());
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-1", 1'004).has_value()
    );

    auto starting_replay = (*registry)->mark_starting(
        execution_binding, *receipt_reservation, "starting-session-1", 3'000
    );
    REQUIRE(starting_replay == starting);
    REQUIRE((*registry)->record_count() == 3);
    auto changed_execution = execution_binding;
    changed_execution.profile_digest = std::string(64, 'f');
    REQUIRE(
        !(*registry)
             ->mark_starting(changed_execution, *receipt_reservation, "starting-session-1", 1'004)
             .has_value()
    );
    auto changed_cgroup_execution = execution_binding;
    ++changed_cgroup_execution.cgroup_identity.inode;
    REQUIRE(!(*registry)
                 ->mark_starting(
                     changed_cgroup_execution, *receipt_reservation, "starting-session-1", 1'004
                 )
                 .has_value());
    REQUIRE(!(*registry)
                 ->mark_starting(
                     execution_binding, *receipt_reservation, "starting-session-duplicate", 1'004
                 )
                 .has_value());

    const glove::control::session_running_commitment running_commitment{
        .schema_version = 1,
        .session_id = execution_binding.session_id,
        .controller_plan_digest = execution_binding.controller_plan_digest,
        .plan_content_digest = execution_binding.plan_content_digest,
        .authorization_id = execution_binding.authorization_id,
        .profile_digest = execution_binding.profile_digest,
        .process_identity = process_identity(4242),
        .filesystem_identity = filesystem_identity(),
    };
    auto wrong_running = running_commitment;
    wrong_running.process_identity.pid = 0;
    REQUIRE(
        !(*registry)
             ->mark_running(wrong_running, *receipt_reservation, "running-session-invalid", 1'004)
             .has_value()
    );
    auto wrong_running_cgroup = running_commitment;
    ++wrong_running_cgroup.process_identity.cgroup_inode;
    REQUIRE(
        !(*registry)
             ->mark_running(
                 wrong_running_cgroup, *receipt_reservation, "running-session-invalid-cgroup", 1'004
             )
             .has_value()
    );
    auto wrong_filesystem = running_commitment;
    wrong_filesystem.filesystem_identity.partitions.front().quota_bytes =
        wrong_filesystem.filesystem_identity.disk_limit_bytes;
    REQUIRE(
        !(*registry)
             ->mark_running(
                 wrong_filesystem, *receipt_reservation, "running-session-invalid-filesystem", 1'004
             )
             .has_value()
    );
    auto running = (*registry)->mark_running(
        running_commitment, *receipt_reservation, "running-session-1", 1'004
    );
    REQUIRE(running.has_value());
    REQUIRE(running->session.state == glove::control::session_state::running);
    REQUIRE(running->profile_digest == execution_binding.profile_digest);
    REQUIRE(running->starting_at_ms == starting->starting_at_ms);
    REQUIRE(running->running_at_ms == 1'004);
    REQUIRE(running->process_identity == running_commitment.process_identity);
    REQUIRE(running->filesystem_identity == running_commitment.filesystem_identity);
    REQUIRE((*registry)->running_status("session-1") == running);
    REQUIRE(!(*registry)->starting_status("session-1").has_value());
    REQUIRE((*registry)->record_count() == 4);
    auto running_candidates = (*registry)->recovery_candidates();
    REQUIRE(running_candidates.has_value());
    REQUIRE(running_candidates->size() == 1);
    REQUIRE(running_candidates->front().session == running->session);
    REQUIRE(running_candidates->front().running_at_ms == running->running_at_ms);
    REQUIRE(running_candidates->front().process_identity == running->process_identity);
    REQUIRE(running_candidates->front().cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(running_candidates->front().filesystem_identity == running->filesystem_identity);
    REQUIRE(
        (*registry)->mark_running(
            running_commitment, *receipt_reservation, "running-session-1", 3'000
        ) == running
    );

    auto direct_created = (*registry)->create(
        "session-direct", controller_digest, direct_write_plan(), "create-session-direct", 1'003
    );
    REQUIRE(direct_created.has_value());
    const glove::control::session_start_authorization direct_authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-direct",
        .session_id = "session-direct",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = direct_created->plan_content_digest,
        .approved_at_ms = 1'004,
        .expires_at_ms = 2'004,
    };
    auto direct_reservation =
        (*registry)->reserve_start(direct_authorization, "reserve-session-direct", 1'005);
    REQUIRE(!direct_reservation.has_value());
    REQUIRE(
        direct_reservation.error().code ==
        glove::control::session_registry_error_code::invalid_authorization
    );
    REQUIRE((*registry)->status("session-direct")->state == glove::control::session_state::created);
    REQUIRE((*registry)->record_count() == 5);

    registry->reset();
    auto recovered = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(recovered.has_value());
    REQUIRE((*recovered)->record_count() == 5);
    REQUIRE((*recovered)->status("session-1") == running->session);
    REQUIRE((*recovered)->running_status("session-1") == running);
    REQUIRE(!(*recovered)->starting_status("session-1").has_value());
    REQUIRE((*recovered)->canonical_plan("session-1") == canonical);
    REQUIRE((*recovered)->reserve_start(authorization, "reserve-session-1", 3'000) == reserved);
    REQUIRE(
        (*recovered)
            ->mark_starting(execution_binding, *receipt_reservation, "starting-session-1", 3'000) ==
        starting
    );
    REQUIRE(
        (*recovered)
            ->create("session-1", controller_digest, valid_plan(), "create-session-1", 62'000) ==
        created
    );
    bool observed_committed_identity = false;
    const glove::control::session_process_observer mismatch_observer =
        [&](
            const glove::control::session_recovery_record& candidate
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        observed_committed_identity = candidate.process_identity == running->process_identity;
        return glove::control::session_process_observation::mismatch;
    };
    auto mismatched = glove::control::reconcile_session_registry(
        **recovered, **producer, 3'000, mismatch_observer
    );
    REQUIRE(mismatched.has_value());
    REQUIRE(observed_committed_identity);
    REQUIRE(mismatched->inspected == 1);
    REQUIRE(mismatched->recovered_exited == 0);
    REQUIRE(mismatched->recovered_failed == 0);
    REQUIRE(mismatched->unresolved_running_session_ids.empty());
    REQUIRE(mismatched->live_running_session_ids.empty());
    REQUIRE(mismatched->identity_mismatch_session_ids == std::vector<std::string>{"session-1"});
    REQUIRE((*recovered)->running_status("session-1") == running);

    const glove::control::session_process_observer exact_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::exact;
    };
    auto live =
        glove::control::reconcile_session_registry(**recovered, **producer, 3'000, exact_observer);
    REQUIRE(live.has_value());
    REQUIRE(live->inspected == 1);
    REQUIRE(live->recovered_exited == 0);
    REQUIRE(live->recovered_failed == 0);
    REQUIRE(live->unresolved_running_session_ids.empty());
    REQUIRE(live->live_running_session_ids == std::vector<std::string>{"session-1"});
    REQUIRE(live->identity_mismatch_session_ids.empty());
    REQUIRE((*recovered)->running_status("session-1") == running);

    const glove::control::session_failure_commitment abandoned_failure{
        .schema_version = 1,
        .session_id = execution_binding.session_id,
        .controller_plan_digest = execution_binding.controller_plan_digest,
        .plan_content_digest = execution_binding.plan_content_digest,
        .authorization_id = execution_binding.authorization_id,
        .profile_digest = execution_binding.profile_digest,
        .code = glove::control::session_failure_code::supervisor_error,
    };
    auto wrong_failure = abandoned_failure;
    wrong_failure.profile_digest = std::string(64, 'f');
    REQUIRE(
        !(*recovered)->mark_failed(wrong_failure, "fail-session-wrong-profile", 3'001).has_value()
    );
    auto wrong_running_failure = abandoned_failure;
    wrong_running_failure.code = glove::control::session_failure_code::launch_failed;
    REQUIRE(!(*recovered)
                 ->mark_failed(wrong_running_failure, "fail-session-wrong-running-code", 3'001)
                 .has_value());
    const glove::control::session_process_observer terminated_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::terminated;
    };
    auto terminated = glove::control::reconcile_session_registry(
        **recovered, **producer, 3'001, terminated_observer
    );
    REQUIRE(terminated.has_value());
    REQUIRE(terminated->inspected == 1);
    REQUIRE(terminated->recovered_failed == 1);
    REQUIRE(terminated->recovered_terminated == 1);
    auto failed = (*recovered)->failed_status("session-1");
    REQUIRE(failed.has_value());
    REQUIRE(failed->session.state == glove::control::session_state::failed);
    REQUIRE(failed->profile_digest == execution_binding.profile_digest);
    REQUIRE(failed->starting_at_ms == starting->starting_at_ms);
    REQUIRE(failed->running_at_ms == running->running_at_ms);
    REQUIRE(failed->process_identity == running->process_identity);
    REQUIRE(failed->cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(failed->filesystem_identity == running->filesystem_identity);
    REQUIRE(failed->failed_at_ms == 3'001);
    REQUIRE(failed->code == glove::control::session_failure_code::recovered_terminated);
    REQUIRE((*recovered)->failed_status("session-1") == failed);
    REQUIRE(!(*recovered)->starting_status("session-1").has_value());
    REQUIRE((*recovered)->record_count() == 6);
    auto changed_failure = abandoned_failure;
    changed_failure.code = glove::control::session_failure_code::launch_failed;
    REQUIRE(!(*recovered)->mark_failed(changed_failure, "fail-session-1", 3'002).has_value());
    REQUIRE(
        !(*recovered)->mark_failed(abandoned_failure, "fail-session-duplicate", 3'002).has_value()
    );

    auto terminal_created = (*recovered)
                                ->create(
                                    "session-terminal",
                                    controller_digest,
                                    valid_plan_at(3'002),
                                    "create-session-terminal",
                                    3'002
                                );
    REQUIRE(terminal_created.has_value());
    const glove::control::session_start_authorization terminal_authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-terminal",
        .session_id = "session-terminal",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = terminal_created->plan_content_digest,
        .approved_at_ms = 3'003,
        .expires_at_ms = 4'003,
    };
    auto terminal_start =
        (*recovered)->reserve_start(terminal_authorization, "reserve-session-terminal", 3'004);
    REQUIRE(terminal_start.has_value());
    const glove::control::session_execution_binding terminal_binding{
        .schema_version = 1,
        .session_id = "session-terminal",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = terminal_created->plan_content_digest,
        .authorization_id = terminal_authorization.authorization_id,
        .profile_digest = std::string(64, 'a'),
        .cgroup_identity = cgroup_identity(4343),
        .filesystem_identity = filesystem_identity(),
    };
    auto terminal_reservation = (*producer)->reserve_terminal(
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_binding.profile_digest
    );
    REQUIRE(terminal_reservation.has_value());
    auto terminal_starting =
        (*recovered)
            ->mark_starting(
                terminal_binding, *terminal_reservation, "starting-session-terminal", 3'005
            );
    REQUIRE(terminal_starting.has_value());
    const glove::control::session_running_commitment terminal_running_commitment{
        .schema_version = 1,
        .session_id = terminal_binding.session_id,
        .controller_plan_digest = terminal_binding.controller_plan_digest,
        .plan_content_digest = terminal_binding.plan_content_digest,
        .authorization_id = terminal_binding.authorization_id,
        .profile_digest = terminal_binding.profile_digest,
        .process_identity = process_identity(4343),
        .filesystem_identity = filesystem_identity(),
    };
    auto terminal_running = (*recovered)
                                ->mark_running(
                                    terminal_running_commitment,
                                    *terminal_reservation,
                                    "running-session-terminal",
                                    3'006
                                );
    REQUIRE(terminal_running.has_value());
    auto wrong_stopping_commitment = terminal_running_commitment;
    ++wrong_stopping_commitment.process_identity.start_time_ticks;
    REQUIRE(
        !(*recovered)
             ->mark_stopping(wrong_stopping_commitment, "stopping-session-terminal-wrong", 3'007)
             .has_value()
    );
    auto terminal_stopping =
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 3'007);
    REQUIRE(terminal_stopping.has_value());
    REQUIRE(terminal_stopping->session.state == glove::control::session_state::stopping);
    REQUIRE(terminal_stopping->profile_digest == terminal_running->profile_digest);
    REQUIRE(terminal_stopping->starting_at_ms == terminal_running->starting_at_ms);
    REQUIRE(terminal_stopping->running_at_ms == terminal_running->running_at_ms);
    REQUIRE(terminal_stopping->stopping_at_ms == 3'007);
    REQUIRE(terminal_stopping->process_identity == terminal_running->process_identity);
    REQUIRE(terminal_stopping->filesystem_identity == terminal_running->filesystem_identity);
    REQUIRE((*recovered)->stopping_status("session-terminal") == terminal_stopping);
    REQUIRE(!(*recovered)->running_status("session-terminal").has_value());
    auto stopping_candidates = (*recovered)->recovery_candidates();
    REQUIRE(stopping_candidates.has_value());
    REQUIRE(stopping_candidates->size() == 1);
    REQUIRE(stopping_candidates->front().session == terminal_stopping->session);
    REQUIRE(stopping_candidates->front().stopping_at_ms == terminal_stopping->stopping_at_ms);
    REQUIRE(stopping_candidates->front().process_identity == terminal_stopping->process_identity);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );
    auto changed_stopping_commitment = terminal_running_commitment;
    ++changed_stopping_commitment.process_identity.cgroup_inode;
    REQUIRE(!(*recovered)
                 ->mark_stopping(changed_stopping_commitment, "stopping-session-terminal", 3'008)
                 .has_value());
    REQUIRE(!(*recovered)
                 ->mark_stopping(
                     terminal_running_commitment, "stopping-session-terminal-duplicate", 3'008
                 )
                 .has_value());
    auto terminal = (*producer)->commit_terminal(
        std::move(*terminal_reservation),
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_receipt(terminal_binding.profile_digest, 3'005, 3'500)
    );
    REQUIRE(terminal.has_value());
    auto forged_terminal = *terminal;
    forged_terminal.this_hmac = std::string(64, 'f');
    REQUIRE(!(*recovered)
                 ->mark_exited(forged_terminal, **producer, "exited-session-terminal-forged")
                 .has_value());
    auto terminal_lookup = (*producer)->terminal_for_execution(
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_binding.profile_digest
    );
    REQUIRE(terminal_lookup.has_value());
    REQUIRE(terminal_lookup->has_value());
    REQUIRE(**terminal_lookup == *terminal);
    auto reconciled = glove::control::reconcile_session_registry(**recovered, **producer, 3'501);
    REQUIRE(reconciled.has_value());
    REQUIRE(reconciled->inspected == 1);
    REQUIRE(reconciled->recovered_exited == 1);
    REQUIRE(reconciled->recovered_failed == 0);
    REQUIRE(reconciled->unresolved_running_session_ids.empty());
    auto exited = (*recovered)->exited_status("session-terminal");
    REQUIRE(exited.has_value());
    REQUIRE(exited->session.state == glove::control::session_state::exited);
    REQUIRE(exited->profile_digest == terminal_binding.profile_digest);
    REQUIRE(exited->starting_at_ms == terminal_starting->starting_at_ms);
    REQUIRE(exited->running_at_ms == terminal_running->running_at_ms);
    REQUIRE(exited->stopping_at_ms == terminal_stopping->stopping_at_ms);
    REQUIRE(exited->process_identity == terminal_running->process_identity);
    REQUIRE(exited->filesystem_identity == terminal_running->filesystem_identity);
    REQUIRE(exited->finished_at_ms == terminal->receipt.finished_at_ms);
    REQUIRE(exited->receipt_sequence == terminal->sequence);
    REQUIRE(exited->receipt_key_id == terminal->key_id);
    REQUIRE(exited->receipt_digest == terminal->receipt_digest);
    REQUIRE(exited->receipt_hmac == terminal->this_hmac);
    REQUIRE(exited->exit_code == terminal->receipt.exit_code);
    REQUIRE((*recovered)->exited_status("session-terminal") == exited);
    REQUIRE((*recovered)->record_count() == 12);
    REQUIRE((*recovered)->mark_exited(*terminal, **producer, "recovery-exit-1") == exited);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );
    REQUIRE(!(*recovered)
                 ->mark_exited(*terminal, **producer, "exited-session-terminal-duplicate")
                 .has_value());
    REQUIRE(!(*recovered)
                 ->mark_running(
                     terminal_running_commitment,
                     *receipt_reservation,
                     "running-session-terminal-after-exit",
                     3'501
                 )
                 .has_value());

    recovered->reset();
    recovered = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(recovered.has_value());
    REQUIRE((*recovered)->record_count() == 12);
    REQUIRE((*recovered)->status("session-1") == failed->session);
    REQUIRE((*recovered)->failed_status("session-1") == failed);
    REQUIRE((*recovered)->status("session-terminal") == exited->session);
    REQUIRE((*recovered)->exited_status("session-terminal") == exited);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );

    const auto recovery_store_path = temp.root() / "recovery-sessions.journal";
    auto recovery_registry =
        glove::control::session_registry::open_or_create(recovery_store_path, shared_validator);
    REQUIRE(recovery_registry.has_value());
    auto recovery_created = (*recovery_registry)
                                ->create(
                                    "session-starting-recovery",
                                    controller_digest,
                                    valid_plan_at(4'000),
                                    "create-starting-recovery",
                                    4'000
                                );
    REQUIRE(recovery_created.has_value());
    const glove::control::session_start_authorization recovery_authorization{
        .schema_version = 1,
        .authorization_id = "approval-starting-recovery",
        .session_id = recovery_created->session_id,
        .controller_plan_digest = recovery_created->controller_plan_digest,
        .plan_content_digest = recovery_created->plan_content_digest,
        .approved_at_ms = 4'001,
        .expires_at_ms = 5'001,
    };
    REQUIRE((*recovery_registry)
                ->reserve_start(recovery_authorization, "reserve-starting-recovery", 4'002)
                .has_value());
    const glove::control::session_execution_binding recovery_binding{
        .schema_version = 1,
        .session_id = recovery_created->session_id,
        .controller_plan_digest = recovery_created->controller_plan_digest,
        .plan_content_digest = recovery_created->plan_content_digest,
        .authorization_id = recovery_authorization.authorization_id,
        .profile_digest = std::string(64, 'b'),
        .cgroup_identity = cgroup_identity(4545),
        .filesystem_identity = filesystem_identity(),
    };
    auto recovery_receipt_reservation = (*producer)->reserve_terminal(
        recovery_binding.session_id,
        recovery_binding.controller_plan_digest,
        recovery_binding.profile_digest
    );
    REQUIRE(recovery_receipt_reservation.has_value());
    REQUIRE((*recovery_registry)
                ->mark_starting(
                    recovery_binding, *recovery_receipt_reservation, "starting-recovery", 4'003
                )
                .has_value());
    auto recovered_starting =
        glove::control::reconcile_session_registry(**recovery_registry, **producer, 4'004);
    REQUIRE(recovered_starting.has_value());
    REQUIRE(recovered_starting->inspected == 1);
    REQUIRE(recovered_starting->recovered_exited == 0);
    REQUIRE(recovered_starting->recovered_failed == 1);
    REQUIRE(recovered_starting->unresolved_running_session_ids.empty());
    auto recovered_failure = (*recovery_registry)->failed_status("session-starting-recovery");
    REQUIRE(recovered_failure.has_value());
    REQUIRE(
        recovered_failure->code == glove::control::session_failure_code::recovered_without_process
    );
    REQUIRE(recovered_failure->running_at_ms == 0);
    REQUIRE(!recovered_failure->process_identity.has_value());
    REQUIRE(recovered_failure->cgroup_identity == recovery_binding.cgroup_identity);
    REQUIRE(recovered_failure->filesystem_identity == recovery_binding.filesystem_identity);
    REQUIRE((*recovery_registry)->record_count() == 4);
    auto recovery_replay =
        glove::control::reconcile_session_registry(**recovery_registry, **producer, 4'005);
    REQUIRE(recovery_replay.has_value());
    REQUIRE(recovery_replay->inspected == 0);
    REQUIRE((*recovery_registry)->record_count() == 4);

    auto absent_created = (*recovery_registry)
                              ->create(
                                  "session-absent-recovery",
                                  controller_digest,
                                  valid_plan_at(5'000),
                                  "create-absent-recovery",
                                  5'000
                              );
    REQUIRE(absent_created.has_value());
    const glove::control::session_start_authorization absent_authorization{
        .schema_version = 1,
        .authorization_id = "approval-absent-recovery",
        .session_id = absent_created->session_id,
        .controller_plan_digest = absent_created->controller_plan_digest,
        .plan_content_digest = absent_created->plan_content_digest,
        .approved_at_ms = 5'001,
        .expires_at_ms = 6'001,
    };
    REQUIRE((*recovery_registry)
                ->reserve_start(absent_authorization, "reserve-absent-recovery", 5'002)
                .has_value());
    const glove::control::session_execution_binding absent_binding{
        .schema_version = 1,
        .session_id = absent_created->session_id,
        .controller_plan_digest = absent_created->controller_plan_digest,
        .plan_content_digest = absent_created->plan_content_digest,
        .authorization_id = absent_authorization.authorization_id,
        .profile_digest = std::string(64, 'e'),
        .cgroup_identity = cgroup_identity(4444),
        .filesystem_identity = filesystem_identity(),
    };
    auto absent_receipt_reservation = (*producer)->reserve_terminal(
        absent_binding.session_id,
        absent_binding.controller_plan_digest,
        absent_binding.profile_digest
    );
    REQUIRE(absent_receipt_reservation.has_value());
    REQUIRE((*recovery_registry)
                ->mark_starting(
                    absent_binding, *absent_receipt_reservation, "starting-absent-recovery", 5'003
                )
                .has_value());
    const glove::control::session_running_commitment absent_running_commitment{
        .schema_version = 1,
        .session_id = absent_binding.session_id,
        .controller_plan_digest = absent_binding.controller_plan_digest,
        .plan_content_digest = absent_binding.plan_content_digest,
        .authorization_id = absent_binding.authorization_id,
        .profile_digest = absent_binding.profile_digest,
        .process_identity = process_identity(4444),
        .filesystem_identity = filesystem_identity(),
    };
    REQUIRE((*recovery_registry)
                ->mark_running(
                    absent_running_commitment,
                    *absent_receipt_reservation,
                    "running-absent-recovery",
                    5'004
                )
                .has_value());
    auto absent_stopping =
        (*recovery_registry)
            ->mark_stopping(absent_running_commitment, "stopping-absent-recovery", 5'005);
    REQUIRE(absent_stopping.has_value());
    const glove::control::session_process_observer absent_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::absent;
    };
    auto absent_reconciled = glove::control::reconcile_session_registry(
        **recovery_registry, **producer, 5'006, absent_observer
    );
    REQUIRE(absent_reconciled.has_value());
    REQUIRE(absent_reconciled->inspected == 1);
    REQUIRE(absent_reconciled->recovered_exited == 0);
    REQUIRE(absent_reconciled->recovered_failed == 1);
    REQUIRE(absent_reconciled->unresolved_running_session_ids.empty());
    REQUIRE(absent_reconciled->live_running_session_ids.empty());
    REQUIRE(absent_reconciled->identity_mismatch_session_ids.empty());
    auto absent_failure = (*recovery_registry)->failed_status(absent_running_commitment.session_id);
    REQUIRE(absent_failure.has_value());
    REQUIRE(
        absent_failure->code == glove::control::session_failure_code::recovered_without_process
    );
    REQUIRE(absent_failure->process_identity == absent_running_commitment.process_identity);
    REQUIRE(absent_failure->filesystem_identity == absent_running_commitment.filesystem_identity);
    REQUIRE(absent_failure->stopping_at_ms == absent_stopping->stopping_at_ms);
    REQUIRE((*recovery_registry)->record_count() == 10);

    {
        std::ofstream output{store_path, std::ios::binary | std::ios::app};
        output.put('x');
    }
    REQUIRE(!(*recovered)->status("session-1").has_value());

    recovered->reset();
    REQUIRE(::chmod(store_path.c_str(), 0644) == 0);
    REQUIRE(
        !glove::control::session_registry::open_or_create(store_path, shared_validator).has_value()
    );
    REQUIRE(::chmod(store_path.c_str(), 0600) == 0);
    const auto insecure_parent = temp.root() / "insecure-parent";
    REQUIRE(std::filesystem::create_directory(insecure_parent));
    REQUIRE(::chmod(insecure_parent.c_str(), 0755) == 0);
    const auto insecure_store = insecure_parent / "sessions.journal";
    REQUIRE(!glove::control::session_registry::open_or_create(insecure_store, shared_validator)
                 .has_value());
    REQUIRE(!std::filesystem::exists(insecure_store));
    REQUIRE(
        !glove::control::session_registry::open_or_create(store_path, shared_validator).has_value()
    );
    return 0;
}

auto run_managed_runtime_registry() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    auto validator =
        validator_for(source, glove::supervisor::sandbox_backend::apple_container);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto store_path = temp.root() / "managed-sessions.journal";
    auto registry =
        glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    auto created = (*registry)->create(
        "managed-session", controller_digest, managed_plan(), "managed-create", 1'000
    );
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "managed-approval",
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = 1'001,
        .expires_at_ms = 5'000,
    };
    REQUIRE((*registry)->reserve_start(authorization, "managed-reserve", 1'002).has_value());

    const auto audit_key_path = temp.root() / "managed-receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = temp.root() / "managed-receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    const glove::control::managed_runtime_recovery_identity runtime_identity{
        .schema_version = 1,
        .backend = "apple_container",
        .instance_id = "glove-managed-session",
        .launch_identity_digest = std::string(64, '7'),
    };
    const glove::control::managed_session_execution_binding binding{
        .schema_version = 1,
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = std::string(64, '8'),
        .runtime_identity = runtime_identity,
    };
    auto receipt_reservation = (*producer)->reserve_terminal(
        binding.session_id, binding.controller_plan_digest, binding.profile_digest
    );
    REQUIRE(receipt_reservation.has_value());
    auto starting = (*registry)->mark_managed_starting(
        binding, *receipt_reservation, "managed-starting", 1'003
    );
    REQUIRE(starting.has_value());
    REQUIRE(starting->runtime_identity == runtime_identity);
    REQUIRE((*registry)->managed_recovery_candidates()->size() == 1);
    REQUIRE((*registry)->recovery_candidates()->empty());
    REQUIRE(
        (*registry)->mark_managed_starting(
            binding, *receipt_reservation, "managed-starting", 9'000
        ) == starting
    );
    auto changed_binding = binding;
    changed_binding.runtime_identity.instance_id = "changed-instance";
    REQUIRE(!(*registry)
                 ->mark_managed_starting(
                     changed_binding, *receipt_reservation, "managed-starting", 1'004
                 )
                 .has_value());

    const glove::control::managed_session_running_commitment running_commitment{
        .schema_version = 1,
        .session_id = binding.session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = binding.profile_digest,
        .runtime_identity = runtime_identity,
    };
    auto running = (*registry)->mark_managed_running(
        running_commitment, *receipt_reservation, "managed-running", 1'004
    );
    REQUIRE(running.has_value());
    REQUIRE(running->session.state == glove::control::session_state::running);
    auto stopping =
        (*registry)->mark_managed_stopping(running_commitment, "managed-stopping", 1'005);
    REQUIRE(stopping.has_value());
    REQUIRE(stopping->session.state == glove::control::session_state::stopping);

    registry->reset();
    registry = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    auto recovered = (*registry)->managed_recovery_candidates();
    REQUIRE(recovered.has_value());
    REQUIRE(recovered->size() == 1);
    REQUIRE(recovered->front() == *stopping);

    auto receipt = terminal_receipt(binding.profile_digest, 1'003, 1'006);
    receipt.backend = glove::container::sandbox_backend::apple_container;
    receipt.backend_id = "apple-container:vm-v1";
    auto terminal = (*producer)->commit_terminal(
        std::move(*receipt_reservation),
        binding.session_id,
        binding.controller_plan_digest,
        std::move(receipt)
    );
    REQUIRE(terminal.has_value());
    auto exited =
        (*registry)->mark_managed_exited(*terminal, **producer, "managed-exited");
    REQUIRE(exited.has_value());
    REQUIRE(exited->lifecycle.runtime_identity == runtime_identity);
    REQUIRE(exited->termination_cause == glove::container::resource_termination_cause::exited);
    REQUIRE((*registry)->managed_recovery_candidates()->empty());

    registry->reset();
    registry = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    REQUIRE((*registry)->record_count() == 6);
    REQUIRE(
        (*registry)->managed_lifecycle_status(binding.session_id)->session.state ==
        glove::control::session_state::exited
    );
    return 0;
}

} // namespace

int main() {
    if (const auto result = run(); result != 0) {
        return result;
    }
    return run_managed_runtime_registry();
}
