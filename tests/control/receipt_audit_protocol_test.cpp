#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/path_exposure.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "receipt_audit_wire.hpp"

#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view bootstrap_secret =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
constexpr std::string_view plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-receipt-protocol-test-XXXXXX";
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

auto write_owner_only(const std::filesystem::path& path, std::string_view value) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << value << '\n';
    output.flush();
    return output.good() && ::chmod(path.c_str(), 0600) == 0;
}

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
        .library_projections = {},
        .retained_changes = {},
    };
}

} // namespace

namespace wire_test {

struct rpc_error {
    std::string code;
    std::string message;
};

struct rpc_response {
    std::string jsonrpc;
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<rpc_error> error;
};

struct page_result {
    std::uint8_t schema_version = 0;
    std::vector<glove::container::authenticated_resource_enforcement_receipt> envelopes;
    bool has_more = false;
    glove::container::receipt_audit_anchor local_anchor;
};

struct acknowledgement_result {
    std::uint8_t schema_version = 0;
    glove::container::receipt_audit_anchor acknowledged_anchor;
};

struct receipt_audit_capabilities {
    std::uint8_t envelope_schema_version = 0;
    std::string algorithm;
    std::string key_id;
};

struct session_control_capabilities {
    bool validate_plan = true;
    bool create_session = true;
    bool start_session = true;
    bool session_status = true;
    bool attach = true;
    bool resize = true;
    bool write_stdin = true;
    bool signal = true;
    bool detach = true;
    bool stop_session = true;
    bool cleanup_session = true;
};

struct resource_enforcement_capabilities {
    std::string cpu_time;
    std::string memory;
    std::string pids;
    std::string wall_time;
    std::string disk;
    std::string terminal_output;
    std::uint8_t receipt_schema_version = 1;
};

struct backend_capabilities {
    std::string backend;
    resource_enforcement_capabilities resource_enforcement;
};

struct supervisor_capabilities {
    std::uint8_t schema_version = 0;
    receipt_audit_capabilities receipt_audit;
    session_control_capabilities session_control;
    std::uint8_t agent_runtime_adapter_schema_version = 0;
    std::uint8_t path_exposure_admin_schema_version = 0;
    std::uint8_t path_exposure_catalog_schema_version = 0;
    std::uint8_t retained_write_schema_version = 0;
    std::uint8_t change_manifest_schema_version = 0;
    std::uint8_t change_apply_authorization_schema_version = 0;
    std::vector<backend_capabilities> backends;
};

struct supervisor_health {
    std::uint8_t schema_version = 0;
    std::string status;
};

struct path_exposure_mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct path_exposure_projection {
    std::uint8_t schema_version = 0;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    std::string state;
};

struct path_exposure_result {
    std::uint8_t schema_version = 0;
    path_exposure_projection exposure;
};

struct path_exposure_list_result {
    std::uint8_t schema_version = 0;
    std::vector<path_exposure_projection> exposures;
};

struct session_plan_validation {
    std::uint8_t schema_version = 0;
    std::uint64_t policy_revision = 0;
};

struct session_record_result {
    std::uint8_t schema_version = 0;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::optional<std::string> profile_digest;
};

} // namespace wire_test

namespace {

using wire_test::acknowledgement_result;
using wire_test::page_result;
using wire_test::rpc_error;
using wire_test::rpc_response;
using wire_test::supervisor_capabilities;
using wire_test::supervisor_health;

auto valid_plan() -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
}

auto plan_validator_for(const std::filesystem::path& source)
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
                        .adapter_command_digest = std::string(64, 'a'),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = {},
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
}

auto decode_response(std::string_view frame) -> std::optional<rpc_response> {
    rpc_response response;
    constexpr glz::opts strict{.error_on_unknown_keys = true};
    if (glz::read<strict>(response, frame)) {
        return std::nullopt;
    }
    return response;
}

auto make_request(
    std::string_view id,
    std::string_view method,
    std::string_view secret,
    std::string_view payload,
    std::optional<std::string_view> idempotency_key = std::nullopt,
    std::uint64_t deadline_ms = 2'000
) -> std::string {
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"" + std::string{id} + "\",\"method\":\"" +
                          std::string{method} +
                          "\",\"params\":{\"schema_version\":1,\"bootstrap_secret\":\"" +
                          std::string{secret} + "\",\"deadline_ms\":" + std::to_string(deadline_ms);
    if (idempotency_key) {
        request += ",\"idempotency_key\":\"" + std::string{*idempotency_key} + "\"";
    }
    request += ",\"payload\":" + std::string{payload} + "}}";
    return request;
}

auto run() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    REQUIRE(write_owner_only(key_path, audit_key));
    const glove::container::receipt_audit_producer_config config{
        .key_path = key_path,
        .journal_path = journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(config);
    REQUIRE(producer.has_value());
    const auto genesis = (*producer)->anchor();
    REQUIRE((*producer)->acknowledge_bootstrap(genesis).has_value());
    std::vector<glove::container::authenticated_resource_enforcement_receipt> terminals;
    for (std::size_t index = 1; index <= 16; ++index) {
        auto reservation = (*producer)->reserve_terminal();
        REQUIRE(reservation.has_value());
        auto terminal = (*producer)->commit_terminal(
            std::move(*reservation), "session-" + std::to_string(index), plan_digest, receipt()
        );
        REQUIRE(terminal.has_value());
        terminals.push_back(std::move(*terminal));
    }
    const auto terminal_anchor = (*producer)->anchor();
    producer->reset();

    auto recovered = glove::container::receipt_audit_producer::recover(config, genesis);
    REQUIRE(recovered.has_value());
    REQUIRE(!(*recovered)->bootstrap_reconciled());
    auto protocol = glove::control::receipt_audit_protocol::create(bootstrap_secret, *recovered);
    REQUIRE(protocol.has_value());

    auto health_frame = (*protocol)->handle_frame(
        make_request("health-1", "health", bootstrap_secret, "null"), 1'000
    );
    REQUIRE(health_frame.has_value());
    auto health_response = decode_response(*health_frame);
    REQUIRE(health_response.has_value());
    REQUIRE(health_response->result.has_value());
    REQUIRE(!health_response->error.has_value());
    supervisor_health health;
    REQUIRE(
        !glz::read<glz::opts{.error_on_unknown_keys = true}>(health, health_response->result->str)
    );
    REQUIRE(health.schema_version == 1);
    REQUIRE(health.status == "ready");

    auto invalid_health = (*protocol)->handle_frame(
        make_request("invalid-health", "health", bootstrap_secret, "{}"), 1'000
    );
    REQUIRE(invalid_health.has_value());
    auto invalid_health_response = decode_response(*invalid_health);
    REQUIRE(invalid_health_response.has_value());
    REQUIRE(invalid_health_response->error.has_value());
    REQUIRE(invalid_health_response->error->code == "invalid_request");

    auto keyed_health = (*protocol)->handle_frame(
        make_request(
            "keyed-health", "health", bootstrap_secret, "null", "health-must-be-read-only"
        ),
        1'000
    );
    REQUIRE(keyed_health.has_value());
    auto keyed_health_response = decode_response(*keyed_health);
    REQUIRE(keyed_health_response.has_value());
    REQUIRE(keyed_health_response->error.has_value());
    REQUIRE(keyed_health_response->error->code == "invalid_request");

    auto capabilities_frame = (*protocol)->handle_frame(
        make_request("capabilities-1", "capabilities", bootstrap_secret, "null"), 1'000
    );
    REQUIRE(capabilities_frame.has_value());
    auto capabilities_response = decode_response(*capabilities_frame);
    REQUIRE(capabilities_response.has_value());
    REQUIRE(capabilities_response->result.has_value());
    REQUIRE(!capabilities_response->error.has_value());
    supervisor_capabilities capabilities;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        capabilities, capabilities_response->result->str
    ));
    REQUIRE(capabilities.schema_version == 1);
    REQUIRE(capabilities.receipt_audit.envelope_schema_version == 1);
    REQUIRE(capabilities.receipt_audit.algorithm == "hmac_sha256");
    REQUIRE(capabilities.receipt_audit.key_id == genesis.key_id);
    REQUIRE(!capabilities.session_control.validate_plan);
    REQUIRE(!capabilities.session_control.create_session);
    REQUIRE(!capabilities.session_control.start_session);
    REQUIRE(!capabilities.session_control.session_status);
    REQUIRE(!capabilities.session_control.attach);
    REQUIRE(!capabilities.session_control.resize);
    REQUIRE(!capabilities.session_control.write_stdin);
    REQUIRE(!capabilities.session_control.signal);
    REQUIRE(!capabilities.session_control.detach);
    REQUIRE(!capabilities.session_control.stop_session);
    REQUIRE(!capabilities.session_control.cleanup_session);
    REQUIRE(capabilities.agent_runtime_adapter_schema_version == 0);
    REQUIRE(capabilities.path_exposure_admin_schema_version == 0);
    REQUIRE(capabilities.path_exposure_catalog_schema_version == 0);
    REQUIRE(capabilities.retained_write_schema_version == 0);
    REQUIRE(capabilities.change_manifest_schema_version == 0);
    REQUIRE(capabilities.change_apply_authorization_schema_version == 0);
    REQUIRE(capabilities.backends.size() == 2);
    for (const auto& backend : capabilities.backends) {
        REQUIRE(backend.resource_enforcement.cpu_time == "unavailable");
        REQUIRE(backend.resource_enforcement.memory == "unavailable");
        REQUIRE(backend.resource_enforcement.pids == "unavailable");
        REQUIRE(backend.resource_enforcement.wall_time == "unavailable");
        REQUIRE(backend.resource_enforcement.disk == "unavailable");
        REQUIRE(backend.resource_enforcement.terminal_output == "unavailable");
        REQUIRE(backend.resource_enforcement.receipt_schema_version == 0);
    }
    REQUIRE(capabilities.backends[0].backend == "linux_production");
    REQUIRE(capabilities.backends[1].backend == "macos_experimental");

    constexpr std::array<std::string_view, 11> unavailable_session_methods{
        "validate_plan",
        "create_session",
        "start_session",
        "session_status",
        "attach",
        "resize",
        "write_stdin",
        "signal",
        "detach",
        "stop_session",
        "cleanup_session",
    };
    for (const auto method : unavailable_session_methods) {
        auto unavailable = (*protocol)->handle_frame(
            make_request(
                std::string{"unavailable-"} + std::string{method},
                method,
                bootstrap_secret,
                "null",
                std::string{"unavailable-"} + std::string{method}
            ),
            1'000
        );
        REQUIRE(unavailable.has_value());
        auto unavailable_response = decode_response(*unavailable);
        REQUIRE(unavailable_response.has_value());
        REQUIRE(unavailable_response->error.has_value());
        REQUIRE(unavailable_response->error->code == "method_not_found");
    }

    const auto exposure_root = temp.root() / "exposure-root";
    const auto exposure_source = exposure_root / "sage-protocol";
    REQUIRE(std::filesystem::create_directories(exposure_source));
    const auto canonical_exposure_root = std::filesystem::canonical(exposure_root);
    const auto canonical_exposure_source = std::filesystem::canonical(exposure_source);
    auto exposure_registry = glove::supervisor::path_exposure_registry::open(
        {
            glove::supervisor::path_exposure_root_policy{
                .root_id = "projects",
                .host_root = canonical_exposure_root.string(),
                .allowed_modes =
                    {
                        glove::supervisor::path_exposure_mode{
                            .access = glove::supervisor::path_access::read,
                            .materialization = glove::supervisor::path_materialization::bind,
                            .max_bytes = 0,
                            .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
                        },
                        glove::supervisor::path_exposure_mode{
                            .access = glove::supervisor::path_access::retained_write,
                            .materialization = glove::supervisor::path_materialization::copy,
                            .max_bytes = 67'108'864,
                            .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
                        },
                    },
                .max_ttl_secs = 7'200,
                .allowed_runtime_template_ids = {"codex-safe"},
            },
        },
        temp.root() / "path-exposures.journal",
        std::uint64_t{8} * 1024U * 1024U
    );
    REQUIRE(exposure_registry.has_value());
    auto shared_exposures =
        std::make_shared<glove::supervisor::path_exposure_registry>(std::move(*exposure_registry));
    auto exposure_protocol = glove::control::receipt_audit_protocol::create(
        bootstrap_secret, *recovered, {}, {}, {}, shared_exposures
    );
    REQUIRE(exposure_protocol.has_value());
    auto exposure_capabilities =
        (*exposure_protocol)
            ->handle_frame(
                make_request("exposure-capabilities", "capabilities", bootstrap_secret, "null"),
                1'000
            );
    REQUIRE(exposure_capabilities.has_value());
    auto exposure_capabilities_response = decode_response(*exposure_capabilities);
    REQUIRE(exposure_capabilities_response.has_value());
    REQUIRE(exposure_capabilities_response->result.has_value());
    supervisor_capabilities exposure_capability_set;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        exposure_capability_set, exposure_capabilities_response->result->str
    ));
    REQUIRE(exposure_capability_set.path_exposure_admin_schema_version == 1);
    REQUIRE(exposure_capability_set.path_exposure_catalog_schema_version == 1);
    REQUIRE(exposure_capability_set.retained_write_schema_version == 0);
    REQUIRE(exposure_capability_set.change_manifest_schema_version == 0);
    REQUIRE(exposure_capability_set.change_apply_authorization_schema_version == 0);

    const auto exposure_payload =
        std::string{
            "{\"exposure_id\":\"sage-workspace\",\"root_id\":\"projects\",\"host_path\":\""
        } +
        canonical_exposure_source.string() +
        "\",\"display_label\":\"Sage "
        "protocol\",\"allowed_modes\":[{\"access\":\"read\",\"materialization\":\"bind\",\"max_"
        "bytes\":0,\"cleanup_policy\":\"retain\"},{\"access\":\"retained_write\","
        "\"materialization\":\"copy\",\"max_bytes\":33554432,\"cleanup_policy\":\"retain\"}],\"ttl_"
        "secs\":3600,\"allowed_runtime_template_ids\":[\"codex-safe\"]}";
    auto exposure_created = (*exposure_protocol)
                                ->handle_frame(
                                    make_request(
                                        "exposure-create",
                                        "create_path_exposure",
                                        bootstrap_secret,
                                        exposure_payload,
                                        "exposure-create-1"
                                    ),
                                    1'000
                                );
    REQUIRE(exposure_created.has_value());
    REQUIRE(exposure_created->find(canonical_exposure_source.string()) == std::string::npos);
    auto exposure_created_response = decode_response(*exposure_created);
    REQUIRE(exposure_created_response.has_value());
    REQUIRE(exposure_created_response->result.has_value());
    wire_test::path_exposure_result created_exposure;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        created_exposure, exposure_created_response->result->str
    ));
    REQUIRE(created_exposure.exposure.exposure_id == "sage-workspace");
    REQUIRE(created_exposure.exposure.generation == 1);
    REQUIRE(created_exposure.exposure.scope_digest.size() == 64U);
    REQUIRE(created_exposure.exposure.state == "active");

    auto exposure_listed =
        (*exposure_protocol)
            ->handle_frame(
                make_request("exposure-list", "list_path_exposures", bootstrap_secret, "null"),
                2'000
            );
    REQUIRE(exposure_listed.has_value());
    auto exposure_listed_response = decode_response(*exposure_listed);
    REQUIRE(exposure_listed_response.has_value());
    REQUIRE(exposure_listed_response->result.has_value());
    wire_test::path_exposure_list_result listed_exposures;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        listed_exposures, exposure_listed_response->result->str
    ));
    REQUIRE(listed_exposures.exposures.size() == 1U);

    const std::string revoke_payload = R"({"exposure_id":"sage-workspace","generation":1})";
    auto exposure_revoked = (*exposure_protocol)
                                ->handle_frame(
                                    make_request(
                                        "exposure-revoke",
                                        "revoke_path_exposure",
                                        bootstrap_secret,
                                        revoke_payload,
                                        "exposure-revoke-1",
                                        4'000
                                    ),
                                    3'000
                                );
    REQUIRE(exposure_revoked.has_value());
    auto exposure_revoked_response = decode_response(*exposure_revoked);
    REQUIRE(exposure_revoked_response.has_value());
    if (exposure_revoked_response->error) {
        std::fprintf(
            stderr,
            "exposure revoke failed: %s: %s\n",
            exposure_revoked_response->error->code.c_str(),
            exposure_revoked_response->error->message.c_str()
        );
    }
    REQUIRE(exposure_revoked_response->result.has_value());
    wire_test::path_exposure_result revoked_exposure;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        revoked_exposure, exposure_revoked_response->result->str
    ));
    REQUIRE(revoked_exposure.exposure.state == "revoked");
    auto revoke_replay = (*exposure_protocol)
                             ->handle_frame(
                                 make_request(
                                     "exposure-revoke-replay",
                                     "revoke_path_exposure",
                                     bootstrap_secret,
                                     revoke_payload,
                                     "exposure-revoke-1",
                                     4'000
                                 ),
                                 3'001
                             );
    REQUIRE(revoke_replay.has_value());
    auto revoke_replay_response = decode_response(*revoke_replay);
    REQUIRE(revoke_replay_response.has_value());
    REQUIRE(revoke_replay_response->result.has_value());

    const auto plan_source = temp.root() / "plan-source";
    REQUIRE(std::filesystem::create_directory(plan_source));
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    auto validator = plan_validator_for(plan_source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    auto session_registry = glove::control::session_registry::open_or_create(
        temp.root() / "sessions.journal", shared_validator
    );
    REQUIRE(session_registry.has_value());
    auto shared_sessions =
        std::shared_ptr<glove::control::session_registry>{std::move(*session_registry)};
    REQUIRE(!glove::control::receipt_audit_protocol::create(
                 bootstrap_secret, *recovered, {}, shared_sessions
    )
                 .has_value());
    auto planned_protocol = glove::control::receipt_audit_protocol::create(
        bootstrap_secret, *recovered, shared_validator, shared_sessions
    );
    REQUIRE(planned_protocol.has_value());

    auto planned_capabilities =
        (*planned_protocol)
            ->handle_frame(
                make_request("planned-capabilities", "capabilities", bootstrap_secret, "null"),
                1'000
            );
    REQUIRE(planned_capabilities.has_value());
    auto planned_capabilities_response = decode_response(*planned_capabilities);
    REQUIRE(planned_capabilities_response.has_value());
    REQUIRE(planned_capabilities_response->result.has_value());
    supervisor_capabilities planned_capability_set;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        planned_capability_set, planned_capabilities_response->result->str
    ));
    REQUIRE(planned_capability_set.session_control.validate_plan);
    REQUIRE(planned_capability_set.session_control.create_session);
    REQUIRE(planned_capability_set.session_control.session_status);
    REQUIRE(!planned_capability_set.session_control.start_session);

    auto validated =
        (*planned_protocol)
            ->handle_frame(
                make_request("validate-plan", "validate_plan", bootstrap_secret, valid_plan()),
                1'000
            );
    REQUIRE(validated.has_value());
    auto validated_response = decode_response(*validated);
    REQUIRE(validated_response.has_value());
    REQUIRE(validated_response->result.has_value());
    wire_test::session_plan_validation validation;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        validation, validated_response->result->str
    ));
    REQUIRE(validation.schema_version == 1);
    REQUIRE(validation.policy_revision == 7);

    auto invalid_plan = (*planned_protocol)
                            ->handle_frame(
                                make_request(
                                    "invalid-plan",
                                    "validate_plan",
                                    bootstrap_secret,
                                    "{\"schema_version\":1,\"argv\":[\"/bin/sh\"]}"
                                ),
                                1'000
                            );
    REQUIRE(invalid_plan.has_value());
    auto invalid_plan_response = decode_response(*invalid_plan);
    REQUIRE(invalid_plan_response.has_value());
    REQUIRE(invalid_plan_response->error.has_value());
    REQUIRE(invalid_plan_response->error->code == "invalid_plan");

    auto keyed_validation =
        (*planned_protocol)
            ->handle_frame(
                make_request(
                    "keyed-plan", "validate_plan", bootstrap_secret, valid_plan(), "read-only-plan"
                ),
                1'000
            );
    REQUIRE(keyed_validation.has_value());
    auto keyed_validation_response = decode_response(*keyed_validation);
    REQUIRE(keyed_validation_response.has_value());
    REQUIRE(keyed_validation_response->error.has_value());
    REQUIRE(keyed_validation_response->error->code == "invalid_request");

    const auto create_payload = "{\"session_id\":\"session-17\",\"controller_plan_digest\":\"" +
                                std::string{plan_digest} + "\",\"plan\":" + valid_plan() + "}";
    auto missing_create_idempotency =
        (*planned_protocol)
            ->handle_frame(
                make_request(
                    "create-without-key", "create_session", bootstrap_secret, create_payload
                ),
                1'000
            );
    REQUIRE(missing_create_idempotency.has_value());
    auto missing_create_response = decode_response(*missing_create_idempotency);
    REQUIRE(missing_create_response.has_value());
    REQUIRE(missing_create_response->error.has_value());
    REQUIRE(missing_create_response->error->code == "invalid_request");

    auto created = (*planned_protocol)
                       ->handle_frame(
                           make_request(
                               "create-session",
                               "create_session",
                               bootstrap_secret,
                               create_payload,
                               "create-session-17"
                           ),
                           1'000
                       );
    REQUIRE(created.has_value());
    auto created_response = decode_response(*created);
    REQUIRE(created_response.has_value());
    REQUIRE(created_response->result.has_value());
    wire_test::session_record_result created_record;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        created_record, created_response->result->str
    ));
    REQUIRE(created_record.schema_version == 1);
    REQUIRE(created_record.session_id == "session-17");
    REQUIRE(created_record.controller_plan_digest == plan_digest);
    REQUIRE(created_record.plan_content_digest.size() == 64);
    REQUIRE(created_record.state == "created");
    REQUIRE(created_record.policy_revision == 7);

    auto create_replay = (*planned_protocol)
                             ->handle_frame(
                                 make_request(
                                     "create-replay",
                                     "create_session",
                                     bootstrap_secret,
                                     create_payload,
                                     "create-session-17"
                                 ),
                                 1'001
                             );
    REQUIRE(create_replay.has_value());
    auto create_replay_response = decode_response(*create_replay);
    REQUIRE(create_replay_response.has_value());
    REQUIRE(create_replay_response->result.has_value());
    REQUIRE(create_replay_response->result->str == created_response->result->str);

    auto status = (*planned_protocol)
                      ->handle_frame(
                          make_request(
                              "status-session",
                              "session_status",
                              bootstrap_secret,
                              "{\"session_id\":\"session-17\"}"
                          ),
                          1'001
                      );
    REQUIRE(status.has_value());
    auto status_response = decode_response(*status);
    REQUIRE(status_response.has_value());
    REQUIRE(status_response->result.has_value());
    REQUIRE(status_response->result->str == created_response->result->str);

    auto keyed_status = (*planned_protocol)
                            ->handle_frame(
                                make_request(
                                    "keyed-status",
                                    "session_status",
                                    bootstrap_secret,
                                    "{\"session_id\":\"session-17\"}",
                                    "status-is-read-only"
                                ),
                                1'001
                            );
    REQUIRE(keyed_status.has_value());
    auto keyed_status_response = decode_response(*keyed_status);
    REQUIRE(keyed_status_response.has_value());
    REQUIRE(keyed_status_response->error.has_value());
    REQUIRE(keyed_status_response->error->code == "invalid_request");

    const auto genesis_json = glz::write_json(genesis);
    REQUIRE(genesis_json.has_value());
    const auto page_payload = "{\"sage_anchor\":" + *genesis_json + ",\"limit\":1000}";
    auto page_frame = (*protocol)->handle_frame(
        make_request("page-1", "verify_audit_chain", bootstrap_secret, page_payload), 1'000
    );
    REQUIRE(page_frame.has_value());
    auto page_response = decode_response(*page_frame);
    REQUIRE(page_response.has_value());
    REQUIRE(page_response->result.has_value());
    REQUIRE(!page_response->error.has_value());
    page_result page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(page, page_response->result->str));
    REQUIRE(page.schema_version == 1);
    REQUIRE(page.envelopes.size() == 15);
    REQUIRE(page.envelopes.front() == terminals.front());
    REQUIRE(page.envelopes.back() == terminals[14]);
    REQUIRE(page.has_more);
    REQUIRE(page.local_anchor == terminal_anchor);
    REQUIRE(!(*recovered)->bootstrap_reconciled());

    const glove::container::receipt_audit_anchor first_page_anchor{
        .key_id = page.envelopes.back().key_id,
        .sequence = page.envelopes.back().sequence,
        .head_hmac = page.envelopes.back().this_hmac,
    };
    const auto first_page_anchor_json = glz::write_json(first_page_anchor);
    REQUIRE(first_page_anchor_json.has_value());
    const auto final_page_payload =
        "{\"sage_anchor\":" + *first_page_anchor_json + ",\"limit\":1000}";
    auto final_page_frame = (*protocol)->handle_frame(
        make_request("page-2", "verify_audit_chain", bootstrap_secret, final_page_payload), 1'000
    );
    REQUIRE(final_page_frame.has_value());
    auto final_page_response = decode_response(*final_page_frame);
    REQUIRE(final_page_response.has_value());
    REQUIRE(final_page_response->result.has_value());
    page_result final_page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        final_page, final_page_response->result->str
    ));
    REQUIRE(final_page.envelopes.size() == 1);
    REQUIRE(final_page.envelopes.front() == terminals.back());
    REQUIRE(!final_page.has_more);
    REQUIRE(final_page.local_anchor == terminal_anchor);
    REQUIRE(!(*recovered)->bootstrap_reconciled());

    auto denied = (*protocol)->handle_frame(
        make_request(
            "ack-denied",
            "acknowledge_audit_chain",
            std::string(64, 'e'),
            "{}",
            "receipt-ack-denied"
        ),
        1'000
    );
    REQUIRE(denied.has_value());
    auto denied_response = decode_response(*denied);
    REQUIRE(denied_response.has_value());
    REQUIRE(denied_response->error.has_value());
    REQUIRE(denied_response->error->code == "unauthorized");
    REQUIRE(!(*recovered)->bootstrap_reconciled());

    const auto terminal_anchor_json = glz::write_json(terminal_anchor);
    REQUIRE(terminal_anchor_json.has_value());
    const auto ack_payload = "{\"anchor\":" + *terminal_anchor_json + "}";
    const auto ack_request = make_request(
        "ack-1", "acknowledge_audit_chain", bootstrap_secret, ack_payload, "receipt-ack-1"
    );
    auto ack_frame = (*protocol)->handle_frame(ack_request, 1'000);
    REQUIRE(ack_frame.has_value());
    auto ack_response = decode_response(*ack_frame);
    REQUIRE(ack_response.has_value());
    REQUIRE(ack_response->result.has_value());
    acknowledgement_result acknowledgement;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        acknowledgement, ack_response->result->str
    ));
    REQUIRE(acknowledgement.acknowledged_anchor == terminal_anchor);
    REQUIRE((*recovered)->bootstrap_reconciled());

    const auto replay_request = make_request(
        "ack-2", "acknowledge_audit_chain", bootstrap_secret, ack_payload, "receipt-ack-1"
    );
    auto replay = (*protocol)->handle_frame(replay_request, 1'001);
    REQUIRE(replay.has_value());
    auto replay_response = decode_response(*replay);
    REQUIRE(replay_response.has_value());
    REQUIRE(replay_response->id == "ack-2");
    REQUIRE(replay_response->result.has_value());
    REQUIRE(replay_response->result->str == ack_response->result->str);

    const auto conflicting_payload = "{\"anchor\":" + *genesis_json + "}";
    auto conflict = (*protocol)->handle_frame(
        make_request(
            "ack-conflict",
            "acknowledge_audit_chain",
            bootstrap_secret,
            conflicting_payload,
            "receipt-ack-1"
        ),
        1'001
    );
    REQUIRE(conflict.has_value());
    auto conflict_response = decode_response(*conflict);
    REQUIRE(conflict_response.has_value());
    REQUIRE(conflict_response->error.has_value());
    REQUIRE(conflict_response->error->code == "idempotency_conflict");

    auto expired = (*protocol)->handle_frame(
        make_request(
            "expired", "verify_audit_chain", bootstrap_secret, page_payload, std::nullopt, 999
        ),
        1'000
    );
    REQUIRE(expired.has_value());
    auto expired_response = decode_response(*expired);
    REQUIRE(expired_response.has_value());
    REQUIRE(expired_response->error.has_value());
    REQUIRE(expired_response->error->code == "deadline_exceeded");

    auto fresh_config = config;
    fresh_config.journal_path = temp.root() / "fresh-receipts.journal";
    auto fresh_protocol =
        glove::control::receipt_audit_protocol::create(bootstrap_secret, fresh_config);
    REQUIRE(fresh_protocol.has_value());
    auto fresh_capabilities =
        (*fresh_protocol)
            ->handle_frame(
                make_request("fresh-capabilities", "capabilities", bootstrap_secret, "null"), 1'000
            );
    REQUIRE(fresh_capabilities.has_value());
    auto fresh_capabilities_response = decode_response(*fresh_capabilities);
    REQUIRE(fresh_capabilities_response.has_value());
    REQUIRE(fresh_capabilities_response->result.has_value());
    REQUIRE(!std::filesystem::exists(fresh_config.journal_path));

    auto invalid_capabilities = (*fresh_protocol)
                                    ->handle_frame(
                                        make_request(
                                            "invalid-capabilities",
                                            "capabilities",
                                            bootstrap_secret,
                                            "null",
                                            "capabilities-must-be-read-only"
                                        ),
                                        1'000
                                    );
    REQUIRE(invalid_capabilities.has_value());
    auto invalid_capabilities_response = decode_response(*invalid_capabilities);
    REQUIRE(invalid_capabilities_response.has_value());
    REQUIRE(invalid_capabilities_response->error.has_value());
    REQUIRE(invalid_capabilities_response->error->code == "invalid_request");
    REQUIRE(!std::filesystem::exists(fresh_config.journal_path));

    const auto genesis_ack_payload = "{\"anchor\":" + *genesis_json + "}";
    auto premature_ack = (*fresh_protocol)
                             ->handle_frame(
                                 make_request(
                                     "fresh-ack-before-page",
                                     "acknowledge_audit_chain",
                                     bootstrap_secret,
                                     genesis_ack_payload,
                                     "fresh-receipt-ack"
                                 ),
                                 1'000
                             );
    REQUIRE(premature_ack.has_value());
    auto premature_ack_response = decode_response(*premature_ack);
    REQUIRE(premature_ack_response.has_value());
    REQUIRE(premature_ack_response->error.has_value());
    REQUIRE(premature_ack_response->error->code == "audit_reconciliation_failed");
    REQUIRE(!std::filesystem::exists(fresh_config.journal_path));

    auto fresh_page =
        (*fresh_protocol)
            ->handle_frame(
                make_request("fresh-page", "verify_audit_chain", bootstrap_secret, page_payload),
                1'000
            );
    REQUIRE(fresh_page.has_value());
    auto fresh_page_response = decode_response(*fresh_page);
    REQUIRE(fresh_page_response.has_value());
    REQUIRE(fresh_page_response->result.has_value());
    page_result empty_page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        empty_page, fresh_page_response->result->str
    ));
    REQUIRE(empty_page.envelopes.empty());
    REQUIRE(!empty_page.has_more);
    REQUIRE(empty_page.local_anchor == genesis);
    REQUIRE(std::filesystem::exists(fresh_config.journal_path));

    auto fresh_ack = (*fresh_protocol)
                         ->handle_frame(
                             make_request(
                                 "fresh-ack",
                                 "acknowledge_audit_chain",
                                 bootstrap_secret,
                                 genesis_ack_payload,
                                 "fresh-receipt-ack"
                             ),
                             1'000
                         );
    REQUIRE(fresh_ack.has_value());
    auto fresh_ack_response = decode_response(*fresh_ack);
    REQUIRE(fresh_ack_response.has_value());
    REQUIRE(fresh_ack_response->result.has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
