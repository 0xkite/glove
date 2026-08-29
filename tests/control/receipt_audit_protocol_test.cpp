#include "glove/container/digest.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/path_exposure.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "receipt_audit_wire.hpp"
#include "remote_session_runtime.hpp"

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
#include <span>
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
constexpr std::string_view intent_bootstrap_secret =
    "9999999999999999999999999999999999999999999999999999999999999999";
constexpr std::string_view plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view intent_controller_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

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

auto refinement_receipt() -> glove::container::refinement_evaluation_receipt {
    using namespace glove::container;
    refinement_outcome outcome{
        .schema = std::string{refinement_outcome_schema},
        .encoding = std::string{refinement_outcome_encoding},
        .metrics = {{"failed_assertions", 0}, {"latency_us", 750'000}, {"passed", 1}},
    };
    const auto outcome_bytes = canonical_refinement_outcome_bytes(outcome).value();
    const auto outcome_digest = sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(outcome_bytes.data()), outcome_bytes.size()
        }
    );
    return {
        .schema_version = refinement_evaluation_receipt_schema_version,
        .runtime_template_id = std::string{refinement_runtime_template_id},
        .resource_receipt = receipt(),
        .evidence_status = refinement_evidence_status::valid_outcome,
        .variant = refinement_variant::candidate,
        .fixture = {"fixture", std::string(64, 'f'), "fixtures"},
        .base = {"base", std::string(64, 'b'), "skills"},
        .candidate = {"candidate", std::string(64, 'c'), "skills"},
        .matched_context_digest = std::string(64, 'd'),
        .outcome =
            {
                .schema = outcome.schema,
                .encoding = outcome.encoding,
                .digest = *outcome_digest,
                .byte_length = outcome_bytes.size(),
            },
        .evaluated_outcome = outcome,
        .transcript =
            {
                .schema = std::string{raw_pty_transcript_schema},
                .digest = std::string(64, 'e'),
                .byte_count = 1'024,
                .complete = true,
            },
        .evaluator = {
            .schema = std::string{refinement_evaluator_schema},
            .fixture_complete = true,
            .transcript_utf8 = true,
            .required_literals = 1,
            .forbidden_literals = 1,
        },
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
    std::vector<glove::container::authenticated_refinement_evaluation_receipt> refinement_envelopes;
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
    std::vector<std::string> managed_runtime_ids;
    std::uint8_t path_exposure_admin_schema_version = 0;
    std::uint8_t path_exposure_catalog_schema_version = 0;
    std::uint8_t retained_write_schema_version = 0;
    std::uint8_t change_manifest_schema_version = 0;
    std::uint8_t change_apply_authorization_schema_version = 0;
    std::uint8_t refinement_evaluation_protocol_schema_version = 0;
    std::uint8_t observation_intent_channel_schema_version = 0;
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

struct observation_intent_body_wire {
    std::string schema;
    std::string intent_id;
    std::string observation;
    std::string value_digest;
    std::uint64_t item_count = 0;
};

struct observation_intent_context_wire {
    std::string session_id;
    std::string controller_plan_digest;
    std::string profile_digest;
    std::string runtime_id;
    std::string projection_digest;
    std::uint64_t policy_revision = 0;
    std::string channel_id;
    std::uint64_t channel_generation = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
};

struct observation_intent_queue_item_wire {
    std::uint64_t sequence = 0;
    observation_intent_body_wire body;
    observation_intent_context_wire context;
    std::string intent_digest;
    std::string disposition;
    std::uint64_t decided_at_ms = 0;
};

struct page_observation_intents_result {
    std::uint8_t schema_version = 0;
    std::vector<observation_intent_queue_item_wire> items;
    std::optional<std::uint64_t> next_after_sequence;
};

struct observation_intent_disposition_result {
    std::uint8_t schema_version = 0;
    observation_intent_queue_item_wire item;
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
                        .adoption = std::nullopt,
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
            .secret_mounts = {},
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

auto library_bundle_digest() -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(library_bundle.data());
    return glove::container::sha256_hex(std::span{bytes, library_bundle.size()}).value_or("");
}

auto intent_launch_template() -> glove::supervisor::runtime_launch_template {
    return {
        .runtime_discovery = {},
        .executable_path = "/usr/bin/true",
        .executable_search_paths = {},
        .arguments = {"--version"},
        .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
        .read_only_paths = {},
    };
}

auto intent_runtime_digest() -> std::string {
    return glove::supervisor::runtime_launch_template_digest(intent_launch_template()).value_or("");
}

auto intent_valid_plan_at(std::uint64_t now_ms) -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
           intent_runtime_digest() +
           R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":")" +
           library_bundle_digest() +
           R"(","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":)" +
           std::to_string(now_ms + 120'000) + "}";
}

auto intent_sage_guest_plan_at(std::uint64_t now_ms) -> std::string {
    auto plan = intent_valid_plan_at(now_ms);
    for (const auto& [from, to] : {
             std::pair{std::string_view{"\"runtime_id\":\"codex\""},
                       std::string_view{"\"runtime_id\":\"sage-guest\""}},
             std::pair{std::string_view{"\"runtime_template_id\":\"codex-safe\""},
                       std::string_view{"\"runtime_template_id\":\"sage-guest-safe\""}},
             std::pair{std::string_view{"\"secret_handles\":[\"codex-token\"]"},
                       std::string_view{"\"secret_handles\":[]"}},
         }) {
        const auto offset = plan.find(from);
        if (offset != std::string::npos) {
            plan.replace(offset, from.size(), to);
        }
    }
    return plan;
}

auto intent_validator_for(const std::filesystem::path& source)
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
                        .adapter_command_digest = intent_runtime_digest(),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = intent_launch_template(),
                        .adoption = std::nullopt,
                    },
                    runtime_template_policy{
                        .runtime_template_id = "sage-guest-safe",
                        .runtime_id = "sage-guest",
                        .adapter_command_digest = intent_runtime_digest(),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = intent_launch_template(),
                        .adoption = std::nullopt,
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
            .secret_mounts = {},
        },
        std::move(*paths)
    );
}

auto intent_cgroup_identity(std::uint32_t pid) -> glove::control::linux_cgroup_recovery_identity {
    return {
        .schema_version = 1,
        .device = 42,
        .inode = 20'000U + pid,
    };
}

auto intent_filesystem_identity() -> glove::control::linux_filesystem_recovery_identity {
    return {
        .schema_version = 1,
        .disk_limit_bytes = 2'097'152,
        .partitions = {{.alias = "workspace", .quota_bytes = 1'048'576}},
    };
}

auto intent_process_identity(std::uint32_t pid) -> glove::control::linux_process_identity {
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

auto response_excludes_sensitive_material(std::string_view frame) -> bool {
    return frame.find("codex-token") == std::string_view::npos &&
           frame.find("\"secret_handles\"") == std::string_view::npos &&
           frame.find("\"path_grants\"") == std::string_view::npos &&
           frame.find("\"bootstrap_secret\"") == std::string_view::npos &&
           frame.find(intent_bootstrap_secret) == std::string_view::npos &&
           frame.find("\"runtime_template_id\"") == std::string_view::npos &&
           frame.find("\"plan\"") == std::string_view::npos &&
           frame.find("intent-source") == std::string_view::npos;
}

auto run_observation_intent_control_contract() -> int {
    using wire_test::observation_intent_disposition_result;
    using wire_test::page_observation_intents_result;
    using wire_test::supervisor_capabilities;
    constexpr std::uint64_t intent_deadline_ms = 60'000;
    const auto intent_request =
        [](std::string_view id,
           std::string_view method,
           std::string_view payload,
           std::optional<std::string_view> idempotency_key = std::nullopt) {
            return make_request(
                id, method, intent_bootstrap_secret, payload, idempotency_key, intent_deadline_ms
            );
        };
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "intent-source";
    REQUIRE(std::filesystem::create_directory(source));
    auto validator = intent_validator_for(source);
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

    const auto intent_key_path = temp.root() / "intent-receipt.key";
    REQUIRE(write_owner_only(intent_key_path, audit_key));
    auto intent_producer = glove::container::receipt_audit_producer::initialize({
        .key_path = intent_key_path,
        .journal_path = temp.root() / "intent-receipts.journal",
    });
    REQUIRE(intent_producer.has_value());
    REQUIRE((*intent_producer)->acknowledge_bootstrap((*intent_producer)->anchor()).has_value());

    auto registry = glove::control::session_registry::open_or_create(
        temp.root() / "intent-sessions.journal", shared_validator, shared_bundle_store
    );
    REQUIRE(registry.has_value());
    auto shared_sessions =
        std::shared_ptr<glove::control::session_registry>{std::move(*registry)};

    auto intent_protocol = glove::control::receipt_audit_protocol::create(
        intent_bootstrap_secret, *intent_producer, shared_validator, shared_sessions
    );
    REQUIRE(intent_protocol.has_value());

    auto capabilities_frame =
        (*intent_protocol)
            ->handle_frame(intent_request("intent-capabilities", "capabilities", "null"), 50'000);
    REQUIRE(capabilities_frame.has_value());
    auto capabilities_response = decode_response(*capabilities_frame);
    REQUIRE(capabilities_response.has_value());
    REQUIRE(capabilities_response->result.has_value());
    supervisor_capabilities capability_set;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        capability_set, capabilities_response->result->str
    ));
    REQUIRE(capability_set.observation_intent_channel_schema_version == 1);

    auto unauthorized_page = (*intent_protocol)->handle_frame(
        make_request(
            "intent-page-unauthorized",
            "page_observation_intents",
            std::string(64, 'f'),
            "{\"after_sequence\":0,\"limit\":1}",
            std::nullopt,
            intent_deadline_ms
        ),
        50'000
    );
    REQUIRE(unauthorized_page.has_value());
    auto unauthorized_page_response = decode_response(*unauthorized_page);
    REQUIRE(unauthorized_page_response.has_value());
    REQUIRE(unauthorized_page_response->error.has_value());
    REQUIRE(unauthorized_page_response->error->code == "unauthorized");

    auto keyed_page = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-keyed",
            "page_observation_intents",
            "{\"after_sequence\":0,\"limit\":1}",
            "page-must-be-read-only"
        ),
        50'000
    );
    REQUIRE(keyed_page.has_value());
    auto keyed_page_response = decode_response(*keyed_page);
    REQUIRE(keyed_page_response.has_value());
    REQUIRE(keyed_page_response->error.has_value());
    REQUIRE(keyed_page_response->error->code == "invalid_request");

    auto missing_limit = (*intent_protocol)->handle_frame(
        intent_request("intent-page-missing-limit", "page_observation_intents", "{\"after_sequence\":0}"),
        50'000
    );
    REQUIRE(missing_limit.has_value());
    auto missing_limit_response = decode_response(*missing_limit);
    REQUIRE(missing_limit_response.has_value());
    REQUIRE(missing_limit_response->error.has_value());
    REQUIRE(missing_limit_response->error->code == "invalid_request");

    auto missing_after_sequence = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-missing-after", "page_observation_intents", "{\"limit\":1}"
        ),
        50'000
    );
    REQUIRE(missing_after_sequence.has_value());
    auto missing_after_sequence_response = decode_response(*missing_after_sequence);
    REQUIRE(missing_after_sequence_response.has_value());
    REQUIRE(missing_after_sequence_response->error.has_value());
    REQUIRE(missing_after_sequence_response->error->code == "invalid_request");

    auto unknown_page_field = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-unknown",
            "page_observation_intents",
            "{\"after_sequence\":0,\"limit\":1,\"now_ms\":1}"
        ),
        50'000
    );
    REQUIRE(unknown_page_field.has_value());
    auto unknown_page_field_response = decode_response(*unknown_page_field);
    REQUIRE(unknown_page_field_response.has_value());
    REQUIRE(unknown_page_field_response->error.has_value());
    REQUIRE(unknown_page_field_response->error->code == "invalid_request");

    auto zero_limit = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-zero", "page_observation_intents", "{\"after_sequence\":0,\"limit\":0}"
        ),
        50'000
    );
    REQUIRE(zero_limit.has_value());
    auto zero_limit_response = decode_response(*zero_limit);
    REQUIRE(zero_limit_response.has_value());
    REQUIRE(zero_limit_response->error.has_value());
    REQUIRE(zero_limit_response->error->code == "invalid_request");

    auto oversize_limit = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-oversize",
            "page_observation_intents",
            std::string{"{\"after_sequence\":0,\"limit\":"} +
                std::to_string(glove::control::max_pending_intent_page_size + 1U) + "}"
        ),
        50'000
    );
    REQUIRE(oversize_limit.has_value());
    auto oversize_limit_response = decode_response(*oversize_limit);
    REQUIRE(oversize_limit_response.has_value());
    REQUIRE(oversize_limit_response->error.has_value());
    REQUIRE(oversize_limit_response->error->code == "invalid_request");

    auto missing_disposition_key =
        (*intent_protocol)
            ->handle_frame(
                intent_request(
                    "intent-disposition-no-key",
                    "set_observation_intent_disposition",
                    "{\"session_id\":\"missing\",\"channel_generation\":1,\"intent_id\":\"intent-1\","
                    "\"intent_digest\":\"" +
                        std::string(64, 'a') +
                        "\",\"disposition\":\"accepted\",\"decided_at_ms\":50000}"
                ),
                50'000
            );
    REQUIRE(missing_disposition_key.has_value());
    auto missing_disposition_key_response = decode_response(*missing_disposition_key);
    REQUIRE(missing_disposition_key_response.has_value());
    REQUIRE(missing_disposition_key_response->error.has_value());
    REQUIRE(missing_disposition_key_response->error->code == "invalid_request");

    auto timestamped_disposition = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-timestamp",
            "set_observation_intent_disposition",
            "{\"session_id\":\"missing\",\"channel_generation\":1,\"intent_id\":\"intent-1\","
            "\"intent_digest\":\"" +
                std::string(64, 'a') +
                "\",\"disposition\":\"accepted\",\"decided_at_ms\":50001}",
            "intent-disposition-timestamp"
        ),
        50'000
    );
    REQUIRE(timestamped_disposition.has_value());
    auto timestamped_disposition_response = decode_response(*timestamped_disposition);
    REQUIRE(timestamped_disposition_response.has_value());
    REQUIRE(timestamped_disposition_response->error.has_value());
    REQUIRE(timestamped_disposition_response->error->code == "invalid_request");

    const std::string session_id = "intent-session";
    const std::uint64_t start_ms = 50'000;
    auto created = shared_sessions->create(
        session_id,
        intent_controller_digest,
        intent_sage_guest_plan_at(start_ms),
        "create-intent-session",
        start_ms
    );
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-intent-session",
        .session_id = session_id,
        .controller_plan_digest = std::string{intent_controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = start_ms + 1U,
        .expires_at_ms = start_ms + 60'000U,
    };
    auto reserved = shared_sessions->reserve_start(
        authorization, "reserve-intent-session", start_ms + 2U
    );
    REQUIRE(reserved.has_value());
    const glove::control::session_execution_binding binding{
        .schema_version = 1,
        .session_id = session_id,
        .controller_plan_digest = std::string{intent_controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = std::string(64, 'a'),
        .cgroup_identity = intent_cgroup_identity(6001),
        .filesystem_identity = intent_filesystem_identity(),
    };
    auto reservation = (*intent_producer)->reserve_terminal(
        binding.session_id, binding.controller_plan_digest, binding.profile_digest
    );
    REQUIRE(reservation.has_value());
    auto starting = shared_sessions->mark_starting(
        binding, *reservation, "starting-intent-session", start_ms + 3U
    );
    REQUIRE(starting.has_value());
    glove::control::session_running_commitment running{
        .schema_version = 1,
        .session_id = session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = binding.profile_digest,
        .process_identity = intent_process_identity(6001),
        .filesystem_identity = binding.filesystem_identity,
    };
    auto marked_running = shared_sessions->mark_running(
        running, *reservation, "running-intent-session", start_ms + 4U
    );
    REQUIRE(marked_running.has_value());

    const glove::control::glove_observation_body body{
        .schema = "sage.glove-observation.v1",
        .intent_id = "intent-1",
        .observation = "guest-capability-inventory",
        .value_digest = std::string(64, 'd'),
        .item_count = 4,
    };
    const glove::control::observation_intent_context context{
        .session_id = session_id,
        .controller_plan_digest = running.controller_plan_digest,
        .profile_digest = running.profile_digest,
        .runtime_id = "sage-guest",
        .projection_digest = std::string(64, 'c'),
        .policy_revision = 7,
        .channel_id = "intent-session-observation-v1",
        .channel_generation = 1,
        .issued_at_ms = 50'010,
        .expires_at_ms = 50'110,
    };
    auto enqueued = shared_sessions->enqueue_observation_intent(body, context, 50'010);
    REQUIRE(enqueued.has_value());

    auto second_body = body;
    second_body.intent_id = "intent-2";
    second_body.value_digest = std::string(64, 'e');
    auto second_context = context;
    second_context.issued_at_ms = 50'011;
    second_context.expires_at_ms = 50'111;
    auto second = shared_sessions->enqueue_observation_intent(second_body, second_context, 50'011);
    REQUIRE(second.has_value());

    auto expiring_body = body;
    expiring_body.intent_id = "intent-expired";
    expiring_body.value_digest = std::string(64, 'f');
    auto expiring_context = context;
    expiring_context.issued_at_ms = 50'012;
    expiring_context.expires_at_ms = 50'020;
    auto expiring =
        shared_sessions->enqueue_observation_intent(expiring_body, expiring_context, 50'012);
    REQUIRE(expiring.has_value());

    auto first_page_frame = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-first", "page_observation_intents", "{\"after_sequence\":0,\"limit\":1}"
        ),
        50'015
    );
    REQUIRE(first_page_frame.has_value());
    REQUIRE(response_excludes_sensitive_material(*first_page_frame));
    auto first_page_response = decode_response(*first_page_frame);
    REQUIRE(first_page_response.has_value());
    REQUIRE(first_page_response->result.has_value());
    page_observation_intents_result first_page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        first_page, first_page_response->result->str
    ));
    REQUIRE(first_page.schema_version == 1);
    REQUIRE(first_page.items.size() == 1U);
    REQUIRE(first_page.items.front().body.intent_id == "intent-1");
    REQUIRE(first_page.items.front().disposition == "pending");
    REQUIRE(first_page.next_after_sequence.has_value());
    REQUIRE(*first_page.next_after_sequence == first_page.items.front().sequence);

    auto second_page_frame = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-second",
            "page_observation_intents",
            std::string{"{\"after_sequence\":"} +
                std::to_string(*first_page.next_after_sequence) + ",\"limit\":1}"
        ),
        50'015
    );
    REQUIRE(second_page_frame.has_value());
    auto second_page_response = decode_response(*second_page_frame);
    REQUIRE(second_page_response.has_value());
    REQUIRE(second_page_response->result.has_value());
    page_observation_intents_result second_page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        second_page, second_page_response->result->str
    ));
    REQUIRE(second_page.items.size() == 1U);
    REQUIRE(second_page.items.front().body.intent_id == "intent-2");
    REQUIRE(second_page.items.front().sequence > first_page.items.front().sequence);
    REQUIRE(second_page.next_after_sequence.has_value());
    REQUIRE(*second_page.next_after_sequence == second_page.items.front().sequence);

    const std::string disposition_payload =
        std::string{"{\"session_id\":\""} + session_id +
        "\",\"channel_generation\":1,\"intent_id\":\"intent-1\",\"intent_digest\":\"" +
        enqueued->intent_digest +
        "\",\"disposition\":\"accepted\",\"decided_at_ms\":50020}";
    auto accepted_frame = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-accepted",
            "set_observation_intent_disposition",
            disposition_payload,
            "intent-disposition-accepted"
        ),
        50'020
    );
    REQUIRE(accepted_frame.has_value());
    REQUIRE(response_excludes_sensitive_material(*accepted_frame));
    auto accepted_response = decode_response(*accepted_frame);
    REQUIRE(accepted_response.has_value());
    REQUIRE(accepted_response->result.has_value());
    observation_intent_disposition_result accepted_result;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        accepted_result, accepted_response->result->str
    ));
    REQUIRE(accepted_result.schema_version == 1);
    REQUIRE(accepted_result.item.disposition == "accepted");
    REQUIRE(accepted_result.item.decided_at_ms == 50'020);

    auto accepted_replay = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-replay",
            "set_observation_intent_disposition",
            disposition_payload,
            "intent-disposition-accepted"
        ),
        50'021
    );
    REQUIRE(accepted_replay.has_value());
    auto accepted_replay_response = decode_response(*accepted_replay);
    REQUIRE(accepted_replay_response.has_value());
    REQUIRE(accepted_replay_response->result.has_value());
    REQUIRE(accepted_replay_response->result->str == accepted_response->result->str);

    auto restarted_protocol = glove::control::receipt_audit_protocol::create(
        intent_bootstrap_secret, *intent_producer, shared_validator, shared_sessions
    );
    REQUIRE(restarted_protocol.has_value());
    auto accepted_restart_replay = (*restarted_protocol)->handle_frame(
        intent_request(
            "intent-disposition-restart-replay",
            "set_observation_intent_disposition",
            disposition_payload,
            "intent-disposition-accepted"
        ),
        50'022
    );
    REQUIRE(accepted_restart_replay.has_value());
    auto accepted_restart_response = decode_response(*accepted_restart_replay);
    REQUIRE(accepted_restart_response.has_value());
    REQUIRE(accepted_restart_response->result.has_value());
    REQUIRE(accepted_restart_response->result->str == accepted_response->result->str);

    auto disposition_conflict = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-conflict",
            "set_observation_intent_disposition",
            std::string{"{\"session_id\":\""} + session_id +
                "\",\"channel_generation\":1,\"intent_id\":\"intent-1\",\"intent_digest\":\"" +
                enqueued->intent_digest +
                "\",\"disposition\":\"rejected\",\"decided_at_ms\":50020}",
            "intent-disposition-accepted"
        ),
        50'022
    );
    REQUIRE(disposition_conflict.has_value());
    auto disposition_conflict_response = decode_response(*disposition_conflict);
    REQUIRE(disposition_conflict_response.has_value());
    REQUIRE(disposition_conflict_response->error.has_value());
    REQUIRE(disposition_conflict_response->error->code == "idempotency_conflict");
    REQUIRE(response_excludes_sensitive_material(*disposition_conflict));

    auto missing_intent_payload =
        std::string{"{\"session_id\":\""} + session_id +
        "\",\"channel_generation\":1,\"intent_id\":\"missing-intent\",\"intent_digest\":\"" +
        std::string(64, 'b') +
        "\",\"disposition\":\"accepted\",\"decided_at_ms\":50023}";
    auto missing_intent = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-missing",
            "set_observation_intent_disposition",
            missing_intent_payload,
            "intent-disposition-missing"
        ),
        50'023
    );
    REQUIRE(missing_intent.has_value());
    auto missing_intent_response = decode_response(*missing_intent);
    REQUIRE(missing_intent_response.has_value());
    REQUIRE(missing_intent_response->error.has_value());
    REQUIRE(missing_intent_response->error->code == "observation_intent_not_found");
    REQUIRE(missing_intent_response->error->message == "observation intent was not found");
    REQUIRE(response_excludes_sensitive_material(*missing_intent));

    auto expired_disposition_payload =
        std::string{"{\"session_id\":\""} + session_id +
        "\",\"channel_generation\":1,\"intent_id\":\"intent-expired\",\"intent_digest\":\"" +
        expiring->intent_digest +
        "\",\"disposition\":\"accepted\",\"decided_at_ms\":50030}";
    auto expired_disposition = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-disposition-expired",
            "set_observation_intent_disposition",
            expired_disposition_payload,
            "intent-disposition-expired"
        ),
        50'030
    );
    REQUIRE(expired_disposition.has_value());
    auto expired_disposition_response = decode_response(*expired_disposition);
    REQUIRE(expired_disposition_response.has_value());
    REQUIRE(expired_disposition_response->error.has_value());
    REQUIRE(expired_disposition_response->error->code == "invalid_request");
    REQUIRE(expired_disposition_response->error->message == "invalid observation intent request");
    REQUIRE(response_excludes_sensitive_material(*expired_disposition));

    auto expired_page = (*intent_protocol)->handle_frame(
        intent_request(
            "intent-page-after-expiry",
            "page_observation_intents",
            "{\"after_sequence\":0,\"limit\":16}"
        ),
        50'030
    );
    REQUIRE(expired_page.has_value());
    auto expired_page_response = decode_response(*expired_page);
    REQUIRE(expired_page_response.has_value());
    REQUIRE(expired_page_response->result.has_value());
    page_observation_intents_result expired_page_result;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        expired_page_result, expired_page_response->result->str
    ));
    REQUIRE(std::ranges::none_of(expired_page_result.items, [](const auto& item) {
        return item.body.intent_id == "intent-expired";
    }));

    return 0;
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
    auto refinement_reservation = (*producer)->reserve_terminal();
    REQUIRE(refinement_reservation.has_value());
    auto refinement_terminal = (*producer)->commit_refinement_terminal(
        std::move(*refinement_reservation), "session-refinement", plan_digest, refinement_receipt()
    );
    REQUIRE(refinement_terminal.has_value());
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
    REQUIRE(capabilities.managed_runtime_ids.empty());
    REQUIRE(capabilities.path_exposure_admin_schema_version == 0);
    REQUIRE(capabilities.path_exposure_catalog_schema_version == 0);
    REQUIRE(capabilities.retained_write_schema_version == 0);
    REQUIRE(capabilities.change_manifest_schema_version == 0);
    REQUIRE(capabilities.change_apply_authorization_schema_version == 0);
    REQUIRE(capabilities.refinement_evaluation_protocol_schema_version == 0);
    REQUIRE(capabilities.observation_intent_channel_schema_version == 0);
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
    REQUIRE(capabilities.backends[1].backend == "apple_container");

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

    constexpr std::array<std::string_view, 2> unavailable_intent_methods{
        "page_observation_intents",
        "set_observation_intent_disposition",
    };
    for (const auto method : unavailable_intent_methods) {
        auto unavailable = (*protocol)->handle_frame(
            make_request(
                std::string{"unavailable-intent-"} + std::string{method},
                method,
                bootstrap_secret,
                method == "page_observation_intents" ? "{\"after_sequence\":0,\"limit\":1}"
                                                     : "{\"session_id\":\"missing\","
                                                       "\"channel_generation\":1,"
                                                       "\"intent_id\":\"intent-1\","
                                                       "\"intent_digest\":\"" +
                                                           std::string(64, 'a') +
                                                           "\",\"disposition\":\"accepted\","
                                                           "\"decided_at_ms\":1000}",
                method == "set_observation_intent_disposition"
                    ? std::optional<std::string_view>{"unavailable-intent-key"}
                    : std::nullopt
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
    REQUIRE(exposure_capability_set.refinement_evaluation_protocol_schema_version == 0);

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
    REQUIRE(planned_capability_set.observation_intent_channel_schema_version == 1);

    auto remote_runtime = glove::control::remote_session_runtime::create({
        .ssh_argv = {"/usr/bin/ssh", "-F", "/tmp/glove-remote/config", "glove-remote"},
        .executor_digest = "sha256:" + std::string(64U, 'a'),
        .container_image = "registry.example.test/glove/runtime@sha256:" + std::string(64U, 'b'),
        .container_image_digest = "sha256:" + std::string(64U, 'b'),
        .channel_timeout_ms = 5'000,
        .max_clock_skew_ms = 250,
        .max_sessions = 4,
        .staging_root = "/var/lib/glove-remote/staging",
    });
    REQUIRE(remote_runtime.has_value());
    auto remote_control = glove::control::receipt_audit_protocol::create(
        bootstrap_secret, *recovered, shared_validator, shared_sessions, *remote_runtime
    );
    REQUIRE(remote_control.has_value());
    auto remote_capabilities =
        (*remote_control)
            ->handle_frame(
                make_request("remote-capabilities", "capabilities", bootstrap_secret, "null"), 1'000
            );
    REQUIRE(remote_capabilities.has_value());
    auto remote_capabilities_response = decode_response(*remote_capabilities);
    REQUIRE(remote_capabilities_response.has_value());
    REQUIRE(remote_capabilities_response->result.has_value());
    supervisor_capabilities remote_capability_set;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        remote_capability_set, remote_capabilities_response->result->str
    ));
    REQUIRE(remote_capability_set.session_control.create_session);
    REQUIRE(remote_capability_set.session_control.session_status);
    REQUIRE(!remote_capability_set.session_control.start_session);
    REQUIRE(!remote_capability_set.session_control.attach);
    REQUIRE(!remote_capability_set.session_control.resize);
    REQUIRE(!remote_capability_set.session_control.write_stdin);
    REQUIRE(!remote_capability_set.session_control.signal);
    REQUIRE(!remote_capability_set.session_control.detach);
    REQUIRE(!remote_capability_set.session_control.stop_session);
    REQUIRE(!remote_capability_set.session_control.cleanup_session);
    REQUIRE(remote_capability_set.agent_runtime_adapter_schema_version == 0);
    REQUIRE(remote_capability_set.managed_runtime_ids.empty());
    REQUIRE(remote_capability_set.refinement_evaluation_protocol_schema_version == 0);
    REQUIRE(remote_capability_set.backends.size() == 2);
    for (const auto& backend : remote_capability_set.backends) {
        REQUIRE(backend.resource_enforcement.cpu_time == "unavailable");
        REQUIRE(backend.resource_enforcement.receipt_schema_version == 0);
    }
    constexpr std::array<std::string_view, 8> remote_unavailable_methods{
        "start_session",
        "attach",
        "resize",
        "write_stdin",
        "signal",
        "detach",
        "stop_session",
        "cleanup_session",
    };
    for (const auto method : remote_unavailable_methods) {
        auto unavailable = (*remote_control)
                               ->handle_frame(
                                   make_request(
                                       std::string{"remote-unavailable-"} + std::string{method},
                                       method,
                                       bootstrap_secret,
                                       "null",
                                       "remote-unavailable"
                                   ),
                                   1'000
                               );
        REQUIRE(unavailable.has_value());
        auto response = decode_response(*unavailable);
        REQUIRE(response.has_value());
        REQUIRE(response->error.has_value());
        REQUIRE(response->error->code == "method_not_found");
    }

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
    REQUIRE(final_page.refinement_envelopes.size() == 1);
    REQUIRE(final_page.refinement_envelopes.front() == *refinement_terminal);
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
    REQUIRE(empty_page.refinement_envelopes.empty());
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

    REQUIRE(run_observation_intent_control_contract() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
