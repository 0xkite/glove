#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "linux_session_executor.hpp"
#include "linux_session_preparation.hpp"
#include "receipt_audit_wire.hpp"

#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
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

namespace glove_test {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view controller_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view runtime_digest =
    "05a49649e7973f6f8d6b119c9d525472517e6021fb38f8b191e0b40c8c4741d0";
constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view bootstrap_secret =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

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

struct session_control_capabilities {
    bool validate_plan = false;
    bool create_session = false;
    bool start_session = false;
    bool session_status = false;
    bool attach = false;
    bool resize = false;
    bool write_stdin = false;
    bool signal = false;
    bool detach = false;
    bool stop_session = false;
    bool cleanup_session = false;
};

struct resource_enforcement_capabilities {
    std::string cpu_time;
    std::string memory;
    std::string pids;
    std::string wall_time;
    std::string disk;
    std::string terminal_output;
    std::uint8_t receipt_schema_version = 0;
};

struct backend_capabilities {
    std::string backend;
    resource_enforcement_capabilities resource_enforcement;
};

struct supervisor_capabilities {
    std::uint8_t schema_version = 0;
    glz::raw_json receipt_audit;
    session_control_capabilities session_control;
    std::uint8_t agent_runtime_adapter_schema_version = 0;
    std::vector<backend_capabilities> backends;
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

struct transcript_result {
    std::uint8_t schema_version = 0;
    std::string session_id;
    std::uint64_t oldest_cursor = 0;
    std::uint64_t next_cursor = 0;
    bool truncated = false;
    bool eof = false;
    std::vector<std::uint8_t> bytes;
};

struct session_mutation_result {
    std::uint8_t schema_version = 0;
    std::string session_id;
};

struct session_cursor_result {
    std::uint8_t schema_version = 0;
    std::string session_id;
    std::uint64_t transcript_cursor = 0;
};

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
    std::string_view payload,
    std::optional<std::string_view> idempotency_key,
    std::uint64_t deadline_ms
) -> std::string {
    std::string request =
        "{\"jsonrpc\":\"2.0\",\"id\":\"" + std::string{id} + "\",\"method\":\"" +
        std::string{method} + "\",\"params\":{\"schema_version\":1,\"bootstrap_secret\":\"" +
        std::string{bootstrap_secret} + "\",\"deadline_ms\":" + std::to_string(deadline_ms);
    if (idempotency_key) {
        request += ",\"idempotency_key\":\"" + std::string{*idempotency_key} + "\"";
    }
    request += ",\"payload\":" + std::string{payload} + "}}";
    return request;
}

auto interactive_runtime_digest() -> std::string {
    auto digest = glove::supervisor::runtime_launch_template_digest({
        .executable_path = "/usr/bin/cat",
        .arguments = {},
        .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
    });
    return digest.value_or(std::string{});
}

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-linux-executor-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto validator_for(const std::filesystem::path& source, std::uint64_t page)
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
                    .max_bytes = page * 4U,
                },
            },
        },
    });
    if (!paths) {
        return std::unexpected(paths.error());
    }
    const auto interactive_digest = interactive_runtime_digest();
    if (interactive_digest.empty()) {
        return std::unexpected(std::string{"derive interactive runtime digest"});
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
                        .adapter_command_digest = std::string{runtime_digest},
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch =
                            runtime_launch_template{
                                .executable_path = "/usr/bin/true",
                                .arguments = {"--version"},
                                .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
                            },
                    },
                    runtime_template_policy{
                        .runtime_template_id = "codex-interactive",
                        .runtime_id = "codex",
                        .adapter_command_digest = interactive_digest,
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch =
                            runtime_launch_template{
                                .executable_path = "/usr/bin/cat",
                                .arguments = {},
                                .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
                            },
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
                        .cpu_time_ms = 10'000,
                        .memory_bytes = std::uint64_t{128} * 1024U * 1024U,
                        .pids = 16,
                        .wall_time_ms = 5'000,
                        .disk_bytes = page * 16U,
                        .terminal_output_bytes = std::uint64_t{1024} * 1024U,
                    },
                },
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles = {},
        },
        std::move(*paths)
    );
}

auto plan(
    std::uint64_t now_ms, std::uint64_t page, std::string_view runtime_template_id = "codex-safe"
) -> std::string {
    const auto adapter_digest = runtime_template_id == "codex-interactive"
                                    ? interactive_runtime_digest()
                                    : std::string{runtime_digest};
    return std::string{"{\"schema_version\":1,\"runtime_id\":\"codex\","} +
           "\"runtime_template_id\":\"" + std::string{runtime_template_id} +
           "\",\"adapter_command_digest\":\"" + adapter_digest +
           "\",\"sandbox_backend\":\"linux_production\",\"egress_policy_id\":\"no-network\"," +
           "\"tool_policy_id\":\"sage-readonly\",\"path_grants\":[{\"alias\":\"workspace\"," +
           "\"access\":\"ephemeral_write\",\"materialization\":\"copy\",\"max_bytes\":" +
           std::to_string(page * 4U) +
           ",\"ttl_secs\":60,\"cleanup_policy\":\"remove\"}],\"library_projections\":[]," +
           "\"secret_handles\":[],\"limits\":{\"cpu_time_ms\":10000,\"memory_bytes\":134217728," +
           "\"pids\":16,\"wall_time_ms\":5000,\"disk_bytes\":" + std::to_string(page * 16U) +
           ",\"terminal_output_bytes\":1048576},\"policy_revision\":7,\"expires_at_ms\":" +
           std::to_string(now_ms + 120'000) + "}";
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto source = tree.root() / "source";
    const auto materializations = tree.root() / "materializations";
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(materializations));
    REQUIRE(::chmod(materializations.c_str(), 0700) == 0);
    std::ofstream{source / "tracked.txt"} << "host-owned\n";
    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const auto page = static_cast<std::uint64_t>(page_size);
    const auto now_ms = epoch_ms();

    auto validator = validator_for(source, page);
    if (!validator) {
        std::fprintf(stderr, "validator unavailable: %s\n", validator.error().c_str());
    }
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    auto registry = glove::control::session_registry::open_or_create(
        tree.root() / "sessions.journal", shared_validator
    );
    REQUIRE(registry.has_value());
    auto created = (*registry)->create(
        "session-executor", controller_digest, plan(now_ms, page), "create-session-executor", now_ms
    );
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-executor",
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = now_ms,
        .expires_at_ms = now_ms + 30'000U,
    };
    REQUIRE((*registry)
                ->reserve_start(authorization, "reserve-session-executor", now_ms + 1U)
                .has_value());

    const auto key_path = tree.root() / "receipt.key";
    {
        std::ofstream output{key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
        output.flush();
        REQUIRE(output.good());
    }
    REQUIRE(::chmod(key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = key_path,
        .journal_path = tree.root() / "receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());

    auto preparer =
        glove::control::linux_detail::linux_session_preparer::create(materializations.string());
    if (!preparer) {
        std::fprintf(stderr, "Linux executor topology unavailable: %s\n", preparer.error().c_str());
        return 77;
    }
    auto exited = glove::control::linux_detail::execute_linux_session(
        **registry,
        *preparer,
        **producer,
        {
            .session_id = created->session_id,
            .authorization_id = authorization.authorization_id,
            .idempotency_namespace = "execute-session-executor",
        }
    );
    REQUIRE(exited.has_value());
    REQUIRE(exited->session.state == glove::control::session_state::exited);
    REQUIRE(exited->session.session_id == created->session_id);
    REQUIRE(exited->receipt_sequence == 1);
    REQUIRE(exited->termination_cause == glove::container::resource_termination_cause::exited);
    REQUIRE(exited->exit_code == 0);
    REQUIRE(exited->filesystem_identity.schema_version == 1);
    REQUIRE(exited->filesystem_identity.disk_limit_bytes == page * 16U);
    REQUIRE(exited->filesystem_identity.partitions.size() == 1);
    REQUIRE(exited->filesystem_identity.partitions.front().alias == "workspace");
    REQUIRE(exited->filesystem_identity.partitions.front().quota_bytes == page * 4U);
    auto durable_exited = (*registry)->exited_status(created->session_id);
    REQUIRE(durable_exited.has_value());
    REQUIRE(*durable_exited == *exited);
    REQUIRE((*producer)->anchor().sequence == 1);
    REQUIRE(std::filesystem::is_empty(materializations));
    REQUIRE(std::filesystem::exists(source / "tracked.txt"));

    const auto crash_pid = ::fork();
    REQUIRE(crash_pid >= 0);
    if (crash_pid == 0) {
        const auto crash_now_ms = epoch_ms();
        auto crash_created = (*registry)->create(
            "session-starting-crash",
            controller_digest,
            plan(crash_now_ms, page),
            "create-session-starting-crash",
            crash_now_ms
        );
        if (!crash_created) {
            ::_exit(11);
        }
        const glove::control::session_start_authorization crash_authorization{
            .schema_version = 1,
            .authorization_id = "approval-session-starting-crash",
            .session_id = crash_created->session_id,
            .controller_plan_digest = crash_created->controller_plan_digest,
            .plan_content_digest = crash_created->plan_content_digest,
            .approved_at_ms = crash_now_ms,
            .expires_at_ms = crash_now_ms + 30'000U,
        };
        if (!(*registry)
                 ->reserve_start(
                     crash_authorization, "reserve-session-starting-crash", crash_now_ms + 1U
                 )
                 .has_value()) {
            ::_exit(12);
        }
        auto crash_inputs = (*registry)->resolve_start_inputs(
            crash_created->session_id, crash_authorization.authorization_id, crash_now_ms + 2U
        );
        if (!crash_inputs) {
            ::_exit(13);
        }
        auto crash_prepared = preparer->prepare(std::move(*crash_inputs), crash_now_ms + 2U);
        if (!crash_prepared) {
            ::_exit(14);
        }
        auto crash_receipt_reservation = (*producer)->reserve_terminal(
            crash_prepared->session_id,
            crash_prepared->controller_plan_digest,
            crash_prepared->binding.profile_digest
        );
        if (!crash_receipt_reservation) {
            ::_exit(15);
        }
        if (!(*registry)
                 ->mark_starting(
                     crash_prepared->execution_binding(),
                     *crash_receipt_reservation,
                     "starting-session-starting-crash",
                     crash_now_ms + 3U
                 )
                 .has_value()) {
            ::_exit(16);
        }
        ::_exit(0);
    }
    int crash_status = 0;
    REQUIRE(::waitpid(crash_pid, &crash_status, 0) == crash_pid);
    REQUIRE(WIFEXITED(crash_status));
    REQUIRE(WEXITSTATUS(crash_status) == 0);
    REQUIRE(!std::filesystem::is_empty(materializations));

    registry->reset();
    auto recovered_registry = glove::control::session_registry::open_or_create(
        tree.root() / "sessions.journal", shared_validator
    );
    REQUIRE(recovered_registry.has_value());
    REQUIRE(!glove::control::linux_detail::linux_session_runtime::create(
                 **recovered_registry, *preparer, {}, 0
    )
                 .has_value());
    auto session_runtime_result = glove::control::linux_detail::linux_session_runtime::create(
        **recovered_registry,
        *preparer,
        {
            .transcript_bytes = page,
            .max_read_bytes = page,
            .max_input_frame_bytes = page,
            .input_timeout_ms = 1'000,
            .initial_rows = 24,
            .initial_columns = 80,
        },
        1
    );
    REQUIRE(session_runtime_result.has_value());
    REQUIRE(!(*session_runtime_result)
                 ->start(**producer, authorization, "unreconciled-start", epoch_ms())
                 .has_value());
    auto reconciliation = (*session_runtime_result)->reconcile(**producer, epoch_ms() + 1U);
    REQUIRE(reconciliation.has_value());
    REQUIRE(reconciliation->inspected == 1);
    REQUIRE(reconciliation->recovered_failed == 1);
    REQUIRE(reconciliation->recovered_exited == 0);
    REQUIRE(reconciliation->recovered_terminated == 0);
    REQUIRE((*session_runtime_result)->reconcile(**producer, epoch_ms() + 2U) == reconciliation);
    auto recovered_failure = (*recovered_registry)->failed_status("session-starting-crash");
    REQUIRE(recovered_failure.has_value());
    REQUIRE(
        recovered_failure->code == glove::control::session_failure_code::recovered_without_process
    );
    REQUIRE(!recovered_failure->process_identity);
    REQUIRE(recovered_failure->cgroup_identity.has_value());
    REQUIRE(recovered_failure->filesystem_identity.has_value());
    REQUIRE(std::filesystem::is_empty(materializations));
    REQUIRE(std::filesystem::exists(source / "tracked.txt"));

    auto shared_registry =
        std::shared_ptr<glove::control::session_registry>{std::move(*recovered_registry)};
    auto shared_producer =
        std::shared_ptr<glove::container::receipt_audit_producer>{std::move(*producer)};

    const auto interactive_now_ms = epoch_ms();
    auto interactive_created = shared_registry->create(
        "session-interactive",
        controller_digest,
        plan(interactive_now_ms, page, "codex-interactive"),
        "create-session-interactive",
        interactive_now_ms
    );
    REQUIRE(interactive_created.has_value());
    const glove::control::session_start_authorization interactive_authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-interactive",
        .session_id = interactive_created->session_id,
        .controller_plan_digest = interactive_created->controller_plan_digest,
        .plan_content_digest = interactive_created->plan_content_digest,
        .approved_at_ms = interactive_now_ms,
        .expires_at_ms = interactive_now_ms + 30'000U,
    };
    auto wire_runtime_result = glove::control::linux_detail::linux_session_runtime::create(
        *shared_registry,
        *preparer,
        {
            .transcript_bytes = page,
            .max_read_bytes = page,
            .max_input_frame_bytes = page,
            .input_timeout_ms = 1'000,
            .initial_rows = 24,
            .initial_columns = 80,
        },
        1
    );
    REQUIRE(wire_runtime_result.has_value());
    auto session_runtime = std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
        std::move(*wire_runtime_result)
    };
    auto protocol = glove::control::receipt_audit_protocol::create(
        bootstrap_secret, shared_producer, shared_validator, shared_registry, session_runtime
    );
    REQUIRE(protocol.has_value());
    auto capabilities_frame = (*protocol)->handle_frame(
        make_request(
            "runtime-capabilities",
            "capabilities",
            "null",
            std::nullopt,
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms
    );
    REQUIRE(capabilities_frame.has_value());
    auto capabilities_response = decode_response(*capabilities_frame);
    REQUIRE(capabilities_response.has_value());
    REQUIRE(capabilities_response->result.has_value());
    supervisor_capabilities capabilities;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        capabilities, capabilities_response->result->str
    ));
    REQUIRE(capabilities.schema_version == 1);
    REQUIRE(capabilities.session_control.start_session);
    REQUIRE(capabilities.session_control.stop_session);
    REQUIRE(capabilities.session_control.attach);
    REQUIRE(capabilities.session_control.resize);
    REQUIRE(capabilities.session_control.write_stdin);
    REQUIRE(capabilities.session_control.signal);
    REQUIRE(capabilities.session_control.detach);
    REQUIRE(capabilities.session_control.cleanup_session);
    REQUIRE(capabilities.agent_runtime_adapter_schema_version == 0);
    REQUIRE(capabilities.backends.size() == 2);
    REQUIRE(capabilities.backends[0].backend == "linux_production");
    REQUIRE(capabilities.backends[0].resource_enforcement.cpu_time == "cgroup_v2");
    REQUIRE(capabilities.backends[0].resource_enforcement.memory == "cgroup_v2");
    REQUIRE(capabilities.backends[0].resource_enforcement.pids == "cgroup_v2");
    REQUIRE(capabilities.backends[0].resource_enforcement.wall_time == "watchdog");
    REQUIRE(capabilities.backends[0].resource_enforcement.disk == "filesystem_quota");
    REQUIRE(capabilities.backends[0].resource_enforcement.terminal_output == "byte_counter");
    REQUIRE(capabilities.backends[0].resource_enforcement.receipt_schema_version == 1);
    REQUIRE(capabilities.backends[1].backend == "macos_experimental");
    REQUIRE(capabilities.backends[1].resource_enforcement.cpu_time == "unavailable");

    auto authorization_json = glz::write_json(interactive_authorization);
    REQUIRE(authorization_json.has_value());
    const auto start_payload = "{\"authorization\":" + *authorization_json + "}";
    auto missing_start_idempotency = (*protocol)->handle_frame(
        make_request(
            "start-interactive-without-key",
            "start_session",
            start_payload,
            std::nullopt,
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 1U
    );
    REQUIRE(missing_start_idempotency.has_value());
    auto missing_start_response = decode_response(*missing_start_idempotency);
    REQUIRE(missing_start_response.has_value());
    REQUIRE(missing_start_response->error.has_value());
    REQUIRE(missing_start_response->error->code == "invalid_request");
    REQUIRE(session_runtime->list()->empty());
    auto start_frame = (*protocol)->handle_frame(
        make_request(
            "start-interactive",
            "start_session",
            start_payload,
            "execute-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 1U
    );
    REQUIRE(start_frame.has_value());
    auto start_response = decode_response(*start_frame);
    REQUIRE(start_response.has_value());
    REQUIRE(start_response->result.has_value());
    session_record_result interactive_running;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        interactive_running, start_response->result->str
    ));
    REQUIRE(interactive_running.session_id == interactive_created->session_id);
    REQUIRE(interactive_running.state == "running");
    auto interactive_running_status =
        shared_registry->running_status(interactive_created->session_id);
    REQUIRE(interactive_running_status.has_value());
    REQUIRE(
        interactive_running.profile_digest ==
        std::optional<std::string>{interactive_running_status->profile_digest}
    );
    auto start_replay_frame = (*protocol)->handle_frame(
        make_request(
            "start-interactive-replay",
            "start_session",
            start_payload,
            "execute-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 2U
    );
    REQUIRE(start_replay_frame.has_value());
    auto start_replay_response = decode_response(*start_replay_frame);
    REQUIRE(start_replay_response.has_value());
    REQUIRE(start_replay_response->result.has_value());
    REQUIRE(start_replay_response->result->str == start_response->result->str);
    REQUIRE(session_runtime->list() == std::vector<std::string>{"session-interactive"});
    REQUIRE(!session_runtime->cleanup(interactive_created->session_id).has_value());
    const std::string input_text = "interactive control\n";
    const std::vector<std::uint8_t> input_bytes{input_text.begin(), input_text.end()};
    auto input_json = glz::write_json(input_bytes);
    REQUIRE(input_json.has_value());
    const auto input_payload = "{\"session_id\":\"" + interactive_created->session_id +
                               "\",\"bytes\":" + *input_json + "}";
    auto input_frame = (*protocol)->handle_frame(
        make_request(
            "input-interactive",
            "write_stdin",
            input_payload,
            "input-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 2U
    );
    REQUIRE(input_frame.has_value());
    auto input_response = decode_response(*input_frame);
    REQUIRE(input_response.has_value());
    REQUIRE(input_response->result.has_value());
    session_mutation_result input_result;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        input_result, input_response->result->str
    ));
    REQUIRE(input_result.schema_version == 1);
    REQUIRE(input_result.session_id == interactive_created->session_id);
    auto input_replay_frame = (*protocol)->handle_frame(
        make_request(
            "input-interactive-replay",
            "write_stdin",
            input_payload,
            "input-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 3U
    );
    REQUIRE(input_replay_frame.has_value());
    auto input_replay_response = decode_response(*input_replay_frame);
    REQUIRE(input_replay_response.has_value());
    REQUIRE(input_replay_response->result.has_value());
    REQUIRE(input_replay_response->result->str == input_response->result->str);
    const auto conflicting_input_payload =
        "{\"session_id\":\"" + interactive_created->session_id + "\",\"bytes\":[120]}";
    auto input_conflict_frame = (*protocol)->handle_frame(
        make_request(
            "input-interactive-conflict",
            "write_stdin",
            conflicting_input_payload,
            "input-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 4U
    );
    REQUIRE(input_conflict_frame.has_value());
    auto input_conflict_response = decode_response(*input_conflict_frame);
    REQUIRE(input_conflict_response.has_value());
    REQUIRE(input_conflict_response->error.has_value());
    REQUIRE(input_conflict_response->error->code == "idempotency_conflict");
    auto interactive_output =
        session_runtime->wait_read(interactive_created->session_id, 0, page, 1'000);
    REQUIRE(interactive_output.has_value());
    REQUIRE(interactive_output->bytes.find("interactive control") != std::string::npos);
    const auto attach_payload = "{\"session_id\":\"" + interactive_created->session_id +
                                "\",\"cursor\":0,\"max_bytes\":" + std::to_string(page) + "}";
    auto attach_frame = (*protocol)->handle_frame(
        make_request(
            "attach-interactive",
            "attach",
            attach_payload,
            std::nullopt,
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 5U
    );
    REQUIRE(attach_frame.has_value());
    auto attach_response = decode_response(*attach_frame);
    REQUIRE(attach_response.has_value());
    REQUIRE(attach_response->result.has_value());
    transcript_result attached;
    REQUIRE(
        !glz::read<glz::opts{.error_on_unknown_keys = true}>(attached, attach_response->result->str)
    );
    REQUIRE(attached.schema_version == 1);
    REQUIRE(attached.session_id == interactive_created->session_id);
    REQUIRE(attached.oldest_cursor == interactive_output->oldest_cursor);
    REQUIRE(attached.next_cursor >= attached.oldest_cursor);
    REQUIRE(attached.next_cursor >= interactive_output->next_cursor);
    REQUIRE(!attached.truncated);
    const std::string attached_text{attached.bytes.begin(), attached.bytes.end()};
    REQUIRE(attached_text.find("interactive control") != std::string::npos);
    const auto detach_payload = "{\"session_id\":\"" + interactive_created->session_id +
                                "\",\"transcript_cursor\":" + std::to_string(attached.next_cursor) +
                                "}";
    auto detach_frame = (*protocol)->handle_frame(
        make_request(
            "detach-interactive",
            "detach",
            detach_payload,
            "detach-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 6U
    );
    REQUIRE(detach_frame.has_value());
    auto detach_response = decode_response(*detach_frame);
    REQUIRE(detach_response.has_value());
    REQUIRE(detach_response->result.has_value());
    session_cursor_result detached;
    REQUIRE(
        !glz::read<glz::opts{.error_on_unknown_keys = true}>(detached, detach_response->result->str)
    );
    REQUIRE(detached.schema_version == 1);
    REQUIRE(detached.session_id == interactive_created->session_id);
    REQUIRE(detached.transcript_cursor == attached.next_cursor);
    const auto invalid_signal_payload =
        "{\"session_id\":\"" + interactive_created->session_id + "\",\"signal\":\"kill\"}";
    auto invalid_signal_frame = (*protocol)->handle_frame(
        make_request(
            "signal-interactive-invalid",
            "signal",
            invalid_signal_payload,
            "signal-session-interactive-invalid",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 7U
    );
    REQUIRE(invalid_signal_frame.has_value());
    auto invalid_signal_response = decode_response(*invalid_signal_frame);
    REQUIRE(invalid_signal_response.has_value());
    REQUIRE(invalid_signal_response->error.has_value());
    REQUIRE(invalid_signal_response->error->code == "invalid_request");
    const auto resize_payload =
        "{\"session_id\":\"" + interactive_created->session_id + "\",\"rows\":50,\"columns\":140}";
    auto resize_frame = (*protocol)->handle_frame(
        make_request(
            "resize-interactive",
            "resize",
            resize_payload,
            "resize-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 6U
    );
    REQUIRE(resize_frame.has_value());
    auto resize_response = decode_response(*resize_frame);
    REQUIRE(resize_response.has_value());
    REQUIRE(resize_response->result.has_value());
    session_mutation_result resize_result;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        resize_result, resize_response->result->str
    ));
    REQUIRE(resize_result.schema_version == 1);
    REQUIRE(resize_result.session_id == interactive_created->session_id);
    auto resize_replay_frame = (*protocol)->handle_frame(
        make_request(
            "resize-interactive-replay",
            "resize",
            resize_payload,
            "resize-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 7U
    );
    REQUIRE(resize_replay_frame.has_value());
    auto resize_replay_response = decode_response(*resize_replay_frame);
    REQUIRE(resize_replay_response.has_value());
    REQUIRE(resize_replay_response->result.has_value());
    REQUIRE(resize_replay_response->result->str == resize_response->result->str);
    const auto stop_payload = "{\"session_id\":\"" + interactive_created->session_id + "\"}";
    auto stop_frame = (*protocol)->handle_frame(
        make_request(
            "stop-interactive",
            "stop_session",
            stop_payload,
            "stop-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 3U
    );
    REQUIRE(stop_frame.has_value());
    auto stop_response = decode_response(*stop_frame);
    REQUIRE(stop_response.has_value());
    REQUIRE(stop_response->result.has_value());
    session_record_result stop_record;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        stop_record, stop_response->result->str
    ));
    REQUIRE(stop_record.session_id == interactive_created->session_id);
    REQUIRE(stop_record.state == "stopping" || stop_record.state == "exited");
    REQUIRE(stop_record.profile_digest == interactive_running.profile_digest);
    auto interactive_stopping = shared_registry->stopping_status(interactive_created->session_id);
    std::uint64_t stopping_at_ms = 0;
    if (interactive_stopping) {
        REQUIRE(interactive_stopping->stopping_at_ms >= interactive_stopping->running_at_ms);
        stopping_at_ms = interactive_stopping->stopping_at_ms;
    } else {
        auto early_exit = shared_registry->exited_status(interactive_created->session_id);
        REQUIRE(early_exit.has_value());
        REQUIRE(early_exit->stopping_at_ms >= early_exit->running_at_ms);
        stopping_at_ms = early_exit->stopping_at_ms;
    }
    auto stop_replay_frame = (*protocol)->handle_frame(
        make_request(
            "stop-interactive-replay",
            "stop_session",
            stop_payload,
            "stop-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 4U
    );
    REQUIRE(stop_replay_frame.has_value());
    auto stop_replay_response = decode_response(*stop_replay_frame);
    REQUIRE(stop_replay_response.has_value());
    REQUIRE(stop_replay_response->result.has_value());
    session_record_result stop_replay_record;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        stop_replay_record, stop_replay_response->result->str
    ));
    REQUIRE(stop_replay_record.session_id == interactive_created->session_id);
    REQUIRE(stop_replay_record.state == "stopping" || stop_replay_record.state == "exited");
    auto interactive_exited = session_runtime->wait(interactive_created->session_id);
    REQUIRE(interactive_exited.has_value());
    REQUIRE(interactive_exited->session.state == glove::control::session_state::exited);
    REQUIRE(
        interactive_exited->termination_cause ==
        glove::container::resource_termination_cause::signaled
    );
    REQUIRE(interactive_exited->stopping_at_ms == stopping_at_ms);
    auto durable_interactive = shared_registry->exited_status("session-interactive");
    REQUIRE(durable_interactive.has_value());
    REQUIRE(*durable_interactive == *interactive_exited);
    const auto cleanup_payload = "{\"session_id\":\"" + interactive_created->session_id + "\"}";
    auto cleanup_frame = (*protocol)->handle_frame(
        make_request(
            "cleanup-interactive",
            "cleanup_session",
            cleanup_payload,
            "cleanup-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 10U
    );
    REQUIRE(cleanup_frame.has_value());
    auto cleanup_response = decode_response(*cleanup_frame);
    REQUIRE(cleanup_response.has_value());
    REQUIRE(cleanup_response->result.has_value());
    session_mutation_result cleanup_result;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(
        cleanup_result, cleanup_response->result->str
    ));
    REQUIRE(cleanup_result.schema_version == 1);
    REQUIRE(cleanup_result.session_id == interactive_created->session_id);
    auto cleanup_replay_frame = (*protocol)->handle_frame(
        make_request(
            "cleanup-interactive-replay",
            "cleanup_session",
            cleanup_payload,
            "cleanup-session-interactive",
            interactive_now_ms + 10'000U
        ),
        interactive_now_ms + 11U
    );
    REQUIRE(cleanup_replay_frame.has_value());
    auto cleanup_replay_response = decode_response(*cleanup_replay_frame);
    REQUIRE(cleanup_replay_response.has_value());
    REQUIRE(cleanup_replay_response->result.has_value());
    REQUIRE(cleanup_replay_response->result->str == cleanup_response->result->str);
    REQUIRE(session_runtime->list()->empty());
    REQUIRE(!session_runtime->stop(interactive_created->session_id).has_value());
    REQUIRE(
        session_runtime->start(
            *shared_producer,
            interactive_authorization,
            "execute-session-interactive",
            interactive_now_ms + 3U
        ) == interactive_exited->session
    );
    REQUIRE(shared_producer->anchor().sequence == 2);
    REQUIRE(std::filesystem::is_empty(materializations));
    REQUIRE(std::filesystem::exists(source / "tracked.txt"));
    return 0;
}

} // namespace glove_test

auto main() -> int {
    return glove_test::run();
}
