#include "glove/audit/sink.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/receipt_audit_unix_server.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "receipt_audit_unix_server_detail.hpp"
#include "receipt_audit_wire.hpp"

#include <arpa/inet.h>
#include <glaze/glaze.hpp>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

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

} // namespace wire_test

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
constexpr std::string_view audit_key_id =
    "b97d6f8d2ae381761ea00f360c230cf75e8de5fdc6a8d25624a5c36b97f0d475";
constexpr std::string_view bootstrap_secret =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
constexpr std::string_view plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-receipt-server-test-XXXXXX";
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

class unique_fd {
public:
    explicit unique_fd(int value = -1) noexcept : value_{value} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : value_{std::exchange(other.value_, -1)} {}

    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (value_ >= 0) {
            ::close(value_);
        }
    }

    void reset(int value = -1) noexcept {
        if (value_ >= 0) {
            ::close(value_);
        }
        value_ = value;
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_;
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

auto write_exact(int descriptor, const void* input, std::size_t size) -> bool {
    const auto* bytes = static_cast<const std::byte*>(input);
    std::size_t written = 0;
    while (written < size) {
        const auto result = ::write(descriptor, bytes + written, size - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

auto read_exact(int descriptor, void* output, std::size_t size) -> bool {
    auto* bytes = static_cast<std::byte*>(output);
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto result = ::read(descriptor, bytes + consumed, size - consumed);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        consumed += static_cast<std::size_t>(result);
    }
    return true;
}

auto connect_to(const std::filesystem::path& socket_path) -> unique_fd {
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (descriptor.get() < 0) {
        return unique_fd{};
    }
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto value = socket_path.string();
    if (value.size() >= sizeof(address.sun_path)) {
        return unique_fd{};
    }
    std::memcpy(address.sun_path, value.c_str(), value.size() + 1U);
    if (::connect(
            descriptor.get(), reinterpret_cast<const ::sockaddr*>(&address), sizeof(address)
        ) != 0) {
        return unique_fd{};
    }
    return descriptor;
}

auto transact(const std::filesystem::path& socket_path, std::string_view frame)
    -> std::optional<std::string> {
    auto descriptor = connect_to(socket_path);
    if (descriptor.get() < 0) {
        return std::nullopt;
    }
    const auto size = htonl(static_cast<std::uint32_t>(frame.size()));
    if (!write_exact(descriptor.get(), &size, sizeof(size)) ||
        !write_exact(descriptor.get(), frame.data(), frame.size())) {
        return std::nullopt;
    }
    std::uint32_t response_size = 0;
    if (!read_exact(descriptor.get(), &response_size, sizeof(response_size))) {
        return std::nullopt;
    }
    const auto decoded_size = ntohl(response_size);
    if (decoded_size == 0 || decoded_size > glove::control::max_control_frame_bytes) {
        return std::nullopt;
    }
    std::string response(decoded_size, '\0');
    if (!read_exact(descriptor.get(), response.data(), response.size())) {
        return std::nullopt;
    }
    return response;
}

auto make_request(
    std::string_view id,
    std::string_view method,
    std::string_view payload,
    std::optional<std::string_view> idempotency_key = std::nullopt,
    std::string_view secret = bootstrap_secret,
    std::uint64_t deadline_ms = 4102444800000
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

auto decode_response(std::string_view frame) -> std::optional<wire_test::rpc_response> {
    wire_test::rpc_response response;
    constexpr glz::opts strict{.error_on_unknown_keys = true};
    if (glz::read<strict>(response, frame)) {
        return std::nullopt;
    }
    return response;
}

// Regression stub for connection-scoped delivery degradation: records every
// start() and stop() so tests can prove a guest launched by a genuinely
// authenticated+applied start_session is torn down through the normal
// idempotent stop path when its controller connection fails at the transport
// level, and that unauthenticated or unapplied requests never tear anything
// down.
class degrade_test_runtime final : public glove::control::session_runtime {
public:
    degrade_test_runtime() = default;

    explicit degrade_test_runtime(bool stop_succeeds) : stop_succeeds_{stop_succeeds} {}

    [[nodiscard]] auto backend_id() const noexcept -> std::string_view override {
        return "degrade-test";
    }

    [[nodiscard]] auto agent_runtime_adapter_schema_version() const noexcept
        -> std::uint8_t override {
        return 0;
    }

    [[nodiscard]] auto managed_runtime_ids() const -> std::vector<std::string> override {
        return {};
    }

    [[nodiscard]] auto resource_capabilities() const noexcept
        -> glove::container::resource_enforcement_capabilities override {
        return {};
    }

    auto start(
        glove::container::receipt_audit_producer&,
        const glove::control::session_start_authorization& authorization,
        std::string_view idempotency_key,
        std::uint64_t now_ms
    ) -> std::expected<glove::control::session_start_result, std::string> override {
        // Gate handshake: the block decision is read under the same mutex
        // that arms it, and the test observes — via the condition variable —
        // that the dispatch is parked inside the blocked gate BEFORE the
        // client resets the connection. That makes the broken-pipe outcome
        // deterministic instead of racy.
        {
            std::unique_lock lock{mutex_};
            if (block_start_) {
                gate_entered_ = true;
                start_gate_.notify_all();
                start_gate_.wait(lock, [this] { return gate_open_; });
            }
        }
        // The start is recorded only AFTER the dispatch completes (and the
        // handler has decided outcome.applied), so cross-thread observers
        // never see a start before it is committed.
        const bool replay = [this, &idempotency_key] {
            const std::scoped_lock lock{mutex_};
            return !used_keys_.insert(std::string{idempotency_key}).second;
        }();
        {
            const std::scoped_lock lock{mutex_};
            started.emplace_back(authorization.session_id);
        }
        // State `created` needs no registry projection: handle_start_session
        // encodes the record directly. A repeated idempotency key models an
        // authenticated idempotent replay: the same record is returned, but
        // with the explicit replay disposition (fresh_launch == false), so
        // the handler must not treat the replay as applied.
        glove::control::session_record record{
            .schema_version = 1,
            .session_id = authorization.session_id,
            .controller_plan_digest = authorization.controller_plan_digest,
            .plan_content_digest = authorization.plan_content_digest,
            .state = glove::control::session_state::created,
            .policy_revision = 1,
            .expires_at_ms = authorization.expires_at_ms,
            .created_at_ms = now_ms,
        };
        return glove::control::session_start_result{
            .record = std::move(record), .fresh_launch = !replay
        };
    }

    auto reconcile(glove::container::receipt_audit_producer&, std::uint64_t)
        -> std::expected<glove::control::session_reconciliation_report, std::string> override {
        return glove::control::session_reconciliation_report{};
    }

    [[nodiscard]] auto list() const
        -> std::expected<std::vector<std::string>, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    [[nodiscard]] auto read(std::string_view, std::uint64_t, std::size_t) const
        -> std::expected<glove::control::session_transcript_read, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    [[nodiscard]] auto wait_read(std::string_view, std::uint64_t, std::size_t, std::uint64_t)
        -> std::expected<glove::control::session_transcript_read, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    auto write_input(std::string_view, std::string_view)
        -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    auto resize(std::string_view, std::uint16_t, std::uint16_t)
        -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    auto signal(std::string_view, glove::control::session_signal)
        -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    auto stop(std::string_view session_id) -> std::expected<void, std::string> override {
        const std::scoped_lock lock{mutex_};
        stopped.emplace_back(session_id);
        if (!stop_succeeds_) {
            return std::unexpected(std::string{"stop unavailable"});
        }
        return {};
    }

    auto stop(std::string_view session_id, std::string_view)
        -> std::expected<void, std::string> override {
        return stop(session_id);
    }

    [[nodiscard]] auto wait(std::string_view)
        -> std::expected<glove::control::session_terminal_record, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    auto cleanup(std::string_view) -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"unavailable"});
    }

    // Thread-safe snapshot helpers for cross-thread synchronization.
    [[nodiscard]] auto started_snapshot() -> std::vector<std::string> {
        const std::scoped_lock lock{mutex_};
        return started;
    }

    [[nodiscard]] auto stopped_snapshot() -> std::vector<std::string> {
        const std::scoped_lock lock{mutex_};
        return stopped;
    }

    // Arm the start() gate before the request is sent; the handshake proves
    // the dispatch is parked inside the blocked gate before the client
    // resets, and release it after the connection is torn down.
    void arm_start_gate() {
        const std::scoped_lock lock{mutex_};
        block_start_ = true;
        gate_entered_ = false;
        gate_open_ = false;
    }

    template<class Rep, class Period>
    [[nodiscard]] auto wait_for_start_gate(std::chrono::duration<Rep, Period> timeout) -> bool {
        std::unique_lock lock{mutex_};
        return start_gate_.wait_for(lock, timeout, [this] { return gate_entered_; });
    }

    void release_start_gate() {
        {
            const std::scoped_lock lock{mutex_};
            gate_open_ = true;
        }
        start_gate_.notify_all();
    }

    std::vector<std::string> started;
    std::vector<std::string> stopped;

private:
    mutable std::mutex mutex_;
    std::condition_variable start_gate_;
    bool block_start_ = false;
    bool gate_entered_ = false;
    bool gate_open_ = false;
    bool stop_succeeds_ = true;
    std::set<std::string> used_keys_;
};

// Minimal bounded plan validator for the full protocol/server stack below
// (mirrors the receipt audit server fixture policy).
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

// Regression test (Workflow #218, sol-audit MEDIUM): degradation authority is
// bound to the REAL authenticated/applied dispatch outcome. handle_frame must
// produce structured metadata, and degrade_failed_delivery must act ONLY on
// genuinely authenticated+applied start_session frames — never by re-decoding
// a raw frame. Wrong-secret, expired-deadline, rejected-start, and non-start
// outcomes must never stop a guest; they record only the connection-scoped
// audit event.
auto verify_degrade_requires_authenticated_applied_outcome() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto audit_key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    const auto sessions_path = temp.root() / "sessions.journal";
    const auto plan_source = temp.root() / "plan-source";
    REQUIRE(std::filesystem::create_directory(plan_source));
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    REQUIRE(write_owner_only(audit_key_path, audit_key));

    auto validator_result = plan_validator_for(plan_source);
    REQUIRE(validator_result.has_value());
    auto validator = std::make_shared<const glove::supervisor::session_plan_validator>(
        std::move(*validator_result)
    );
    auto sessions = glove::control::session_registry::open_or_create(sessions_path, validator);
    REQUIRE(sessions.has_value());
    auto registry = std::shared_ptr<glove::control::session_registry>{std::move(*sessions)};

    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = journal_path,
    };
    // Initialize + acknowledge so the real dispatch (receipt paging) can
    // bootstrap a reconciled producer from the journal.
    auto seed_producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(seed_producer.has_value());
    REQUIRE((*seed_producer)->acknowledge_bootstrap((*seed_producer)->anchor()).has_value());
    seed_producer->reset();

    auto audit_sink = glove::audit::make_memory_sink();
    auto runtime = std::make_shared<degrade_test_runtime>();
    const glove::control::receipt_audit_unix_server_config config{
        .socket_path = {},
        .bootstrap_secret_path = {},
        .producer = producer_config,
        .plan_validator = validator,
        .sessions = registry,
        .runtime = runtime,
        .local_services = {},
        .path_exposures = {},
        .materialization_root = (temp.root() / "materializations").string(),
        .io_timeout_ms = 5'000,
        .control_audit = audit_sink,
    };

    auto protocol = glove::control::receipt_audit_protocol::create(
        bootstrap_secret,
        producer_config,
        validator,
        registry,
        runtime,
        {},
        config.materialization_root
    );
    REQUIRE(protocol.has_value());

    const auto start_payload =
        R"({"authorization":{"schema_version":1,"authorization_id":"auth-1",)"
        R"("session_id":"session-9","controller_plan_digest":")" +
        std::string(plan_digest) + R"(","plan_content_digest":")" + std::string(plan_digest) +
        R"(","approved_at_ms":1,"expires_at_ms":4102444800000}})";

    // Initialize the producer through the real dispatch (receipt paging).
    const glove::container::receipt_audit_anchor genesis{
        .key_id = std::string{audit_key_id},
        .sequence = 0,
        .head_hmac = std::string(64, '0'),
    };
    auto genesis_json = glz::write_json(genesis);
    REQUIRE(genesis_json.has_value());
    auto page_frame = (*protocol)->handle_frame(
        make_request(
            "page-1", "verify_audit_chain", "{\"sage_anchor\":" + *genesis_json + ",\"limit\":10}"
        ),
        1'000
    );
    REQUIRE(page_frame.has_value());

    // A genuinely authenticated+applied start_session: the outcome metadata
    // must say so, and degradation must tear the guest down.
    glove::control::receipt_control_outcome outcome;
    auto start_frame = (*protocol)->handle_frame(
        make_request("start-1", "start_session", start_payload, "degrade-start-1"), 1'000, &outcome
    );
    REQUIRE(start_frame.has_value());
    auto start_response = decode_response(*start_frame);
    REQUIRE(start_response.has_value());
    REQUIRE(start_response->result.has_value());
    REQUIRE(outcome.authenticated);
    REQUIRE(outcome.applied);
    REQUIRE(outcome.response_success);
    REQUIRE(outcome.method == "start_session");
    REQUIRE(outcome.session_id == "session-9");
    REQUIRE(runtime->started_snapshot() == std::vector<std::string>{"session-9"});

    glove::control::detail::degrade_failed_delivery(
        config, outcome, "write control frame: Broken pipe"
    );
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // An authenticated idempotent start replay (same request, same
    // idempotency key): the response is still the existing record, but the
    // outcome must mark it as a replay — never applied — so a broken
    // delivery during a replay must NOT tear down the already-running
    // guest.
    glove::control::receipt_control_outcome replay_outcome;
    auto replay_frame = (*protocol)->handle_frame(
        make_request("start-1-replay", "start_session", start_payload, "degrade-start-1"),
        1'000,
        &replay_outcome
    );
    REQUIRE(replay_frame.has_value());
    auto replay_response = decode_response(*replay_frame);
    REQUIRE(replay_response.has_value());
    REQUIRE(replay_response->result.has_value());
    REQUIRE(replay_response->result->str == start_response->result->str);
    REQUIRE(replay_outcome.authenticated);
    REQUIRE(replay_outcome.replay);
    REQUIRE(!replay_outcome.applied);
    glove::control::detail::degrade_failed_delivery(
        config, replay_outcome, "write control frame: Broken pipe"
    );
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // Wrong secret: unauthenticated. No stop attempt; only the audit event.
    glove::control::receipt_control_outcome bad_secret_outcome;
    auto bad_secret_frame = (*protocol)->handle_frame(
        make_request(
            "start-2",
            "start_session",
            start_payload,
            "degrade-start-2",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        ),
        1'000,
        &bad_secret_outcome
    );
    REQUIRE(bad_secret_frame.has_value());
    auto bad_secret_response = decode_response(*bad_secret_frame);
    REQUIRE(bad_secret_response.has_value());
    REQUIRE(bad_secret_response->error.has_value());
    REQUIRE(bad_secret_response->error->code == "unauthorized");
    REQUIRE(!bad_secret_outcome.authenticated);
    REQUIRE(!bad_secret_outcome.applied);
    REQUIRE(bad_secret_outcome.method == "start_session");
    REQUIRE(bad_secret_outcome.session_id.empty());
    glove::control::detail::degrade_failed_delivery(
        config, bad_secret_outcome, "write control frame: Broken pipe"
    );
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // Expired deadline: unauthenticated for degradation purposes.
    glove::control::receipt_control_outcome expired_outcome;
    auto expired_frame = (*protocol)->handle_frame(
        make_request(
            "start-3", "start_session", start_payload, "degrade-start-3", bootstrap_secret, 1
        ),
        2'000,
        &expired_outcome
    );
    REQUIRE(expired_frame.has_value());
    auto expired_response = decode_response(*expired_frame);
    REQUIRE(expired_response.has_value());
    REQUIRE(expired_response->error.has_value());
    REQUIRE(expired_response->error->code == "deadline_exceeded");
    REQUIRE(!expired_outcome.authenticated);
    REQUIRE(!expired_outcome.applied);
    glove::control::detail::degrade_failed_delivery(config, expired_outcome, "deadline");
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // Non-start methods never gain teardown authority.
    glove::control::receipt_control_outcome health_outcome;
    auto health_frame = (*protocol)->handle_frame(
        make_request("health-1", "health", "null"), 1'000, &health_outcome
    );
    REQUIRE(health_frame.has_value());
    REQUIRE(health_outcome.authenticated);
    REQUIRE(health_outcome.method == "health");
    REQUIRE(health_outcome.session_id.empty());
    REQUIRE(!health_outcome.applied);
    glove::control::detail::degrade_failed_delivery(config, health_outcome, "timeout");
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // A rejected start (missing idempotency key) is authenticated but never
    // applied: no teardown.
    glove::control::receipt_control_outcome rejected_outcome;
    auto rejected_frame = (*protocol)->handle_frame(
        make_request("start-4", "start_session", start_payload), 1'000, &rejected_outcome
    );
    REQUIRE(rejected_frame.has_value());
    auto rejected_response = decode_response(*rejected_frame);
    REQUIRE(rejected_response.has_value());
    REQUIRE(rejected_response->error.has_value());
    REQUIRE(!rejected_outcome.applied);
    glove::control::detail::degrade_failed_delivery(config, rejected_outcome, "timeout");
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-9"});

    // Audit journal: one event per degrade call, naming method and session
    // where the typed decode succeeded; a replayed start's event reflects
    // the replay disposition.
    auto events = audit_sink->take();
    REQUIRE(events.size() == 6);
    REQUIRE(events[0].tool_name == "start_session:session-9");
    REQUIRE(events[1].tool_name == "start_session:replay:session-9");
    REQUIRE(events[2].tool_name == "start_session");
    REQUIRE(events[3].tool_name == "start_session");
    REQUIRE(events[4].tool_name == "health");
    REQUIRE(events[5].tool_name == "start_session");
    for (const auto& event : events) {
        REQUIRE(event.what == glove::audit::action::control);
        REQUIRE(event.status == glove::mcp::tool_call_status::transport_error);
    }

    // A failed stop must stay non-fatal and still be audited.
    auto failing_sink = glove::audit::make_memory_sink();
    auto failing_runtime = std::make_shared<degrade_test_runtime>(false);
    const glove::control::receipt_audit_unix_server_config failing_config{
        .socket_path = {},
        .bootstrap_secret_path = {},
        .producer = producer_config,
        .plan_validator = validator,
        .sessions = registry,
        .runtime = failing_runtime,
        .local_services = {},
        .path_exposures = {},
        .materialization_root = {},
        .io_timeout_ms = 5'000,
        .control_audit = failing_sink,
    };
    glove::control::detail::degrade_failed_delivery(
        failing_config, outcome, "write control frame: Broken pipe"
    );
    REQUIRE(failing_runtime->stopped == std::vector<std::string>{"session-9"});
    auto failing_events = failing_sink->take();
    REQUIRE(failing_events.size() == 2);
    REQUIRE(failing_events[0].tool_name == "start_session:session-9");
    REQUIRE(failing_events[1].tool_name == "degrade_stop:session-9");
    REQUIRE(failing_events[1].status == glove::mcp::tool_call_status::transport_error);
    return 0;
}

// Regression test (Workflow #218): gloved exited fatally when the control
// client vanished between sending its request and reading the response. The
// response write must fail as a connection-scoped outcome — the daemon keeps
// serving — with the delivery failure recorded in the structured control
// audit journal. Read timeouts and listener failures remain errors.
//
// This drives the REAL server through create() and a genuinely
// authenticated+applied start_session through the real handle_frame, so the
// post-construction runtime ownership is exercised: on the pre-fix code the
// server's stored config held a moved-from runtime pointer and the guest was
// never torn down. Determinism: the client resets the socket only after the
// mutex-protected gate handshake proves the dispatch is parked inside the
// blocked gate, so the server is guaranteed to fail at the response write.
auto verify_broken_pipe_delivery_is_connection_scoped() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto socket_path = temp.root() / "gloved.sock";
    const auto secret_path = temp.root() / "bootstrap-secret";
    const auto audit_key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    const auto sessions_path = temp.root() / "sessions.journal";
    const auto plan_source = temp.root() / "plan-source";
    REQUIRE(std::filesystem::create_directory(plan_source));
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    REQUIRE(write_owner_only(secret_path, bootstrap_secret));
    REQUIRE(write_owner_only(audit_key_path, audit_key));

    auto validator_result = plan_validator_for(plan_source);
    REQUIRE(validator_result.has_value());
    auto validator = std::make_shared<const glove::supervisor::session_plan_validator>(
        std::move(*validator_result)
    );
    auto sessions = glove::control::session_registry::open_or_create(sessions_path, validator);
    REQUIRE(sessions.has_value());
    auto registry = std::shared_ptr<glove::control::session_registry>{std::move(*sessions)};

    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    producer->reset();

    auto audit_sink = glove::audit::make_memory_sink();
    auto runtime = std::make_shared<degrade_test_runtime>();
    const glove::control::receipt_audit_unix_server_config server_config{
        .socket_path = socket_path,
        .bootstrap_secret_path = secret_path,
        .producer = producer_config,
        .plan_validator = validator,
        .sessions = registry,
        .runtime = runtime,
        .local_services = {},
        .path_exposures = {},
        .materialization_root = (temp.root() / "materializations").string(),
        .io_timeout_ms = 5'000,
        .control_audit = audit_sink,
    };
    auto server = glove::control::receipt_audit_unix_server::create(server_config);
    REQUIRE(server.has_value());

    std::optional<glove::control::receipt_audit_serve_outcome> outcome;
    std::optional<std::string> server_error;
    std::thread server_thread{[&] {
        if (auto served = (*server)->serve_one(); !served) {
            server_error = served.error();
        } else {
            outcome = *served;
        }
    }};

    // Prime the receipt producer through the real dispatch (receipt paging):
    // start_session requires an initialized, reconciled producer.
    const glove::container::receipt_audit_anchor genesis{
        .key_id = std::string{audit_key_id},
        .sequence = 0,
        .head_hmac = std::string(64, '0'),
    };
    auto genesis_json = glz::write_json(genesis);
    REQUIRE(genesis_json.has_value());
    auto primed = transact(
        socket_path,
        make_request(
            "page-prime",
            "verify_audit_chain",
            "{\"sage_anchor\":" + *genesis_json + ",\"limit\":10}"
        )
    );
    server_thread.join();
    REQUIRE(!server_error.has_value());
    REQUIRE(outcome.has_value());
    REQUIRE(*outcome == glove::control::receipt_audit_serve_outcome::served);
    REQUIRE(primed.has_value());
    auto primed_response = decode_response(*primed);
    REQUIRE(primed_response.has_value());
    REQUIRE(primed_response->result.has_value());
    REQUIRE(audit_sink->take().empty());
    outcome.reset();

    server_thread = std::thread{[&] {
        if (auto served = (*server)->serve_one(); !served) {
            server_error = served.error();
        } else {
            outcome = *served;
        }
    }};

    const auto start_payload =
        R"({"authorization":{"schema_version":1,"authorization_id":"auth-e2e",)"
        R"("session_id":"session-degraded","controller_plan_digest":")" +
        std::string(plan_digest) + R"(","plan_content_digest":")" + std::string(plan_digest) +
        R"(","approved_at_ms":1,"expires_at_ms":4102444800000}})";

    auto descriptor = connect_to(socket_path);
    REQUIRE(descriptor.get() >= 0);
    // Arm the start gate: the runtime's start() will block inside the real
    // handle_frame dispatch until we release it after tearing the connection
    // down, guaranteeing the server's response write hits a dead peer.
    runtime->arm_start_gate();
    const auto frame =
        make_request("start-e2e", "start_session", start_payload, "degrade-start-e2e");
    const auto size = htonl(static_cast<std::uint32_t>(frame.size()));
    REQUIRE(write_exact(descriptor.get(), &size, sizeof(size)));
    REQUIRE(write_exact(descriptor.get(), frame.data(), frame.size()));

    // Synchronize on the gate handshake: the condition variable proves the
    // dispatch is parked inside the blocked gate (inside handle_frame,
    // before the start has been applied) BEFORE the reset, so the server's
    // response write failure is deterministic rather than racy with the
    // read. The started snapshot is only recorded after start() returns, so
    // it is not usable as a "dispatch is inside the gate" observable.
    REQUIRE(runtime->wait_for_start_gate(std::chrono::seconds{5}));
    const ::linger reset_on_close{.l_onoff = 1, .l_linger = 0};
    REQUIRE(
        ::setsockopt(
            descriptor.get(), SOL_SOCKET, SO_LINGER, &reset_on_close, sizeof(reset_on_close)
        ) == 0
    );
    descriptor.reset();
    // Now the peer is gone; let the applied start complete so the server
    // fails at the response write, deterministically.
    runtime->release_start_gate();

    server_thread.join();
    REQUIRE(!server_error.has_value());
    REQUIRE(outcome.has_value());
    REQUIRE(*outcome == glove::control::receipt_audit_serve_outcome::connection_failed);

    // The HIGH blocker under repair: the degrade path must hold the SAME live
    // runtime the protocol dispatched through, so the guest launched by the
    // applied start_session is torn down despite the vanished controller.
    REQUIRE(runtime->started_snapshot() == std::vector<std::string>{"session-degraded"});
    REQUIRE(runtime->stopped_snapshot() == std::vector<std::string>{"session-degraded"});

    const auto events = audit_sink->take();
    REQUIRE(events.size() == 1);
    REQUIRE(events.front().what == glove::audit::action::control);
    REQUIRE(events.front().tool_name == "start_session:session-degraded");
    REQUIRE(events.front().status == glove::mcp::tool_call_status::transport_error);

    // The daemon-level invariant under repair: the server keeps serving
    // subsequent connections after a connection-scoped delivery failure.
    std::optional<std::string> recovery_error;
    std::thread recovery_thread{[&] {
        if (auto served = (*server)->serve_one(); !served) {
            recovery_error = served.error();
        }
    }};
    auto recovery = transact(socket_path, make_request("health-2", "health", "null"));
    recovery_thread.join();
    REQUIRE(!recovery_error.has_value());
    REQUIRE(recovery.has_value());
    auto recovery_response = decode_response(*recovery);
    REQUIRE(recovery_response.has_value());
    REQUIRE(recovery_response->result.has_value());
    return 0;
}

// Regression test (Workflow #218, round 3): an authenticated idempotent
// start_session replay is a success response but never a freshly applied
// launch. If the transport fails while a replay is being served, the live
// guest — launched by the earlier, already-delivered request — must NOT be
// stopped, outcome.applied must stay false, and the control audit event
// must reflect the replay disposition. The replay dispatch is parked inside
// a mutex-protected gate and observed via a condition-variable handshake
// before the client resets, so the broken pipe is deterministic.
auto verify_replay_broken_pipe_never_stops_live_session() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto socket_path = temp.root() / "gloved.sock";
    const auto secret_path = temp.root() / "bootstrap-secret";
    const auto audit_key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    const auto sessions_path = temp.root() / "sessions.journal";
    const auto plan_source = temp.root() / "plan-source";
    REQUIRE(std::filesystem::create_directory(plan_source));
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    REQUIRE(write_owner_only(secret_path, bootstrap_secret));
    REQUIRE(write_owner_only(audit_key_path, audit_key));

    auto validator_result = plan_validator_for(plan_source);
    REQUIRE(validator_result.has_value());
    auto validator = std::make_shared<const glove::supervisor::session_plan_validator>(
        std::move(*validator_result)
    );
    auto sessions = glove::control::session_registry::open_or_create(sessions_path, validator);
    REQUIRE(sessions.has_value());
    auto registry = std::shared_ptr<glove::control::session_registry>{std::move(*sessions)};

    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    producer->reset();

    auto audit_sink = glove::audit::make_memory_sink();
    auto runtime = std::make_shared<degrade_test_runtime>();
    const glove::control::receipt_audit_unix_server_config server_config{
        .socket_path = socket_path,
        .bootstrap_secret_path = secret_path,
        .producer = producer_config,
        .plan_validator = validator,
        .sessions = registry,
        .runtime = runtime,
        .local_services = {},
        .path_exposures = {},
        .materialization_root = (temp.root() / "materializations").string(),
        .io_timeout_ms = 5'000,
        .control_audit = audit_sink,
    };
    auto server = glove::control::receipt_audit_unix_server::create(server_config);
    REQUIRE(server.has_value());

    const glove::container::receipt_audit_anchor genesis{
        .key_id = std::string{audit_key_id},
        .sequence = 0,
        .head_hmac = std::string(64, '0'),
    };
    auto genesis_json = glz::write_json(genesis);
    REQUIRE(genesis_json.has_value());

    const auto start_payload =
        R"({"authorization":{"schema_version":1,"authorization_id":"auth-replay",)"
        R"("session_id":"session-replayed","controller_plan_digest":")" +
        std::string(plan_digest) + R"(","plan_content_digest":")" + std::string(plan_digest) +
        R"(","approved_at_ms":1,"expires_at_ms":4102444800000}})";

    // Each delivered connection pairs one serve_one() with one transact().
    auto serve_and_transact = [&](std::string_view frame) -> std::optional<std::string> {
        std::optional<std::string> server_failure;
        std::thread server_thread{[&] {
            if (auto served = (*server)->serve_one(); !served) {
                server_failure = served.error();
            }
        }};
        auto response = transact(socket_path, frame);
        server_thread.join();
        // REQUIRE's `return 1` does not fit this lambda's optional return
        // type, so failures exit the test process directly.
        if (server_failure.has_value() || !response.has_value()) {
            std::fprintf(
                stderr, "REQUIRE failed: serve_and_transact @ %s:%d\n", __FILE__, __LINE__
            );
            std::exit(1);
        }
        return response;
    };

    // Connection 1: prime the producer and deliver a genuine fresh start.
    auto primed = serve_and_transact(make_request(
        "page-prime", "verify_audit_chain", "{\"sage_anchor\":" + *genesis_json + ",\"limit\":10}"
    ));
    auto primed_response = decode_response(*primed);
    REQUIRE(primed_response.has_value());
    REQUIRE(primed_response->result.has_value());
    auto delivered = serve_and_transact(
        make_request("start-live", "start_session", start_payload, "replay-start-e2e")
    );
    auto delivered_response = decode_response(*delivered);
    REQUIRE(delivered_response.has_value());
    REQUIRE(delivered_response->result.has_value());
    REQUIRE(runtime->started_snapshot() == std::vector<std::string>{"session-replayed"});
    REQUIRE(runtime->stopped_snapshot().empty());
    REQUIRE(audit_sink->take().empty());

    // Connection 2: authenticated idempotent replay of the same request.
    std::optional<glove::control::receipt_audit_serve_outcome> outcome;
    std::optional<std::string> server_error;
    std::thread server_thread{[&] {
        if (auto served = (*server)->serve_one(); !served) {
            server_error = served.error();
        } else {
            outcome = *served;
        }
    }};
    auto descriptor = connect_to(socket_path);
    REQUIRE(descriptor.get() >= 0);
    runtime->arm_start_gate();
    const auto frame =
        make_request("start-replay", "start_session", start_payload, "replay-start-e2e");
    const auto size = htonl(static_cast<std::uint32_t>(frame.size()));
    REQUIRE(write_exact(descriptor.get(), &size, sizeof(size)));
    REQUIRE(write_exact(descriptor.get(), frame.data(), frame.size()));
    // The gate handshake proves the replay dispatch is parked inside the
    // blocked gate before the connection is reset.
    REQUIRE(runtime->wait_for_start_gate(std::chrono::seconds{5}));
    const ::linger reset_on_close{.l_onoff = 1, .l_linger = 0};
    REQUIRE(
        ::setsockopt(
            descriptor.get(), SOL_SOCKET, SO_LINGER, &reset_on_close, sizeof(reset_on_close)
        ) == 0
    );
    descriptor.reset();
    runtime->release_start_gate();

    server_thread.join();
    REQUIRE(!server_error.has_value());
    REQUIRE(outcome.has_value());
    REQUIRE(*outcome == glove::control::receipt_audit_serve_outcome::connection_failed);

    // The replay must not be treated as a fresh launch: the live session is
    // still running (no stop), and the replay's delivery failure produced
    // exactly one control audit event carrying the replay disposition.
    const std::vector<std::string> expected_started{"session-replayed", "session-replayed"};
    REQUIRE(runtime->started_snapshot() == expected_started);
    REQUIRE(runtime->stopped_snapshot().empty());

    const auto events = audit_sink->take();
    REQUIRE(events.size() == 1);
    REQUIRE(events.front().what == glove::audit::action::control);
    REQUIRE(events.front().tool_name == "start_session:replay:session-replayed");
    REQUIRE(events.front().status == glove::mcp::tool_call_status::transport_error);

    // The daemon keeps serving after the connection-scoped failure.
    std::optional<std::string> recovery_error;
    std::thread recovery_thread{[&] {
        if (auto served = (*server)->serve_one(); !served) {
            recovery_error = served.error();
        }
    }};
    auto recovery = transact(socket_path, make_request("health-3", "health", "null"));
    recovery_thread.join();
    REQUIRE(!recovery_error.has_value());
    REQUIRE(recovery.has_value());
    auto recovery_response = decode_response(*recovery);
    REQUIRE(recovery_response.has_value());
    REQUIRE(recovery_response->result.has_value());
    return 0;
}

auto verify_peer_credential_contract() -> int {
    int descriptors[2] = {-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors) == 0);
    const unique_fd local{descriptors[0]};
    const unique_fd peer{descriptors[1]};
    const auto owner = ::geteuid();
    REQUIRE(glove::control::detail::verify_peer_owner(local.get(), owner).has_value());
    const auto wrong_owner = owner == std::numeric_limits<::uid_t>::max() ? owner - 1U : owner + 1U;
    REQUIRE(!glove::control::detail::verify_peer_owner(local.get(), wrong_owner).has_value());
    return 0;
}

auto run() -> int {
    REQUIRE(verify_peer_credential_contract() == 0);
    REQUIRE(verify_degrade_requires_authenticated_applied_outcome() == 0);
    REQUIRE(verify_broken_pipe_delivery_is_connection_scoped() == 0);
    REQUIRE(verify_replay_broken_pipe_never_stops_live_session() == 0);
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto socket_path = temp.root() / "gloved.sock";
    const auto secret_path = temp.root() / "bootstrap-secret";
    const auto audit_key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    REQUIRE(write_owner_only(secret_path, bootstrap_secret));
    REQUIRE(write_owner_only(audit_key_path, audit_key));

    const glove::container::receipt_audit_anchor genesis{
        .key_id = std::string{audit_key_id},
        .sequence = 0,
        .head_hmac = std::string(64, '0'),
    };
    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->anchor() == genesis);
    REQUIRE((*producer)->acknowledge_bootstrap(genesis).has_value());
    auto reservation = (*producer)->reserve_terminal();
    REQUIRE(reservation.has_value());
    auto terminal =
        (*producer)->commit_terminal(std::move(*reservation), "session-1", plan_digest, receipt());
    REQUIRE(terminal.has_value());
    const auto terminal_anchor = (*producer)->anchor();
    producer->reset();

    const glove::control::receipt_audit_unix_server_config server_config{
        .socket_path = socket_path,
        .bootstrap_secret_path = secret_path,
        .producer = producer_config,
        .plan_validator = {},
        .sessions = {},
        .runtime = {},
        .local_services = {},
        .path_exposures = {},
        .materialization_root = {},
        .io_timeout_ms = 100,
        .control_audit = {},
    };
    auto server = glove::control::receipt_audit_unix_server::create(server_config);
    REQUIRE(server.has_value());

    struct stat socket_status{};

    REQUIRE(::lstat(socket_path.c_str(), &socket_status) == 0);
    REQUIRE(S_ISSOCK(socket_status.st_mode));
    REQUIRE(socket_status.st_uid == ::geteuid());
    REQUIRE((socket_status.st_mode & 0777U) == 0600U);

    std::optional<std::string> server_error;
    std::thread server_thread{[&] {
        for (std::size_t request = 0; request < 2; ++request) {
            if (auto served = (*server)->serve_one(); !served) {
                server_error = served.error();
                return;
            }
        }
    }};

    const auto genesis_json = glz::write_json(genesis);
    REQUIRE(genesis_json.has_value());
    const auto page_payload = "{\"sage_anchor\":" + *genesis_json + ",\"limit\":1000}";
    auto page_frame =
        transact(socket_path, make_request("page-1", "verify_audit_chain", page_payload));
    REQUIRE(page_frame.has_value());
    auto page_response = decode_response(*page_frame);
    REQUIRE(page_response.has_value());
    REQUIRE(page_response->result.has_value());
    wire_test::page_result page;
    REQUIRE(!glz::read<glz::opts{.error_on_unknown_keys = true}>(page, page_response->result->str));
    REQUIRE(page.envelopes.size() == 1);
    REQUIRE(page.envelopes.front() == *terminal);
    REQUIRE(page.local_anchor == terminal_anchor);

    const auto terminal_anchor_json = glz::write_json(terminal_anchor);
    REQUIRE(terminal_anchor_json.has_value());
    const auto ack_payload = "{\"anchor\":" + *terminal_anchor_json + "}";
    auto ack_frame = transact(
        socket_path,
        make_request("ack-1", "acknowledge_audit_chain", ack_payload, "receipt-audit-ack-1")
    );
    REQUIRE(ack_frame.has_value());
    auto ack_response = decode_response(*ack_frame);
    REQUIRE(ack_response.has_value());
    REQUIRE(ack_response->result.has_value());
    server_thread.join();
    REQUIRE(!server_error.has_value());

    server->reset();
    REQUIRE(::access(socket_path.c_str(), F_OK) != 0);

    REQUIRE(::chmod(secret_path.c_str(), 0644) == 0);
    REQUIRE(!glove::control::receipt_audit_unix_server::create(server_config).has_value());
    REQUIRE(::chmod(secret_path.c_str(), 0600) == 0);
    REQUIRE(::chmod(temp.root().c_str(), 0755) == 0);
    REQUIRE(!glove::control::receipt_audit_unix_server::create(server_config).has_value());
    REQUIRE(::chmod(temp.root().c_str(), 0700) == 0);

    auto timeout_server = glove::control::receipt_audit_unix_server::create(server_config);
    REQUIRE(timeout_server.has_value());
    std::optional<std::string> timeout_error;
    std::thread timeout_thread{[&] {
        auto served = (*timeout_server)->serve_one();
        if (!served) {
            timeout_error = served.error();
        }
    }};
    auto stalled = connect_to(socket_path);
    REQUIRE(stalled.get() >= 0);
    timeout_thread.join();
    REQUIRE(timeout_error.has_value());
    REQUIRE(timeout_error->find("timed out") != std::string::npos);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
