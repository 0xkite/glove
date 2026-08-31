#include "glove/container/digest.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/control/guest_channel.hpp"
#include "glove/control/observation_intent_unix_server.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace wire_test {

struct enqueue_success {
    std::uint8_t schema_version = 0;
    std::string status;
    std::uint64_t sequence = 0;
    std::string intent_digest;
};

struct enqueue_error {
    std::uint8_t schema_version = 0;
    std::string code;
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
constexpr std::string_view controller_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view channel_token =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr std::string_view library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

static_assert(std::is_same_v<
              decltype(glove::control::observation_intent_unix_server_config::expected_peer_uid),
              std::uint32_t>);

auto write_owner_only(const std::filesystem::path& path, std::string_view value) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << value;
    output.flush();
    return output.good() && ::chmod(path.c_str(), 0600) == 0;
}

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-observation-server-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    temporary_directory(temporary_directory&& other) noexcept : root_{std::move(other.root_)} {}

    auto operator=(temporary_directory&& other) noexcept -> temporary_directory& {
        if (this != &other) {
            std::error_code error;
            std::filesystem::remove_all(root_, error);
            root_ = std::move(other.root_);
        }
        return *this;
    }

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

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_;
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

auto valid_plan_at(std::uint64_t now_ms) -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
           runtime_digest() +
           R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":")" +
           library_bundle_digest() +
           R"(","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":)" +
           std::to_string(now_ms + 120'000) + "}";
}

auto sage_guest_plan_at(std::uint64_t now_ms) -> std::string {
    auto plan = valid_plan_at(now_ms);
    for (const auto& [from, to] : {
             std::pair{
                 std::string_view{"\"runtime_id\":\"codex\""},
                 std::string_view{"\"runtime_id\":\"sage-guest\""}
             },
             std::pair{
                 std::string_view{"\"runtime_template_id\":\"codex-safe\""},
                 std::string_view{"\"runtime_template_id\":\"sage-guest-safe\""}
             },
             std::pair{
                 std::string_view{"\"secret_handles\":[\"codex-token\"]"},
                 std::string_view{"\"secret_handles\":[]"}
             },
         }) {
        const auto offset = plan.find(from);
        if (offset != std::string::npos) {
            plan.replace(offset, from.size(), to);
        }
    }
    return plan;
}

// Registration example (test fixture): the host owns payload semantics.
auto test_channel_host() -> std::shared_ptr<const glove::control::channel_host> {
    auto host = std::make_shared<glove::control::channel_host>();
    if (!host->register_channel({
            .schema_id = "test.observation.v1",
            .body_validator =
                [](const glove::control::glove_observation_body&) noexcept { return true; },
            .bounds =
                {
                    .max_items = 4'096,
                    .max_body_bytes = 8'192,
                    .max_ttl_ms = 600'000,
                    .max_skew_ms = 30'000,
                },
        }) ||
        !host->freeze()) {
        return {};
    }
    return host;
}

auto validator_for(const std::filesystem::path& source)
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
                        .adapter_command_digest = runtime_digest(),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = launch_template(),
                        .adoption = std::nullopt,
                    },
                    runtime_template_policy{
                        .runtime_template_id = "sage-guest-safe",
                        .runtime_id = "sage-guest",
                        .adapter_command_digest = runtime_digest(),
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = launch_template(),
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

struct running_session_fixture {
    temporary_directory temp;
    std::shared_ptr<glove::control::session_registry> registry;
    std::shared_ptr<glove::container::receipt_audit_producer> producer;
    std::string session_id;
    std::string profile_digest;
    std::string projection_digest;
    std::uint64_t start_ms = 0;

    running_session_fixture(const running_session_fixture&) = delete;
    auto operator=(const running_session_fixture&) -> running_session_fixture& = delete;
    running_session_fixture(running_session_fixture&&) = default;
    auto operator=(running_session_fixture&&) -> running_session_fixture& = default;
    running_session_fixture() = default;
};

auto open_running_session(std::uint64_t start_ms) -> std::optional<running_session_fixture> {
    running_session_fixture fixture;
    fixture.start_ms = start_ms;
    if (fixture.temp.root().empty()) {
        return std::nullopt;
    }
    const auto source = fixture.temp.root() / "source";
    if (!std::filesystem::create_directory(source)) {
        return std::nullopt;
    }
    auto validator = validator_for(source);
    if (!validator) {
        return std::nullopt;
    }
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));

    const auto bundle_root = fixture.temp.root() / "library-bundles";
    if (!std::filesystem::create_directory(bundle_root)) {
        return std::nullopt;
    }
    if (::chmod(bundle_root.c_str(), 0700) != 0) {
        return std::nullopt;
    }
    const auto bundle_path = bundle_root / (library_bundle_digest() + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary};
        output.write(library_bundle.data(), static_cast<std::streamsize>(library_bundle.size()));
    }
    if (::chmod(bundle_path.c_str(), 0600) != 0) {
        return std::nullopt;
    }
    auto opened_bundle_store = glove::supervisor::library_bundle_store::open(bundle_root);
    if (!opened_bundle_store) {
        return std::nullopt;
    }
    auto shared_bundle_store = std::make_shared<const glove::supervisor::library_bundle_store>(
        std::move(*opened_bundle_store)
    );

    const auto audit_key_path = fixture.temp.root() / "receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
    }
    if (::chmod(audit_key_path.c_str(), 0600) != 0) {
        return std::nullopt;
    }
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = fixture.temp.root() / "receipts.journal",
    });
    if (!producer) {
        return std::nullopt;
    }
    if (!(*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value()) {
        return std::nullopt;
    }
    fixture.producer = *producer;

    auto registry = glove::control::session_registry::open_or_create(
        fixture.temp.root() / "sessions.journal",
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    if (!registry) {
        return std::nullopt;
    }
    fixture.registry = std::move(*registry);
    fixture.session_id = "observation-session";
    fixture.profile_digest = std::string(64, 'a');
    fixture.projection_digest = std::string(64, 'c');

    auto created = fixture.registry->create(
        fixture.session_id,
        controller_digest,
        sage_guest_plan_at(start_ms),
        "create-observation-session",
        start_ms
    );
    if (!created) {
        return std::nullopt;
    }
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-observation-session",
        .session_id = fixture.session_id,
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = start_ms + 1U,
        .expires_at_ms = start_ms + 60'000U,
    };
    auto reserved = fixture.registry->reserve_start(
        authorization, "reserve-observation-session", start_ms + 2U
    );
    if (!reserved) {
        return std::nullopt;
    }
    const glove::control::session_execution_binding binding{
        .schema_version = 1,
        .session_id = fixture.session_id,
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = fixture.profile_digest,
        .cgroup_identity = cgroup_identity(7001),
        .filesystem_identity = filesystem_identity(),
    };
    auto reservation = fixture.producer->reserve_terminal(
        binding.session_id, binding.controller_plan_digest, binding.profile_digest
    );
    if (!reservation) {
        return std::nullopt;
    }
    auto starting = fixture.registry->mark_starting(
        binding, *reservation, "starting-observation-session", start_ms + 3U
    );
    if (!starting) {
        return std::nullopt;
    }
    const glove::control::session_running_commitment running{
        .schema_version = 1,
        .session_id = fixture.session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = fixture.profile_digest,
        .process_identity = process_identity(7001),
        .filesystem_identity = binding.filesystem_identity,
    };
    if (!fixture.registry
             ->mark_running(running, *reservation, "running-observation-session", start_ms + 4U)
             .has_value()) {
        return std::nullopt;
    }
    return std::optional<running_session_fixture>{std::move(fixture)};
}

auto make_enqueue_request(
    std::string_view token,
    std::string_view intent_id = "intent-1",
    std::string_view observation = "guest-capability-inventory",
    std::string_view value_digest =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    std::uint64_t item_count = 4,
    std::optional<std::string_view> extra_field = std::nullopt
) -> std::string {
    std::string request =
        std::string{"{\"schema_version\":1,\"channel_token\":\""} + std::string{token} +
        "\",\"body\":{\"schema\":\"test.observation.v1\",\"intent_id\":\"" +
        std::string{intent_id} + "\",\"observation\":\"" + std::string{observation} +
        "\",\"value_digest\":\"" + std::string{value_digest} +
        "\",\"item_count\":" + std::to_string(item_count) + "}";
    if (extra_field) {
        request += ",\"" + std::string{*extra_field} + "\":1";
    }
    request += "}";
    return request;
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
#if defined(__linux__)
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
#else
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (descriptor.get() >= 0) {
        (void)::fcntl(descriptor.get(), F_SETFD, FD_CLOEXEC);
    }
#endif
    if (descriptor.get() < 0) {
        return unique_fd{};
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (::setsockopt(descriptor.get(), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return unique_fd{};
    }
#endif
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

// Locate and duplicate the private listening descriptor without adding a
// production native-handle API or creating a second public transport owner.
auto duplicate_listener_for(const std::filesystem::path& socket_path) -> unique_fd {
    const auto expected = socket_path.string();
    const long open_max = ::sysconf(_SC_OPEN_MAX);
    const int upper_bound = static_cast<int>(std::clamp<long>(open_max, 0, 4'096));
    for (int descriptor = 0; descriptor < upper_bound; ++descriptor) {
        ::sockaddr_un address{};
        ::socklen_t address_size = sizeof(address);
        if (::getsockname(descriptor, reinterpret_cast<::sockaddr*>(&address), &address_size) !=
                0 ||
            address.sun_family != AF_UNIX || std::string_view{address.sun_path} != expected) {
            continue;
        }
        return unique_fd{::dup(descriptor)};
    }
    return unique_fd{};
}

auto transact(const std::filesystem::path& socket_path, std::string_view frame)
    -> std::optional<std::string> {
    auto descriptor = connect_to(socket_path);
    if (descriptor.get() < 0) {
        return std::nullopt;
    }
    const auto size = htonl(static_cast<std::uint32_t>(frame.size()));
    if (!write_exact(descriptor.get(), &size, sizeof(size))) {
        return std::nullopt;
    }
    // An oversized-frame rejection may arrive before the peer drains the
    // caller's body. Preserve the response even when that final write closes.
    static_cast<void>(write_exact(descriptor.get(), frame.data(), frame.size()));
    std::uint32_t response_size = 0;
    if (!read_exact(descriptor.get(), &response_size, sizeof(response_size))) {
        return std::nullopt;
    }
    const auto decoded_size = ntohl(response_size);
    if (decoded_size == 0 || decoded_size > glove::control::max_observation_frame_bytes) {
        return std::nullopt;
    }
    std::string response(decoded_size, '\0');
    if (!read_exact(descriptor.get(), response.data(), response.size())) {
        return std::nullopt;
    }
    return response;
}

auto decode_success(std::string_view frame) -> std::optional<wire_test::enqueue_success> {
    wire_test::enqueue_success value{};
    if (glz::read<glz::opts{.error_on_unknown_keys = true}>(value, frame)) {
        return std::nullopt;
    }
    return value;
}

auto decode_error(std::string_view frame) -> std::optional<wire_test::enqueue_error> {
    wire_test::enqueue_error value{};
    if (glz::read<glz::opts{.error_on_unknown_keys = true}>(value, frame)) {
        return std::nullopt;
    }
    return value;
}

auto response_is_redacted(std::string_view frame) -> bool {
    return frame.find(channel_token) == std::string_view::npos &&
           frame.find("\"channel_token\"") == std::string_view::npos &&
           frame.find("observation-session") == std::string_view::npos &&
           frame.find("secret_handles") == std::string_view::npos &&
           frame.find("path_grants") == std::string_view::npos &&
           frame.find("runtime_template_id") == std::string_view::npos &&
           frame.find("intent-source") == std::string_view::npos;
}

auto server_config_for(
    const running_session_fixture& fixture,
    const std::filesystem::path& socket_path,
    std::uint64_t session_expires_at_ms,
    std::uint64_t io_timeout_ms = 100
) -> glove::control::observation_intent_unix_server_config {
    return {
        .socket_path = socket_path,
        .sessions = fixture.registry.get(),
        .session_id = fixture.session_id,
        .runtime_id = "sage-guest",
        .controller_plan_digest = std::string{controller_digest},
        .profile_digest = fixture.profile_digest,
        .projection_digest = fixture.projection_digest,
        .policy_revision = 7,
        .service_channel_id = "observation-session-observation-v1",
        .channel_generation = 1,
        .session_expires_at_ms = session_expires_at_ms,
        .channel_token = std::string{channel_token},
        .io_timeout_ms = io_timeout_ms,
        .expected_peer_uid = ::geteuid(),
    };
}

auto serve_in_background(
    glove::control::observation_intent_unix_server& server,
    std::size_t count,
    std::optional<std::string>& error_out
) -> std::thread {
    return std::thread{[&server, count, &error_out] {
        for (std::size_t index = 0; index < count; ++index) {
            auto served = server.serve_one_for(5'000);
            if (!served) {
                std::fprintf(stderr, "observation server failed: %s\n", served.error().c_str());
                error_out = served.error();
                return;
            }
            if (!*served) {
                error_out = "accept deadline elapsed";
                return;
            }
        }
    }};
}

auto run() -> int {
    using glove::control::guest_channel_transport_error;
    using glove::control::guest_channel_transport_error_code;

    const auto classified_send_failure = [](guest_channel_transport_error_code code) {
        return glove::control::classify_observation_response_send(
            std::unexpected(guest_channel_transport_error{.code = code, .message = "send failed"})
        );
    };
    for (const auto code : {
             guest_channel_transport_error_code::deadline_exceeded,
             guest_channel_transport_error_code::disconnected,
             guest_channel_transport_error_code::io,
         }) {
        auto classified = classified_send_failure(code);
        REQUIRE(!classified.has_value());
        REQUIRE(classified.error() == "send failed");
    }
    auto cancelled_send = classified_send_failure(guest_channel_transport_error_code::cancelled);
    REQUIRE(cancelled_send.has_value());
    REQUIRE(!*cancelled_send);
    REQUIRE(glove::control::classify_observation_response_send({}).value_or(false));

    // F5: transient accept-boundary errors are retryable; fatal config and
    // descriptor-state errors are not.
    REQUIRE(glove::control::observation_transient_accept_error(EINTR));
    REQUIRE(glove::control::observation_transient_accept_error(EAGAIN));
    REQUIRE(glove::control::observation_transient_accept_error(ECONNABORTED));
    REQUIRE(glove::control::observation_transient_accept_error(EMFILE));
    REQUIRE(glove::control::observation_transient_accept_error(ENFILE));
    REQUIRE(glove::control::observation_transient_accept_error(ENOBUFS));
    REQUIRE(glove::control::observation_transient_accept_error(ENOMEM));
    REQUIRE(!glove::control::observation_transient_accept_error(EBADF));
    REQUIRE(!glove::control::observation_transient_accept_error(EINVAL));
    REQUIRE(!glove::control::observation_transient_accept_error(EACCES));

    const auto now_ms = []() -> std::uint64_t {
        using namespace std::chrono;
        const auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
        return ms.count() < 0 ? 0U : static_cast<std::uint64_t>(ms.count());
    }();
    const std::uint64_t start_ms = now_ms > 10'000U ? now_ms - 10'000U : 1U;

    auto fixture = open_running_session(start_ms);
    REQUIRE(fixture.has_value());
    const auto socket_path = fixture->temp.root() / "observation.sock";

    auto config = server_config_for(*fixture, socket_path, start_ms + 120'000U);
    auto server = glove::control::observation_intent_unix_server::create(config);
    REQUIRE(server.has_value());
    REQUIRE((*server)->socket_path() == socket_path);

    struct stat socket_status{};
    REQUIRE(::lstat(socket_path.c_str(), &socket_status) == 0);
    REQUIRE(S_ISSOCK(socket_status.st_mode));
    REQUIRE(socket_status.st_uid == ::geteuid());
    REQUIRE((socket_status.st_mode & 0777U) == 0600U);

    std::optional<std::string> serve_error;
    auto server_thread = serve_in_background(**server, 1, serve_error);

    const auto request = make_enqueue_request(channel_token);
    auto response = transact(socket_path, request);
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(response.has_value());
    REQUIRE(response_is_redacted(*response));
    auto success = decode_success(*response);
    REQUIRE(success.has_value());
    REQUIRE(success->schema_version == 1);
    REQUIRE(success->status == "queued");
    REQUIRE(success->sequence != 0);
    REQUIRE(success->intent_digest.size() == 64U);
    const auto count_after_enqueue = fixture->registry->record_count();

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto replay_response = transact(socket_path, request);
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(replay_response.has_value());
    auto replay_success = decode_success(*replay_response);
    REQUIRE(replay_success.has_value());
    REQUIRE(replay_success->sequence == success->sequence);
    REQUIRE(replay_success->intent_digest == success->intent_digest);
    REQUIRE(fixture->registry->record_count() == count_after_enqueue);

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto conflict_response = transact(
        socket_path,
        make_enqueue_request(
            channel_token, "intent-1", "guest-capability-inventory", std::string(64, 'e')
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(conflict_response.has_value());
    auto conflict_error = decode_error(*conflict_response);
    REQUIRE(conflict_error.has_value());
    REQUIRE(conflict_error->code == "idempotency_conflict");
    REQUIRE(response_is_redacted(*conflict_response));
    REQUIRE(fixture->registry->record_count() == count_after_enqueue);

    const auto count_before_bad_token = fixture->registry->record_count();
    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto bad_token_response =
        transact(socket_path, make_enqueue_request(std::string(64, 'f'), "intent-2"));
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(bad_token_response.has_value());
    auto bad_token_error = decode_error(*bad_token_response);
    REQUIRE(bad_token_error.has_value());
    REQUIRE(bad_token_error->code == "unauthorized");
    REQUIRE(fixture->registry->record_count() == count_before_bad_token);

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto unknown_field_response = transact(
        socket_path,
        make_enqueue_request(
            channel_token,
            "intent-3",
            "guest-capability-inventory",
            std::string(64, 'b'),
            4,
            "issued_at_ms"
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(unknown_field_response.has_value());
    auto unknown_field_error = decode_error(*unknown_field_response);
    REQUIRE(unknown_field_error.has_value());
    REQUIRE(unknown_field_error->code == "invalid_request");

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto missing_body_response = transact(
        socket_path,
        std::string{"{\"schema_version\":1,\"channel_token\":\""} + std::string{channel_token} +
            "\"}"
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(missing_body_response.has_value());
    auto missing_body_error = decode_error(*missing_body_response);
    REQUIRE(missing_body_error.has_value());
    REQUIRE(missing_body_error->code == "invalid_request");

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    const std::string oversized(glove::control::max_observation_frame_bytes + 1U, 'x');
    auto oversized_response = transact(
        socket_path,
        std::string{"{\"schema_version\":1,\"channel_token\":\""} + std::string{channel_token} +
            "\",\"body\":{\"schema\":\"test.observation.v1\",\"intent_id\":\"intent-4\","
            "\"observation\":\"" +
            oversized + "\",\"value_digest\":\"" + std::string(64, 'c') + "\",\"item_count\":1}}"
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(oversized_response.has_value());
    auto oversized_error = decode_error(*oversized_response);
    REQUIRE(oversized_error.has_value());
    REQUIRE(oversized_error->code == "invalid_request");

    const auto count_before_resilience = fixture->registry->record_count();
    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    {
        auto truncated_descriptor = connect_to(socket_path);
        REQUIRE(truncated_descriptor.get() >= 0);
        const std::uint32_t declared = htonl(128U);
        REQUIRE(write_exact(truncated_descriptor.get(), &declared, sizeof(declared)));
        REQUIRE(write_exact(truncated_descriptor.get(), "{\"schema_version\":1", 18U));
    }
    server_thread.join();
    REQUIRE(!serve_error.has_value());

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto resilience_after_truncation = transact(
        socket_path,
        make_enqueue_request(
            channel_token,
            "intent-resilience-truncated",
            "guest-capability-inventory",
            std::string(64, '7')
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(resilience_after_truncation.has_value());
    auto resilience_truncated_success = decode_success(*resilience_after_truncation);
    REQUIRE(resilience_truncated_success.has_value());
    REQUIRE(resilience_truncated_success->status == "queued");
    REQUIRE(fixture->registry->record_count() > count_before_resilience);

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    {
        auto stalled = connect_to(socket_path);
        REQUIRE(stalled.get() >= 0);
    }
    server_thread.join();
    REQUIRE(!serve_error.has_value());

    serve_error.reset();
    server_thread = serve_in_background(**server, 1, serve_error);
    auto resilience_after_disconnect = transact(
        socket_path,
        make_enqueue_request(
            channel_token,
            "intent-resilience-disconnect",
            "guest-capability-inventory",
            std::string(64, '6')
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(resilience_after_disconnect.has_value());
    auto resilience_disconnect_success = decode_success(*resilience_after_disconnect);
    REQUIRE(resilience_disconnect_success.has_value());
    REQUIRE(resilience_disconnect_success->status == "queued");
    REQUIRE(fixture->registry->record_count() > count_before_resilience + 1U);

    server->reset();
    REQUIRE(::access(socket_path.c_str(), F_OK) != 0);

    // A stop token tears down idle accept and partial header/body service
    // without a concurrent listener/channel close. Destruction happens only
    // after each owning worker has joined.
    {
        auto idle_config = server_config_for(
            *fixture, fixture->temp.root() / "idle-stop.sock", start_ms + 120'000U
        );
        auto idle_server = glove::control::observation_intent_unix_server::create(idle_config);
        REQUIRE(idle_server.has_value());
        std::expected<bool, std::string> idle_result =
            std::unexpected(std::string{"worker did not run"});
        const auto started = std::chrono::steady_clock::now();
        std::jthread idle_worker{[&](std::stop_token stop) {
            idle_result = (*idle_server)->serve_one_for(5'000, stop);
        }};
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        idle_worker.request_stop();
        idle_worker.join();
        REQUIRE(idle_result.has_value());
        REQUIRE(!*idle_result);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::milliseconds{250});
        idle_server->reset();

        // A competing raw accept consumes readiness without taking public
        // ownership of the observation transport. The listener itself must be
        // nonblocking, and the next service call must remain deadline/stop bounded.
        auto race_config = server_config_for(
            *fixture, fixture->temp.root() / "consumed-readiness.sock", start_ms + 120'000U
        );
        auto race_server = glove::control::observation_intent_unix_server::create(race_config);
        REQUIRE(race_server.has_value());
        auto competing_listener = duplicate_listener_for(race_server->get()->socket_path());
        REQUIRE(competing_listener.get() >= 0);
        const int listener_flags = ::fcntl(competing_listener.get(), F_GETFL);
        REQUIRE(listener_flags >= 0);
        REQUIRE((listener_flags & O_NONBLOCK) != 0);

        const auto compete_after_wait = [&](std::uint64_t timeout_ms, bool cancel) -> bool {
            std::expected<bool, std::string> result =
                std::unexpected(std::string{"worker did not run"});
            const auto started = std::chrono::steady_clock::now();
            std::jthread worker{[&](std::stop_token stop) {
                result = (*race_server)->serve_one_for(timeout_ms, stop);
            }};
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            auto pending = connect_to(race_server->get()->socket_path());
            if (pending.get() < 0) {
                worker.request_stop();
                worker.join();
                return false;
            }
            ::pollfd event{.fd = competing_listener.get(), .events = POLLIN, .revents = 0};
            if (::poll(&event, 1, 10) != 1 || (event.revents & POLLIN) == 0) {
                worker.request_stop();
                worker.join();
                return false;
            }
            unique_fd consumed{::accept(competing_listener.get(), nullptr, nullptr)};
            if (consumed.get() < 0) {
                worker.request_stop();
                worker.join();
                return false;
            }
            if (cancel) {
                worker.request_stop();
            }
            worker.join();
            return result.has_value() && !*result &&
                   std::chrono::steady_clock::now() - started < std::chrono::milliseconds{250};
        };

        bool deadline_race_exercised = false;
        for (unsigned attempt = 0; attempt < 16U && !deadline_race_exercised; ++attempt) {
            deadline_race_exercised = compete_after_wait(40, false);
        }
        REQUIRE(deadline_race_exercised);

        bool cancellation_race_exercised = false;
        for (unsigned attempt = 0; attempt < 16U && !cancellation_race_exercised; ++attempt) {
            cancellation_race_exercised = compete_after_wait(5'000, true);
        }
        REQUIRE(cancellation_race_exercised);
        race_server->reset();

        for (const bool partial_body : {false, true}) {
            const auto name = partial_body ? "partial-body-stop.sock" : "partial-header-stop.sock";
            auto partial_config = server_config_for(
                *fixture, fixture->temp.root() / name, start_ms + 120'000U, 5'000
            );
            auto partial_server =
                glove::control::observation_intent_unix_server::create(partial_config);
            REQUIRE(partial_server.has_value());
            auto partial_client = connect_to(partial_server->get()->socket_path());
            REQUIRE(partial_client.get() >= 0);
            const auto declared = htonl(128U);
            if (partial_body) {
                REQUIRE(write_exact(partial_client.get(), &declared, sizeof(declared)));
                REQUIRE(write_exact(partial_client.get(), "{", 1U));
            } else {
                REQUIRE(write_exact(partial_client.get(), &declared, 1U));
            }
            std::expected<bool, std::string> partial_result =
                std::unexpected(std::string{"worker did not run"});
            const auto partial_started = std::chrono::steady_clock::now();
            std::jthread partial_worker{[&](std::stop_token stop) {
                partial_result = (*partial_server)->serve_one_for(5'000, stop);
            }};
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            partial_worker.request_stop();
            partial_worker.join();
            REQUIRE(partial_result.has_value());
            REQUIRE(!*partial_result);
            REQUIRE(
                std::chrono::steady_clock::now() - partial_started < std::chrono::milliseconds{250}
            );
            partial_server->reset();
        }
    }

    REQUIRE(::chmod(fixture->temp.root().c_str(), 0755) == 0);
    REQUIRE(
        !glove::control::observation_intent_unix_server::create(
             server_config_for(*fixture, fixture->temp.root() / "unsafe.sock", start_ms + 120'000U)
        )
             .has_value()
    );
    REQUIRE(::chmod(fixture->temp.root().c_str(), 0700) == 0);

    REQUIRE(write_owner_only(socket_path, "not-a-socket"));
    REQUIRE(!glove::control::observation_intent_unix_server::create(
                 server_config_for(*fixture, socket_path, start_ms + 120'000U)
    )
                 .has_value());
    std::filesystem::remove(socket_path);

    auto mismatched_config =
        server_config_for(*fixture, fixture->temp.root() / "mismatch.sock", start_ms + 120'000U);
    mismatched_config.profile_digest = std::string(64, 'f');
    auto mismatch_server =
        glove::control::observation_intent_unix_server::create(mismatched_config);
    REQUIRE(mismatch_server.has_value());
    const auto count_before_mismatch = fixture->registry->record_count();
    serve_error.reset();
    server_thread = serve_in_background(**mismatch_server, 1, serve_error);
    auto mismatch_response = transact(
        mismatch_server->get()->socket_path(),
        make_enqueue_request(
            channel_token, "intent-mismatch", "guest-capability-inventory", std::string(64, '9')
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(mismatch_response.has_value());
    auto mismatch_error = decode_error(*mismatch_response);
    REQUIRE(mismatch_error.has_value());
    REQUIRE(mismatch_error->code == "intent_rejected");
    REQUIRE(fixture->registry->record_count() == count_before_mismatch);

    auto expired_config =
        server_config_for(*fixture, fixture->temp.root() / "expired.sock", start_ms - 1U);
    auto expired_server = glove::control::observation_intent_unix_server::create(expired_config);
    REQUIRE(expired_server.has_value());
    serve_error.reset();
    server_thread = serve_in_background(**expired_server, 1, serve_error);
    auto expired_response = transact(
        expired_server->get()->socket_path(),
        make_enqueue_request(
            channel_token, "intent-expired", "guest-capability-inventory", std::string(64, '8')
        )
    );
    server_thread.join();
    REQUIRE(!serve_error.has_value());
    REQUIRE(expired_response.has_value());
    auto expired_error = decode_error(*expired_response);
    REQUIRE(expired_error.has_value());
    REQUIRE(expired_error->code == "intent_expired");

    // F3: peer-credential enforcement. A server configured with an expected
    // uid that cannot match the (same-uid) test client rejects connections
    // before any frame is read, and the registry stays untouched.
    {
        auto guarded_config =
            server_config_for(*fixture, fixture->temp.root() / "guarded.sock", start_ms + 120'000U);
        guarded_config.expected_peer_uid = ::geteuid() + 1U;
        auto guarded_server =
            glove::control::observation_intent_unix_server::create(guarded_config);
        REQUIRE(guarded_server.has_value());
        const auto count_before_guard = fixture->registry->record_count();
        serve_error.reset();
        server_thread = serve_in_background(**guarded_server, 1, serve_error);
        auto guarded_response = transact(
            guarded_server->get()->socket_path(),
            make_enqueue_request(channel_token, "intent-guarded")
        );
        server_thread.join();
        REQUIRE(!serve_error.has_value());
        // The peer is rejected without a response frame.
        REQUIRE(!guarded_response.has_value());
        REQUIRE(fixture->registry->record_count() == count_before_guard);
    }

    // Durable replay survives server reconstruction; host timestamps are
    // stamped only by the first acceptance and a changed stable body conflicts.
    {
        auto reconstructed_config = server_config_for(
            *fixture, fixture->temp.root() / "reconstructed.sock", start_ms + 120'000U
        );
        auto reconstructed_server =
            glove::control::observation_intent_unix_server::create(reconstructed_config);
        REQUIRE(reconstructed_server.has_value());
        const auto reconstructed_socket = reconstructed_server->get()->socket_path();
        const auto count_before_reconstruction = fixture->registry->record_count();
        serve_error.reset();
        server_thread = serve_in_background(**reconstructed_server, 1, serve_error);
        auto first = transact(
            reconstructed_socket, make_enqueue_request(channel_token, "reconstructed-intent")
        );
        server_thread.join();
        REQUIRE(!serve_error.has_value());
        REQUIRE(first.has_value());
        auto first_success = decode_success(*first);
        REQUIRE(first_success.has_value());
        reconstructed_server->reset();

        std::this_thread::sleep_for(std::chrono::milliseconds{2});
        reconstructed_server =
            glove::control::observation_intent_unix_server::create(reconstructed_config);
        REQUIRE(reconstructed_server.has_value());
        serve_error.reset();
        server_thread = serve_in_background(**reconstructed_server, 2, serve_error);
        auto replay = transact(
            reconstructed_server->get()->socket_path(),
            make_enqueue_request(channel_token, "reconstructed-intent")
        );
        REQUIRE(replay.has_value());
        auto reconstructed_replay_success = decode_success(*replay);
        REQUIRE(reconstructed_replay_success.has_value());
        REQUIRE(reconstructed_replay_success->sequence == first_success->sequence);
        REQUIRE(reconstructed_replay_success->intent_digest == first_success->intent_digest);
        auto changed = transact(
            reconstructed_server->get()->socket_path(),
            make_enqueue_request(
                channel_token,
                "reconstructed-intent",
                "guest-capability-inventory",
                std::string(64, '1')
            )
        );
        server_thread.join();
        REQUIRE(!serve_error.has_value());
        REQUIRE(changed.has_value());
        REQUIRE(decode_error(*changed)->code == "idempotency_conflict");
        REQUIRE(fixture->registry->record_count() == count_before_reconstruction + 1U);
    }

    // F5: a transient accept failure (real fd exhaustion) is retried with a
    // bounded backoff and must not permanently kill the channel.
    {
        auto retry_config =
            server_config_for(*fixture, fixture->temp.root() / "retry.sock", start_ms + 120'000U);
        auto retry_server = glove::control::observation_intent_unix_server::create(retry_config);
        REQUIRE(retry_server.has_value());
        const auto retry_socket = retry_server->get()->socket_path();

        auto held = connect_to(retry_socket);
        REQUIRE(held.get() >= 0);
        const auto held_request = make_enqueue_request(channel_token, "intent-retry");
        const auto held_size = htonl(static_cast<std::uint32_t>(held_request.size()));
        REQUIRE(write_exact(held.get(), &held_size, sizeof(held_size)));
        REQUIRE(write_exact(held.get(), held_request.data(), held_request.size()));

        // Genuinely exhaust descriptors so the next accept() fails with
        // EMFILE where the platform enforces it at allocation time.
        std::vector<int> exhausted;
        bool exhausted_descriptors = false;
        for (;;) {
            const int descriptor = ::dup(0);
            if (descriptor < 0) {
                exhausted_descriptors = errno == EMFILE;
                break;
            }
            exhausted.push_back(descriptor);
            if (exhausted.size() > 4096U) {
                break;
            }
        }
        if (exhausted_descriptors) {
            // Every failed accept and backoff shares the original deadline;
            // retries cannot turn 40 ms into one fresh timeout per attempt.
            const auto deadline_started = std::chrono::steady_clock::now();
            auto deadline_result = (*retry_server)->serve_one_for(40);
            REQUIRE(deadline_result.has_value());
            REQUIRE(!*deadline_result);
            REQUIRE(
                std::chrono::steady_clock::now() - deadline_started < std::chrono::milliseconds{250}
            );

            // Cancellation also interrupts the transient accept backoff.
            std::expected<bool, std::string> stop_result =
                std::unexpected(std::string{"worker did not run"});
            const auto stop_started = std::chrono::steady_clock::now();
            std::jthread retry_worker{[&](std::stop_token stop) {
                stop_result = (*retry_server)->serve_one_for(2'000, stop);
            }};
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            retry_worker.request_stop();
            retry_worker.join();
            REQUIRE(stop_result.has_value());
            REQUIRE(!*stop_result);
            REQUIRE(
                std::chrono::steady_clock::now() - stop_started < std::chrono::milliseconds{250}
            );

            for (const int descriptor : exhausted) {
                ::close(descriptor);
            }
            // The channel recovers: both the queued connection and the new
            // recovery request are accepted and processed.
            const auto count_before_retry = fixture->registry->record_count();
            serve_error.reset();
            server_thread = serve_in_background(**retry_server, 2, serve_error);
            auto retry_response = transact(
                retry_socket, make_enqueue_request(channel_token, "intent-retry-recovered")
            );
            server_thread.join();
            REQUIRE(!serve_error.has_value());
            REQUIRE(retry_response.has_value());
            REQUIRE(decode_success(*retry_response).has_value());
            REQUIRE(fixture->registry->record_count() == count_before_retry + 2U);
        } else {
            // macOS keeps new allocations below its high-water mark, so the
            // accept may simply succeed; the channel must still stay healthy
            // and process both the queued and a fresh request.
            for (const int descriptor : exhausted) {
                ::close(descriptor);
            }
            const auto count_before_retry = fixture->registry->record_count();
            serve_error.reset();
            server_thread = serve_in_background(**retry_server, 2, serve_error);
            auto retry_response = transact(
                retry_socket, make_enqueue_request(channel_token, "intent-retry-recovered")
            );
            server_thread.join();
            REQUIRE(!serve_error.has_value());
            REQUIRE(retry_response.has_value());
            REQUIRE(decode_success(*retry_response).has_value());
            REQUIRE(fixture->registry->record_count() >= count_before_retry + 1U);
        }
    }

    auto cleanup_config =
        server_config_for(*fixture, fixture->temp.root() / "cleanup.sock", start_ms + 120'000U);
    auto cleanup_server = glove::control::observation_intent_unix_server::create(cleanup_config);
    REQUIRE(cleanup_server.has_value());
    struct stat created_socket{};
    REQUIRE(::lstat(cleanup_config.socket_path.c_str(), &created_socket) == 0);
    const auto created_inode = created_socket.st_ino;
    REQUIRE(::unlink(cleanup_config.socket_path.c_str()) == 0);
    REQUIRE(write_owner_only(cleanup_config.socket_path, "replacement"));
    struct stat replacement{};
    REQUIRE(::lstat(cleanup_config.socket_path.c_str(), &replacement) == 0);
    REQUIRE(replacement.st_ino != created_inode);
    cleanup_server->reset();
    REQUIRE(std::filesystem::exists(cleanup_config.socket_path));
    REQUIRE(std::filesystem::file_size(cleanup_config.socket_path) > 0U);

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
