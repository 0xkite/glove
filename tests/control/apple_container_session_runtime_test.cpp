#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "apple_container_session_runtime.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <thread>

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
constexpr std::string_view bootstrap_secret =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
constexpr std::uint64_t mode_a_cpu_time_ms = 60'000;
constexpr std::uint64_t mode_a_memory_bytes = 1'073'741'824;
constexpr std::uint32_t mode_a_pids = 256;
constexpr std::uint64_t mode_a_wall_time_ms = 120'000;
constexpr std::uint64_t mode_a_disk_bytes = 2'147'483'648;
constexpr std::uint64_t mode_a_terminal_output_bytes = 16'777'216;
constexpr std::uint64_t mode_a_plan_ttl_ms = 300'000;
constexpr std::string_view credential_guest_target = "/home/agent/.pi/test-auth.json";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-apple-runtime-test-XXXXXX";
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

class origin_server {
public:
    origin_server() = default;
    origin_server(const origin_server&) = delete;
    auto operator=(const origin_server&) -> origin_server& = delete;

    ~origin_server() {
        if (descriptor_ >= 0) {
            ::shutdown(descriptor_, SHUT_RDWR);
            ::close(descriptor_);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    auto start() -> bool {
        descriptor_ = ::socket(AF_INET, SOCK_STREAM, 0);
        ::sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (descriptor_ < 0 ||
            ::bind(descriptor_, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(descriptor_, 1) != 0) {
            return false;
        }
        ::sockaddr_in bound{};
        ::socklen_t size = sizeof(bound);
        if (::getsockname(descriptor_, reinterpret_cast<::sockaddr*>(&bound), &size) != 0) {
            return false;
        }
        port_ = ntohs(bound.sin_port);
        thread_ = std::thread{[this] {
            const int connection = ::accept(descriptor_, nullptr, nullptr);
            if (connection >= 0) {
                constexpr std::string_view marker = "ORIGIN_HELLO";
                static_cast<void>(::write(connection, marker.data(), marker.size()));
                ::close(connection);
            }
        }};
        return true;
    }

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return port_; }

private:
    int descriptor_ = -1;
    std::uint16_t port_ = 0;
    std::thread thread_;
};

auto epoch_ms() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch()
    )
                                          .count());
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

auto run() -> int {
    const char* image = std::getenv("GLOVE_APPLE_CONTAINER_IMAGE");
    const char* image_digest = std::getenv("GLOVE_APPLE_CONTAINER_IMAGE_DIGEST");
    if (image == nullptr || *image == '\0' || image_digest == nullptr || *image_digest == '\0') {
        std::fprintf(
            stderr,
            "SKIP: set GLOVE_APPLE_CONTAINER_IMAGE and "
            "GLOVE_APPLE_CONTAINER_IMAGE_DIGEST for the live Apple lane\n"
        );
        return 77;
    }
    const char* configured_cli = std::getenv("GLOVE_APPLE_CONTAINER_CLI");
    const char* closure_digest = std::getenv("GLOVE_APPLE_CONTAINER_HARNESS_CLOSURE_DIGEST");
    const bool managed_closure = closure_digest != nullptr && *closure_digest != '\0';
    const bool egress_probe =
        managed_closure && std::getenv("GLOVE_APPLE_CONTAINER_EGRESS_PROBE") != nullptr;
    const bool secret_lane = managed_closure && !egress_probe &&
                             std::getenv("GLOVE_APPLE_CONTAINER_SECRET_LEASE") != nullptr;
    origin_server origin;
    if (egress_probe) {
        REQUIRE(origin.start());
    }
    const std::filesystem::path cli = configured_cli != nullptr && *configured_cli != '\0'
                                          ? configured_cli
                                          : "/usr/local/bin/container";

    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto session_root = temp.root() / "sessions";
    REQUIRE(std::filesystem::create_directory(session_root));
    REQUIRE(::chmod(session_root.c_str(), 0700) == 0);
    const auto unused_source = temp.root() / "unused-source";
    REQUIRE(std::filesystem::create_directory(unused_source));
    const auto credential_source = temp.root() / "credential.json";
    constexpr std::string_view secret_sentinel = "apple-secret-sentinel";
    if (secret_lane) {
        std::ofstream output{credential_source, std::ios::binary};
        output << "{\"token\":\"" << secret_sentinel << "\"}\n";
        output.close();
        REQUIRE(::chmod(credential_source.c_str(), 0600) == 0);
        struct stat metadata{};
        REQUIRE(::stat(credential_source.c_str(), &metadata) == 0);
        REQUIRE((metadata.st_mode & 0777) == 0600);
        REQUIRE(metadata.st_uid == ::geteuid());
    }

    const glove::supervisor::runtime_launch_template launch{
        .runtime_discovery = {},
        .executable_path = managed_closure ? "/image/managed/adapter" : "/bin/bash",
        .executable_search_paths = {},
        .arguments =
            egress_probe
                ? std::vector<std::string>{"localhost", std::to_string(origin.port())}
                : managed_closure ? std::vector<std::string>{
                    secret_lane ? "--help" : "--version",
                }
                            : std::vector<std::string>{
                "-lc",
                "printf 'APPLE_READY\\n'; IFS= read -r line; "
                "printf 'APPLE_ECHO:%s\\n' \"$line\"",
            },
        .environment = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        .read_only_paths = {},
    };
    const auto adapter_digest = glove::supervisor::runtime_launch_template_digest(launch);
    REQUIRE(adapter_digest.has_value());
    auto paths = glove::supervisor::path_alias_registry::build({
        {
            .alias = "unused",
            .host_path = std::filesystem::canonical(unused_source).string(),
            .target_path = "/unused",
            .max_ttl_secs = 120,
            .access = {
                {
                    .access = glove::supervisor::path_access::ephemeral_write,
                    .materialization = glove::supervisor::path_materialization::copy,
                    .create_policy = glove::supervisor::path_create_policy::empty_directory,
                    .cleanup_policy = glove::supervisor::path_cleanup_policy::remove,
                    .max_bytes = 1'048'576,
                },
            },
        },
    });
    REQUIRE(paths.has_value());
    auto validator = glove::supervisor::session_plan_validator::build(
        {
            .revision = 1,
            .max_plan_ttl_ms = mode_a_plan_ttl_ms,
            .runtime_templates =
                {
                    {
                        .runtime_template_id = "apple-probe",
                        .runtime_id = egress_probe
                                          ? "glove-egress-probe"
                                          : managed_closure ? "pi" : "probe",
                        .adapter_command_digest = *adapter_digest,
                        .backend = glove::supervisor::sandbox_backend::apple_container,
                        .allowed_path_aliases = {},
                        .allowed_projection_destinations = {},
                        .launch = launch,
                        .adoption = std::nullopt,
                    },
                },
            .library_projection_destinations = {},
            .resource_profiles =
                {
                    {
                        .cpu_time_ms = mode_a_cpu_time_ms,
                        .memory_bytes = mode_a_memory_bytes,
                        .pids = mode_a_pids,
                        .wall_time_ms = mode_a_wall_time_ms,
                        .disk_bytes = mode_a_disk_bytes,
                        .terminal_output_bytes = mode_a_terminal_output_bytes,
                    },
                },
            .egress_policy_ids = egress_probe
                                     ? std::vector<std::string>{"test-online"}
                                     : std::vector<std::string>{"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles =
                secret_lane ? std::vector<std::string>{"test-auth"} : std::vector<std::string>{},
            .egress_policies =
                egress_probe
                    ? std::vector<glove::supervisor::egress_policy>{
                          {
                              .policy_id = "test-online",
                              .targets =
                                  {
                                      {
                                          .host = "localhost",
                                          .port = origin.port(),
                                          .allow_private = true,
                                      },
                                  },
                          },
                      }
                    : std::vector<glove::supervisor::egress_policy>{},
            .secret_mounts =
                secret_lane
                    ? std::vector<glove::supervisor::secret_mount_policy>{
                          {
                              .handle = "test-auth",
                              .runtime_id = "pi",
                              .source_path = credential_source.string(),
                              .target_path = std::string{credential_guest_target},
                          },
                      }
                    : std::vector<glove::supervisor::secret_mount_policy>{},
        },
        std::move(*paths)
    );
    if (!validator) {
        std::fprintf(stderr, "validator build failed: %s\n", validator.error().c_str());
    }
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto registry_path = temp.root() / "sessions.journal";
    auto registry =
        glove::control::session_registry::open_or_create(registry_path, shared_validator);
    REQUIRE(registry.has_value());
    auto shared_registry = std::shared_ptr<glove::control::session_registry>{std::move(*registry)};

    const auto audit_key_path = temp.root() / "audit.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = temp.root() / "receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());

    auto runtime = glove::control::apple_detail::apple_container_session_runtime::create(
        *shared_registry,
        {
            .container_cli = cli,
            .image_reference = image,
            .image_digest = image_digest,
            .harness_closure_digest =
                managed_closure ? std::optional<std::string>{closure_digest} : std::nullopt,
            .egress_audit = glove::audit::make_memory_sink(),
            .session_root = session_root,
        }
    );
    if (!runtime) {
        std::fprintf(stderr, "runtime build failed: %s\n", runtime.error().c_str());
    }
    REQUIRE(runtime.has_value());
    auto shared_runtime = std::shared_ptr<glove::control::session_runtime>{std::move(*runtime)};
    REQUIRE(shared_runtime->resource_capabilities().complete());
    if (managed_closure) {
        const std::vector<std::string> expected_runtime_ids{
            "claude-code", "pi", "copilot", "opencode"
        };
        REQUIRE(shared_runtime->managed_runtime_ids() == expected_runtime_ids);
    } else {
        REQUIRE(shared_runtime->managed_runtime_ids().empty());
    }
    auto protocol = glove::control::receipt_audit_protocol::create(
        bootstrap_secret,
        *producer,
        shared_validator,
        shared_registry,
        shared_runtime,
        {},
        session_root.string()
    );
    REQUIRE(protocol.has_value());
    const auto now_ms = epoch_ms();
    const auto plan =
        std::string{R"({"schema_version":1,"runtime_id":")"} +
        (egress_probe      ? "glove-egress-probe"
         : managed_closure ? "pi"
                           : "probe") +
        R"(","runtime_template_id":"apple-probe","adapter_command_digest":")" + *adapter_digest +
        R"(","sandbox_backend":"apple_container","egress_policy_id":")" +
        (egress_probe ? "test-online" : "no-network") +
        R"(","tool_policy_id":"sage-readonly","path_grants":[],"library_projections":[],"secret_handles":)" +
        (secret_lane ? R"(["test-auth"])" : "[]") + R"(,"limits":{"cpu_time_ms":)" +
        std::to_string(mode_a_cpu_time_ms) + R"(,"memory_bytes":)" +
        std::to_string(mode_a_memory_bytes) + R"(,"pids":)" + std::to_string(mode_a_pids) +
        R"(,"wall_time_ms":)" + std::to_string(mode_a_wall_time_ms) + R"(,"disk_bytes":)" +
        std::to_string(mode_a_disk_bytes) + R"(,"terminal_output_bytes":)" +
        std::to_string(mode_a_terminal_output_bytes) + R"(},"policy_revision":1,"expires_at_ms":)" +
        std::to_string(now_ms + mode_a_plan_ttl_ms) + "}";
    REQUIRE(plan.find(secret_sentinel) == std::string::npos);
    REQUIRE(plan.find(credential_source.string()) == std::string::npos);
    REQUIRE(plan.find(credential_guest_target) == std::string::npos);
    auto created =
        shared_registry->create("apple-live", controller_digest, plan, "apple-create", now_ms);
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "apple-approval",
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = now_ms + 1U,
        .expires_at_ms = now_ms + 30'000U,
    };
    const auto start_payload =
        "{\"authorization\":{\"schema_version\":1,\"authorization_id\":\"" +
        authorization.authorization_id + "\",\"session_id\":\"" + authorization.session_id +
        "\",\"controller_plan_digest\":\"" + authorization.controller_plan_digest +
        "\",\"plan_content_digest\":\"" + authorization.plan_content_digest +
        "\",\"approved_at_ms\":" + std::to_string(authorization.approved_at_ms) +
        ",\"expires_at_ms\":" + std::to_string(authorization.expires_at_ms) + "}}";
    auto start_frame = (*protocol)->handle_frame(
        make_request(
            "start-apple-live", "start_session", start_payload, "apple-live", now_ms + 10'000U
        ),
        now_ms + 2U
    );
    if (!start_frame) {
        std::fprintf(stderr, "Apple protocol start failed: %s\n", start_frame.error().c_str());
    }
    REQUIRE(start_frame.has_value());
    REQUIRE(start_frame->find("\"result\":") != std::string::npos);
    REQUIRE(start_frame->find("\"error\":") == std::string::npos);
    auto started = shared_registry->status("apple-live");
    REQUIRE(started.has_value());
    REQUIRE(started->state == glove::control::session_state::running);

    std::uint64_t cursor = 0;
    std::string transcript;
    const std::string expected_ready = egress_probe      ? "GLOVE_EGRESS_OK"
                                       : secret_lane     ? "Usage:"
                                       : managed_closure ? "0.84.1"
                                                         : "APPLE_READY";
    for (int attempt = 0; attempt < 20 && transcript.find(expected_ready) == std::string::npos;
         ++attempt) {
        auto page = shared_runtime->wait_read("apple-live", cursor, 65'536, 1'000);
        if (!page) {
            continue;
        }
        cursor = page->next_cursor;
        transcript += page->bytes;
    }
    REQUIRE(transcript.find(secret_sentinel) == std::string::npos);
    REQUIRE(transcript.find(credential_source.string()) == std::string::npos);
    if (!managed_closure) {
        REQUIRE(transcript.find(expected_ready) != std::string::npos);
        REQUIRE(shared_runtime->resize("apple-live", 40, 120).has_value());
        REQUIRE(shared_runtime->write_input("apple-live", "managed-input\n").has_value());
        for (int attempt = 0;
             attempt < 20 && transcript.find("APPLE_ECHO:managed-input") == std::string::npos;
             ++attempt) {
            auto page = shared_runtime->wait_read("apple-live", cursor, 65'536, 1'000);
            if (!page) {
                continue;
            }
            cursor = page->next_cursor;
            transcript += page->bytes;
        }
        REQUIRE(transcript.find("APPLE_ECHO:managed-input") != std::string::npos);
    }
    auto terminal = shared_runtime->wait("apple-live");
    if (!terminal) {
        std::fprintf(stderr, "Apple runtime wait failed: %s\n", terminal.error().c_str());
    }
    REQUIRE(terminal.has_value());
    if (!secret_lane && transcript.find(expected_ready) == std::string::npos) {
        std::fprintf(
            stderr,
            "Apple runtime transcript missing %s; exit code: %d; transcript: %s\n",
            expected_ready.c_str(),
            terminal->exit_code.value_or(-1),
            transcript.c_str()
        );
    }
    if (!secret_lane) {
        REQUIRE(transcript.find(expected_ready) != std::string::npos);
    }
    REQUIRE(terminal->session.state == glove::control::session_state::exited);
    REQUIRE(terminal->exit_code == 0);
    REQUIRE(terminal->termination_cause == glove::container::resource_termination_cause::exited);
    REQUIRE(shared_registry->managed_recovery_candidates()->empty());
    REQUIRE(shared_runtime->cleanup("apple-live").has_value());
    REQUIRE(shared_runtime->list()->empty());
    if (secret_lane) {
        const auto lease_root = session_root / ".credential-leases";
        REQUIRE(std::filesystem::is_empty(lease_root));
        REQUIRE(std::filesystem::exists(credential_source));
        std::ifstream source{credential_source, std::ios::binary};
        std::string source_contents{
            std::istreambuf_iterator<char>{source}, std::istreambuf_iterator<char>{}
        };
        REQUIRE(source_contents == "{\"token\":\"apple-secret-sentinel\"}\n");
        struct stat metadata{};
        REQUIRE(::stat(credential_source.c_str(), &metadata) == 0);
        REQUIRE((metadata.st_mode & 0777) == 0600);
        REQUIRE(metadata.st_uid == ::geteuid());

        for (const auto& journal_path : {temp.root() / "receipts.journal", registry_path}) {
            std::ifstream journal{journal_path, std::ios::binary};
            std::string journal_contents{
                std::istreambuf_iterator<char>{journal}, std::istreambuf_iterator<char>{}
            };
            REQUIRE(journal_contents.find(secret_sentinel) == std::string::npos);
            REQUIRE(journal_contents.find(credential_source.string()) == std::string::npos);
        }
    }
    return 0;
}

} // namespace

int main() {
    return run();
}
