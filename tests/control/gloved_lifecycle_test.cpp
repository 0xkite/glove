#include "glove/container/receipt_chain.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/host/config.hpp"
#include "glove/host/control_client.hpp"

#include "receipt_audit_wire.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
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
    bool has_more = false;
    glove::container::receipt_audit_anchor local_anchor;
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

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/gloved-lifecycle-test-XXXXXX";
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
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_ = -1;
};

class child_process {
public:
    explicit child_process(::pid_t process = -1) noexcept : process_{process} {}

    child_process(const child_process&) = delete;
    auto operator=(const child_process&) -> child_process& = delete;

    child_process(child_process&& other) noexcept
        : process_{std::exchange(other.process_, -1)}, status_{std::move(other.status_)} {}

    auto operator=(child_process&&) -> child_process& = delete;

    ~child_process() { (void)stop(); }

    [[nodiscard]] auto running() -> bool {
        if (process_ <= 0) {
            return false;
        }
        int status = 0;
        const auto waited = ::waitpid(process_, &status, WNOHANG);
        if (waited == process_) {
            process_ = -1;
            status_ = status;
            return false;
        }
        return waited == 0;
    }

    auto wait_for_exit() -> std::optional<int> {
        if (status_) {
            return status_;
        }
        for (int attempt = 0; attempt < 300; ++attempt) {
            if (!running()) {
                return status_;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return std::nullopt;
    }

    auto stop() -> bool {
        if (process_ <= 0) {
            return status_ && WIFEXITED(*status_) && WEXITSTATUS(*status_) == 0;
        }
        if (::kill(process_, SIGTERM) != 0 && errno != ESRCH) {
            return false;
        }
        auto status = wait_for_exit();
        if (status) {
            return WIFEXITED(*status) && WEXITSTATUS(*status) == 0;
        }
        (void)::kill(process_, SIGKILL);
        int forced_status = 0;
        (void)::waitpid(process_, &forced_status, 0);
        process_ = -1;
        status_ = forced_status;
        return false;
    }

    auto kill_hard() -> bool {
        if (process_ <= 0 || ::kill(process_, SIGKILL) != 0) {
            return false;
        }
        int status = 0;
        while (::waitpid(process_, &status, 0) < 0) {
            if (errno != EINTR) {
                return false;
            }
        }
        process_ = -1;
        status_ = status;
        return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    }

private:
    ::pid_t process_ = -1;
    std::optional<int> status_;
};

auto write_owner_only(const std::filesystem::path& path, std::string_view value) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << value << '\n';
    output.flush();
    return output.good() && ::chmod(path.c_str(), 0600) == 0;
}

auto start_gloved(
    const std::filesystem::path& runtime_dir,
    const std::filesystem::path& key_path,
    const std::filesystem::path& journal_path,
    const std::optional<std::filesystem::path>& session_policy = std::nullopt,
    const std::optional<std::filesystem::path>& session_store = std::nullopt,
    const std::optional<std::filesystem::path>& materialization_root = std::nullopt,
    const std::optional<std::filesystem::path>& library_bundle_root = std::nullopt
) -> child_process {
    const auto process = ::fork();
    if (process != 0) {
        return child_process{process};
    }
    if (session_policy && session_store && materialization_root && library_bundle_root) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--session-policy",
            session_policy->c_str(),
            "--session-store",
            session_store->c_str(),
            "--materialization-root",
            materialization_root->c_str(),
            "--library-bundle-root",
            library_bundle_root->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (session_policy && session_store && library_bundle_root) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--session-policy",
            session_policy->c_str(),
            "--session-store",
            session_store->c_str(),
            "--library-bundle-root",
            library_bundle_root->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (session_policy && session_store && materialization_root) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--session-policy",
            session_policy->c_str(),
            "--session-store",
            session_store->c_str(),
            "--materialization-root",
            materialization_root->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (materialization_root) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--materialization-root",
            materialization_root->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (library_bundle_root) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--library-bundle-root",
            library_bundle_root->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (session_policy && session_store) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--session-policy",
            session_policy->c_str(),
            "--session-store",
            session_store->c_str(),
            static_cast<char*>(nullptr)
        );
    } else if (session_policy) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            "--session-policy",
            session_policy->c_str(),
            static_cast<char*>(nullptr)
        );
    } else {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::execl(
            GLOVED_BIN,
            GLOVED_BIN,
            "--runtime-dir",
            runtime_dir.c_str(),
            "--audit-key",
            key_path.c_str(),
            "--journal",
            journal_path.c_str(),
            static_cast<char*>(nullptr)
        );
    }
    _exit(127);
}

auto start_gloved_config(const std::filesystem::path& config_path) -> child_process {
    const auto process = ::fork();
    if (process != 0) {
        return child_process{process};
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    ::execl(GLOVED_BIN, GLOVED_BIN, "--config", config_path.c_str(), static_cast<char*>(nullptr));
    _exit(127);
}

auto wait_until_ready(
    child_process& process,
    const std::filesystem::path& socket_path,
    const std::filesystem::path& secret_path
) -> bool {
    for (int attempt = 0; attempt < 300; ++attempt) {
        if (std::filesystem::exists(socket_path) && std::filesystem::exists(secret_path)) {
            return true;
        }
        if (!process.running()) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
}

auto read_secret(const std::filesystem::path& path) -> std::optional<std::string> {
    std::ifstream input{path, std::ios::binary};
    std::string value;
    input >> value;
    if (!input || value.size() != 64U) {
        return std::nullopt;
    }
    return value;
}

auto wait_until_secret_changes(
    child_process& process,
    const std::filesystem::path& socket_path,
    const std::filesystem::path& secret_path,
    std::string_view previous_secret
) -> bool {
    for (int attempt = 0; attempt < 300; ++attempt) {
        const auto secret = read_secret(secret_path);
        if (std::filesystem::exists(socket_path) && secret && *secret != previous_secret) {
            return true;
        }
        if (!process.running()) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
}

auto wait_until_authenticated(const glove::host::config& configured) -> bool {
    for (int attempt = 0; attempt < 300; ++attempt) {
        if (glove::host::supervisor_health(configured)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
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
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (descriptor.get() < 0 || ::fcntl(descriptor.get(), F_SETFD, FD_CLOEXEC) != 0) {
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

auto transact_with_retry(const std::filesystem::path& socket_path, std::string_view frame)
    -> std::optional<std::string> {
    for (int attempt = 0; attempt < 300; ++attempt) {
        if (auto response = transact(socket_path, frame)) {
            return response;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return std::nullopt;
}

auto make_request(
    std::string_view id,
    std::string_view method,
    std::string_view secret,
    std::string_view payload,
    std::optional<std::string_view> idempotency = std::nullopt
) -> std::string {
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"" + std::string{id} + "\",\"method\":\"" +
                          std::string{method} +
                          "\",\"params\":{\"schema_version\":1,\"bootstrap_secret\":\"" +
                          std::string{secret} + "\",\"deadline_ms\":4102444800000";
    if (idempotency) {
        request += ",\"idempotency_key\":\"" + std::string{*idempotency} + "\"";
    }
    request += ",\"payload\":" + std::string{payload} + "}}";
    return request;
}

auto decode_response(std::string_view frame) -> std::optional<wire_test::rpc_response> {
    wire_test::rpc_response response;
    if (glz::read<glz::opts{.error_on_unknown_keys = true}>(response, frame)) {
        return std::nullopt;
    }
    return response;
}

auto page_and_acknowledge(
    const std::filesystem::path& socket_path,
    std::string_view secret,
    const glove::container::receipt_audit_anchor& genesis
) -> bool {
    const auto genesis_json = glz::write_json(genesis);
    if (!genesis_json) {
        return false;
    }
    const auto page_payload = "{\"sage_anchor\":" + *genesis_json + ",\"limit\":10}";
    auto page_frame = transact_with_retry(
        socket_path, make_request("page", "verify_audit_chain", secret, page_payload)
    );
    if (!page_frame) {
        return false;
    }
    auto page_response = decode_response(*page_frame);
    if (!page_response || !page_response->result || page_response->error) {
        return false;
    }
    wire_test::page_result page;
    if (glz::read<glz::opts{.error_on_unknown_keys = true}>(page, page_response->result->str) ||
        !page.envelopes.empty() || page.has_more || page.local_anchor != genesis) {
        return false;
    }
    const auto ack_payload = "{\"anchor\":" + *genesis_json + "}";
    auto ack_frame = transact_with_retry(
        socket_path,
        make_request("ack", "acknowledge_audit_chain", secret, ack_payload, "lifecycle-ack")
    );
    auto ack_response = ack_frame ? decode_response(*ack_frame) : std::nullopt;
    return ack_response && ack_response->result && !ack_response->error;
}

auto policy_json(const std::filesystem::path& source) -> std::string {
    return R"({"schema_version":1,"revision":7,"max_plan_ttl_ms":120000,"runtime_templates":[{"runtime_template_id":"codex-safe","runtime_id":"codex","adapter_command_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_backend":"linux_production","allowed_path_aliases":["workspace"],"allowed_projection_destinations":["libraries"]}],"path_aliases":[{"alias":"workspace","host_path":")" +
           std::filesystem::canonical(source).string() +
           R"(","target_path":"/workspace","max_ttl_secs":120,"access":[{"access":"ephemeral_write","materialization":"copy","create_policy":"empty_directory","cleanup_policy":"remove","max_bytes":2097152}]}],"library_projection_destinations":[{"alias":"libraries","target_path":"/opt/sage/library-bundles"}],"resource_profiles":[{"profile_id":"small","cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576}],"egress_policy_ids":["no-network"],"tool_policy_ids":["sage-readonly"],"secret_handles":["codex-token"]})";
}

auto exposure_policy_json(const std::filesystem::path& root) -> std::string {
    return R"({"schema_version":1,"roots":[{"root_id":"projects","host_root":")" +
           std::filesystem::canonical(root).string() +
           R"(","allowed_modes":[{"access":"read","materialization":"bind","max_bytes":0,"cleanup_policy":"retain"}],"max_ttl_secs":3600,"allowed_runtime_template_ids":["codex-safe"]}]})";
}

auto plan_json(std::uint64_t expires_at_ms) -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":)" +
           std::to_string(expires_at_ms) + "}";
}

auto validate_plan(const std::filesystem::path& socket_path, std::string_view secret) -> bool {
    const auto now_ms =
        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch()
        )
                                       .count());
    auto frame = transact_with_retry(
        socket_path,
        make_request("validate-plan", "validate_plan", secret, plan_json(now_ms + 60'000U))
    );
    auto response = frame ? decode_response(*frame) : std::nullopt;
    if (!response || !response->result || response->error) {
        return false;
    }
    wire_test::session_plan_validation validation;
    return !glz::read<glz::opts{.error_on_unknown_keys = true}>(
               validation, response->result->str
           ) &&
           validation.schema_version == 1 && validation.policy_revision == 7;
}

auto create_or_read_session(
    const std::filesystem::path& socket_path, std::string_view secret, bool create
) -> bool {
    constexpr std::string_view digest =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    if (create) {
        const auto now_ms =
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::system_clock::now().time_since_epoch()
            )
                                           .count());
        const auto payload = "{\"session_id\":\"lifecycle-session\",\"controller_plan_digest\":\"" +
                             std::string{digest} + "\",\"plan\":" + plan_json(now_ms + 60'000U) +
                             "}";
        auto frame = transact_with_retry(
            socket_path,
            make_request(
                "create-session", "create_session", secret, payload, "lifecycle-create-session"
            )
        );
        auto response = frame ? decode_response(*frame) : std::nullopt;
        if (!response || !response->result || response->error) {
            return false;
        }
    }
    auto status_frame = transact_with_retry(
        socket_path,
        make_request(
            "session-status", "session_status", secret, "{\"session_id\":\"lifecycle-session\"}"
        )
    );
    auto status_response = status_frame ? decode_response(*status_frame) : std::nullopt;
    if (!status_response || !status_response->result || status_response->error) {
        return false;
    }
    wire_test::session_record_result record;
    return !glz::read<glz::opts{.error_on_unknown_keys = true}>(
               record, status_response->result->str
           ) &&
           record.schema_version == 1 && record.session_id == "lifecycle-session" &&
           record.controller_plan_digest == digest && record.plan_content_digest.size() == 64 &&
           record.state == "created" && record.policy_revision == 7;
}

auto run() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    REQUIRE(::chmod(temp.root().c_str(), 0700) == 0);
    const auto key_path = temp.root() / "audit.key";
    const auto journal_path = temp.root() / "receipts.journal";
    const auto socket_path = temp.root() / "gloved.sock";
    const auto secret_path = temp.root() / "bootstrap-secret";
    REQUIRE(write_owner_only(key_path, audit_key));
    auto genesis = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(genesis.has_value());

    REQUIRE(::chmod(temp.root().c_str(), 0755) == 0);
    auto unsafe_permissions = start_gloved(temp.root(), key_path, journal_path);
    auto unsafe_status = unsafe_permissions.wait_for_exit();
    REQUIRE(unsafe_status.has_value());
    REQUIRE(WIFEXITED(*unsafe_status));
    REQUIRE(WEXITSTATUS(*unsafe_status) != 0);
    REQUIRE(::chmod(temp.root().c_str(), 0700) == 0);
    REQUIRE(!std::filesystem::exists(secret_path));

    auto relative_path = start_gloved(temp.root(), "audit.key", journal_path);
    auto relative_status = relative_path.wait_for_exit();
    REQUIRE(relative_status.has_value());
    REQUIRE(WIFEXITED(*relative_status));
    REQUIRE(WEXITSTATUS(*relative_status) != 0);
    REQUIRE(!std::filesystem::exists(secret_path));

    auto first = start_gloved(temp.root(), key_path, journal_path);
    REQUIRE(wait_until_ready(first, socket_path, secret_path));
    const auto first_secret = read_secret(secret_path);
    REQUIRE(first_secret.has_value());
    struct stat metadata{};
    REQUIRE(::lstat(secret_path.c_str(), &metadata) == 0);
    REQUIRE(S_ISREG(metadata.st_mode));
    REQUIRE((metadata.st_mode & 0777U) == 0600U);

    auto competing = start_gloved(temp.root(), key_path, journal_path);
    auto competing_status = competing.wait_for_exit();
    REQUIRE(competing_status.has_value());
    REQUIRE(WIFEXITED(*competing_status));
    REQUIRE(WEXITSTATUS(*competing_status) != 0);
    const auto unchanged_secret = read_secret(secret_path);
    REQUIRE(unchanged_secret == first_secret);
    REQUIRE(first.running());

    REQUIRE(page_and_acknowledge(socket_path, *first_secret, **genesis));
    REQUIRE(first.kill_hard());
    REQUIRE(std::filesystem::exists(socket_path));

    auto second = start_gloved(temp.root(), key_path, journal_path);
    REQUIRE(wait_until_secret_changes(second, socket_path, secret_path, *first_secret));
    const auto second_secret = read_secret(secret_path);
    REQUIRE(second_secret.has_value());
    REQUIRE(*second_secret != *first_secret);
    REQUIRE(page_and_acknowledge(socket_path, *second_secret, **genesis));
    REQUIRE(second.stop());
    REQUIRE(!std::filesystem::exists(socket_path));

    auto third = start_gloved(temp.root(), key_path, journal_path);
    REQUIRE(wait_until_secret_changes(third, socket_path, secret_path, *second_secret));
    const auto third_secret = read_secret(secret_path);
    REQUIRE(third_secret.has_value());
    REQUIRE(*third_secret != *second_secret);
    REQUIRE(page_and_acknowledge(socket_path, *third_secret, **genesis));
    REQUIRE(third.stop());
    REQUIRE(!std::filesystem::exists(socket_path));

    const auto config_path = temp.root() / "gloved.json";
    const auto exposure_root = temp.root() / "projects";
    const auto exposure_project = exposure_root / "sage-protocol";
    REQUIRE(std::filesystem::create_directories(exposure_project));
    const auto exposure_policy_path = temp.root() / "path-exposure-policy.json";
    const auto exposure_journal_path = temp.root() / "path-exposures.journal";
    REQUIRE(write_owner_only(exposure_policy_path, exposure_policy_json(exposure_root)));
    const glove::host::config host_config{
        .runtime_directory = temp.root(),
        .audit_key = key_path,
        .receipt_journal = journal_path,
        .path_exposure_policy = exposure_policy_path,
        .path_exposure_journal = exposure_journal_path,
    };
    const auto encoded_config = glove::host::encode_config(host_config);
    REQUIRE(encoded_config.has_value());
    REQUIRE(write_owner_only(config_path, *encoded_config));
    auto configured = start_gloved_config(config_path);
    REQUIRE(wait_until_secret_changes(configured, socket_path, secret_path, *third_secret));
    REQUIRE(wait_until_authenticated(host_config));
    auto exposure = glove::host::enroll_project(
        host_config,
        glove::host::project_enrollment{
            .project = exposure_project,
            .exposure_id = "sage-protocol",
            .root_id = "projects",
            .display_label = "Sage protocol",
            .access = glove::host::project_access::read,
            .max_bytes = 0,
            .ttl_secs = 3'600,
            .runtime_template_ids = {"codex-safe"},
            .idempotency_key = "lifecycle-enrollment",
        }
    );
    REQUIRE(exposure.has_value());
    REQUIRE(exposure->generation == 1);
    REQUIRE(configured.stop());
    REQUIRE(!std::filesystem::exists(socket_path));

    const auto plan_source = temp.root() / "plan-source";
    REQUIRE(std::filesystem::create_directory(plan_source));
    std::ofstream{plan_source / "tracked.txt"} << "host-owned\n";
    const auto policy_path = temp.root() / "session-policy.json";
    REQUIRE(write_owner_only(policy_path, policy_json(plan_source)));
    const auto pre_policy_secret = read_secret(secret_path);
    REQUIRE(pre_policy_secret.has_value());
    REQUIRE(::chmod(policy_path.c_str(), 0644) == 0);
    auto unsafe_policy = start_gloved(temp.root(), key_path, journal_path, policy_path);
    auto unsafe_policy_status = unsafe_policy.wait_for_exit();
    REQUIRE(unsafe_policy_status.has_value());
    REQUIRE(WIFEXITED(*unsafe_policy_status));
    REQUIRE(WEXITSTATUS(*unsafe_policy_status) != 0);
    REQUIRE(read_secret(secret_path) == pre_policy_secret);
    const auto materialization_root = temp.root() / "materializations";
    REQUIRE(std::filesystem::create_directory(materialization_root));
    REQUIRE(::chmod(materialization_root.c_str(), 0700) == 0);
    auto unbound_materialization = start_gloved(
        temp.root(), key_path, journal_path, std::nullopt, std::nullopt, materialization_root
    );
    auto unbound_materialization_status = unbound_materialization.wait_for_exit();
    REQUIRE(unbound_materialization_status.has_value());
    REQUIRE(WIFEXITED(*unbound_materialization_status));
    REQUIRE(WEXITSTATUS(*unbound_materialization_status) != 0);
    REQUIRE(read_secret(secret_path) == pre_policy_secret);
    REQUIRE(::chmod(policy_path.c_str(), 0600) == 0);
    auto colliding_store =
        start_gloved(temp.root(), key_path, journal_path, policy_path, journal_path);
    auto colliding_store_status = colliding_store.wait_for_exit();
    REQUIRE(colliding_store_status.has_value());
    REQUIRE(WIFEXITED(*colliding_store_status));
    REQUIRE(WEXITSTATUS(*colliding_store_status) != 0);
    REQUIRE(read_secret(secret_path) == pre_policy_secret);
    const auto library_bundle_root = temp.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(library_bundle_root));
    REQUIRE(::chmod(library_bundle_root.c_str(), 0700) == 0);
    auto unbound_library_root = start_gloved(
        temp.root(),
        key_path,
        journal_path,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        library_bundle_root
    );
    auto unbound_library_root_status = unbound_library_root.wait_for_exit();
    REQUIRE(unbound_library_root_status.has_value());
    REQUIRE(WIFEXITED(*unbound_library_root_status));
    REQUIRE(WEXITSTATUS(*unbound_library_root_status) != 0);
    REQUIRE(read_secret(secret_path) == pre_policy_secret);
    auto policy_enabled = start_gloved(temp.root(), key_path, journal_path, policy_path);
    REQUIRE(
        wait_until_secret_changes(policy_enabled, socket_path, secret_path, *pre_policy_secret)
    );
    const auto policy_secret = read_secret(secret_path);
    REQUIRE(policy_secret.has_value());
    REQUIRE(validate_plan(socket_path, *policy_secret));
    REQUIRE(policy_enabled.stop());
    REQUIRE(!std::filesystem::exists(socket_path));

    const auto session_store = temp.root() / "sessions.journal";
    auto session_enabled =
        start_gloved(temp.root(), key_path, journal_path, policy_path, session_store);
    REQUIRE(wait_until_secret_changes(session_enabled, socket_path, secret_path, *policy_secret));
    const auto session_secret = read_secret(secret_path);
    REQUIRE(session_secret.has_value());
    REQUIRE(create_or_read_session(socket_path, *session_secret, true));
    const auto competing_store_path = temp.root() / "competing-sessions.journal";
    auto competing_store =
        start_gloved(temp.root(), key_path, journal_path, policy_path, competing_store_path);
    auto competing_store_status = competing_store.wait_for_exit();
    REQUIRE(competing_store_status.has_value());
    REQUIRE(WIFEXITED(*competing_store_status));
    REQUIRE(WEXITSTATUS(*competing_store_status) != 0);
    REQUIRE(!std::filesystem::exists(competing_store_path));
    REQUIRE(read_secret(secret_path) == session_secret);
    REQUIRE(session_enabled.stop());
    REQUIRE(std::filesystem::exists(session_store));

    REQUIRE(::chmod(library_bundle_root.c_str(), 0755) == 0);
    auto unsafe_library_root = start_gloved(
        temp.root(),
        key_path,
        journal_path,
        policy_path,
        session_store,
        std::nullopt,
        library_bundle_root
    );
    auto unsafe_library_root_status = unsafe_library_root.wait_for_exit();
    REQUIRE(unsafe_library_root_status.has_value());
    REQUIRE(WIFEXITED(*unsafe_library_root_status));
    REQUIRE(WEXITSTATUS(*unsafe_library_root_status) != 0);
    REQUIRE(::chmod(library_bundle_root.c_str(), 0700) == 0);

    auto library_enabled = start_gloved(
        temp.root(),
        key_path,
        journal_path,
        policy_path,
        session_store,
        std::nullopt,
        library_bundle_root
    );
    REQUIRE(wait_until_secret_changes(library_enabled, socket_path, secret_path, *session_secret));
    const auto library_secret = read_secret(secret_path);
    REQUIRE(library_secret.has_value());
    REQUIRE(create_or_read_session(socket_path, *library_secret, false));
    REQUIRE(library_enabled.stop());

    const auto pre_unsafe_store_secret = read_secret(secret_path);
    REQUIRE(pre_unsafe_store_secret.has_value());
    REQUIRE(::chmod(session_store.c_str(), 0644) == 0);
    auto unsafe_store =
        start_gloved(temp.root(), key_path, journal_path, policy_path, session_store);
    auto unsafe_store_status = unsafe_store.wait_for_exit();
    REQUIRE(unsafe_store_status.has_value());
    REQUIRE(WIFEXITED(*unsafe_store_status));
    REQUIRE(WEXITSTATUS(*unsafe_store_status) != 0);
    REQUIRE(read_secret(secret_path) == pre_unsafe_store_secret);
    REQUIRE(::chmod(session_store.c_str(), 0600) == 0);

    auto session_recovered =
        start_gloved(temp.root(), key_path, journal_path, policy_path, session_store);
    REQUIRE(wait_until_secret_changes(
        session_recovered, socket_path, secret_path, *pre_unsafe_store_secret
    ));
    const auto recovered_secret = read_secret(secret_path);
    REQUIRE(recovered_secret.has_value());
    REQUIRE(create_or_read_session(socket_path, *recovered_secret, false));
    REQUIRE(session_recovered.stop());
    REQUIRE(!std::filesystem::exists(socket_path));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
