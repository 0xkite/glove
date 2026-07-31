#include "glove/container/receipt_producer.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/receipt_audit_unix_server.hpp"

#include "receipt_audit_unix_server_detail.hpp"
#include "receipt_audit_wire.hpp"

#include <arpa/inet.h>
#include <glaze/glaze.hpp>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
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
    std::vector<glove::container::authenticated_refinement_evaluation_receipt>
        refinement_envelopes;
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
    std::optional<std::string_view> idempotency_key = std::nullopt
) -> std::string {
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"" + std::string{id} + "\",\"method\":\"" +
                          std::string{method} +
                          "\",\"params\":{\"schema_version\":1,\"bootstrap_secret\":\"" +
                          std::string{bootstrap_secret} + "\",\"deadline_ms\":4102444800000";
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
        .session_runtime = {},
        .path_exposures = {},
        .materialization_root = {},
        .io_timeout_ms = 100,
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
