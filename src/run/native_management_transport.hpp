#pragma once

#include "native_session_model.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

// Host-only management protocol v1: AF_UNIX stream below the session's
// owner-private control directory, 4-octet big-endian length framing, closed
// I-JSON auth/ready/request/result objects. Authentication binds the session,
// the current supervisor epoch and a per-epoch 256-bit capability kept in the
// owner-only capability file. Nothing here is a provider, MCP or tmux channel.
inline constexpr std::size_t management_max_frame_bytes = 65536U;
inline constexpr std::size_t management_max_connections = 8U;
inline constexpr std::chrono::milliseconds management_auth_timeout{2000};
inline constexpr std::chrono::milliseconds management_request_timeout{5000};
// Short leaves keep the absolute socket path inside sun_path (104 bytes on
// Darwin) for owner-private state roots below a user home.
inline constexpr std::string_view management_socket_name = "s";
inline constexpr std::string_view management_capability_name = "cap";

struct management_request {
    std::uint64_t observed_generation = 0;
    std::string request;
    session_operation op = session_operation::status;
    std::optional<std::string> checkpoint;
    std::string body_digest;
};

struct management_result {
    std::string session;
    std::string epoch;
    std::uint64_t generation = 0;
    std::string request;
    session_operation op = session_operation::status;
    session_phase state = session_phase::fresh;
    history_status history = history_status::absent;
    std::optional<std::string> checkpoint;
    effects_status effects = effects_status::unassessed;
    result_code code = result_code::ok;
    bool final = true;

    auto operator==(const management_result&) const -> bool = default;
};

using management_handler = std::function<operation_result(const management_request&)>;
using management_listener_hook = std::function<void(std::string_view detail)>;

class native_management_server {
public:
    native_management_server(const native_management_server&) = delete;
    auto operator=(const native_management_server&) -> native_management_server& = delete;
    native_management_server(native_management_server&&) = delete;
    auto operator=(native_management_server&&) -> native_management_server& = delete;
    ~native_management_server();

    // Mints the epoch capability, writes it to the owner-only capability file,
    // binds a fresh socket and starts the single worker. The handler runs on
    // that worker; `on_listener` reports recreation/refusal for journaling.
    [[nodiscard]] static auto start(
        const std::filesystem::path& control_directory,
        std::string session,
        std::string epoch,
        std::vector<std::string> capabilities,
        management_handler handler,
        management_listener_hook on_listener = {}
    ) -> std::expected<std::unique_ptr<native_management_server>, std::string>;

    [[nodiscard]] auto socket_path() const -> std::filesystem::path;
    // dev/ino of the currently bound socket object; changes on recreation.
    [[nodiscard]] auto listener_identity() const -> std::pair<std::uint64_t, std::uint64_t>;
    [[nodiscard]] auto recreations() const -> std::uint64_t;
    [[nodiscard]] auto refusals() const -> std::uint64_t;
    [[nodiscard]] auto connections() const -> std::uint64_t;

private:
    struct implementation;
    explicit native_management_server(std::unique_ptr<implementation> state) noexcept;
    std::unique_ptr<implementation> state_;
};

enum class management_client_error : std::uint8_t {
    capability_unavailable,
    socket_missing,
    connection_refused,
    peer_identity,
    authentication_refused,
    timeout,
    malformed,
    io
};

struct management_client_failure {
    management_client_error code = management_client_error::io;
    std::string message;
};

// Reads the admitted capability, connects to the admitted socket, performs
// one authenticated request and closes. It never infers liveness from the
// socket pathname: only an authenticated result is evidence.
[[nodiscard]] auto management_request_once(
    const std::filesystem::path& control_directory,
    std::string_view session,
    const management_request& request,
    std::chrono::milliseconds timeout = management_request_timeout
) -> std::expected<management_result, management_client_failure>;

// Exact mutation bodies must be byte-identical on retry; the client therefore
// renders the request body once and callers reuse it for replay tests.
[[nodiscard]] auto render_management_request(
    std::string_view session,
    std::string_view epoch,
    std::uint64_t observed_generation,
    std::string_view request_id,
    session_operation op,
    const std::optional<std::string>& checkpoint
) -> std::expected<std::string, std::string>;

[[nodiscard]] auto management_request_raw(
    const std::filesystem::path& control_directory,
    std::string_view session,
    std::string_view body,
    std::chrono::milliseconds timeout = management_request_timeout
) -> std::expected<management_result, management_client_failure>;

[[nodiscard]] auto read_management_capability(
    const std::filesystem::path& control_directory, std::string_view session
) -> std::expected<std::pair<std::string, std::string>, management_client_failure>; // epoch, token

} // namespace glove::run::detail
