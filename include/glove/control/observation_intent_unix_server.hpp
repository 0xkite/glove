#pragma once

#include "glove/control/guest_channel_transport.hpp"
#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <stop_token>
#include <string>

namespace glove::control {

inline constexpr std::size_t max_observation_frame_bytes = std::size_t{16} * 1024U;

// Accept-boundary failures that must not permanently kill the observation
// channel worker: serve_one_for retries them with a bounded backoff before
// surfacing an error. Exposed for regression tests.
[[nodiscard]] inline auto observation_transient_accept_error(int error_number) noexcept -> bool {
    switch (error_number) {
    case EINTR:
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case ECONNABORTED:
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        return true;
    default:
        return false;
    }
}

// Response-send classification consumed by the owning worker's audit path.
// Cancellation is an intentional shutdown; every other send failure remains
// observable as an error. Exposed for regression tests.
[[nodiscard]] auto classify_observation_response_send(guest_channel_transport_result<void> sent)
    -> std::expected<bool, std::string>;

struct observation_intent_unix_server_config {
    std::filesystem::path socket_path;
    session_registry* sessions = nullptr;
    std::string session_id;
    // Parsed runtime identity of the bound session; stamped onto every
    // enqueued observation intent. Core never hardcodes a runtime id.
    std::string runtime_id;
    std::string controller_plan_digest;
    std::string profile_digest;
    std::string projection_digest;
    std::uint64_t policy_revision = 0;
    std::string service_channel_id;
    std::uint64_t channel_generation = 0;
    std::uint64_t session_expires_at_ms = 0;
    std::string channel_token;
    std::uint64_t io_timeout_ms = 5'000;
    // Required defense-in-depth identity: peers whose uid (SO_PEERCRED /
    // LOCAL_PEERCRED) differs are rejected before any frame is read.
    std::uint32_t expected_peer_uid;
};

// Per-session guest observation ingress over an owner-only Unix socket. Accept
// and framed I/O are deadline- and stop-bounded. Registry persistence is trusted
// synchronous local work: stop/deadline are checked immediately around it, but
// an in-progress persistence call cannot be forcibly interrupted. The host binds
// session context and stamps timing; guests supply only the observation body.
class observation_intent_unix_server final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class observation_intent_unix_server;
    };

    observation_intent_unix_server(construction_token token, std::unique_ptr<implementation> state);
    observation_intent_unix_server(const observation_intent_unix_server&) = delete;
    auto operator=(const observation_intent_unix_server&)
        -> observation_intent_unix_server& = delete;
    observation_intent_unix_server(observation_intent_unix_server&&) = delete;
    auto operator=(observation_intent_unix_server&&) -> observation_intent_unix_server& = delete;
    ~observation_intent_unix_server();

    [[nodiscard]] static auto create(observation_intent_unix_server_config config)
        -> std::expected<std::unique_ptr<observation_intent_unix_server>, std::string>;

    [[nodiscard]] auto serve_one_for(std::uint64_t accept_timeout_ms, std::stop_token stop = {})
        -> std::expected<bool, std::string>;

    [[nodiscard]] auto socket_path() const -> const std::filesystem::path&;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
