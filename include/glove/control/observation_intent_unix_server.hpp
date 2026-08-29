#pragma once

#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>

namespace glove::control {

inline constexpr std::size_t max_observation_frame_bytes = std::size_t{16} * 1024U;

struct observation_intent_unix_server_config {
    std::filesystem::path socket_path;
    session_registry* sessions = nullptr;
    std::string session_id;
    std::string controller_plan_digest;
    std::string profile_digest;
    std::string projection_digest;
    std::uint64_t policy_revision = 0;
    std::string service_channel_id;
    std::uint64_t channel_generation = 0;
    std::uint64_t session_expires_at_ms = 0;
    std::string channel_token;
    std::uint64_t io_timeout_ms = 5'000;
};

// Per-session guest observation ingress. One bounded request/response per
// connection over an owner-only Unix socket. The host binds session context and
// stamps observation intent timing; guests supply only the observation body.
class observation_intent_unix_server final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class observation_intent_unix_server;
    };

    observation_intent_unix_server(
        construction_token token, std::unique_ptr<implementation> state
    );
    observation_intent_unix_server(const observation_intent_unix_server&) = delete;
    auto operator=(const observation_intent_unix_server&) -> observation_intent_unix_server& =
        delete;
    observation_intent_unix_server(observation_intent_unix_server&&) = delete;
    auto operator=(observation_intent_unix_server&&) -> observation_intent_unix_server& = delete;
    ~observation_intent_unix_server();

    [[nodiscard]] static auto create(observation_intent_unix_server_config config)
        -> std::expected<std::unique_ptr<observation_intent_unix_server>, std::string>;

    [[nodiscard]] auto serve_one_for(std::uint64_t accept_timeout_ms)
        -> std::expected<bool, std::string>;

    [[nodiscard]] auto socket_path() const -> const std::filesystem::path&;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
