#pragma once

#include "../../include/glove/control/remote_protocol.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace glove::control {

struct remote_validation_executor_config {
    std::string executor_digest;
    std::string container_image;
    std::string container_image_digest;
    std::string workerd_digest;
    std::string descriptor_digest;
    std::filesystem::path staging_root;
    std::uint32_t max_sessions = 0;
    std::uint64_t max_ttl_ms = 0;
    std::filesystem::path docker_executable = "/usr/bin/docker";
    std::string docker_executable_digest;
};

// Owns only the validation-only fixed-descriptor rail. This type is not a
// session_runtime and cannot advertise managed-session capabilities.
class remote_validation_executor final {
public:
    remote_validation_executor(const remote_validation_executor&) = delete;
    auto operator=(const remote_validation_executor&) -> remote_validation_executor& = delete;
    remote_validation_executor(remote_validation_executor&&) = delete;
    auto operator=(remote_validation_executor&&) -> remote_validation_executor& = delete;
    ~remote_validation_executor();

    [[nodiscard]] static auto create(remote_validation_executor_config configured)
        -> std::expected<std::unique_ptr<remote_validation_executor>, std::string>;

    // Private-module test seam: all production construction still requires
    // /usr/bin/docker. The alternate executable remains digest-pinned.
    [[nodiscard]] static auto create_for_testing(remote_validation_executor_config configured)
        -> std::expected<std::unique_ptr<remote_validation_executor>, std::string>;

    [[nodiscard]] auto
    handle(std::string_view frame, std::chrono::steady_clock::time_point request_deadline)
        -> std::expected<std::string, std::string>;

    // A stdio owner disconnect is terminal authority for all of its live
    // validator containers. Cleanup is bounded and idempotent.
    void disconnect_cleanup();

    [[nodiscard]] auto identity() const -> remote_executor_identity;

private:
    class implementation;

    explicit remote_validation_executor(std::unique_ptr<implementation> state);

    std::unique_ptr<implementation> state_;
};

} // namespace glove::control
