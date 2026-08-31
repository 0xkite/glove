#pragma once

#include "glove/audit/sink.hpp"
#include "glove/control/guest_channel.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/linux_session_filesystem.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {
class session_runtime;
}

namespace glove::control::linux_detail {

class linux_session_runtime;

inline constexpr std::string_view local_service_guest_directory = "/run/glove-services/local";
inline constexpr std::string_view local_service_environment =
    "GLOVE_LOCAL_SERVICE_DIR=/run/glove-services/local";

struct local_service_endpoint {
    std::string alias;
    std::filesystem::path socket_path;
    std::vector<std::string> runtime_ids;
};

struct local_service_proxy_options {
    std::filesystem::path runtime_root;
    std::uint64_t io_timeout_ms = 5'000;
    std::uint32_t max_concurrency = 4;
    std::vector<local_service_endpoint> endpoints;
    std::shared_ptr<audit::sink> audit;
    std::shared_ptr<const guest_channel_adapter_binding> guest_channel_adapter;
};

class local_service_proxy_session final {
public:
    struct implementation;

    local_service_proxy_session(const local_service_proxy_session&) = delete;
    auto operator=(const local_service_proxy_session&) -> local_service_proxy_session& = delete;
    local_service_proxy_session(local_service_proxy_session&&) = delete;
    auto operator=(local_service_proxy_session&&) -> local_service_proxy_session& = delete;
    ~local_service_proxy_session();

    [[nodiscard]] auto mount() const
        -> std::expected<supervisor::linux_detail::session_mount, std::string>;

private:
    friend class local_service_proxy_factory;
    explicit local_service_proxy_session(std::unique_ptr<implementation> state) noexcept;

    std::unique_ptr<implementation> state_;
};

class local_service_proxy_capability final {
public:
    local_service_proxy_capability(const local_service_proxy_capability&) = delete;
    auto operator=(const local_service_proxy_capability&)
        -> local_service_proxy_capability& = delete;
    local_service_proxy_capability(local_service_proxy_capability&&) = delete;
    auto operator=(local_service_proxy_capability&&) -> local_service_proxy_capability& = delete;
    ~local_service_proxy_capability() = default;

    [[nodiscard]] auto
    operational_for(const session_runtime* runtime, const session_registry* registry) const noexcept
        -> bool;

private:
    friend class local_service_proxy_factory;

    class construction_token {
        construction_token() = default;
        friend class local_service_proxy_factory;
    };

    local_service_proxy_capability(
        construction_token token, std::shared_ptr<const linux_session_runtime> runtime
    ) noexcept;

    std::shared_ptr<const linux_session_runtime> runtime_;
};

// Immutable host endpoint catalog with descriptor-pinned parent directories.
// Creation validates the exact frozen
// guest catalog held by the registry. Session construction is runtime-filtered
// and returns no object when the runtime has no configured endpoint.
class local_service_proxy_factory final {
public:
    struct implementation;
    using capability_result = std::
        expected<std::optional<std::shared_ptr<const local_service_proxy_capability>>, std::string>;

    local_service_proxy_factory(const local_service_proxy_factory&) = delete;
    auto operator=(const local_service_proxy_factory&) -> local_service_proxy_factory& = delete;
    local_service_proxy_factory(local_service_proxy_factory&&) = delete;
    auto operator=(local_service_proxy_factory&&) -> local_service_proxy_factory& = delete;
    ~local_service_proxy_factory();

    [[nodiscard]] static auto
    create(local_service_proxy_options options, std::shared_ptr<session_registry> registry)
        -> std::expected<std::shared_ptr<local_service_proxy_factory>, std::string>;

    [[nodiscard]] auto prepare_session(std::string_view session_id, std::string_view runtime_id)
        -> std::expected<std::unique_ptr<local_service_proxy_session>, std::string>;
    [[nodiscard]] auto manages_runtime(std::string_view runtime_id) const noexcept -> bool;
    [[nodiscard]] auto operational() const noexcept -> bool;
    [[nodiscard]] auto
    validate_path_grants(std::span<const supervisor::resolved_path_grant> grants) const
        -> std::expected<void, std::string>;

    // Only the concrete Linux runtime can prove that its preparer owns this
    // exact factory. Absence of an adapter binding or of an adapter/endpoint/
    // runtime intersection returns an empty optional. Every exact-composition
    // identity or operational failure remains an error.
    [[nodiscard]] auto try_seal(std::shared_ptr<const linux_session_runtime> runtime)
        -> capability_result;

private:
    friend class linux_session_runtime;
    friend class local_service_proxy_capability;

    class construction_token {
        construction_token() = default;
        friend class local_service_proxy_factory;
    };

    local_service_proxy_factory(
        construction_token token, std::unique_ptr<implementation> state
    ) noexcept;
    [[nodiscard]] auto adapter_manages_runtime(std::string_view runtime_id) const noexcept -> bool;
    [[nodiscard]] auto capability_current(const session_registry& registry) const noexcept -> bool;
    [[nodiscard]] auto sealed_for(
        const linux_session_runtime& runtime, const session_registry& registry
    ) const noexcept -> bool;

    std::unique_ptr<implementation> state_;
};

} // namespace glove::control::linux_detail
