#pragma once

#include "glove/control/session_registry.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {

inline constexpr std::size_t max_wallet_status_frame_bytes = std::size_t{64} * 1024U;
inline constexpr std::size_t max_wallet_status_chain_ids = 16U;
inline constexpr std::uint64_t max_wallet_status_request_ttl_ms = 5'000U;
inline constexpr std::uint64_t max_wallet_status_age_ms = 60'000U;

struct wallet_status_observation {
    bool connected = false;
    std::uint64_t observed_at_ms = 0;
    std::string wallet_server_alias;
    std::vector<std::uint64_t> allowed_chain_ids;

    auto operator==(const wallet_status_observation&) const -> bool = default;
};

struct wallet_status_time {
    std::uint64_t unix_time_ms = 0;
    std::chrono::steady_clock::time_point monotonic_time;
};

class wallet_status_clock {
public:
    wallet_status_clock() = default;
    wallet_status_clock(const wallet_status_clock&) = delete;
    auto operator=(const wallet_status_clock&) -> wallet_status_clock& = delete;
    wallet_status_clock(wallet_status_clock&&) = delete;
    auto operator=(wallet_status_clock&&) -> wallet_status_clock& = delete;
    virtual ~wallet_status_clock() = default;
    [[nodiscard]] virtual auto now() noexcept -> wallet_status_time = 0;
};

struct wallet_status_bridge_policy {
    std::uint8_t schema_version = 1;
    std::string tool_policy_id;
    std::string wallet_server_alias;
    std::string wallet_server_node_digest;
    std::vector<std::uint64_t> allowed_chain_ids;
    std::uint64_t maximum_status_age_ms = 5'000U;

    auto operator==(const wallet_status_bridge_policy&) const -> bool = default;
};

struct wallet_status_bridge_response {
    std::string id;
    std::uint8_t schema_version = 0;
    bool connected = false;
    std::uint64_t fresh_at_ms = 0;
    std::string wallet_server_alias;
    std::vector<std::uint64_t> allowed_chain_ids;
    std::vector<std::string> available_actions;
    std::vector<std::string> mutating_actions;
    std::string error_code;
};

enum class wallet_status_authority_error : std::uint8_t {
    unavailable,
    deadline,
    stale,
    revised,
    ambiguous,
    rollback,
    mismatch,
};

struct wallet_status_plan_binding {
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t generation = 0;

    auto operator==(const wallet_status_plan_binding&) const -> bool = default;
};

struct wallet_status_plan_snapshot {
    wallet_status_plan_binding binding;
    session_record session;
    wallet_status_bridge_policy policy;
    std::string adapter_command_digest;

    auto operator==(const wallet_status_plan_snapshot&) const -> bool = default;
};

struct wallet_status_readiness_snapshot {
    wallet_status_plan_binding binding;
    std::uint64_t audit_generation = 0;
    std::uint64_t journal_generation = 0;

    auto operator==(const wallet_status_readiness_snapshot&) const -> bool = default;
};

struct wallet_status_adapter_snapshot {
    wallet_status_plan_binding binding;
    std::string adapter_command_digest;

    auto operator==(const wallet_status_adapter_snapshot&) const -> bool = default;
};

struct wallet_status_server_snapshot {
    wallet_status_plan_binding binding;
    std::string wallet_server_node_digest;
    wallet_status_observation observation;

    auto operator==(const wallet_status_server_snapshot&) const -> bool = default;
};

template<typename Snapshot>
using wallet_status_authority_result = std::expected<Snapshot, wallet_status_authority_error>;

// Private construction contracts. Each plan-authority instance is scoped to
// one immutable host-selected session/plan identity. Implementations must be
// thread-safe, enforce the supplied absolute deadline, return `revised` if that
// identity changes, reject ambiguous, reused, or rolled-back durable
// generations, and return owned snapshots. Only offline fakes exist today.
class wallet_status_plan_authority {
public:
    wallet_status_plan_authority() = default;
    wallet_status_plan_authority(const wallet_status_plan_authority&) = delete;
    auto operator=(const wallet_status_plan_authority&) -> wallet_status_plan_authority& = delete;
    wallet_status_plan_authority(wallet_status_plan_authority&&) = delete;
    auto operator=(wallet_status_plan_authority&&) -> wallet_status_plan_authority& = delete;
    virtual ~wallet_status_plan_authority() = default;
    [[nodiscard]] virtual auto snapshot(std::chrono::steady_clock::time_point deadline) const
        -> wallet_status_authority_result<wallet_status_plan_snapshot> = 0;
};

// A successful snapshot attests that protected audit and journal sinks are
// usable, the contained guest remains route-less, and its secret-handle set is
// empty for the exact binding. Generations are monotonic and never reused.
class wallet_status_readiness_authority {
public:
    wallet_status_readiness_authority() = default;
    wallet_status_readiness_authority(const wallet_status_readiness_authority&) = delete;
    auto operator=(const wallet_status_readiness_authority&)
        -> wallet_status_readiness_authority& = delete;
    wallet_status_readiness_authority(wallet_status_readiness_authority&&) = delete;
    auto operator=(wallet_status_readiness_authority&&)
        -> wallet_status_readiness_authority& = delete;
    virtual ~wallet_status_readiness_authority() = default;
    [[nodiscard]] virtual auto snapshot(
        const wallet_status_plan_binding& binding, std::chrono::steady_clock::time_point deadline
    ) const -> wallet_status_authority_result<wallet_status_readiness_snapshot> = 0;
};

// Confirms the exact owner-local adapter bytes selected by the current plan.
class wallet_status_adapter_authority {
public:
    wallet_status_adapter_authority() = default;
    wallet_status_adapter_authority(const wallet_status_adapter_authority&) = delete;
    auto operator=(const wallet_status_adapter_authority&)
        -> wallet_status_adapter_authority& = delete;
    wallet_status_adapter_authority(wallet_status_adapter_authority&&) = delete;
    auto operator=(wallet_status_adapter_authority&&) -> wallet_status_adapter_authority& = delete;
    virtual ~wallet_status_adapter_authority() = default;
    [[nodiscard]] virtual auto snapshot(
        const wallet_status_plan_binding& binding, std::chrono::steady_clock::time_point deadline
    ) const -> wallet_status_authority_result<wallet_status_adapter_snapshot> = 0;
};

// A successful snapshot attests stable wallet-server peer pinning for the exact
// binding. It exposes status only and never returns peer connection material.
class wallet_status_server_authority {
public:
    wallet_status_server_authority() = default;
    wallet_status_server_authority(const wallet_status_server_authority&) = delete;
    auto operator=(const wallet_status_server_authority&)
        -> wallet_status_server_authority& = delete;
    wallet_status_server_authority(wallet_status_server_authority&&) = delete;
    auto operator=(wallet_status_server_authority&&) -> wallet_status_server_authority& = delete;
    virtual ~wallet_status_server_authority() = default;
    [[nodiscard]] virtual auto snapshot(
        const wallet_status_plan_binding& binding, std::chrono::steady_clock::time_point deadline
    ) const -> wallet_status_authority_result<wallet_status_server_snapshot> = 0;
};

class wallet_status_bridge {
public:
    wallet_status_bridge(
        std::unique_ptr<wallet_status_plan_authority> plan_authority,
        std::unique_ptr<wallet_status_readiness_authority> readiness_authority,
        std::unique_ptr<wallet_status_adapter_authority> adapter_authority,
        std::unique_ptr<wallet_status_server_authority> server_authority,
        std::unique_ptr<wallet_status_clock> clock
    );

    wallet_status_bridge(const wallet_status_bridge&) = delete;
    auto operator=(const wallet_status_bridge&) -> wallet_status_bridge& = delete;
    wallet_status_bridge(wallet_status_bridge&&) = delete;
    auto operator=(wallet_status_bridge&&) -> wallet_status_bridge& = delete;
    ~wallet_status_bridge() = default;

    // Every current value is obtained from owned, protected local authorities
    // under one absolute deadline. No caller-attested session or status enters
    // this protocol step.
    [[nodiscard]] auto handle_request(
        std::string_view frame, std::chrono::steady_clock::time_point receive_inclusive_deadline
    ) const -> std::expected<std::string, std::string>;

private:
    std::unique_ptr<wallet_status_plan_authority> plan_authority_;
    std::unique_ptr<wallet_status_readiness_authority> readiness_authority_;
    std::unique_ptr<wallet_status_adapter_authority> adapter_authority_;
    std::unique_ptr<wallet_status_server_authority> server_authority_;
    std::unique_ptr<wallet_status_clock> clock_;
    bool constructed_ = false;
};

[[nodiscard]] auto
encode_wallet_status_request(std::string_view id, std::uint64_t deadline_remaining_ms)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto decode_wallet_status_response(std::string_view frame)
    -> std::expected<wallet_status_bridge_response, std::string>;

// Four-byte big-endian framing for one inherited per-session Unix socket. These
// helpers do not create, discover, connect, own, or close the socket.
[[nodiscard]] auto
read_wallet_status_frame(int descriptor, std::chrono::steady_clock::time_point deadline)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto write_wallet_status_frame(
    int descriptor, std::string_view frame, std::chrono::steady_clock::time_point deadline
) -> std::expected<void, std::string>;

} // namespace glove::control
