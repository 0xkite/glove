#pragma once

#include "glove/mcp/messages.hpp"

#include "wallet_status_bridge.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control {

// Private construction-only channel. It has one operation and cannot name or
// connect to a server, invoke another tool, or pass through MCP/CLI/IPC calls.
class wallet_pi_status_channel {
public:
    wallet_pi_status_channel() = default;
    wallet_pi_status_channel(const wallet_pi_status_channel&) = delete;
    auto operator=(const wallet_pi_status_channel&) -> wallet_pi_status_channel& = delete;
    wallet_pi_status_channel(wallet_pi_status_channel&&) = delete;
    auto operator=(wallet_pi_status_channel&&) -> wallet_pi_status_channel& = delete;
    virtual ~wallet_pi_status_channel() = default;

    // Implementations must enforce both the absolute deadline and stop token;
    // returning after either is never authority for advertisement.
    [[nodiscard]] virtual auto exchange_status(
        std::string_view request,
        std::chrono::steady_clock::time_point deadline,
        const std::stop_token& stop
    ) -> std::expected<std::string, std::string> = 0;
};

struct wallet_pi_status_adapter_options {
    bool enabled = false;
    std::chrono::milliseconds request_timeout{0};
};

// Synthetic Pi-shaped projection only. It does not implement kernel::extension
// and is absent from every production registry, launcher, and capability list.
class wallet_pi_status_adapter final {
public:
    wallet_pi_status_adapter(
        std::unique_ptr<wallet_pi_status_channel> channel, wallet_pi_status_adapter_options options
    );

    wallet_pi_status_adapter(const wallet_pi_status_adapter&) = delete;
    auto operator=(const wallet_pi_status_adapter&) -> wallet_pi_status_adapter& = delete;
    wallet_pi_status_adapter(wallet_pi_status_adapter&&) = delete;
    auto operator=(wallet_pi_status_adapter&&) -> wallet_pi_status_adapter& = delete;
    ~wallet_pi_status_adapter() = default;

    // Discovery re-attests on every call. Any disabled, stale, malformed,
    // cancelled, unavailable, or mismatched state disappears as an empty list.
    [[nodiscard]] auto advertised_tools(
        std::chrono::steady_clock::time_point deadline, const std::stop_token& stop = {}
    ) noexcept -> std::vector<mcp::tool_descriptor>;

    // Invocation never relies on a prior listing and accepts only the exact
    // status tool with an empty object. Host failures become generic absence.
    [[nodiscard]] auto invoke(
        std::string_view tool_name,
        std::string_view arguments_json,
        std::chrono::steady_clock::time_point deadline,
        const std::stop_token& stop = {}
    ) noexcept -> mcp::tool_call_result;

private:
    [[nodiscard]] auto
    probe_status(std::chrono::steady_clock::time_point deadline, const std::stop_token& stop)
        -> std::expected<wallet_status_bridge_response, std::string>;

    std::unique_ptr<wallet_pi_status_channel> channel_;
    wallet_pi_status_adapter_options options_;
    std::timed_mutex transaction_mutex_;
    std::uint64_t next_request_id_ = 0;
    bool constructed_ = false;
};

} // namespace glove::control
