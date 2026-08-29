#include "wallet_pi_status_adapter.hpp"

#include "wallet_status_json.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::control {
namespace detail {

struct pi_status_result {
    std::uint8_t schema_version = 1;
    bool connected = true;
    std::uint64_t fresh_at_ms = 0;
    std::string wallet_server_alias;
    std::vector<std::uint64_t> allowed_chain_ids;
    std::vector<std::string> available_actions;
    std::vector<std::string> mutating_actions;
};

} // namespace detail

namespace {

using steady_time = std::chrono::steady_clock::time_point;

constexpr std::string_view status_tool_name = "wallet_status";
constexpr std::string_view status_input_schema =
    R"({"type":"object","properties":{},"additionalProperties":false})";

[[nodiscard]] auto empty_object(std::string_view input) noexcept -> bool {
    if (!valid_wallet_status_json(input)) {
        return false;
    }
    std::size_t cursor = 0;
    const auto skip_whitespace = [&] {
        while (cursor < input.size() &&
               std::isspace(static_cast<unsigned char>(input[cursor])) != 0) {
            ++cursor;
        }
    };
    skip_whitespace();
    if (cursor >= input.size() || input[cursor] != '{') {
        return false;
    }
    ++cursor;
    skip_whitespace();
    if (cursor >= input.size() || input[cursor] != '}') {
        return false;
    }
    ++cursor;
    skip_whitespace();
    return cursor == input.size();
}

[[nodiscard]] auto tool_not_found() -> mcp::tool_call_result {
    return {
        .status = mcp::tool_call_status::tool_not_found,
        .content = "",
        .structured_json = "",
        .error_message = "tool not found",
    };
}

[[nodiscard]] auto allocation_free_absence() noexcept -> mcp::tool_call_result {
    mcp::tool_call_result result;
    result.status = mcp::tool_call_status::tool_not_found;
    return result;
}

[[nodiscard]] auto
acquire_transaction(std::timed_mutex& mutex, steady_time deadline, const std::stop_token& stop)
    -> std::optional<std::unique_lock<std::timed_mutex>> {
    std::unique_lock<std::timed_mutex> lock{mutex, std::defer_lock};
    while (!stop.stop_requested()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::nullopt;
        }
        const auto checkpoint = std::min(deadline, now + std::chrono::milliseconds{10});
        if (lock.try_lock_until(checkpoint)) {
            return std::optional{std::move(lock)};
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto status_descriptor() -> mcp::tool_descriptor {
    return {
        .name = std::string{status_tool_name},
        .description = "Read redacted wallet connectivity status.",
        .input_schema_json = std::string{status_input_schema},
        .annotations = {
            .read_only_hint = true,
            .destructive_hint = false,
            .idempotent_hint = true,
            .open_world_hint = false,
            .has_annotations = true,
        },
    };
}

} // namespace

wallet_pi_status_adapter::wallet_pi_status_adapter(
    std::unique_ptr<wallet_pi_status_channel> channel, wallet_pi_status_adapter_options options
)
    : channel_(std::move(channel)),
      options_(options),
      constructed_(
          options_.enabled && channel_ != nullptr &&
          options_.request_timeout > std::chrono::milliseconds::zero() &&
          options_.request_timeout <= std::chrono::milliseconds{max_wallet_status_request_ttl_ms}
      ) {}

auto wallet_pi_status_adapter::probe_status(
    steady_time caller_deadline, const std::stop_token& stop
) -> std::expected<wallet_status_bridge_response, std::string> {
    if (!constructed_ || stop.stop_requested()) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }
    const auto now = std::chrono::steady_clock::now();
    if (caller_deadline <= now) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }
    const auto deadline = std::min(caller_deadline, now + options_.request_timeout);
    const auto remaining = deadline - now;
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
    if (remaining_ms <= 0) {
        remaining_ms = 1;
    }
    if (remaining_ms > static_cast<std::int64_t>(max_wallet_status_request_ttl_ms) ||
        next_request_id_ == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }

    const auto request_id = std::string{"pi-status-"} + std::to_string(++next_request_id_);
    auto request =
        encode_wallet_status_request(request_id, static_cast<std::uint64_t>(remaining_ms));
    if (!request || request->size() > max_wallet_status_frame_bytes || stop.stop_requested() ||
        std::chrono::steady_clock::now() >= deadline) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }
    auto response = channel_->exchange_status(*request, deadline, stop);
    if (!response || response->size() > max_wallet_status_frame_bytes || stop.stop_requested() ||
        std::chrono::steady_clock::now() >= deadline) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }
    auto decoded = decode_wallet_status_response(*response);
    if (!decoded || stop.stop_requested() || std::chrono::steady_clock::now() >= deadline ||
        decoded->id != request_id || !decoded->error_code.empty() || decoded->schema_version != 1 ||
        decoded->fresh_at_ms == 0 ||
        decoded->available_actions != std::vector<std::string>{"status"} ||
        !decoded->mutating_actions.empty()) {
        return std::unexpected(std::string{"wallet status is unavailable"});
    }
    return decoded;
}

auto wallet_pi_status_adapter::advertised_tools(
    steady_time deadline, const std::stop_token& stop
) noexcept -> std::vector<mcp::tool_descriptor> {
    try {
        if (!constructed_ || stop.stop_requested()) {
            return {};
        }
        auto lock = acquire_transaction(transaction_mutex_, deadline, stop);
        if (!lock || !probe_status(deadline, stop)) {
            return {};
        }
        std::vector<mcp::tool_descriptor> tools;
        tools.push_back(status_descriptor());
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return {};
        }
        return tools;
    } catch (...) {
        return {};
    }
}

auto wallet_pi_status_adapter::invoke(
    std::string_view tool_name,
    std::string_view arguments_json,
    steady_time deadline,
    const std::stop_token& stop
) noexcept -> mcp::tool_call_result {
    try {
        if (tool_name != status_tool_name || !constructed_ || stop.stop_requested()) {
            return tool_not_found();
        }
        if (!empty_object(arguments_json)) {
            return tool_not_found();
        }
        auto lock = acquire_transaction(transaction_mutex_, deadline, stop);
        if (!lock) {
            return tool_not_found();
        }
        auto status = probe_status(deadline, stop);
        if (!status) {
            return tool_not_found();
        }
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return tool_not_found();
        }
        auto structured = glz::write_json(
            detail::pi_status_result{
                .schema_version = status->schema_version,
                .connected = status->connected,
                .fresh_at_ms = status->fresh_at_ms,
                .wallet_server_alias = std::move(status->wallet_server_alias),
                .allowed_chain_ids = std::move(status->allowed_chain_ids),
                .available_actions = std::move(status->available_actions),
                .mutating_actions = {},
            }
        );
        if (!structured || structured->size() > max_wallet_status_frame_bytes ||
            stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return tool_not_found();
        }
        mcp::tool_call_result result{
            .status = mcp::tool_call_status::ok,
            .content =
                status->connected ? "Wallet status is available." : "Wallet is not connected.",
            .structured_json = std::move(*structured),
            .error_message = "",
        };
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return tool_not_found();
        }
        return result;
    } catch (...) {
        return allocation_free_absence();
    }
}

} // namespace glove::control
