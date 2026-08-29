#include "wallet_status_bridge.hpp"

#include "wallet_status_json.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::control {
namespace wire {

struct wallet_status_request {
    std::string jsonrpc;
    std::string id;
    std::string method;
    std::uint8_t schema_version = 0;
    std::uint64_t deadline_remaining_ms = 0;
};

struct wallet_status_result {
    std::uint8_t schema_version = 0;
    bool connected = false;
    std::uint64_t fresh_at_ms = 0;
    std::string wallet_server_alias;
    std::vector<std::uint64_t> allowed_chain_ids;
    std::vector<std::string> available_actions;
    std::vector<std::string> mutating_actions;
};

struct wallet_status_result_decode {
    std::uint8_t schema_version = 0;
    std::optional<bool> connected;
    std::uint64_t fresh_at_ms = 0;
    std::string wallet_server_alias;
    std::vector<std::uint64_t> allowed_chain_ids;
    std::vector<std::string> available_actions;
    std::optional<std::vector<std::string>> mutating_actions;
};

struct wallet_status_error {
    std::string code;
    std::string message;
};

struct wallet_status_response {
    std::string jsonrpc;
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<wallet_status_error> error;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t max_request_id_bytes = 128U;
constexpr std::size_t max_policy_id_bytes = 128U;
constexpr std::size_t max_server_alias_bytes = 64U;

using steady_time = std::chrono::steady_clock::time_point;

auto valid_identifier(std::string_view value, std::size_t maximum_size) -> bool {
    return !value.empty() && value.size() <= maximum_size && value.front() != '-' &&
           value.front() != '.' && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_chain_ids(const std::vector<std::uint64_t>& values) -> bool {
    return !values.empty() && values.size() <= max_wallet_status_chain_ids &&
           std::ranges::all_of(values, [](std::uint64_t value) { return value != 0; }) &&
           std::ranges::adjacent_find(values, std::greater_equal{}) == values.end();
}

auto valid_session(const session_record& session) -> bool {
    return session.schema_version == 1 &&
           valid_identifier(session.session_id, max_request_id_bytes) &&
           valid_digest(session.controller_plan_digest) &&
           valid_digest(session.plan_content_digest) && session.state == session_state::running &&
           session.policy_revision != 0 && session.created_at_ms != 0 &&
           session.expires_at_ms > session.created_at_ms;
}

auto valid_policy(const wallet_status_bridge_policy& policy) -> bool {
    return policy.schema_version == 1 &&
           valid_identifier(policy.tool_policy_id, max_policy_id_bytes) &&
           valid_identifier(policy.wallet_server_alias, max_server_alias_bytes) &&
           valid_digest(policy.wallet_server_node_digest) &&
           valid_chain_ids(policy.allowed_chain_ids) && policy.maximum_status_age_ms != 0 &&
           policy.maximum_status_age_ms <= max_wallet_status_age_ms;
}

auto valid_binding(const wallet_status_plan_binding& binding) -> bool {
    return valid_identifier(binding.session_id, max_request_id_bytes) &&
           valid_digest(binding.controller_plan_digest) &&
           valid_digest(binding.plan_content_digest) && binding.policy_revision != 0 &&
           binding.expires_at_ms != 0 && binding.generation != 0;
}

auto plan_matches_binding(const wallet_status_plan_snapshot& snapshot) -> bool {
    return valid_binding(snapshot.binding) && valid_session(snapshot.session) &&
           valid_policy(snapshot.policy) && valid_digest(snapshot.adapter_command_digest) &&
           snapshot.session.session_id == snapshot.binding.session_id &&
           snapshot.session.controller_plan_digest == snapshot.binding.controller_plan_digest &&
           snapshot.session.plan_content_digest == snapshot.binding.plan_content_digest &&
           snapshot.session.policy_revision == snapshot.binding.policy_revision &&
           snapshot.session.expires_at_ms == snapshot.binding.expires_at_ms;
}

template<typename Value>
auto encode_json(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded || encoded->empty() || encoded->size() > max_wallet_status_frame_bytes) {
        return std::unexpected(std::string{"wallet status encoding failed or exceeded its cap"});
    }
    return std::move(*encoded);
}

auto decode_request(std::string_view frame)
    -> std::expected<wire::wallet_status_request, std::string> {
    if (!valid_wallet_status_json(frame)) {
        return std::unexpected(std::string{"invalid wallet status request boundary"});
    }
    std::string parse_buffer{frame};
    wire::wallet_status_request request;
    if (const auto error = glz::read<strict_read_options>(request, parse_buffer);
        error || request.jsonrpc != "2.0" || !valid_identifier(request.id, max_request_id_bytes) ||
        request.method.empty() || request.schema_version != 1 ||
        request.deadline_remaining_ms == 0 ||
        request.deadline_remaining_ms > max_wallet_status_request_ttl_ms) {
        return std::unexpected(std::string{"invalid wallet status request"});
    }
    return request;
}

auto error_response(std::string_view id, std::string_view code, std::string_view message)
    -> std::expected<std::string, std::string> {
    return encode_json(
        wire::wallet_status_response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = std::nullopt,
            .error = wire::wallet_status_error{
                .code = std::string{code},
                .message = std::string{message},
            },
        }
    );
}

auto authority_error_response(
    std::string_view id, wallet_status_authority_error error, bool status_source
) -> std::expected<std::string, std::string> {
    if (error == wallet_status_authority_error::deadline) {
        return std::unexpected(std::string{"wallet status request deadline exceeded"});
    }
    if (status_source && error == wallet_status_authority_error::stale) {
        return error_response(id, "status_stale", "wallet status is stale");
    }
    return error_response(id, "status_unavailable", "wallet status is unavailable");
}

auto success_response(
    std::string_view id,
    const wallet_status_bridge_policy& policy,
    const wallet_status_observation& observation
) -> std::expected<std::string, std::string> {
    auto result = encode_json(
        wire::wallet_status_result{
            .schema_version = 1,
            .connected = observation.connected,
            .fresh_at_ms = observation.observed_at_ms,
            .wallet_server_alias = policy.wallet_server_alias,
            .allowed_chain_ids = policy.allowed_chain_ids,
            .available_actions = {"status"},
            .mutating_actions = {},
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return encode_json(
        wire::wallet_status_response{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .result = glz::raw_json{std::move(*result)},
            .error = std::nullopt,
        }
    );
}

} // namespace

wallet_status_bridge::wallet_status_bridge(
    std::unique_ptr<wallet_status_plan_authority> plan_authority,
    std::unique_ptr<wallet_status_readiness_authority> readiness_authority,
    std::unique_ptr<wallet_status_adapter_authority> adapter_authority,
    std::unique_ptr<wallet_status_server_authority> server_authority,
    std::unique_ptr<wallet_status_clock> clock
)
    : plan_authority_(std::move(plan_authority)),
      readiness_authority_(std::move(readiness_authority)),
      adapter_authority_(std::move(adapter_authority)),
      server_authority_(std::move(server_authority)),
      clock_(std::move(clock)),
      constructed_(
          plan_authority_ != nullptr && readiness_authority_ != nullptr &&
          adapter_authority_ != nullptr && server_authority_ != nullptr && clock_ != nullptr
      ) {}

auto wallet_status_bridge::handle_request(
    std::string_view frame, steady_time receive_inclusive_deadline
) const -> std::expected<std::string, std::string> {
    try {
        const auto received = constructed_ ? std::optional{clock_->now()} : std::nullopt;
        auto request = decode_request(frame);
        if (!request) {
            return std::unexpected(request.error());
        }
        if (request->method != "wallet_status" || !constructed_) {
            return error_response(request->id, "method_not_found", "wallet status is unavailable");
        }

        const auto started = *received;
        if (started.unix_time_ms == 0 || receive_inclusive_deadline <= started.monotonic_time) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        const auto deadline = std::min(
            receive_inclusive_deadline,
            started.monotonic_time + std::chrono::milliseconds{request->deadline_remaining_ms}
        );
        auto last_checked = started;
        const auto checkpoint = [&]() -> std::optional<wallet_status_time> {
            const auto current = clock_->now();
            if (current.unix_time_ms < last_checked.unix_time_ms ||
                current.monotonic_time < last_checked.monotonic_time ||
                current.monotonic_time >= deadline) {
                return std::nullopt;
            }
            last_checked = current;
            return current;
        };
        if (!checkpoint()) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }

        auto initial_plan = plan_authority_->snapshot(deadline);
        if (!checkpoint()) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        if (!initial_plan) {
            return authority_error_response(request->id, initial_plan.error(), false);
        }
        if (!plan_matches_binding(*initial_plan)) {
            return error_response(
                request->id, "status_unavailable", "wallet status is unavailable"
            );
        }

        auto readiness = readiness_authority_->snapshot(initial_plan->binding, deadline);
        if (!checkpoint()) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        if (!readiness) {
            return authority_error_response(request->id, readiness.error(), false);
        }
        auto adapter = adapter_authority_->snapshot(initial_plan->binding, deadline);
        if (!checkpoint()) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        if (!adapter) {
            return authority_error_response(request->id, adapter.error(), false);
        }
        auto server = server_authority_->snapshot(initial_plan->binding, deadline);
        if (!checkpoint()) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        if (!server) {
            return authority_error_response(request->id, server.error(), true);
        }
        auto final_plan = plan_authority_->snapshot(deadline);
        const auto finished = checkpoint();
        if (!finished) {
            return std::unexpected(std::string{"wallet status request deadline exceeded"});
        }
        if (!final_plan) {
            return authority_error_response(request->id, final_plan.error(), false);
        }

        const auto binding = initial_plan->binding;
        const auto authorities_match =
            *final_plan == *initial_plan && readiness->binding == binding &&
            adapter->binding == binding && server->binding == binding &&
            readiness->audit_generation != 0 && readiness->journal_generation != 0 &&
            adapter->adapter_command_digest == initial_plan->adapter_command_digest &&
            server->wallet_server_node_digest == initial_plan->policy.wallet_server_node_digest;
        const auto& session = initial_plan->session;
        if (!authorities_match || started.unix_time_ms < session.created_at_ms ||
            session.expires_at_ms <= started.unix_time_ms ||
            finished->unix_time_ms < session.created_at_ms ||
            session.expires_at_ms <= finished->unix_time_ms) {
            return error_response(
                request->id, "status_unavailable", "wallet status is unavailable"
            );
        }

        const auto& observation = server->observation;
        if (observation.observed_at_ms == 0 ||
            observation.observed_at_ms > finished->unix_time_ms ||
            finished->unix_time_ms - observation.observed_at_ms >
                initial_plan->policy.maximum_status_age_ms) {
            return error_response(request->id, "status_stale", "wallet status is stale");
        }
        if (observation.wallet_server_alias != initial_plan->policy.wallet_server_alias ||
            observation.allowed_chain_ids != initial_plan->policy.allowed_chain_ids) {
            return error_response(
                request->id, "status_unavailable", "wallet status is unavailable"
            );
        }
        return success_response(request->id, initial_plan->policy, observation);
    } catch (...) {
        return std::unexpected(std::string{"wallet status processing failed"});
    }
}

auto encode_wallet_status_request(std::string_view id, std::uint64_t deadline_remaining_ms)
    -> std::expected<std::string, std::string> {
    if (!valid_identifier(id, max_request_id_bytes) || deadline_remaining_ms == 0 ||
        deadline_remaining_ms > max_wallet_status_request_ttl_ms) {
        return std::unexpected(std::string{"invalid wallet status request"});
    }
    return encode_json(
        wire::wallet_status_request{
            .jsonrpc = "2.0",
            .id = std::string{id},
            .method = "wallet_status",
            .schema_version = 1,
            .deadline_remaining_ms = deadline_remaining_ms,
        }
    );
}

auto decode_wallet_status_response(std::string_view frame)
    -> std::expected<wallet_status_bridge_response, std::string> {
    if (!valid_wallet_status_json(frame)) {
        return std::unexpected(std::string{"invalid wallet status response boundary"});
    }
    std::string parse_buffer{frame};
    wire::wallet_status_response response;
    if (const auto error = glz::read<strict_read_options>(response, parse_buffer);
        error || response.jsonrpc != "2.0" ||
        !valid_identifier(response.id, max_request_id_bytes) ||
        response.result.has_value() == response.error.has_value() ||
        (response.error && response.error->message.empty())) {
        return std::unexpected(std::string{"invalid wallet status response"});
    }

    wallet_status_bridge_response decoded;
    decoded.id = std::move(response.id);
    if (response.error) {
        if (response.error->code != "method_not_found" &&
            response.error->code != "status_unavailable" &&
            response.error->code != "status_stale") {
            return std::unexpected(std::string{"invalid wallet status response error"});
        }
        decoded.error_code = std::move(response.error->code);
        return decoded;
    }

    std::string result_buffer{response.result->str};
    wire::wallet_status_result_decode result;
    if (const auto error = glz::read<strict_read_options>(result, result_buffer);
        error || result.schema_version != 1 || !result.connected || result.fresh_at_ms == 0 ||
        !valid_identifier(result.wallet_server_alias, max_server_alias_bytes) ||
        !valid_chain_ids(result.allowed_chain_ids) ||
        result.available_actions != std::vector<std::string>{"status"} ||
        !result.mutating_actions || !result.mutating_actions->empty()) {
        return std::unexpected(std::string{"invalid wallet status result"});
    }
    decoded.schema_version = result.schema_version;
    decoded.connected = *result.connected;
    decoded.fresh_at_ms = result.fresh_at_ms;
    decoded.wallet_server_alias = std::move(result.wallet_server_alias);
    decoded.allowed_chain_ids = std::move(result.allowed_chain_ids);
    decoded.available_actions = std::move(result.available_actions);
    decoded.mutating_actions = std::move(*result.mutating_actions);
    return decoded;
}

} // namespace glove::control
