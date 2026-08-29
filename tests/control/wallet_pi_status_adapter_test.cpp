#include "wallet_pi_status_adapter.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using steady_time = std::chrono::steady_clock::time_point;

enum class authority_mode : std::uint8_t { fresh, disconnected, unavailable, stale, mismatch };
enum class channel_mode : std::uint8_t {
    delegate,
    malformed,
    wrong_id,
    mutation,
    oversized,
    transport_error,
    throws,
};

struct fake_state {
    std::atomic<authority_mode> authority{authority_mode::fresh};
    std::atomic<channel_mode> channel{channel_mode::delegate};
    std::atomic<int> calls{0};
    std::atomic<int> active{0};
    std::atomic<int> maximum_active{0};
    std::atomic<int> delay_ms{2};
    std::mutex mutex;
    std::vector<std::string> requests;
    std::vector<steady_time> starts;
    std::vector<steady_time> deadlines;
};

[[nodiscard]] auto session() -> glove::control::session_record {
    return {
        .schema_version = 1,
        .session_id = "private-session-id",
        .controller_plan_digest = std::string(64U, 'a'),
        .plan_content_digest = std::string(64U, 'b'),
        .state = glove::control::session_state::running,
        .policy_revision = 1,
        .expires_at_ms = 20'000U,
        .created_at_ms = 1'000U,
    };
}

[[nodiscard]] auto policy() -> glove::control::wallet_status_bridge_policy {
    return {
        .schema_version = 1,
        .tool_policy_id = "private-wallet-status-policy",
        .wallet_server_alias = "synthetic-wallet-host",
        .wallet_server_node_digest = std::string(64U, 'c'),
        .allowed_chain_ids = {8453U},
        .maximum_status_age_ms = 5'000U,
    };
}

[[nodiscard]] auto binding() -> glove::control::wallet_status_plan_binding {
    const auto current = session();
    return {
        .session_id = current.session_id,
        .controller_plan_digest = current.controller_plan_digest,
        .plan_content_digest = current.plan_content_digest,
        .policy_revision = current.policy_revision,
        .expires_at_ms = current.expires_at_ms,
        .generation = 1U,
    };
}

class fixed_clock final : public glove::control::wallet_status_clock {
public:
    [[nodiscard]] auto now() noexcept -> glove::control::wallet_status_time override {
        return {.unix_time_ms = 10'000U, .monotonic_time = std::chrono::steady_clock::now()};
    }
};

class plan_authority final : public glove::control::wallet_status_plan_authority {
public:
    explicit plan_authority(std::shared_ptr<fake_state> state) : state_(std::move(state)) {}

    [[nodiscard]] auto snapshot(steady_time /*deadline*/) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_plan_snapshot> override {
        if (state_->authority.load() == authority_mode::unavailable) {
            return std::unexpected(glove::control::wallet_status_authority_error::unavailable);
        }
        return glove::control::wallet_status_plan_snapshot{
            .binding = binding(),
            .session = session(),
            .policy = policy(),
            .adapter_command_digest = std::string(64U, 'd'),
        };
    }

private:
    std::shared_ptr<fake_state> state_;
};

class readiness_authority final : public glove::control::wallet_status_readiness_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_readiness_snapshot> override {
        return glove::control::wallet_status_readiness_snapshot{
            .binding = current,
            .audit_generation = 1U,
            .journal_generation = 1U,
        };
    }
};

class adapter_authority final : public glove::control::wallet_status_adapter_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_adapter_snapshot> override {
        return glove::control::wallet_status_adapter_snapshot{
            .binding = current,
            .adapter_command_digest = std::string(64U, 'd'),
        };
    }
};

class server_authority final : public glove::control::wallet_status_server_authority {
public:
    explicit server_authority(std::shared_ptr<fake_state> state) : state_(std::move(state)) {}

    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_server_snapshot> override {
        const auto mode = state_->authority.load();
        return glove::control::wallet_status_server_snapshot{
            .binding = current,
            .wallet_server_node_digest = std::string(64U, 'c'),
            .observation = {
                .connected = mode != authority_mode::disconnected,
                .observed_at_ms = mode == authority_mode::stale ? 1U : 9'000U,
                .wallet_server_alias = mode == authority_mode::mismatch ? "wrong-wallet-host"
                                                                        : "synthetic-wallet-host",
                .allowed_chain_ids = {8453U},
            },
        };
    }

private:
    std::shared_ptr<fake_state> state_;
};

[[nodiscard]] auto make_bridge(std::shared_ptr<fake_state> state)
    -> std::unique_ptr<glove::control::wallet_status_bridge> {
    return std::make_unique<glove::control::wallet_status_bridge>(
        std::make_unique<plan_authority>(state),
        std::make_unique<readiness_authority>(),
        std::make_unique<adapter_authority>(),
        std::make_unique<server_authority>(std::move(state)),
        std::make_unique<fixed_clock>()
    );
}

class fake_channel final : public glove::control::wallet_pi_status_channel {
public:
    explicit fake_channel(std::shared_ptr<fake_state> state)
        : state_(std::move(state)), bridge_(make_bridge(state_)) {}

    [[nodiscard]] auto
    exchange_status(std::string_view request, steady_time deadline, const std::stop_token& stop)
        -> std::expected<std::string, std::string> override {
        state_->calls.fetch_add(1);
        const auto active = state_->active.fetch_add(1) + 1;
        auto maximum = state_->maximum_active.load();
        while (active > maximum && !state_->maximum_active.compare_exchange_weak(maximum, active)) {
        }

        struct active_guard {
            std::shared_ptr<fake_state> state;

            ~active_guard() { state->active.fetch_sub(1); }
        } guard{state_};

        {
            const std::scoped_lock lock{state_->mutex};
            state_->requests.emplace_back(request);
            state_->starts.push_back(std::chrono::steady_clock::now());
            state_->deadlines.push_back(deadline);
        }
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return std::unexpected(std::string{"fake channel deadline"});
        }
        const auto delay_until =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{state_->delay_ms.load()};
        while (std::chrono::steady_clock::now() < delay_until) {
            const auto now = std::chrono::steady_clock::now();
            if (stop.stop_requested() || now >= deadline) {
                return std::unexpected(std::string{"fake channel deadline"});
            }
            std::this_thread::sleep_until(
                std::min({delay_until, deadline, now + std::chrono::milliseconds{1}})
            );
        }
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return std::unexpected(std::string{"fake channel deadline"});
        }
        switch (state_->channel.load()) {
        case channel_mode::malformed:
            return std::string{"{"};
        case channel_mode::oversized:
            return std::string(glove::control::max_wallet_status_frame_bytes + 1U, 'x');
        case channel_mode::transport_error:
            return std::unexpected(std::string{"private transport detail"});
        case channel_mode::throws:
            throw std::runtime_error{"private channel exception"};
        case channel_mode::delegate:
        case channel_mode::wrong_id:
        case channel_mode::mutation:
            break;
        }
        auto response = bridge_->handle_request(request, deadline);
        if (!response) {
            return std::unexpected(response.error());
        }
        if (state_->channel.load() == channel_mode::wrong_id) {
            const auto id_start = response->find(R"("id":")");
            if (id_start != std::string::npos) {
                const auto value_start = id_start + 6U;
                const auto value_end = response->find('"', value_start);
                response->replace(value_start, value_end - value_start, "wrong-id");
            }
        }
        if (state_->channel.load() == channel_mode::mutation) {
            const auto empty = response->find(R"("mutating_actions":[])");
            if (empty != std::string::npos) {
                response->replace(empty, 21U, R"("mutating_actions":["sign"])");
            }
        }
        return response;
    }

private:
    std::shared_ptr<fake_state> state_;
    std::unique_ptr<glove::control::wallet_status_bridge> bridge_;
};

[[nodiscard]] auto enabled_options() -> glove::control::wallet_pi_status_adapter_options {
    return {
        .enabled = true,
        .request_timeout = std::chrono::milliseconds{250},
    };
}

[[nodiscard]] auto make_adapter(
    const std::shared_ptr<fake_state>& state,
    glove::control::wallet_pi_status_adapter_options options = enabled_options()
) -> std::unique_ptr<glove::control::wallet_pi_status_adapter> {
    return std::make_unique<glove::control::wallet_pi_status_adapter>(
        std::make_unique<fake_channel>(state), options
    );
}

[[nodiscard]] auto deadline() -> steady_time {
    return std::chrono::steady_clock::now() + std::chrono::seconds{1};
}

[[nodiscard]] auto run() -> int {
    using glove::control::wallet_pi_status_adapter;
    using glove::mcp::tool_call_status;

    auto disabled_state = std::make_shared<fake_state>();
    auto disabled_options = enabled_options();
    disabled_options.enabled = false;
    auto disabled = make_adapter(disabled_state, disabled_options);
    REQUIRE(disabled->advertised_tools(deadline()).empty());
    REQUIRE(
        disabled->invoke("wallet_status", R"({"sign":true})", deadline()).status ==
        tool_call_status::tool_not_found
    );
    REQUIRE(disabled_state->calls.load() == 0);

    wallet_pi_status_adapter channel_less{nullptr, enabled_options()};
    REQUIRE(channel_less.advertised_tools(deadline()).empty());

    for (const auto invalid_timeout : {
             std::chrono::milliseconds::zero(),
             std::chrono::milliseconds{glove::control::max_wallet_status_request_ttl_ms + 1U},
         }) {
        auto invalid_state = std::make_shared<fake_state>();
        auto invalid_options = enabled_options();
        invalid_options.request_timeout = invalid_timeout;
        auto invalid_adapter = make_adapter(invalid_state, invalid_options);
        REQUIRE(invalid_adapter->advertised_tools(deadline()).empty());
        REQUIRE(invalid_state->calls.load() == 0);
    }

    auto state = std::make_shared<fake_state>();
    auto adapter = make_adapter(state);
    auto tools = adapter->advertised_tools(deadline());
    REQUIRE(tools.size() == 1U);
    REQUIRE(tools.front().name == "wallet_status");
    REQUIRE(tools.front().description == "Read redacted wallet connectivity status.");
    REQUIRE(
        tools.front().input_schema_json ==
        R"({"type":"object","properties":{},"additionalProperties":false})"
    );
    REQUIRE(tools.front().annotations.has_annotations);
    REQUIRE(tools.front().annotations.read_only_hint);
    REQUIRE(!tools.front().annotations.destructive_hint);
    REQUIRE(tools.front().annotations.idempotent_hint);
    REQUIRE(!tools.front().annotations.open_world_hint);

    state->authority.store(authority_mode::stale);
    REQUIRE(adapter->advertised_tools(deadline()).empty());
    state->authority.store(authority_mode::unavailable);
    REQUIRE(adapter->advertised_tools(deadline()).empty());
    state->authority.store(authority_mode::mismatch);
    REQUIRE(adapter->advertised_tools(deadline()).empty());
    state->authority.store(authority_mode::fresh);
    REQUIRE(adapter->advertised_tools(deadline()).size() == 1U);

    state->authority.store(authority_mode::disconnected);
    REQUIRE(adapter->advertised_tools(deadline()).size() == 1U);
    const auto disconnected = adapter->invoke("wallet_status", "{}", deadline());
    REQUIRE(disconnected.status == tool_call_status::ok);
    REQUIRE(
        disconnected.structured_json ==
        R"({"schema_version":1,"connected":false,"fresh_at_ms":9000,"wallet_server_alias":"synthetic-wallet-host","allowed_chain_ids":[8453],"available_actions":["status"],"mutating_actions":[]})"
    );
    REQUIRE(disconnected.content == "Wallet is not connected.");
    state->authority.store(authority_mode::fresh);

    const auto calls_before_invalid_authority_arguments = state->calls.load();
    for (const auto mode : {
             authority_mode::stale,
             authority_mode::unavailable,
             authority_mode::mismatch,
         }) {
        state->authority.store(mode);
        const auto result = adapter->invoke("wallet_status", R"({"sign":true})", deadline());
        REQUIRE(result.status == tool_call_status::tool_not_found);
        REQUIRE(result.error_message == "tool not found");
    }
    REQUIRE(state->calls.load() == calls_before_invalid_authority_arguments);
    state->authority.store(authority_mode::fresh);

    const auto calls_before_unknown_tools = state->calls.load();
    for (const std::string_view name : {
             "sage_status",
             "sage_search",
             "sage_execute",
             "glove_control",
             "wallet_sign",
             "wallet_sign_typed_data",
             "wallet_send_transaction",
             "wallet_authenticate",
             "wallet_transfer",
             "wallet_approve",
             "wallet_provider",
             "wallet_p2p",
         }) {
        const auto result = adapter->invoke(name, "{}", deadline());
        REQUIRE(result.status == tool_call_status::tool_not_found);
        REQUIRE(result.error_message == "tool not found");
    }
    REQUIRE(state->calls.load() == calls_before_unknown_tools);

    const auto calls_before_invalid_arguments = state->calls.load();
    for (const std::string_view arguments : {
             "",
             "null",
             "[]",
             "{",
             R"({"sign":true})",
             R"({"x":1,"x":2})",
         }) {
        const auto result = adapter->invoke("wallet_status", arguments, deadline());
        REQUIRE(result.status == tool_call_status::tool_not_found);
        REQUIRE(result.error_message == "tool not found");
    }
    REQUIRE(state->calls.load() == calls_before_invalid_arguments);
    {
        const std::scoped_lock lock{state->mutex};
        REQUIRE(state->requests.size() == static_cast<std::size_t>(calls_before_invalid_arguments));
    }

    auto success = adapter->invoke("wallet_status", " { } ", deadline());
    REQUIRE(success.status == tool_call_status::ok);
    REQUIRE(success.content == "Wallet status is available.");
    REQUIRE(
        success.structured_json ==
        R"({"schema_version":1,"connected":true,"fresh_at_ms":9000,"wallet_server_alias":"synthetic-wallet-host","allowed_chain_ids":[8453],"available_actions":["status"],"mutating_actions":[]})"
    );
    REQUIRE(success.error_message.empty());
    const auto private_session = session();
    const std::vector<std::string_view> prohibited_values{
        "private-session-id",
        private_session.controller_plan_digest,
        private_session.plan_content_digest,
        "private-wallet-status-policy",
        "private_key",
        "secret",
        "signature",
        "challenge",
        "rpc",
        "socket",
        "peer",
        "provider",
        "p2p",
        "transaction",
        "typed_data",
        "auth",
    };
    for (const auto prohibited : prohibited_values) {
        REQUIRE(success.structured_json.find(prohibited) == std::string::npos);
        REQUIRE(success.content.find(prohibited) == std::string::npos);
    }

    state->authority.store(authority_mode::unavailable);
    auto disappeared = adapter->invoke("wallet_status", "{}", deadline());
    REQUIRE(disappeared.status == tool_call_status::tool_not_found);
    REQUIRE(disappeared.error_message == "tool not found");
    REQUIRE(disappeared.content.empty());
    REQUIRE(disappeared.structured_json.empty());
    state->authority.store(authority_mode::fresh);

    for (const auto mode : {
             channel_mode::malformed,
             channel_mode::wrong_id,
             channel_mode::mutation,
             channel_mode::oversized,
             channel_mode::transport_error,
             channel_mode::throws,
         }) {
        state->channel.store(mode);
        REQUIRE(adapter->advertised_tools(deadline()).empty());
        const auto result = adapter->invoke("wallet_status", "{}", deadline());
        REQUIRE(result.status == tool_call_status::tool_not_found);
        REQUIRE(result.error_message.empty() || result.error_message == "tool not found");
        REQUIRE(result.error_message.find("private") == std::string::npos);
        REQUIRE(result.content.empty());
        REQUIRE(result.structured_json.empty());
    }
    state->channel.store(channel_mode::delegate);

    std::stop_source cancelled;
    cancelled.request_stop();
    const auto calls_before_cancel = state->calls.load();
    REQUIRE(adapter->advertised_tools(deadline(), cancelled.get_token()).empty());
    REQUIRE(
        adapter->invoke("wallet_status", "{}", deadline(), cancelled.get_token()).status ==
        tool_call_status::tool_not_found
    );
    REQUIRE(state->calls.load() == calls_before_cancel);
    REQUIRE(adapter->advertised_tools(std::chrono::steady_clock::now()).empty());
    REQUIRE(
        adapter->invoke("wallet_status", "{}", std::chrono::steady_clock::now()).status ==
        tool_call_status::tool_not_found
    );
    REQUIRE(
        adapter
            ->invoke(
                "wallet_status",
                R"({"sign":true})",
                std::chrono::steady_clock::now(),
                cancelled.get_token()
            )
            .status == tool_call_status::tool_not_found
    );
    REQUIRE(state->calls.load() == calls_before_cancel);

    state->delay_ms.store(100);
    std::atomic<bool> holder_succeeded{false};
    std::thread holder{[&adapter, &holder_succeeded] {
        holder_succeeded.store(adapter->advertised_tools(deadline()).size() == 1U);
    }};
    const auto holder_wait_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{200};
    while (state->active.load() != 1 && std::chrono::steady_clock::now() < holder_wait_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    const auto holder_entered = state->active.load() == 1;
    if (!holder_entered) {
        holder.join();
        REQUIRE(holder_entered);
    }
    const auto calls_with_holder = state->calls.load();
    const auto invalid_invoke_started = std::chrono::steady_clock::now();
    const auto invalid_while_locked =
        adapter->invoke("wallet_status", R"({"sign":true})", deadline());
    REQUIRE(invalid_while_locked.status == tool_call_status::tool_not_found);
    REQUIRE(invalid_while_locked.error_message == "tool not found");
    REQUIRE(
        std::chrono::steady_clock::now() - invalid_invoke_started < std::chrono::milliseconds{80}
    );
    REQUIRE(state->calls.load() == calls_with_holder);

    const auto queued_started = std::chrono::steady_clock::now();
    REQUIRE(adapter->advertised_tools(queued_started + std::chrono::milliseconds{15}).empty());
    REQUIRE(std::chrono::steady_clock::now() - queued_started < std::chrono::milliseconds{80});
    REQUIRE(state->calls.load() == calls_with_holder);

    std::stop_source queued_cancel;
    std::thread cancel_waiter{[&queued_cancel] {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
        queued_cancel.request_stop();
    }};
    const auto cancel_wait_started = std::chrono::steady_clock::now();
    REQUIRE(adapter->advertised_tools(deadline(), queued_cancel.get_token()).empty());
    REQUIRE(std::chrono::steady_clock::now() - cancel_wait_started < std::chrono::milliseconds{80});
    REQUIRE(state->calls.load() == calls_with_holder);
    cancel_waiter.join();
    holder.join();
    REQUIRE(holder_succeeded.load());

    state->delay_ms.store(50);
    std::stop_source exchange_cancel;
    std::thread exchange_canceller{[&exchange_cancel] {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
        exchange_cancel.request_stop();
    }};
    const auto calls_before_exchange_cancel = state->calls.load();
    REQUIRE(adapter->advertised_tools(deadline(), exchange_cancel.get_token()).empty());
    exchange_canceller.join();
    REQUIRE(state->calls.load() == calls_before_exchange_cancel + 1);

    state->delay_ms.store(30);
    const auto calls_before_near_deadline = state->calls.load();
    REQUIRE(adapter
                ->advertised_tools(std::chrono::steady_clock::now() + std::chrono::milliseconds{10})
                .empty());
    REQUIRE(state->calls.load() == calls_before_near_deadline + 1);
    state->delay_ms.store(2);

    std::vector<std::thread> threads;
    threads.reserve(8U);
    for (int index = 0; index < 8; ++index) {
        threads.emplace_back([&adapter] {
            const auto listed = adapter->advertised_tools(deadline());
            if (listed.size() != 1U) {
                std::terminate();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    REQUIRE(state->maximum_active.load() == 1);

    {
        const std::scoped_lock lock{state->mutex};
        REQUIRE(!state->requests.empty());
        REQUIRE(state->requests.back().find(R"("method":"wallet_status")") != std::string::npos);
        REQUIRE(state->requests.back().find("sign") == std::string::npos);
        REQUIRE(state->requests.back().size() <= glove::control::max_wallet_status_frame_bytes);
        REQUIRE(state->starts.size() == state->deadlines.size());
        REQUIRE(state->requests.size() == state->starts.size());
        for (std::size_t index = 0; index < state->deadlines.size(); ++index) {
            const auto expected_id =
                std::string{"\"id\":\"pi-status-"} + std::to_string(index + 1U) + "\"";
            REQUIRE(state->requests[index].find(expected_id) != std::string::npos);
            REQUIRE(state->deadlines[index] > state->starts[index]);
            REQUIRE(
                state->deadlines[index] - state->starts[index] <= std::chrono::milliseconds{250}
            );
        }
    }

    return 0;
}

} // namespace

int main() {
    return run();
}
