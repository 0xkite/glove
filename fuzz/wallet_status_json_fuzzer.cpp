#include "src/control/wallet_status_bridge.hpp"
#include "src/control/wallet_status_json.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace {

using steady_time = std::chrono::steady_clock::time_point;

[[nodiscard]] auto session() -> glove::control::session_record {
    return {
        .schema_version = 1,
        .session_id = "fuzz-session",
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
        .tool_policy_id = "fuzz-status-policy",
        .wallet_server_alias = "fuzz-wallet-host",
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
        return {
            .unix_time_ms = 10'000U,
            .monotonic_time = steady_time{std::chrono::milliseconds{1}},
        };
    }
};

class fixed_plan_authority final : public glove::control::wallet_status_plan_authority {
public:
    [[nodiscard]] auto snapshot(steady_time /*deadline*/) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_plan_snapshot> override {
        return glove::control::wallet_status_plan_snapshot{
            .binding = binding(),
            .session = session(),
            .policy = policy(),
            .adapter_command_digest = std::string(64U, 'd'),
        };
    }
};

class fixed_readiness_authority final : public glove::control::wallet_status_readiness_authority {
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

class fixed_adapter_authority final : public glove::control::wallet_status_adapter_authority {
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

class fixed_server_authority final : public glove::control::wallet_status_server_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_server_snapshot> override {
        return glove::control::wallet_status_server_snapshot{
            .binding = current,
            .wallet_server_node_digest = std::string(64U, 'c'),
            .observation = {
                .connected = true,
                .observed_at_ms = 9'000U,
                .wallet_server_alias = "fuzz-wallet-host",
                .allowed_chain_ids = {8453U},
            },
        };
    }
};

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > glove::control::max_wallet_status_frame_bytes) {
        return 0;
    }

    // libFuzzer owns this byte span for the duration of the callback. Neither
    // parser retains the non-owning view.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view frame{reinterpret_cast<const char*>(data), size};
    static_cast<void>(glove::control::valid_wallet_status_json(frame));
    static_cast<void>(glove::control::decode_wallet_status_response(frame));

    glove::control::wallet_status_bridge bridge{
        std::make_unique<fixed_plan_authority>(),
        std::make_unique<fixed_readiness_authority>(),
        std::make_unique<fixed_adapter_authority>(),
        std::make_unique<fixed_server_authority>(),
        std::make_unique<fixed_clock>(),
    };
    static_cast<void>(bridge.handle_request(frame, steady_time{std::chrono::seconds{1}}));
    return 0;
}
