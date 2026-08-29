#include "../../src/control/wallet_status_bridge.hpp"
#include "../../src/control/wallet_status_json.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
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
using authority_error = glove::control::wallet_status_authority_error;

class socket_pair {
public:
    socket_pair() {
        std::array<int, 2> descriptors{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors.data()) == 0) {
            first_ = descriptors[0];
            second_ = descriptors[1];
        }
    }

    socket_pair(const socket_pair&) = delete;
    auto operator=(const socket_pair&) -> socket_pair& = delete;

    ~socket_pair() {
        if (first_ >= 0) {
            (void)::close(first_);
        }
        if (second_ >= 0) {
            (void)::close(second_);
        }
    }

    [[nodiscard]] auto first() const noexcept -> int { return first_; }

    [[nodiscard]] auto second() const noexcept -> int { return second_; }

    auto close_second() noexcept -> void {
        if (second_ >= 0) {
            (void)::close(second_);
            second_ = -1;
        }
    }

private:
    int first_ = -1;
    int second_ = -1;
};

class scripted_clock final : public glove::control::wallet_status_clock {
public:
    explicit scripted_clock(std::vector<glove::control::wallet_status_time> values)
        : values_(std::move(values)) {}

    [[nodiscard]] auto now() noexcept -> glove::control::wallet_status_time override {
        const std::scoped_lock lock{mutex_};
        ++calls_;
        if (values_.empty()) {
            return {};
        }
        const auto index = std::min(next_, values_.size() - 1U);
        ++next_;
        return values_.at(index);
    }

    [[nodiscard]] auto calls() const -> std::size_t {
        const std::scoped_lock lock{mutex_};
        return calls_;
    }

private:
    mutable std::mutex mutex_;
    std::vector<glove::control::wallet_status_time> values_;
    std::size_t next_ = 0;
    std::size_t calls_ = 0;
};

class fixed_clock final : public glove::control::wallet_status_clock {
public:
    fixed_clock(std::uint64_t unix_time_ms, steady_time monotonic_time)
        : value_{.unix_time_ms = unix_time_ms, .monotonic_time = monotonic_time} {}

    [[nodiscard]] auto now() noexcept -> glove::control::wallet_status_time override {
        return value_;
    }

private:
    glove::control::wallet_status_time value_;
};

[[nodiscard]] auto make_clock(
    std::uint64_t started_ms = 10'000U,
    std::uint64_t finished_ms = 10'001U,
    std::chrono::milliseconds elapsed = std::chrono::milliseconds{1},
    std::chrono::milliseconds start_offset = std::chrono::milliseconds{0}
) -> std::unique_ptr<scripted_clock> {
    const auto monotonic = std::chrono::steady_clock::now() + start_offset;
    return std::make_unique<scripted_clock>(std::vector<glove::control::wallet_status_time>{
        {.unix_time_ms = started_ms, .monotonic_time = monotonic},
        {.unix_time_ms = finished_ms, .monotonic_time = monotonic + elapsed},
    });
}

[[nodiscard]] auto make_session() -> glove::control::session_record {
    return {
        .schema_version = 1,
        .session_id = "session-status-1",
        .controller_plan_digest = std::string(64U, 'a'),
        .plan_content_digest = std::string(64U, 'b'),
        .state = glove::control::session_state::running,
        .policy_revision = 7,
        .expires_at_ms = 50'000U,
        .created_at_ms = 1'000U,
    };
}

[[nodiscard]] auto make_policy() -> glove::control::wallet_status_bridge_policy {
    return {
        .schema_version = 1,
        .tool_policy_id = "sage-wallet-status-readonly-v1",
        .wallet_server_alias = "wallet-test-host",
        .wallet_server_node_digest = std::string(64U, 'c'),
        .allowed_chain_ids = {8453U, 84'532U},
        .maximum_status_age_ms = 5'000U,
    };
}

[[nodiscard]] auto observation(std::uint64_t observed_at_ms = 9'000U)
    -> glove::control::wallet_status_observation {
    return {
        .connected = true,
        .observed_at_ms = observed_at_ms,
        .wallet_server_alias = "wallet-test-host",
        .allowed_chain_ids = {8453U, 84'532U},
    };
}

[[nodiscard]] auto plan_binding() -> glove::control::wallet_status_plan_binding {
    const auto session = make_session();
    return {
        .session_id = session.session_id,
        .controller_plan_digest = session.controller_plan_digest,
        .plan_content_digest = session.plan_content_digest,
        .policy_revision = session.policy_revision,
        .expires_at_ms = session.expires_at_ms,
        .generation = 11U,
    };
}

[[nodiscard]] auto plan_snapshot() -> glove::control::wallet_status_plan_snapshot {
    return {
        .binding = plan_binding(),
        .session = make_session(),
        .policy = make_policy(),
        .adapter_command_digest = std::string(64U, 'd'),
    };
}

struct authority_state {
    mutable std::mutex mutex;
    std::vector<glove::control::wallet_status_plan_snapshot> plans{plan_snapshot()};
    std::vector<std::optional<authority_error>> plan_errors;
    std::optional<authority_error> readiness_error;
    std::optional<authority_error> adapter_error;
    std::optional<authority_error> server_error;
    std::optional<glove::control::wallet_status_plan_binding> readiness_binding;
    std::optional<glove::control::wallet_status_plan_binding> adapter_binding;
    std::optional<glove::control::wallet_status_plan_binding> server_binding;
    std::uint64_t audit_generation = 3U;
    std::uint64_t journal_generation = 5U;
    std::string adapter_command_digest = std::string(64U, 'd');
    std::string wallet_server_node_digest = std::string(64U, 'c');
    glove::control::wallet_status_observation server_observation = observation();
    std::size_t plan_reads = 0;
    std::vector<std::string> call_order;
    std::vector<steady_time> deadlines;
};

class fake_plan_authority final : public glove::control::wallet_status_plan_authority {
public:
    explicit fake_plan_authority(std::shared_ptr<authority_state> state)
        : state_(std::move(state)) {}

    [[nodiscard]] auto snapshot(steady_time deadline) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_plan_snapshot> override {
        const std::scoped_lock lock{state_->mutex};
        const auto index = state_->plan_reads++;
        state_->call_order.emplace_back("plan");
        state_->deadlines.push_back(deadline);
        if (index < state_->plan_errors.size() && state_->plan_errors.at(index)) {
            return std::unexpected(*state_->plan_errors.at(index));
        }
        if (state_->plans.empty()) {
            return std::unexpected(authority_error::unavailable);
        }
        return state_->plans.at(std::min(index, state_->plans.size() - 1U));
    }

private:
    std::shared_ptr<authority_state> state_;
};

class throwing_plan_authority final : public glove::control::wallet_status_plan_authority {
public:
    [[nodiscard]] auto snapshot(steady_time /*deadline*/) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_plan_snapshot> override {
        throw std::bad_alloc{};
    }
};

class fake_readiness_authority final : public glove::control::wallet_status_readiness_authority {
public:
    explicit fake_readiness_authority(std::shared_ptr<authority_state> state)
        : state_(std::move(state)) {}

    [[nodiscard]] auto
    snapshot(const glove::control::wallet_status_plan_binding& binding, steady_time deadline) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_readiness_snapshot> override {
        const std::scoped_lock lock{state_->mutex};
        state_->call_order.emplace_back("readiness");
        state_->deadlines.push_back(deadline);
        if (state_->readiness_error) {
            return std::unexpected(*state_->readiness_error);
        }
        return glove::control::wallet_status_readiness_snapshot{
            .binding = state_->readiness_binding.value_or(binding),
            .audit_generation = state_->audit_generation,
            .journal_generation = state_->journal_generation,
        };
    }

private:
    std::shared_ptr<authority_state> state_;
};

class fake_adapter_authority final : public glove::control::wallet_status_adapter_authority {
public:
    explicit fake_adapter_authority(std::shared_ptr<authority_state> state)
        : state_(std::move(state)) {}

    [[nodiscard]] auto
    snapshot(const glove::control::wallet_status_plan_binding& binding, steady_time deadline) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_adapter_snapshot> override {
        const std::scoped_lock lock{state_->mutex};
        state_->call_order.emplace_back("adapter");
        state_->deadlines.push_back(deadline);
        if (state_->adapter_error) {
            return std::unexpected(*state_->adapter_error);
        }
        return glove::control::wallet_status_adapter_snapshot{
            .binding = state_->adapter_binding.value_or(binding),
            .adapter_command_digest = state_->adapter_command_digest,
        };
    }

private:
    std::shared_ptr<authority_state> state_;
};

class fake_server_authority final : public glove::control::wallet_status_server_authority {
public:
    explicit fake_server_authority(std::shared_ptr<authority_state> state)
        : state_(std::move(state)) {}

    [[nodiscard]] auto
    snapshot(const glove::control::wallet_status_plan_binding& binding, steady_time deadline) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_server_snapshot> override {
        const std::scoped_lock lock{state_->mutex};
        state_->call_order.emplace_back("server");
        state_->deadlines.push_back(deadline);
        if (state_->server_error) {
            return std::unexpected(*state_->server_error);
        }
        return glove::control::wallet_status_server_snapshot{
            .binding = state_->server_binding.value_or(binding),
            .wallet_server_node_digest = state_->wallet_server_node_digest,
            .observation = state_->server_observation,
        };
    }

private:
    std::shared_ptr<authority_state> state_;
};

[[nodiscard]] auto make_bridge(
    const std::shared_ptr<authority_state>& state,
    std::unique_ptr<glove::control::wallet_status_clock> clock = make_clock()
) -> std::unique_ptr<glove::control::wallet_status_bridge> {
    return std::make_unique<glove::control::wallet_status_bridge>(
        std::make_unique<fake_plan_authority>(state),
        std::make_unique<fake_readiness_authority>(state),
        std::make_unique<fake_adapter_authority>(state),
        std::make_unique<fake_server_authority>(state),
        std::move(clock)
    );
}

[[nodiscard]] auto contains_forbidden_status_data(std::string_view value) -> bool {
    constexpr std::array forbidden{
        "private_key",
        "passphrase",
        "rpc_url",
        "signature",
        "challenge",
        "sage.sock",
        "gloved.sock",
        ".sage",
        "0xfeedface",
    };
    return std::ranges::any_of(forbidden, [value](std::string_view candidate) {
        return value.find(candidate) != std::string_view::npos;
    });
}

[[nodiscard]] auto run() -> int {
    using namespace glove::control;

    auto request = encode_wallet_status_request("status-1", 1'000U);
    REQUIRE(request.has_value());

    auto state = std::make_shared<authority_state>();
    auto bridge = make_bridge(state);
    auto response = bridge->handle_request(
        *request, std::chrono::steady_clock::now() + std::chrono::seconds{1}
    );
    REQUIRE(response.has_value());
    auto decoded = decode_wallet_status_response(*response);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->id == "status-1");
    REQUIRE(decoded->schema_version == 1);
    REQUIRE(decoded->connected);
    REQUIRE(decoded->fresh_at_ms == 9'000U);
    REQUIRE(decoded->wallet_server_alias == "wallet-test-host");
    REQUIRE((decoded->allowed_chain_ids == std::vector<std::uint64_t>{8453U, 84'532U}));
    REQUIRE(decoded->available_actions == std::vector<std::string>{"status"});
    REQUIRE(decoded->mutating_actions.empty());
    REQUIRE(decoded->error_code.empty());
    REQUIRE(!contains_forbidden_status_data(*response));
    REQUIRE(response->find(make_session().controller_plan_digest) == std::string::npos);
    REQUIRE(response->find(make_session().plan_content_digest) == std::string::npos);
    {
        const std::scoped_lock lock{state->mutex};
        REQUIRE(
            (state->call_order ==
             std::vector<std::string>{"plan", "readiness", "adapter", "server", "plan"})
        );
        REQUIRE(state->deadlines.size() == 5U);
        REQUIRE(std::ranges::all_of(state->deadlines, [&](steady_time deadline) {
            return deadline == state->deadlines.front();
        }));
    }

    auto missing_connected = *response;
    const auto connected_field = missing_connected.find("\"connected\":true,");
    REQUIRE(connected_field != std::string::npos);
    missing_connected.erase(connected_field, std::string_view{"\"connected\":true,"}.size());
    REQUIRE(!decode_wallet_status_response(missing_connected).has_value());

    auto missing_mutating_actions = *response;
    const auto mutating_field = missing_mutating_actions.find(",\"mutating_actions\":[]");
    REQUIRE(mutating_field != std::string::npos);
    missing_mutating_actions.erase(
        mutating_field, std::string_view{",\"mutating_actions\":[]"}.size()
    );
    REQUIRE(!decode_wallet_status_response(missing_mutating_actions).has_value());

    auto duplicate_request_key = *request;
    duplicate_request_key.insert(1U, R"("method":"wallet_status",)");
    auto malformed_state = std::make_shared<authority_state>();
    auto malformed_bridge = make_bridge(malformed_state);
    REQUIRE(!malformed_bridge
                 ->handle_request(
                     duplicate_request_key,
                     std::chrono::steady_clock::now() + std::chrono::seconds{1}
                 )
                 .has_value());
    {
        const std::scoped_lock lock{malformed_state->mutex};
        REQUIRE(malformed_state->call_order.empty());
    }

    auto duplicate_response_key = *response;
    duplicate_response_key.insert(1U, R"("id":"status-1",)");
    REQUIRE(!decode_wallet_status_response(duplicate_response_key).has_value());
    auto duplicate_result_key = *response;
    const auto nested_mutating = duplicate_result_key.find(R"(,"mutating_actions":[])");
    REQUIRE(nested_mutating != std::string::npos);
    duplicate_result_key.insert(nested_mutating, R"(,"mutating_actions":[])");
    REQUIRE(!decode_wallet_status_response(duplicate_result_key).has_value());

    REQUIRE(valid_wallet_status_json(*request));
    REQUIRE(!valid_wallet_status_json(R"({"method":1,"\u006dethod":2})"));
    REQUIRE(!valid_wallet_status_json(R"({"a/b":1,"a\/b":2})"));
    REQUIRE(!valid_wallet_status_json(R"({"a\\b":1,"a\u005Cb":2})"));
    REQUIRE(!valid_wallet_status_json(R"({"\u0000":1,"\u0000":2})"));
    REQUIRE(valid_wallet_status_json(R"({"emoji":"\uD83D\uDE00"})"));
    REQUIRE(!valid_wallet_status_json(R"({"broken":"\uD800"})"));
    REQUIRE(!valid_wallet_status_json(R"({"broken":"\uDC00"})"));
    REQUIRE(!valid_wallet_status_json(R"({"broken":"\uD800\u0041"})"));
    REQUIRE(!valid_wallet_status_json(R"({"broken":"\x20"})"));
    REQUIRE(valid_wallet_status_json(R"([-1,-0,1.25,1e3,1E-3])"));
    REQUIRE(!valid_wallet_status_json(R"({"number":01})"));
    REQUIRE(!valid_wallet_status_json(R"({"number":1e})"));
    REQUIRE(!valid_wallet_status_json(R"({"array":[1,]})"));
    REQUIRE(!valid_wallet_status_json(R"({"object":{"key":1,}})"));
    REQUIRE(!valid_wallet_status_json(R"({"outer":[{"key":1,"key":2}]})"));
    REQUIRE(!valid_wallet_status_json(R"({"key":1} trailing)"));

    std::string invalid_utf8{R"({"key":")"};
    invalid_utf8.push_back(static_cast<char>(0xC0U));
    invalid_utf8.push_back(static_cast<char>(0xAFU));
    invalid_utf8 += R"("})";
    REQUIRE(!valid_wallet_status_json(invalid_utf8));
    std::string raw_unicode_duplicate{R"({")"};
    raw_unicode_duplicate.push_back(static_cast<char>(0xC3U));
    raw_unicode_duplicate.push_back(static_cast<char>(0xA9U));
    raw_unicode_duplicate += R"(":1,"\u00E9":2})";
    REQUIRE(!valid_wallet_status_json(raw_unicode_duplicate));
    for (const auto& truncated : std::vector<std::vector<unsigned char>>{
             {0xC2U},
             {0xE2U, 0x82U},
             {0xF0U, 0x9FU, 0x92U},
         }) {
        std::string frame{R"({"key":")"};
        for (const auto byte : truncated) {
            frame.push_back(static_cast<char>(byte));
        }
        frame += R"("})";
        REQUIRE(!valid_wallet_status_json(frame));
    }
    std::string maximum_frame(max_wallet_status_frame_bytes - 2U, 'a');
    maximum_frame.insert(maximum_frame.begin(), '"');
    maximum_frame.push_back('"');
    REQUIRE(valid_wallet_status_json(maximum_frame));
    maximum_frame.push_back(' ');
    REQUIRE(!valid_wallet_status_json(maximum_frame));
    std::string maximum_depth(64U, '[');
    maximum_depth += '0';
    maximum_depth.append(64U, ']');
    REQUIRE(valid_wallet_status_json(maximum_depth));
    maximum_depth.insert(maximum_depth.begin(), '[');
    maximum_depth.push_back(']');
    REQUIRE(!valid_wallet_status_json(maximum_depth));

    constexpr std::string_view injected_binding =
        R"({"jsonrpc":"2.0","id":"status-2","method":"wallet_status","schema_version":1,"deadline_remaining_ms":1000,"session_id":"attacker","action":"send_transaction"})";
    REQUIRE(!malformed_bridge
                 ->handle_request(
                     injected_binding, std::chrono::steady_clock::now() + std::chrono::seconds{1}
                 )
                 .has_value());

    auto unknown_method = *request;
    const auto method_position = unknown_method.find("wallet_status");
    REQUIRE(method_position != std::string::npos);
    unknown_method.replace(
        method_position, std::string_view{"wallet_status"}.size(), "wallet_submit"
    );
    auto unknown_state = std::make_shared<authority_state>();
    auto unknown_bridge = make_bridge(unknown_state);
    auto denied = unknown_bridge->handle_request(
        unknown_method, std::chrono::steady_clock::now() + std::chrono::seconds{1}
    );
    REQUIRE(denied.has_value());
    REQUIRE(decode_wallet_status_response(*denied)->error_code == "method_not_found");
    {
        const std::scoped_lock lock{unknown_state->mutex};
        REQUIRE(unknown_state->call_order.empty());
    }

    {
        auto throwing_state = std::make_shared<authority_state>();
        wallet_status_bridge throwing{
            std::make_unique<throwing_plan_authority>(),
            std::make_unique<fake_readiness_authority>(throwing_state),
            std::make_unique<fake_adapter_authority>(throwing_state),
            std::make_unique<fake_server_authority>(throwing_state),
            make_clock(),
        };
        REQUIRE(!throwing
                     .handle_request(
                         *request, std::chrono::steady_clock::now() + std::chrono::seconds{1}
                     )
                     .has_value());
    }

    for (std::size_t missing = 0; missing < 5U; ++missing) {
        auto missing_state = std::make_shared<authority_state>();
        auto plan = std::make_unique<fake_plan_authority>(missing_state);
        auto readiness = std::make_unique<fake_readiness_authority>(missing_state);
        auto adapter = std::make_unique<fake_adapter_authority>(missing_state);
        auto server = std::make_unique<fake_server_authority>(missing_state);
        auto clock = make_clock();
        wallet_status_bridge unavailable{
            missing == 0U ? nullptr : std::move(plan),
            missing == 1U ? nullptr : std::move(readiness),
            missing == 2U ? nullptr : std::move(adapter),
            missing == 3U ? nullptr : std::move(server),
            missing == 4U ? nullptr : std::move(clock),
        };
        auto reply = unavailable.handle_request(
            *request, std::chrono::steady_clock::now() + std::chrono::seconds{1}
        );
        REQUIRE(reply.has_value());
        REQUIRE(decode_wallet_status_response(*reply)->error_code == "method_not_found");
    }

    const auto response_code = [&](const std::shared_ptr<authority_state>& test_state) {
        auto test_bridge = make_bridge(test_state);
        auto reply = test_bridge->handle_request(
            *request, std::chrono::steady_clock::now() + std::chrono::seconds{1}
        );
        if (!reply) {
            return std::string{"transport"};
        }
        auto result = decode_wallet_status_response(*reply);
        return result ? result->error_code : std::string{"decode"};
    };

    for (std::size_t source = 0; source < 4U; ++source) {
        auto unavailable = std::make_shared<authority_state>();
        if (source == 0U) {
            unavailable->plan_errors = {authority_error::unavailable};
        } else if (source == 1U) {
            unavailable->readiness_error = authority_error::unavailable;
        } else if (source == 2U) {
            unavailable->adapter_error = authority_error::unavailable;
        } else {
            unavailable->server_error = authority_error::unavailable;
        }
        REQUIRE(response_code(unavailable) == "status_unavailable");

        auto deadline = std::make_shared<authority_state>();
        if (source == 0U) {
            deadline->plan_errors = {authority_error::deadline};
        } else if (source == 1U) {
            deadline->readiness_error = authority_error::deadline;
        } else if (source == 2U) {
            deadline->adapter_error = authority_error::deadline;
        } else {
            deadline->server_error = authority_error::deadline;
        }
        REQUIRE(response_code(deadline) == "transport");
    }

    for (const auto error : {
             authority_error::stale,
             authority_error::revised,
             authority_error::ambiguous,
             authority_error::rollback,
             authority_error::mismatch,
         }) {
        auto rejected = std::make_shared<authority_state>();
        rejected->plan_errors = {error};
        REQUIRE(response_code(rejected) == "status_unavailable");
    }
    auto stale_source = std::make_shared<authority_state>();
    stale_source->server_error = authority_error::stale;
    REQUIRE(response_code(stale_source) == "status_stale");
    auto final_plan_error = std::make_shared<authority_state>();
    final_plan_error->plan_errors = {std::nullopt, authority_error::ambiguous};
    REQUIRE(response_code(final_plan_error) == "status_unavailable");
    auto final_plan_deadline = std::make_shared<authority_state>();
    final_plan_deadline->plan_errors = {std::nullopt, authority_error::deadline};
    REQUIRE(response_code(final_plan_deadline) == "transport");

    auto revised = std::make_shared<authority_state>();
    revised->plans.push_back(plan_snapshot());
    revised->plans.back().binding.generation += 1U;
    REQUIRE(response_code(revised) == "status_unavailable");
    auto changed_policy = std::make_shared<authority_state>();
    changed_policy->plans.push_back(plan_snapshot());
    changed_policy->plans.back().policy.tool_policy_id = "revised-policy";
    REQUIRE(response_code(changed_policy) == "status_unavailable");
    auto zero_generation = std::make_shared<authority_state>();
    zero_generation->plans.front().binding.generation = 0;
    REQUIRE(response_code(zero_generation) == "status_unavailable");
    auto internally_mismatched = std::make_shared<authority_state>();
    internally_mismatched->plans.front().session.policy_revision += 1U;
    REQUIRE(response_code(internally_mismatched) == "status_unavailable");
    auto stopped = std::make_shared<authority_state>();
    stopped->plans.front().session.state = session_state::exited;
    REQUIRE(response_code(stopped) == "status_unavailable");
    auto expired = std::make_shared<authority_state>();
    expired->plans.front().binding.expires_at_ms = 10'000U;
    expired->plans.front().session.expires_at_ms = 10'000U;
    REQUIRE(response_code(expired) == "status_unavailable");

    for (std::size_t source = 0; source < 3U; ++source) {
        auto mismatch = std::make_shared<authority_state>();
        auto binding = plan_binding();
        binding.generation += 1U;
        if (source == 0U) {
            mismatch->readiness_binding = binding;
        } else if (source == 1U) {
            mismatch->adapter_binding = binding;
        } else {
            mismatch->server_binding = binding;
        }
        REQUIRE(response_code(mismatch) == "status_unavailable");
    }
    auto no_audit = std::make_shared<authority_state>();
    no_audit->audit_generation = 0;
    REQUIRE(response_code(no_audit) == "status_unavailable");
    auto no_journal = std::make_shared<authority_state>();
    no_journal->journal_generation = 0;
    REQUIRE(response_code(no_journal) == "status_unavailable");
    auto adapter_mismatch = std::make_shared<authority_state>();
    adapter_mismatch->adapter_command_digest = std::string(64U, 'e');
    REQUIRE(response_code(adapter_mismatch) == "status_unavailable");
    auto server_mismatch = std::make_shared<authority_state>();
    server_mismatch->wallet_server_node_digest = std::string(64U, 'e');
    REQUIRE(response_code(server_mismatch) == "status_unavailable");
    auto alias_mismatch = std::make_shared<authority_state>();
    alias_mismatch->server_observation.wallet_server_alias = "different-host";
    REQUIRE(response_code(alias_mismatch) == "status_unavailable");
    auto chain_mismatch = std::make_shared<authority_state>();
    chain_mismatch->server_observation.allowed_chain_ids = {1U};
    REQUIRE(response_code(chain_mismatch) == "status_unavailable");

    auto stale = std::make_shared<authority_state>();
    stale->server_observation.observed_at_ms = 4'999U;
    REQUIRE(response_code(stale) == "status_stale");
    auto future = std::make_shared<authority_state>();
    future->server_observation.observed_at_ms = 10'002U;
    REQUIRE(response_code(future) == "status_stale");
    auto missing_status = std::make_shared<authority_state>();
    missing_status->server_observation.observed_at_ms = 0;
    REQUIRE(response_code(missing_status) == "status_stale");

    for (std::size_t expired_checkpoint = 2U; expired_checkpoint <= 6U; ++expired_checkpoint) {
        const auto monotonic = std::chrono::steady_clock::now();
        std::vector<wallet_status_time> times;
        times.reserve(7U);
        for (std::size_t index = 0; index < 7U; ++index) {
            const auto elapsed = index >= expired_checkpoint ? std::chrono::milliseconds{1'000}
                                                             : std::chrono::milliseconds{1};
            times.push_back(
                {.unix_time_ms = 10'000U + index, .monotonic_time = monotonic + elapsed}
            );
        }
        times.front().monotonic_time = monotonic;
        auto step_bridge = make_bridge(
            std::make_shared<authority_state>(), std::make_unique<scripted_clock>(std::move(times))
        );
        REQUIRE(
            !step_bridge->handle_request(*request, monotonic + std::chrono::seconds{2}).has_value()
        );
    }

    auto deadline_state = std::make_shared<authority_state>();
    auto deadline_bridge = make_bridge(
        deadline_state,
        make_clock(10'000U, 10'001U, std::chrono::milliseconds{1}, std::chrono::seconds{2})
    );
    REQUIRE(!deadline_bridge
                 ->handle_request(
                     *request, std::chrono::steady_clock::now() + std::chrono::milliseconds{10}
                 )
                 .has_value());
    auto elapsed_bridge = make_bridge(
        std::make_shared<authority_state>(),
        make_clock(10'000U, 10'001U, std::chrono::milliseconds{1'000})
    );
    REQUIRE(
        !elapsed_bridge
             ->handle_request(*request, std::chrono::steady_clock::now() + std::chrono::seconds{2})
             .has_value()
    );
    auto rollback_bridge = make_bridge(
        std::make_shared<authority_state>(),
        make_clock(10'000U, 9'999U, std::chrono::milliseconds{1})
    );
    REQUIRE(
        !rollback_bridge
             ->handle_request(*request, std::chrono::steady_clock::now() + std::chrono::seconds{1})
             .has_value()
    );

    auto concurrent_state = std::make_shared<authority_state>();
    const auto concurrent_now = std::chrono::steady_clock::now();
    auto concurrent_bridge =
        make_bridge(concurrent_state, std::make_unique<fixed_clock>(10'000U, concurrent_now));
    std::array<int, 8> concurrent_results{};
    std::vector<std::thread> threads;
    threads.reserve(concurrent_results.size());
    for (std::size_t index = 0; index < concurrent_results.size(); ++index) {
        threads.emplace_back([&, index] {
            const auto reply = concurrent_bridge->handle_request(
                *request, concurrent_now + std::chrono::seconds{1}
            );
            if (!reply) {
                concurrent_results.at(index) = -1;
                return;
            }
            const auto concurrent_decoded = decode_wallet_status_response(*reply);
            concurrent_results.at(index) =
                concurrent_decoded && concurrent_decoded->error_code.empty() ? 1 : -1;
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    REQUIRE(std::ranges::all_of(concurrent_results, [](int result) { return result == 1; }));

    socket_pair channel;
    REQUIRE(channel.first() >= 0);
    const auto io_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE(write_wallet_status_frame(channel.first(), *request, io_deadline).has_value());
    auto framed_request = read_wallet_status_frame(channel.second(), io_deadline);
    REQUIRE(framed_request == request);
    socket_pair oversized;
    constexpr std::array<unsigned char, 4> oversized_header{0x00U, 0x01U, 0x00U, 0x01U};
    REQUIRE(
        ::write(oversized.first(), oversized_header.data(), oversized_header.size()) ==
        static_cast<ssize_t>(oversized_header.size())
    );
    REQUIRE(!read_wallet_status_frame(oversized.second(), io_deadline).has_value());
    REQUIRE(
        !write_wallet_status_frame(
             oversized.first(), std::string(max_wallet_status_frame_bytes + 1U, 'x'), io_deadline
        )
             .has_value()
    );
    socket_pair closed_peer;
    closed_peer.close_second();
    REQUIRE(!write_wallet_status_frame(closed_peer.first(), *request, io_deadline).has_value());

    REQUIRE(!encode_wallet_status_request("bad id", 1'000U).has_value());
    REQUIRE(!encode_wallet_status_request("status", 0U).has_value());
    REQUIRE(
        !encode_wallet_status_request("status", max_wallet_status_request_ttl_ms + 1U).has_value()
    );
    return 0;
}

} // namespace

int main() {
    return run();
}
