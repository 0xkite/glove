#include "glove/control/receipt_audit_protocol.hpp"

#include "receipt_handlers.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace glove::control {
namespace {

auto valid_hex_secret(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](const char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

} // namespace

receipt_audit_protocol::receipt_audit_protocol(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

receipt_audit_protocol::~receipt_audit_protocol() = default;

auto receipt_audit_protocol::create(
    std::string_view bootstrap_secret_hex,
    std::shared_ptr<container::receipt_audit_producer> producer,
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator,
    std::shared_ptr<session_registry> sessions,
    std::shared_ptr<session_runtime> session_runtime,
    std::shared_ptr<supervisor::path_exposure_registry> path_exposures,
    std::string materialization_root,
    std::shared_ptr<const linux_detail::local_service_proxy_capability> local_services
) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string> {
    if (!valid_hex_secret(bootstrap_secret_hex) || !producer || (sessions && !plan_validator) ||
        (session_runtime &&
         (!sessions || !plan_validator ||
          (session_runtime->lifecycle_operational() && materialization_root.empty())))) {
        return std::unexpected(std::string{"receipt audit protocol configuration is invalid"});
    }
    auto state = std::make_unique<implementation>();
    state->bootstrap_secret = bootstrap_secret_hex;
    state->audit_key_id = producer->anchor().key_id;
    state->producer = std::move(producer);
    state->plan_validator = std::move(plan_validator);
    state->sessions = std::move(sessions);
    state->runtime = std::move(session_runtime);
    state->local_services = std::move(local_services);
    state->path_exposures = std::move(path_exposures);
    state->materialization_root = std::move(materialization_root);
    return std::make_unique<receipt_audit_protocol>(construction_token{}, std::move(state));
}

auto receipt_audit_protocol::create(
    std::string_view bootstrap_secret_hex,
    container::receipt_audit_producer_config producer_config,
    std::shared_ptr<const supervisor::session_plan_validator> plan_validator,
    std::shared_ptr<session_registry> sessions,
    std::shared_ptr<session_runtime> session_runtime,
    std::shared_ptr<supervisor::path_exposure_registry> path_exposures,
    std::string materialization_root,
    std::shared_ptr<const linux_detail::local_service_proxy_capability> local_services
) -> std::expected<std::unique_ptr<receipt_audit_protocol>, std::string> {
    if (!valid_hex_secret(bootstrap_secret_hex) || producer_config.key_path.empty() ||
        producer_config.journal_path.empty() || (sessions && !plan_validator) ||
        (session_runtime &&
         (!sessions || !plan_validator ||
          (session_runtime->lifecycle_operational() && materialization_root.empty())))) {
        return std::unexpected(std::string{"receipt audit protocol configuration is invalid"});
    }
    auto audit_key_id = container::receipt_audit_producer::audit_key_id(producer_config);
    if (!audit_key_id) {
        return std::unexpected(std::string{"receipt audit protocol key is unavailable"});
    }
    auto state = std::make_unique<implementation>();
    state->bootstrap_secret = bootstrap_secret_hex;
    state->audit_key_id = std::move(*audit_key_id);
    state->producer_config = std::move(producer_config);
    state->plan_validator = std::move(plan_validator);
    state->sessions = std::move(sessions);
    state->runtime = std::move(session_runtime);
    state->local_services = std::move(local_services);
    state->path_exposures = std::move(path_exposures);
    state->materialization_root = std::move(materialization_root);
    return std::make_unique<receipt_audit_protocol>(construction_token{}, std::move(state));
}

auto receipt_audit_protocol::handle_frame(std::string_view frame, std::uint64_t now_ms)
    -> std::expected<std::string, std::string> {
    return handle_frame(frame, now_ms, nullptr);
}

auto receipt_audit_protocol::handle_frame(
    std::string_view frame, std::uint64_t now_ms, receipt_control_outcome* outcome
) -> std::expected<std::string, std::string> {
    return receipt_handlers::handle_frame(*state_, frame, now_ms, outcome);
}

} // namespace glove::control
