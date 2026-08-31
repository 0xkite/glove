#include "remote_session_runtime.hpp"

#include "glove/container/image_identity.hpp"
#include "glove/control/remote_protocol.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace glove::control {
namespace {

constexpr std::string_view unavailable = "remote lifecycle is constructed but not operational";

[[nodiscard]] auto valid_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto valid_absolute_path(const std::filesystem::path& path) -> bool {
    return path.is_absolute() && path != path.root_path() && path.lexically_normal() == path;
}

[[nodiscard]] auto valid_ssh_argv(const std::vector<std::string>& argv) -> bool {
    if (argv.size() != 4U || argv[0] != "/usr/bin/ssh" || argv[1] != "-F" ||
        argv[3] != "glove-remote") {
        return false;
    }
    return valid_absolute_path(std::filesystem::path{argv[2]});
}

template<typename Value>
[[nodiscard]] auto unavailable_result() -> std::expected<Value, std::string> {
    return std::unexpected(std::string{unavailable});
}

} // namespace

remote_session_runtime::remote_session_runtime(
    construction_token /*token*/, remote_session_runtime_config configured
)
    : configured_{std::move(configured)} {}

auto remote_session_runtime::create(remote_session_runtime_config configured)
    -> std::expected<std::shared_ptr<remote_session_runtime>, std::string> {
    if (!valid_ssh_argv(configured.ssh_argv) || !valid_digest(configured.executor_digest) ||
        !container::valid_immutable_container_image(
            configured.container_image, configured.container_image_digest
        ) ||
        configured.channel_timeout_ms < 100U ||
        configured.channel_timeout_ms > max_remote_deadline_ms ||
        configured.max_clock_skew_ms > 5'000U || configured.max_sessions == 0U ||
        configured.max_sessions > 64U || !valid_absolute_path(configured.staging_root)) {
        return std::unexpected(std::string{"invalid remote session runtime configuration"});
    }
    return std::shared_ptr<remote_session_runtime>{
        new remote_session_runtime{construction_token{}, std::move(configured)}
    };
}

auto remote_session_runtime::backend_id() const noexcept -> std::string_view {
    return "remote_linux_container";
}

auto remote_session_runtime::agent_runtime_adapter_schema_version() const noexcept -> std::uint8_t {
    return 0;
}

auto remote_session_runtime::managed_runtime_ids() const -> std::vector<std::string> {
    return {};
}

auto remote_session_runtime::resource_capabilities() const noexcept
    -> container::resource_enforcement_capabilities {
    return {};
}

auto remote_session_runtime::start(
    container::receipt_audit_producer& /*receipt_producer*/,
    const session_start_authorization& /*authorization*/,
    std::string_view /*idempotency_namespace*/,
    std::uint64_t /*now_ms*/
) -> std::expected<session_start_result, std::string> {
    return unavailable_result<session_start_result>();
}

auto remote_session_runtime::reconcile(
    container::receipt_audit_producer& /*receipt_producer*/, std::uint64_t /*now_ms*/
) -> std::expected<session_reconciliation_report, std::string> {
    return unavailable_result<session_reconciliation_report>();
}

auto remote_session_runtime::list() const -> std::expected<std::vector<std::string>, std::string> {
    return unavailable_result<std::vector<std::string>>();
}

auto remote_session_runtime::read(
    std::string_view /*session_id*/, std::uint64_t /*cursor*/, std::size_t /*max_bytes*/
) const -> std::expected<session_transcript_read, std::string> {
    return unavailable_result<session_transcript_read>();
}

auto remote_session_runtime::wait_read(
    std::string_view /*session_id*/,
    std::uint64_t /*cursor*/,
    std::size_t /*max_bytes*/,
    std::uint64_t /*timeout_ms*/
) -> std::expected<session_transcript_read, std::string> {
    return unavailable_result<session_transcript_read>();
}

auto remote_session_runtime::write_input(
    std::string_view /*session_id*/, std::string_view /*bytes*/
) -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

auto remote_session_runtime::resize(
    std::string_view /*session_id*/, std::uint16_t /*rows*/, std::uint16_t /*columns*/
) -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

auto remote_session_runtime::signal(
    std::string_view /*session_id*/, session_signal /*requested*/
) -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

auto remote_session_runtime::stop(std::string_view /*session_id*/)
    -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

auto remote_session_runtime::stop(
    std::string_view /*session_id*/, std::string_view /*idempotency_key*/
) -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

auto remote_session_runtime::wait(std::string_view /*session_id*/)
    -> std::expected<session_terminal_record, std::string> {
    return unavailable_result<session_terminal_record>();
}

auto remote_session_runtime::cleanup(std::string_view /*session_id*/)
    -> std::expected<void, std::string> {
    return unavailable_result<void>();
}

} // namespace glove::control
