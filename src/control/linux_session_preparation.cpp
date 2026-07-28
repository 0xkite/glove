#include "linux_session_preparation.hpp"

#include "glove/supervisor/linux_session_filesystem.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "linux_session_recovery.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <string_view>
#include <utility>

namespace glove::control::linux_detail {

namespace {

auto valid_identifier(std::string_view value) -> bool {
    if (value.empty() || value.size() > 128) {
        return false;
    }
    return std::ranges::all_of(value, [](char value_character) {
        const auto character = static_cast<unsigned char>(value_character);
        return std::isalnum(character) != 0 || value_character == '-' || value_character == '_' ||
               value_character == ':' || value_character == '.';
    });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64 && std::ranges::all_of(value, [](char value_character) {
               return (value_character >= '0' && value_character <= '9') ||
                      (value_character >= 'a' && value_character <= 'f');
           });
}

auto convert_limits(const supervisor::resource_limits& limits) -> container::resource_limits {
    return {
        .cpu_time_ms = limits.cpu_time_ms,
        .memory_bytes = limits.memory_bytes,
        .pids = limits.pids,
        .wall_time_ms = limits.wall_time_ms,
        .disk_bytes = limits.disk_bytes,
        .terminal_output_bytes = limits.terminal_output_bytes,
    };
}

auto current_epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto validate_inputs(const session_start_inputs& inputs, std::uint64_t started_at_ms)
    -> std::expected<void, std::string> {
    if (started_at_ms == 0) {
        return std::unexpected(std::string{"Linux preparation requires a current start time"});
    }
    if (inputs.session.state != session_state::preparing) {
        return std::unexpected(std::string{"session is not durably reserved for preparation"});
    }
    if (inputs.session.schema_version != 1 || inputs.launch.validation.schema_version != 1) {
        return std::unexpected(std::string{"Linux preparation schema is unsupported"});
    }
    if (!valid_identifier(inputs.session.session_id) ||
        !valid_identifier(inputs.authorization_id)) {
        return std::unexpected(std::string{"Linux preparation has an invalid bounded identifier"});
    }
    if (!valid_digest(inputs.session.controller_plan_digest) ||
        !valid_digest(inputs.session.plan_content_digest)) {
        return std::unexpected(std::string{"Linux preparation has an invalid plan digest"});
    }
    if (!valid_identifier(inputs.launch.runtime_id) ||
        !valid_identifier(inputs.launch.runtime_template_id) ||
        !valid_digest(inputs.launch.adapter_command_digest)) {
        return std::unexpected(
            std::string{"Linux preparation has an invalid runtime projection identity"}
        );
    }
    if (inputs.launch.backend != supervisor::sandbox_backend::linux_production) {
        return std::unexpected(std::string{"Linux preparation requires the production backend"});
    }
    if (inputs.launch.requires_direct_write_approval) {
        return std::unexpected(
            std::string{"direct-write preparation requires an independent local-consent verifier"}
        );
    }
    if (inputs.session.policy_revision == 0 ||
        inputs.launch.validation.policy_revision != inputs.session.policy_revision) {
        return std::unexpected(std::string{"Linux preparation policy revision mismatch"});
    }
    if (inputs.launch.expires_at_ms != inputs.session.expires_at_ms) {
        return std::unexpected(std::string{"Linux preparation plan expiry mismatch"});
    }
    if (inputs.authorization_expires_at_ms <= started_at_ms ||
        inputs.session.expires_at_ms <= started_at_ms ||
        inputs.launch.expires_at_ms <= started_at_ms ||
        inputs.authorization_expires_at_ms > inputs.session.expires_at_ms ||
        inputs.authorization_expires_at_ms > inputs.launch.expires_at_ms) {
        return std::unexpected(
            std::string{"Linux preparation authorization is expired or unbounded"}
        );
    }
    if (inputs.launch.argv.empty() || inputs.launch.argv.front().empty()) {
        return std::unexpected(std::string{"Linux preparation requires an explicit executable"});
    }
    if (std::ranges::any_of(inputs.launch.argv, [](const auto& value) { return value.empty(); })) {
        return std::unexpected(std::string{"Linux preparation argv contains an empty value"});
    }
    const auto capabilities = container::linux_detail::managed_session_capabilities();
    if (!capabilities.complete()) {
        return std::unexpected(
            std::string{"Linux managed-session resource capabilities are incomplete"}
        );
    }
    return {};
}

} // namespace

linux_session_preparer::linux_session_preparer(
    std::string materialization_root, container::linux_detail::cgroup_v2_root cgroup_root
) noexcept
    : materialization_root_{std::move(materialization_root)},
      cgroup_root_{std::move(cgroup_root)} {}

auto linux_session_preparer::create(std::string materialization_root)
    -> std::expected<linux_session_preparer, std::string> {
    if (materialization_root.empty()) {
        return std::unexpected(std::string{"Linux preparation materialization root is required"});
    }
    auto cgroup_root = container::linux_detail::cgroup_v2_root::prepare_for_current_process();
    if (!cgroup_root) {
        return std::unexpected(cgroup_root.error());
    }
    return linux_session_preparer{std::move(materialization_root), std::move(*cgroup_root)};
}

auto linux_session_preparer::prepare(session_start_inputs&& inputs, std::uint64_t started_at_ms)
    -> std::expected<linux_prepared_session, std::string> {
    auto owned_inputs = std::move(inputs);
    if (auto valid = validate_inputs(owned_inputs, started_at_ms); !valid) {
        return std::unexpected(valid.error());
    }

    const auto limits = convert_limits(owned_inputs.launch.limits);
    container::profile requested_profile;
    requested_profile.runtime_filesystem.reserve(owned_inputs.launch.read_only_paths.size());
    for (const auto& path : owned_inputs.launch.read_only_paths) {
        requested_profile.runtime_filesystem.push_back({.path = path, .writable = false});
    }
    requested_profile.environment = owned_inputs.launch.environment;
    if (const auto adapter = supervisor::native_skill_runtime_adapter_for(
            owned_inputs.launch.runtime_id
        )) {
        const bool overrides_managed_environment = std::ranges::any_of(
            adapter->managed_environment, [&](const auto& managed) {
                const auto separator = managed.find('=');
                const std::string_view name{managed.data(), separator};
                return std::ranges::any_of(requested_profile.environment, [&](const auto& entry) {
                    return entry.starts_with(std::string{name} + "=");
                });
            }
        );
        if (overrides_managed_environment) {
            return std::unexpected(
                std::string{"native skill runtime state is managed by Glove, not launch policy"}
            );
        }
        requested_profile.managed_home_dir = "/home/agent";
        requested_profile.environment.insert(
            requested_profile.environment.end(),
            adapter->managed_environment.begin(),
            adapter->managed_environment.end()
        );
    }
    requested_profile.required_limits = limits;
    auto profile = container::validate(requested_profile);
    if (!profile) {
        return std::unexpected(std::string{"Linux preparation profile: "} + profile.error());
    }
    if (auto supported = container::require_resource_enforcement(
            *profile, container::linux_detail::managed_session_capabilities()
        );
        !supported) {
        return std::unexpected(supported.error());
    }

    auto filesystem = supervisor::linux_detail::linux_session_filesystem::create(
        materialization_root_,
        owned_inputs.session.session_id,
        limits.disk_bytes,
        std::move(owned_inputs.path_grants),
        std::move(owned_inputs.library_projections),
        owned_inputs.launch.runtime_id
    );
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    linux_filesystem_recovery_identity filesystem_identity{
        .schema_version = 1,
        .disk_limit_bytes = filesystem->disk_limit_bytes(),
        .partitions = {},
    };
    for (auto& partition : filesystem->recovery_partitions()) {
        filesystem_identity.partitions.push_back({
            .alias = std::move(partition.alias),
            .quota_bytes = partition.quota_bytes,
        });
    }
    auto cgroup = cgroup_root_.create_session(owned_inputs.session.session_id, limits);
    if (!cgroup) {
        return std::unexpected(cgroup.error());
    }

    struct stat cgroup_status{};

    if (::fstat(cgroup->directory_fd(), &cgroup_status) < 0 || !S_ISDIR(cgroup_status.st_mode) ||
        cgroup_status.st_dev == 0 || cgroup_status.st_ino == 0) {
        return std::unexpected(std::string{"inspect prepared Linux cgroup identity"});
    }
    const linux_cgroup_recovery_identity cgroup_identity{
        .schema_version = 1,
        .device = static_cast<std::uint64_t>(cgroup_status.st_dev),
        .inode = static_cast<std::uint64_t>(cgroup_status.st_ino),
    };
    auto lifecycle = container::linux_detail::linux_resource_lifecycle::create(
        std::move(*cgroup), std::move(*filesystem), limits, started_at_ms
    );
    if (!lifecycle) {
        return std::unexpected(lifecycle.error());
    }
    auto binding = container::linux_detail::bind_managed_session(
        *profile, owned_inputs.launch.argv, **lifecycle, owned_inputs.session.controller_plan_digest
    );
    if (!binding) {
        return std::unexpected(binding.error());
    }
    if (current_epoch_ms() >= owned_inputs.authorization_expires_at_ms) {
        return std::unexpected(
            std::string{"Linux preparation authorization expired while allocating resources"}
        );
    }

    return linux_prepared_session{
        .session_id = std::move(owned_inputs.session.session_id),
        .controller_plan_digest = std::move(owned_inputs.session.controller_plan_digest),
        .plan_content_digest = std::move(owned_inputs.session.plan_content_digest),
        .authorization_id = std::move(owned_inputs.authorization_id),
        .authorization_expires_at_ms = owned_inputs.authorization_expires_at_ms,
        .profile = std::move(*profile),
        .argv = std::move(owned_inputs.launch.argv),
        .binding = std::move(*binding),
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = std::move(filesystem_identity),
        .lifecycle = std::move(*lifecycle),
    };
}

auto linux_session_preparer::reconcile(
    session_registry& registry,
    container::receipt_audit_producer& receipt_producer,
    std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string> {
    return reconcile_linux_session_registry(
        registry, receipt_producer, cgroup_root_, materialization_root_, now_ms
    );
}

} // namespace glove::control::linux_detail
