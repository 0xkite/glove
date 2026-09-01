#include "linux_session_preparation.hpp"

#include "glove/supervisor/linux_session_filesystem.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "../container/sha256.hpp"
#include "linux_session_recovery.hpp"

#include <fcntl.h>
#include <linux/mount.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <new>
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
    if (inputs.session.schema_version != 1 || (inputs.launch.validation.schema_version != 1 &&
                                               inputs.launch.validation.schema_version != 2)) {
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
    if (inputs.launch.adoption.has_value() != inputs.adoption.has_value() ||
        (inputs.launch.adoption && inputs.adoption->identity() != *inputs.launch.adoption)) {
        return std::unexpected(
            std::string{"Linux preparation adoption binding differs from launch projection"}
        );
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

void close_mounts(std::vector<supervisor::linux_detail::session_mount>& mounts) noexcept {
    for (auto& mount : mounts) {
        if (mount.descriptor_fd >= 0) {
            ::close(mount.descriptor_fd);
            mount.descriptor_fd = -1;
        }
    }
}

void close_descriptors(std::vector<int>& descriptors) noexcept {
    for (int& descriptor : descriptors) {
        if (descriptor >= 0) {
            ::close(descriptor);
            descriptor = -1;
        }
    }
}

struct resolved_secret_mounts {
    std::vector<supervisor::linux_detail::session_mount> mounts;
    std::vector<int> lease_locks;
};

auto write_all_at(int destination, int source, std::uint64_t size)
    -> std::expected<void, std::string> {
    std::array<unsigned char, 16U * 1024U> buffer{};
    std::uint64_t offset = 0;
    while (offset < size) {
        const auto requested =
            static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - offset));
        const auto read = ::pread(source, buffer.data(), requested, static_cast<off_t>(offset));
        if (read <= 0) {
            return std::unexpected(std::string{"read credential source: "} + std::strerror(errno));
        }
        std::size_t written = 0;
        while (written < static_cast<std::size_t>(read)) {
            const auto result = ::pwrite(
                destination,
                buffer.data() + written,
                static_cast<std::size_t>(read) - written,
                static_cast<off_t>(offset + written)
            );
            if (result <= 0) {
                return std::unexpected(
                    std::string{"write managed credential lease: "} + std::strerror(errno)
                );
            }
            written += static_cast<std::size_t>(result);
        }
        offset += static_cast<std::uint64_t>(read);
    }
    if (::ftruncate(destination, static_cast<off_t>(size)) != 0 || ::fsync(destination) != 0) {
        return std::unexpected(
            std::string{"commit managed credential lease: "} + std::strerror(errno)
        );
    }
    return {};
}

auto resolve_secret_mounts(
    const std::vector<supervisor::secret_mount_policy>& policies,
    const std::string& materialization_root
) -> std::expected<resolved_secret_mounts, std::string> {
    constexpr std::uint64_t max_secret_file_bytes = std::uint64_t{1024} * 1024U;
    resolved_secret_mounts resolved;
    resolved.mounts.reserve(policies.size());
    resolved.lease_locks.reserve(policies.size());
    if (policies.empty()) {
        return resolved;
    }
    const auto lease_root = std::filesystem::path{materialization_root} / ".credential-leases";
    std::error_code filesystem_error;
    const bool lease_root_created = std::filesystem::create_directory(lease_root, filesystem_error);
    if (!lease_root_created && filesystem_error && filesystem_error != std::errc::file_exists) {
        return std::unexpected(
            std::string{"create managed credential lease root: "} + filesystem_error.message()
        );
    }
    if (lease_root_created && ::chmod(lease_root.c_str(), 0700) != 0) {
        return std::unexpected(
            std::string{"protect managed credential lease root: "} + std::strerror(errno)
        );
    }
    const int lease_root_fd = ::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        lease_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    struct stat lease_root_status{};
    if (lease_root_fd < 0 || ::fstat(lease_root_fd, &lease_root_status) != 0 ||
        !S_ISDIR(lease_root_status.st_mode) || lease_root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(lease_root_status.st_mode) & 0777U) != 0700U) {
        if (lease_root_fd >= 0) {
            ::close(lease_root_fd);
        }
        return std::unexpected(
            std::string{"managed credential lease root is not an owner-only directory"}
        );
    }
    for (const auto& policy : policies) {
        const int source = ::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
            policy.source_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        );
        if (source < 0) {
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(std::string{"open local secret handle "} + policy.handle);
        }
        struct stat before{};
        const bool safe = ::fstat(source, &before) == 0 && S_ISREG(before.st_mode) &&
                          before.st_uid == ::geteuid() && before.st_nlink == 1 &&
                          (static_cast<unsigned int>(before.st_mode) & 0777U) == 0600U &&
                          before.st_size > 0 &&
                          static_cast<std::uint64_t>(before.st_size) <= max_secret_file_bytes;
        if (!safe) {
            ::close(source);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(
                std::string{"local secret handle is not an owner-only bounded regular file: "} +
                policy.handle
            );
        }
        auto source_digest = container::detail::sha256_fd_hex(source, max_secret_file_bytes);
        struct stat source_after_hash{};
        const bool source_stable = source_digest && ::fstat(source, &source_after_hash) == 0 &&
                                   before.st_dev == source_after_hash.st_dev &&
                                   before.st_ino == source_after_hash.st_ino &&
                                   before.st_mode == source_after_hash.st_mode &&
                                   before.st_size == source_after_hash.st_size &&
                                   before.st_mtim.tv_sec == source_after_hash.st_mtim.tv_sec &&
                                   before.st_mtim.tv_nsec == source_after_hash.st_mtim.tv_nsec;
        if (!source_stable) {
            ::close(source);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(
                std::string{"credential source changed while importing handle: "} + policy.handle
            );
        }
        const std::string lease_identity =
            policy.runtime_id + ":" + policy.handle + ":" + *source_digest;
        const auto* lease_identity_bytes =
            reinterpret_cast<const unsigned char*>(lease_identity.data());
        auto lease_digest =
            container::detail::sha256_hex(std::span{lease_identity_bytes, lease_identity.size()});
        if (!lease_digest) {
            ::close(source);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(std::string{"derive managed credential lease identity"});
        }
        const std::string lease_name = "lease-" + *lease_digest;
        const int lease = ::openat( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
            lease_root_fd,
            lease_name.c_str(),
            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
            0600
        );
        if (lease < 0 || ::flock(lease, LOCK_EX | LOCK_NB) != 0) {
            const int saved = errno;
            if (lease >= 0) {
                ::close(lease);
            }
            ::close(source);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(
                saved == EWOULDBLOCK
                    ? std::string{"managed credential lease is already in use: "} + policy.handle
                    : std::string{"open managed credential lease: "} + std::strerror(saved)
            );
        }
        struct stat lease_status{};
        const bool safe_lease =
            ::fstat(lease, &lease_status) == 0 && S_ISREG(lease_status.st_mode) &&
            lease_status.st_uid == ::geteuid() && lease_status.st_nlink == 1 &&
            (static_cast<unsigned int>(lease_status.st_mode) & 0777U) == 0600U &&
            lease_status.st_size >= 0 &&
            static_cast<std::uint64_t>(lease_status.st_size) <= max_secret_file_bytes;
        if (!safe_lease) {
            ::close(lease);
            ::close(source);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(
                std::string{
                    "managed credential lease is not an owner-only bounded regular file: "
                } +
                policy.handle
            );
        }
        if (lease_status.st_size == 0) {
            if (auto copied =
                    write_all_at(lease, source, static_cast<std::uint64_t>(before.st_size));
                !copied) {
                ::close(lease);
                ::close(source);
                ::close(lease_root_fd);
                close_mounts(resolved.mounts);
                close_descriptors(resolved.lease_locks);
                return std::unexpected(copied.error());
            }
            if (::fstat(lease, &lease_status) != 0) {
                ::close(lease);
                ::close(source);
                ::close(lease_root_fd);
                close_mounts(resolved.mounts);
                close_descriptors(resolved.lease_locks);
                return std::unexpected(std::string{"inspect initialized credential lease"});
            }
        }
        const int descriptor = static_cast<int>(
            // Linux has no typed libc wrapper for open_tree(2).
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
            ::syscall(SYS_open_tree, lease, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
        );
        ::close(source);
        if (descriptor < 0) {
            if (descriptor >= 0) {
                ::close(descriptor);
            }
            ::close(lease);
            ::close(lease_root_fd);
            close_mounts(resolved.mounts);
            close_descriptors(resolved.lease_locks);
            return std::unexpected(
                std::string{"identity-pin managed credential lease failed: "} + policy.handle
            );
        }
        resolved.mounts.push_back({
            .descriptor_fd = descriptor,
            .target_path = policy.target_path,
            .alias = "secret:" + policy.handle,
            .quota_partition = "",
            .quota_bytes = 0,
            .source_identity =
                supervisor::path_identity{
                    .device = static_cast<std::uint64_t>(lease_status.st_dev),
                    .inode = static_cast<std::uint64_t>(lease_status.st_ino),
                    .mode = static_cast<std::uint32_t>(lease_status.st_mode),
                },
            .source_content_digest = std::nullopt,
            .projection_id = std::nullopt,
            .projection_destination_alias = std::nullopt,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .runtime_adoption_manifest_digest = std::nullopt,
            .runtime_adoption_snapshot_digest = std::nullopt,
            .secret_handle = policy.handle,
            .secret_runtime_id = policy.runtime_id,
            .service_proxy_manifest_digest = std::nullopt,
            .writable = true,
            .directory = false,
        });
        resolved.lease_locks.push_back(lease);
    }
    ::close(lease_root_fd);
    return resolved;
}

} // namespace

linux_session_preparer::linux_session_preparer(
    std::string materialization_root,
    container::linux_detail::cgroup_v2_root cgroup_root,
    std::shared_ptr<audit::sink> egress_audit,
    std::shared_ptr<local_service_proxy_factory> local_services
) noexcept
    : materialization_root_{std::move(materialization_root)},
      cgroup_root_{std::move(cgroup_root)},
      egress_audit_{std::move(egress_audit)},
      local_services_{std::move(local_services)} {}

auto linux_session_preparer::create(
    std::string materialization_root,
    std::shared_ptr<audit::sink> egress_audit,
    std::shared_ptr<local_service_proxy_factory> local_services
) -> std::expected<linux_session_preparer, std::string> {
    if (materialization_root.empty()) {
        return std::unexpected(std::string{"Linux preparation materialization root is required"});
    }
    auto cgroup_root = container::linux_detail::cgroup_v2_root::prepare_for_current_process();
    if (!cgroup_root) {
        return std::unexpected(cgroup_root.error());
    }
    return linux_session_preparer{
        std::move(materialization_root),
        std::move(*cgroup_root),
        std::move(egress_audit),
        std::move(local_services)
    };
}

auto linux_session_preparer::prepare(session_start_inputs&& inputs, std::uint64_t started_at_ms)
    -> std::expected<linux_prepared_session, std::string> {
    auto owned_inputs = std::move(inputs);
    if (auto valid = validate_inputs(owned_inputs, started_at_ms); !valid) {
        return std::unexpected(valid.error());
    }
    if (local_services_) {
        if (auto safe = local_services_->validate_path_grants(owned_inputs.path_grants); !safe) {
            return std::unexpected(safe.error());
        }
    }
    const bool local_services_enabled =
        local_services_ && local_services_->manages_runtime(owned_inputs.launch.runtime_id);
    std::unique_ptr<local_service_proxy_session> local_service_proxy;
    if (local_services_enabled) {
        auto service_session = local_services_->prepare_session(
            owned_inputs.session.session_id, owned_inputs.launch.runtime_id
        );
        if (!service_session) {
            return std::unexpected(service_session.error());
        }
        local_service_proxy = std::move(*service_session);
    }

    const auto limits = convert_limits(owned_inputs.launch.limits);
    container::profile requested_profile;
    requested_profile.runtime_filesystem.reserve(owned_inputs.launch.read_only_paths.size());
    for (const auto& path : owned_inputs.launch.read_only_paths) {
        requested_profile.runtime_filesystem.push_back({.path = path, .writable = false});
    }
    requested_profile.environment = owned_inputs.launch.environment;
    if (local_services_) {
        const bool inherited = local_service_proxy && local_service_proxy->inherited();
        const bool spoofed =
            std::ranges::any_of(requested_profile.environment, [&](const auto& entry) {
                const bool generated = entry.starts_with("GLOVE_LOCAL_SERVICE_") ||
                                       entry.starts_with("GLOVE_GUEST_CHANNEL_SERVICE_ALIAS=");
                const bool mixed_legacy =
                    inherited && (entry.starts_with("GLOVE_GUEST_CHANNEL_ENDPOINT=") ||
                                  entry.starts_with("GLOVE_GUEST_CHANNEL_ROOT=") ||
                                  entry.starts_with("GLOVE_GUEST_CHANNEL_OWNER_UID="));
                return generated || mixed_legacy;
            });
        if (spoofed) {
            return std::unexpected(std::string{"local service environment is managed by Glove"});
        }
    }
    if (local_services_enabled) {
        if (local_service_proxy->inherited()) {
            auto environment = local_service_proxy->inherited_environment();
            if (!environment) {
                return std::unexpected(environment.error());
            }
            requested_profile.environment.push_back(std::move(*environment));
            if (auto adapter_environment = local_service_proxy->adapter_environment()) {
                requested_profile.environment.push_back(std::move(*adapter_environment));
            }
        } else {
            requested_profile.environment.emplace_back(local_service_environment);
        }
    }
    const auto adapter =
        supervisor::native_skill_runtime_adapter_for(owned_inputs.launch.runtime_id);
    if (adapter) {
        const bool overrides_managed_environment =
            std::ranges::any_of(adapter->managed_environment, [&](const auto& managed) {
                const auto separator = managed.find('=');
                const std::string_view name{managed.data(), separator};
                return std::ranges::any_of(requested_profile.environment, [&](const auto& entry) {
                    return entry.starts_with(std::string{name} + "=");
                });
            });
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
    std::unique_ptr<net::egress_proxy> egress_proxy;
    if (!owned_inputs.launch.egress_targets.empty()) {
        if (!egress_audit_) {
            return std::unexpected(
                std::string{"online Linux session requires a durable egress audit sink"}
            );
        }
        net::egress_options options;
        options.allow.reserve(owned_inputs.launch.egress_targets.size());
        for (const auto& target : owned_inputs.launch.egress_targets) {
            options.allow.push_back({
                .host = target.host,
                .port = target.port,
                .allow_private = target.allow_private,
            });
        }
        options.on_event = [sink = egress_audit_,
                            session_id = owned_inputs.session.session_id,
                            policy_id = owned_inputs.launch.egress_policy_id](
                               const net::egress_event& event
                           ) -> std::expected<void, std::string> {
            audit::event record{
                .what = audit::action::egress,
                .tool_name = session_id + ":" + policy_id + ":" + event.host + ":" +
                             std::to_string(event.port),
                .arguments_json = {},
                .status = event.allowed ? mcp::tool_call_status::ok
                                        : mcp::tool_call_status::invalid_arguments,
                .error_message = event.detail,
            };
            return sink->record(record);
        };
        auto started = net::start_egress_proxy(std::move(options));
        if (!started) {
            return std::unexpected(std::string{"start audited egress broker: "} + started.error());
        }
        requested_profile.proxy = container::proxy_settings{
            .port = (*started)->port(),
            .url = (*started)->proxy_url(),
        };
        egress_proxy = std::move(*started);
    }
    requested_profile.required_limits = limits;
    auto profile = container::validate(requested_profile);
    if (!profile) {
        return std::unexpected(std::string{"Linux preparation profile: "} + profile.error());
    }
    if (std::ranges::any_of(owned_inputs.path_grants, [](const auto& grant) {
            const std::filesystem::path target{grant.target_path()};
            const std::filesystem::path workspace{"/workspace"};
            return std::mismatch(workspace.begin(), workspace.end(), target.begin(), target.end())
                       .first == workspace.end();
        })) {
        profile->work_dir = "/workspace";
    } else if (adapter) {
        // A no-path harness session starts inside its own Glove-materialized
        // private home. This avoids treating the synthesized root filesystem
        // as a project while keeping explicit /workspace grants operator-
        // visible and subject to the harness's normal trust decision.
        profile->work_dir = "/home/agent";
    }
    if (auto supported = container::require_resource_enforcement(
            *profile, container::linux_detail::managed_session_capabilities()
        );
        !supported) {
        return std::unexpected(supported.error());
    }

    std::shared_ptr<container::refinement_transcript_evaluator> refinement_evaluator;
    if (owned_inputs.launch.refinement) {
        const auto fixture =
            std::ranges::find_if(owned_inputs.library_projections, [&](const auto& projection) {
                return projection.projection_id ==
                           owned_inputs.launch.refinement->fixture.projection_id &&
                       projection.destination_alias ==
                           owned_inputs.launch.refinement->fixture.destination_alias &&
                       projection.bundle.content_digest() ==
                           owned_inputs.launch.refinement->fixture.content_digest;
            });
        if (fixture == owned_inputs.library_projections.end()) {
            return std::unexpected(std::string{"refinement fixture projection is unavailable"});
        }
        auto fixture_bytes = fixture->bundle.read_bytes(container::max_refinement_fixture_bytes);
        if (!fixture_bytes) {
            return std::unexpected(
                std::string{"read refinement fixture projection: "} + fixture_bytes.error()
            );
        }
        auto evaluator = container::refinement_transcript_evaluator::create(
            *fixture_bytes, owned_inputs.session.session_id, *owned_inputs.launch.refinement
        );
        if (!evaluator) {
            return std::unexpected(
                std::string{"construct declarative refinement evaluator: "} + evaluator.error()
            );
        }
        refinement_evaluator = std::move(*evaluator);
        std::vector<supervisor::resolved_library_projection> selected_projections;
        selected_projections.reserve(1);
        for (auto& projection : owned_inputs.library_projections) {
            if (projection.projection_id != owned_inputs.launch.refinement->fixture.projection_id) {
                selected_projections.push_back(std::move(projection));
            }
        }
        if (selected_projections.size() != 1U) {
            return std::unexpected(
                std::string{"refinement selected skill projection is ambiguous"}
            );
        }
        owned_inputs.library_projections = std::move(selected_projections);
    } else if (
        owned_inputs.launch.runtime_template_id == container::refinement_runtime_template_id
    ) {
        return std::unexpected(std::string{"refinement runtime is missing its evaluator binding"});
    }

    auto filesystem = supervisor::linux_detail::linux_session_filesystem::create(
        materialization_root_,
        owned_inputs.session.session_id,
        limits.disk_bytes,
        std::move(owned_inputs.path_grants),
        std::move(owned_inputs.library_projections),
        owned_inputs.launch.runtime_id,
        std::move(owned_inputs.adoption)
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
    auto secret_mounts =
        resolve_secret_mounts(owned_inputs.launch.secret_mounts, materialization_root_);
    if (!secret_mounts) {
        return std::unexpected(secret_mounts.error());
    }
    if (auto installed =
            (*lifecycle)
                ->install_secret_mounts(
                    std::move(secret_mounts->mounts), std::move(secret_mounts->lease_locks)
                );
        !installed) {
        return std::unexpected(installed.error());
    }
    if (local_services_enabled && local_service_proxy->inherited()) {
        auto streams = local_service_proxy->release_inherited_streams();
        if (!streams) {
            return std::unexpected(streams.error());
        }
        std::vector<container::linux_detail::inherited_stream_descriptor> descriptors;
        try {
            descriptors.reserve(streams->size());
            for (const auto& stream : *streams) {
                descriptors.push_back({
                    .alias = stream.alias,
                    .descriptor_fd = stream.descriptor_fd,
                    .child_fd = stream.child_fd,
                    .device = stream.device,
                    .inode = stream.inode,
                    .uid = stream.uid,
                    .mode = stream.mode,
                    .links = stream.links,
                    .peer_device = stream.peer_device,
                    .peer_inode = stream.peer_inode,
                    .peer_uid = stream.peer_uid,
                    .peer_mode = stream.peer_mode,
                    .peer_links = stream.peer_links,
                    .manifest_digest = stream.manifest_digest,
                });
            }
        } catch (const std::bad_alloc&) {
            for (auto& stream : *streams) {
                if (stream.descriptor_fd >= 0) {
                    ::close(stream.descriptor_fd);
                    stream.descriptor_fd = -1;
                }
            }
            return std::unexpected(std::string{"allocate inherited stream launch set"});
        }
        for (auto& stream : *streams) {
            stream.descriptor_fd = -1;
        }
        if (auto installed = (*lifecycle)->install_inherited_streams(std::move(descriptors));
            !installed) {
            return std::unexpected(installed.error());
        }
    } else if (local_services_enabled) {
        auto mount = local_service_proxy->mount();
        if (!mount) {
            return std::unexpected(mount.error());
        }
        if (auto installed = (*lifecycle)->install_service_mount(std::move(*mount)); !installed) {
            return std::unexpected(installed.error());
        }
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
        .egress_proxy = std::move(egress_proxy),
        .local_service_proxy = std::move(local_service_proxy),
        .refinement_evaluator = std::move(refinement_evaluator),
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
