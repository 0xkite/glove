#pragma once

#include "glove/supervisor/change_manifest.hpp"
#include "glove/supervisor/harness_adoption.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/linux_ephemeral_copy.hpp"
#include "glove/supervisor/path_alias.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor::linux_detail {

struct session_mount {
    int descriptor_fd = -1;
    std::string target_path;
    std::string alias;
    std::string quota_partition;
    std::uint64_t quota_bytes = 0;
    std::optional<path_identity> source_identity;
    std::optional<std::string> source_content_digest;
    std::optional<std::string> projection_id;
    std::optional<std::string> projection_destination_alias;
    // Present only for an executor-derived private harness home. These values
    // are not controller input and are committed by managed_launch_binding.
    std::optional<std::string> runtime_adapter_id;
    std::optional<std::string> runtime_context_digest;
    // Redacted adoption evidence for an adapter-owned private home. Both
    // values are required together and are committed into the managed launch
    // profile and terminal receipt; protected source paths remain absent.
    std::optional<std::string> runtime_adoption_manifest_digest;
    std::optional<std::string> runtime_adoption_snapshot_digest;
    // Present only for a local secret-handle projection. The handle and
    // runtime identity are committed; source paths and secret bytes are not.
    std::optional<std::string> secret_handle;
    std::optional<std::string> secret_runtime_id;
    // Canonical identity of a factory-owned ephemeral local service catalog.
    // It is launch-only evidence and is never persisted in registry formats.
    std::optional<std::string> service_proxy_manifest_digest;
    bool writable = false;
    bool directory = false;
};

struct session_filesystem_usage {
    std::uint64_t filesystem_bytes = 0;
    std::uint64_t quota_bytes = 0;
    std::size_t materializations = 0;
    bool limit_hit = false;
};

struct recovered_quota_partition {
    std::string alias;
    std::uint64_t quota_bytes = 0;

    auto operator==(const recovered_quota_partition&) const -> bool = default;
};

struct orphaned_materialization_report {
    std::size_t inspected = 0;
    std::size_t removed_without_stage = 0;
    std::vector<retained_change_manifest> recovered_retained_changes;
};

// Owns every filesystem exposed to one session. Read grants remain pinned,
// descriptor-cloned host objects and consume no write quota. Each ephemeral
// write alias keeps its host-configured quota (tmpfs for ephemeral copies,
// durable ext4 images for retained copies), and the remaining capacity backs
// shared /tmp and /var/tmp directories. Because writable partition capacities
// sum exactly to the session limit, aggregate writes cannot exceed that limit.
class linux_session_filesystem {
public:
    linux_session_filesystem(const linux_session_filesystem&) = delete;
    auto operator=(const linux_session_filesystem&) -> linux_session_filesystem& = delete;
    linux_session_filesystem(linux_session_filesystem&& other) noexcept;
    auto operator=(linux_session_filesystem&&) -> linux_session_filesystem& = delete;
    ~linux_session_filesystem();

    [[nodiscard]] static result<linux_session_filesystem> create(
        std::string_view materialization_root,
        std::string_view session_id,
        std::uint64_t disk_limit_bytes,
        std::vector<resolved_path_grant>&& grants,
        std::vector<resolved_library_projection>&& library_projections = {},
        std::string_view runtime_id = {},
        std::optional<resolved_native_harness_adoption>&& adoption = {}
    );

    // Removes only the deterministic tmpfs partitions whose complete quota
    // layout still matches the durable canonical plan. Every present partition
    // is preflighted before cleanup begins; absent partitions make retries
    // idempotent.
    [[nodiscard]] static result<void> cleanup_recovered(
        std::string_view materialization_root,
        std::string_view session_id,
        std::uint64_t disk_limit_bytes,
        const std::vector<recovered_quota_partition>& partitions
    );

    // Startup-only recovery for a crash that occurred after a deterministic
    // materialization was created but before its identity reached the session
    // registry. Only exact Glove-owned names are considered. Active registry
    // sessions and published retained stages are never touched.
    [[nodiscard]] static result<orphaned_materialization_report> sweep_orphaned(
        std::string_view materialization_root, const std::vector<std::string>& protected_session_ids
    );

    [[nodiscard]] auto mounts() const -> std::vector<session_mount>;

    [[nodiscard]] auto disk_limit_bytes() const noexcept -> std::uint64_t {
        return active_ ? disk_limit_bytes_ : 0;
    }

    [[nodiscard]] auto recovery_partitions() const -> std::vector<recovered_quota_partition>;
    [[nodiscard]] result<session_filesystem_usage> observe() const;
    [[nodiscard]] result<std::vector<retained_change_manifest>> finalize_retained_changes();
    [[nodiscard]] result<void> cleanup();

private:
    linux_session_filesystem(
        std::uint64_t disk_limit_bytes,
        ephemeral_copy_materialization scratch,
        int tmp_fd,
        int var_tmp_fd,
        std::vector<ephemeral_copy_materialization> materializations,
        std::vector<session_mount> mounts
    ) noexcept;

    void close_scratch_descriptors() noexcept;
    void close_mount_descriptors() noexcept;

    std::uint64_t disk_limit_bytes_ = 0;
    ephemeral_copy_materialization scratch_;
    int tmp_fd_ = -1;
    int var_tmp_fd_ = -1;
    std::vector<ephemeral_copy_materialization> materializations_;
    std::vector<session_mount> mounts_;
    std::vector<retained_change_manifest> retained_manifests_;
    bool active_ = true;
};

} // namespace glove::supervisor::linux_detail
