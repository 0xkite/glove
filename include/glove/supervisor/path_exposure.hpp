#pragma once

#include "glove/supervisor/path_alias.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

inline constexpr std::uint64_t minimum_retained_copy_bytes = std::uint64_t{32} * 1024U * 1024U;

enum class path_exposure_state : std::uint8_t {
    active,
    revoked,
    expired,
};

struct path_exposure_mode {
    path_access access = path_access::read;
    path_materialization materialization = path_materialization::bind;
    std::uint64_t max_bytes = 0;
    path_cleanup_policy cleanup_policy = path_cleanup_policy::retain;

    auto operator==(const path_exposure_mode&) const -> bool = default;
};

// Static administrator policy. The root path never leaves Glove's local
// administration boundary.
struct path_exposure_root_policy {
    std::string root_id;
    std::string host_root;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t max_ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

// Owner-local create request. `host_path` is deliberately absent from every
// P2P and session-plan type.
struct path_exposure_create_request {
    std::string request_id;
    std::string exposure_id;
    std::string root_id;
    std::string host_path;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

struct path_exposure_descriptor {
    std::uint8_t schema_version = 1;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string root_id;
    std::string source_identity_digest;
    std::string scope_digest;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    path_exposure_state state = path_exposure_state::active;

    auto operator==(const path_exposure_descriptor&) const -> bool = default;
};

// Remote-safe inventory. It carries no root identifier, host path, or raw
// filesystem identity.
struct path_exposure_projection {
    std::uint8_t schema_version = 1;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    path_exposure_state state = path_exposure_state::active;

    auto operator==(const path_exposure_projection&) const -> bool = default;
};

struct path_exposure_grant {
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    path_access access = path_access::read;
    path_materialization materialization = path_materialization::bind;
    std::uint64_t max_bytes = 0;
    std::uint64_t ttl_secs = 0;
    path_cleanup_policy cleanup_policy = path_cleanup_policy::retain;
};

// Recovery-only handle to the locally journaled parent directory and source
// entry. It carries no launch authority, does not require the lease to remain
// active, and never exposes the raw host path. Callers must still classify the
// journaled transaction state before taking any recovery action.
class path_exposure_recovery_target final {
public:
    path_exposure_recovery_target(const path_exposure_recovery_target&) = delete;
    auto operator=(const path_exposure_recovery_target&) -> path_exposure_recovery_target& = delete;
    path_exposure_recovery_target(path_exposure_recovery_target&& other) noexcept;
    auto operator=(path_exposure_recovery_target&& other) noexcept
        -> path_exposure_recovery_target&;
    ~path_exposure_recovery_target();

    [[nodiscard]] auto parent_descriptor_fd() const noexcept -> int {
        return parent_descriptor_fd_;
    }

    [[nodiscard]] auto basename() const noexcept -> std::string_view { return basename_; }

    [[nodiscard]] auto source_identity_digest() const noexcept -> std::string_view {
        return source_identity_digest_;
    }

    // Recompute the identity of the entry currently installed at basename().
    // This intentionally changes after a successful whole-entry exchange and
    // lets recovery distinguish the original object from its replacement.
    [[nodiscard]] auto current_source_identity_digest() const -> result<std::string>;

private:
    friend class path_exposure_registry;

    path_exposure_recovery_target(
        int parent_descriptor_fd, std::string basename, std::string source_identity_digest
    );

    void close_descriptor() noexcept;

    int parent_descriptor_fd_ = -1;
    std::string basename_;
    std::string source_identity_digest_;
};

// Glove-owned authority for dynamic exposure generations. The initial core is
// in-memory; the control layer must compose it with the durable journal before
// advertising exposure administration capability.
class path_exposure_registry final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class path_exposure_registry;
    };

    path_exposure_registry(construction_token token, std::unique_ptr<implementation> state);
    path_exposure_registry(const path_exposure_registry&) = delete;
    auto operator=(const path_exposure_registry&) -> path_exposure_registry& = delete;
    path_exposure_registry(path_exposure_registry&&) noexcept;
    auto operator=(path_exposure_registry&&) noexcept -> path_exposure_registry&;
    ~path_exposure_registry();

    [[nodiscard]] static auto build(std::vector<path_exposure_root_policy> roots)
        -> result<path_exposure_registry>;

    // Construct the same registry with exclusive durable create/revoke replay.
    // Only this form is eligible for control-plane capability advertisement.
    [[nodiscard]] static auto open(
        std::vector<path_exposure_root_policy> roots,
        const std::filesystem::path& journal_path,
        std::uint64_t max_journal_bytes
    ) -> result<path_exposure_registry>;

    // Strictly load owner-only protected roots and compose their durable
    // journal. Raw roots remain confined to this local configuration path.
    [[nodiscard]] static auto load(
        const std::filesystem::path& policy_path,
        const std::filesystem::path& journal_path,
        std::uint64_t max_journal_bytes
    ) -> result<path_exposure_registry>;

    // Owner-local, read-only policy inspection. This opens and validates the
    // protected roots but does not open or mutate the exposure journal.
    [[nodiscard]] static auto inspect_policy(const std::filesystem::path& policy_path)
        -> result<path_exposure_registry>;

    // Explain protected-root policy mismatches before an owner-local control
    // request. Remote protocol errors remain deliberately redacted.
    [[nodiscard]] auto validate_create_policy(const path_exposure_create_request& request) const
        -> std::expected<void, std::string>;

    [[nodiscard]] auto create(const path_exposure_create_request& request, std::uint64_t now_ms)
        -> result<path_exposure_descriptor>;

    [[nodiscard]] auto revoke(
        std::string_view request_id,
        std::string_view exposure_id,
        std::uint64_t generation,
        std::uint64_t now_ms
    ) -> std::expected<void, std::string>;

    [[nodiscard]] auto list(std::uint64_t now_ms) const -> std::vector<path_exposure_projection>;

    [[nodiscard]] auto validate_grant(
        const path_exposure_grant& grant, std::string_view runtime_template_id, std::uint64_t now_ms
    ) const -> std::expected<void, std::string>;

    // Resolve an exact active generation to a descriptor-pinned grant. The
    // sandbox destination is derived by Glove from the exposure identifier;
    // neither a host path nor a remotely selected target crosses this API.
    [[nodiscard]] auto resolve_grant(
        const path_exposure_grant& grant, std::string_view runtime_template_id, std::uint64_t now_ms
    ) const -> result<resolved_path_grant>;

    // Reopen the parent of an exact journaled generation for apply recovery.
    // Revocation and expiry deliberately do not erase this recovery locator.
    // The source entry itself is not opened because a committed exchange is
    // expected to change its identity.
    [[nodiscard]] auto resolve_recovery_target(
        std::string_view exposure_id,
        std::uint64_t generation,
        std::string_view scope_digest,
        std::string_view source_identity_digest
    ) const -> result<path_exposure_recovery_target>;

private:
    std::unique_ptr<implementation> state_;
};

} // namespace glove::supervisor
