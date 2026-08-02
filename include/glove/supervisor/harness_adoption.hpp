#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

// The protected root is owner-local policy only. A remote plan can select a
// runtime template but never carries this path, a manifest digest, a snapshot
// digest, or any source-artifact selector.
struct native_harness_adoption_policy {
    std::string manifest_root;
    std::string manifest_digest;
    std::string snapshot_digest;

    auto operator==(const native_harness_adoption_policy&) const -> bool = default;
};

// Redacted identity propagated through the resolved launch and receipt. It is
// deliberately path-free so it is safe to retain with a remote session.
struct native_harness_adoption_identity {
    std::string manifest_digest;
    std::string snapshot_digest;

    auto operator==(const native_harness_adoption_identity&) const -> bool = default;
};

// Descriptor-pinned, digest-verified adoption state. Its implementation keeps
// protected host paths and descriptors private; callers can observe only the
// selected runtime, redacted identity, generated configuration, and payload
// count.
class resolved_native_harness_adoption final {
public:
    struct implementation;

    resolved_native_harness_adoption(const resolved_native_harness_adoption&) = delete;
    auto operator=(const resolved_native_harness_adoption&)
        -> resolved_native_harness_adoption& = delete;
    resolved_native_harness_adoption(resolved_native_harness_adoption&&) noexcept;
    auto operator=(resolved_native_harness_adoption&&) noexcept
        -> resolved_native_harness_adoption&;
    ~resolved_native_harness_adoption();

    [[nodiscard]] auto runtime_id() const noexcept -> std::string_view;
    [[nodiscard]] auto identity() const noexcept -> native_harness_adoption_identity;
    [[nodiscard]] auto generated_settings_json() const noexcept -> std::string_view;
    [[nodiscard]] auto payload_count() const noexcept -> std::size_t;

    // Rehashes and reinspects every adopted payload through its pinned
    // descriptors. Mutation, link changes, and invalid payload topology fail
    // before materialization.
    [[nodiscard]] auto verify_identity() const -> std::expected<void, std::string>;

private:
    explicit resolved_native_harness_adoption(std::unique_ptr<implementation> state) noexcept;

    std::unique_ptr<implementation> state_;

    friend auto resolve_native_harness_adoption(
        const native_harness_adoption_policy& policy, std::string_view expected_runtime_id
    ) -> std::expected<resolved_native_harness_adoption, std::string>;
    friend auto materialize_native_harness_adoption_projection(
        int private_home_fd,
        std::string_view runtime_id,
        const resolved_native_harness_adoption& adoption
    ) -> std::expected<void, std::string>;
};

// Structural validation shared by policy loading and owner-local policy
// generation. It does not inspect the host filesystem.
[[nodiscard]] auto
validate_native_harness_adoption_policy(const native_harness_adoption_policy& policy)
    -> std::expected<void, std::string>;

// Canonical generated Pi settings. The only package references are
// adapter-owned private-home-relative extension roots.
[[nodiscard]] auto pi_adoption_settings_json(std::size_t payload_count)
    -> std::expected<std::string, std::string>;

// The persisted Pi manifest digest covers its schema domain, verified snapshot
// digest, selected package identifiers, and canonical generated settings.
[[nodiscard]] auto native_harness_adoption_document_digest(
    std::string_view snapshot_digest, std::span<const std::string> payload_ids
) -> std::expected<std::string, std::string>;

// Resolve the policy-owned manifest and snapshot through no-follow descriptors.
// Only a registered adapter projector may consume the resulting state.
[[nodiscard]] auto resolve_native_harness_adoption(
    const native_harness_adoption_policy& policy, std::string_view expected_runtime_id
) -> std::expected<resolved_native_harness_adoption, std::string>;

// Project an adapter-owned private configuration payload below a fresh private
// home. This is intentionally a closed projector dispatch; unsupported
// runtimes fail rather than receiving generic host filesystem access.
[[nodiscard]] auto materialize_native_harness_adoption_projection(
    int private_home_fd,
    std::string_view runtime_id,
    const resolved_native_harness_adoption& adoption
) -> std::expected<void, std::string>;

} // namespace glove::supervisor
