#pragma once

#include "pi_guest_config.hpp"

#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>

namespace glove::run::detail {

// Borrowed only during create(). The adapter stops and joins its endpoint here
// before owned construction rollback can remove nonce-bearing private state.
// The callback must not mutate that state; it is never retained for later cleanup.
struct pi_creation_rollback_barrier {
    void* context = nullptr;
    void (*before_cleanup)(void*) noexcept = nullptr;
};

// Single-thread-confined host ownership, not a filesystem grant or disk quota.
// Grant only the fixed children/config files, NEVER the root or its lease.
// Same-UID host namespace mutation is detected, not atomically excluded.
class pi_private_state {
public:
    pi_private_state(const pi_private_state&) = delete;
    auto operator=(const pi_private_state&) -> pi_private_state& = delete;
    pi_private_state(pi_private_state&&) noexcept;
    auto operator=(pi_private_state&&) noexcept -> pi_private_state&;
    ~pi_private_state();

    // parent must already exist as a canonical, current-owner 0700 directory.
    [[nodiscard]] static auto create(
        const std::filesystem::path& parent,
        const pi_guest_config& config,
        pi_creation_rollback_barrier rollback_barrier = {}
    ) -> std::expected<pi_private_state, std::string>;
    [[nodiscard]] static auto recover(const std::filesystem::path& parent)
        -> std::expected<std::size_t, std::string>;

    [[nodiscard]] auto root() const -> const std::filesystem::path&;
    [[nodiscard]] auto home() const -> const std::filesystem::path&;
    [[nodiscard]] auto tmp() const -> const std::filesystem::path&;
    [[nodiscard]] auto agent() const -> const std::filesystem::path&;
    [[nodiscard]] auto sessions() const -> const std::filesystem::path&;
    [[nodiscard]] auto models() const -> const std::filesystem::path&;
    [[nodiscard]] auto settings() const -> const std::filesystem::path&;
    [[nodiscard]] auto auth() const -> const std::filesystem::path&;

    // Must succeed durably BEFORE any child may start. Failure retains the root.
    [[nodiscard]] auto mark_launching() -> std::expected<void, std::string>;
    // Caller may invoke ONLY after exec_contained_owned succeeds and confirms
    // whole owned process-group reap. A launch error is NOT quiescence evidence.
    // Revoke endpoint authority before cleanup, independently of these methods.
    [[nodiscard]] auto mark_quiescent() -> std::expected<void, std::string>;
    // Launching/uncertain states are retained. Failure may leave a partial tree;
    // descriptors/ownership remain held for explicit retry, never guessed unlink.
    [[nodiscard]] auto cleanup() -> std::expected<void, std::string>;

private:
    struct implementation;
    explicit pi_private_state(std::unique_ptr<implementation>) noexcept;
    std::unique_ptr<implementation> state_;
};

} // namespace glove::run::detail
