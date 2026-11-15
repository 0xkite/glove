#pragma once

#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

struct native_configuration_file;
struct native_private_paths;

// Borrowed only during create(), never retained. The core revokes/stops/joins
// its endpoint before owned construction rollback removes nonce-bearing state.
struct native_creation_rollback_barrier {
    void* context = nullptr;
    void (*before_cleanup)(void*) noexcept = nullptr;
};

// Planning owns only names/paths, not filesystem authority. create() independently
// admits the parent and proves exclusive, descriptor-bound ownership. The legacy
// run-name and lease wire format remain unchanged; neither identifies a harness.
struct native_private_run_plan {
    std::filesystem::path parent;
    std::string name;

    [[nodiscard]] auto root() const -> std::filesystem::path;
    [[nodiscard]] auto paths() const -> native_private_paths;
};

[[nodiscard]] auto prepare_native_private_run(const std::filesystem::path& parent)
    -> std::expected<native_private_run_plan, std::string>;

// Single-thread-confined owner. Grant only fixed children and immutable payload
// leaves, never the root/lease. Same-UID namespace mutation is detected, not locked
// out. Configuration borrows are synchronous; sealed paths/descriptors are owned.
class native_private_state {
public:
    native_private_state(const native_private_state&) = delete;
    auto operator=(const native_private_state&) -> native_private_state& = delete;
    native_private_state(native_private_state&&) noexcept;
    auto operator=(native_private_state&&) noexcept -> native_private_state&;
    ~native_private_state();

    [[nodiscard]] static auto create(
        const std::filesystem::path& parent,
        std::span<const native_configuration_file> configuration,
        native_creation_rollback_barrier rollback_barrier = {}
    ) -> std::expected<native_private_state, std::string>;
    [[nodiscard]] static auto create(
        const native_private_run_plan& plan,
        std::span<const native_configuration_file> configuration,
        native_creation_rollback_barrier rollback_barrier = {}
    ) -> std::expected<native_private_state, std::string>;
    [[nodiscard]] static auto recover(const std::filesystem::path& parent)
        -> std::expected<std::size_t, std::string>;

    [[nodiscard]] auto root() const -> const std::filesystem::path&;
    [[nodiscard]] auto home() const -> const std::filesystem::path&;
    [[nodiscard]] auto tmp() const -> const std::filesystem::path&;
    [[nodiscard]] auto agent() const -> const std::filesystem::path&;
    [[nodiscard]] auto sessions() const -> const std::filesystem::path&;
    [[nodiscard]] auto configuration_paths() const -> const std::vector<std::filesystem::path>&;
    // Borrowed descriptor of the fixed agent child for descriptor-relative
    // generation-local materialization and finalization. Never a grant.
    [[nodiscard]] auto agent_descriptor() const -> int;

    // Durable transition before execution. Failed/uncertain states remain held.
    [[nodiscard]] auto mark_launching() -> std::expected<void, std::string>;
    // Caller must have successful whole original-group reap evidence, not merely
    // a leader exit or absent lease. Endpoint revocation is independently required.
    [[nodiscard]] auto mark_quiescent() -> std::expected<void, std::string>;
    [[nodiscard]] auto cleanup() -> std::expected<void, std::string>;

private:
    struct implementation;
    explicit native_private_state(std::unique_ptr<implementation>) noexcept;
    [[nodiscard]] static auto create_impl(
        const std::filesystem::path& parent,
        std::span<const native_configuration_file> configuration,
        native_creation_rollback_barrier rollback_barrier,
        std::optional<std::string_view> prepared_name
    ) -> std::expected<native_private_state, std::string>;
    std::unique_ptr<implementation> state_;
};

} // namespace glove::run::detail
