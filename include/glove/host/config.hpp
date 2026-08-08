#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace glove::host {

template<typename Value> using result = std::expected<Value, std::string>;

struct environment {
    std::optional<std::string> home;
    std::optional<std::string> xdg_config_home;
    std::optional<std::string> xdg_state_home;
    std::optional<std::string> xdg_data_home;
    std::optional<std::string> xdg_cache_home;
    std::optional<std::string> xdg_runtime_dir;
    std::optional<std::string> temporary_directory;
};

struct directories {
    std::filesystem::path config;
    std::filesystem::path state;
    std::filesystem::path data;
    std::filesystem::path cache;
    std::filesystem::path runtime;
};

struct apple_container_config {
    std::filesystem::path cli;
    std::string image;
    std::string image_digest;
    std::optional<std::string> harness_closure_digest;

    auto operator==(const apple_container_config&) const -> bool = default;
};

// Operator-authored literal endpoint and immutable remote execution identity.
// No field is sourced from a session plan or inherited SSH configuration.
struct remote_backend_config {
    std::string host;
    std::string user;
    std::uint16_t port = 22;
    std::string host_public_key;
    std::string host_key_fingerprint;
    std::filesystem::path identity_file;
    std::string executor_digest;
    // Exact untagged name@sha256:<64 lowercase hex> identity. The suffix must
    // equal container_image_digest; neither field is accepted independently.
    std::string container_image;
    std::string container_image_digest;
    std::uint64_t channel_timeout_ms = 0;
    std::uint64_t max_clock_skew_ms = 0;
    std::uint32_t max_sessions = 0;
    std::filesystem::path staging_root;

    auto operator==(const remote_backend_config&) const -> bool = default;
};

struct config {
    std::uint8_t schema_version = 1;
    bool persistent_service = false;
    std::filesystem::path runtime_directory;
    std::filesystem::path audit_key;
    std::filesystem::path receipt_journal;
    std::optional<std::filesystem::path> session_policy;
    std::optional<std::filesystem::path> session_store;
    std::optional<std::filesystem::path> materialization_root;
    std::optional<std::filesystem::path> library_bundle_root;
    std::optional<std::filesystem::path> path_exposure_policy;
    std::optional<std::filesystem::path> path_exposure_journal;
    std::optional<apple_container_config> apple_container;
    std::optional<remote_backend_config> remote_backend;

    auto operator==(const config&) const -> bool = default;
};

[[nodiscard]] auto current_environment() -> environment;
[[nodiscard]] auto resolve_directories(const environment& values) -> result<directories>;
[[nodiscard]] auto default_config_path(const directories& values) -> std::filesystem::path;
[[nodiscard]] auto validate(const remote_backend_config& value) -> result<void>;
[[nodiscard]] auto validate(const config& value) -> result<void>;
[[nodiscard]] auto load_config(const std::filesystem::path& path) -> result<config>;
[[nodiscard]] auto encode_config(const config& value) -> result<std::string>;
// Write a validated config only into an existing owner-only directory. The
// target must not exist; callers handle exact-match idempotence explicitly.
[[nodiscard]] auto write_config_exclusive(const std::filesystem::path& path, const config& value)
    -> result<void>;

} // namespace glove::host
