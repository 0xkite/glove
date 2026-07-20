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

struct config {
    std::uint8_t schema_version = 1;
    std::filesystem::path runtime_directory;
    std::filesystem::path audit_key;
    std::filesystem::path receipt_journal;
    std::optional<std::filesystem::path> session_policy;
    std::optional<std::filesystem::path> session_store;
    std::optional<std::filesystem::path> materialization_root;
    std::optional<std::filesystem::path> library_bundle_root;
    std::optional<std::filesystem::path> path_exposure_policy;
    std::optional<std::filesystem::path> path_exposure_journal;

    auto operator==(const config&) const -> bool = default;
};

[[nodiscard]] auto current_environment() -> environment;
[[nodiscard]] auto resolve_directories(const environment& values) -> result<directories>;
[[nodiscard]] auto default_config_path(const directories& values) -> std::filesystem::path;
[[nodiscard]] auto validate(const config& value) -> result<void>;
[[nodiscard]] auto load_config(const std::filesystem::path& path) -> result<config>;
[[nodiscard]] auto encode_config(const config& value) -> result<std::string>;

} // namespace glove::host
