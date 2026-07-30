#pragma once

#include "glove/host/config.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {

struct setup_options {
    std::optional<std::filesystem::path> config_path;
    std::optional<std::filesystem::path> protected_root;
    std::optional<std::filesystem::path> session_policy;
    std::string root_id = "projects";
    std::vector<std::string> runtime_template_ids = {"codex-safe", "pi-safe"};
    std::optional<bool> persistent_service;
    bool dry_run = false;
};

struct setup_plan {
    config service;
    std::filesystem::path config_path;
    std::optional<std::filesystem::path> migrate_runtime_from;
    bool add_paired_apple_runtime = false;
    std::optional<std::filesystem::path> canonical_protected_root;
    std::string root_id;
    std::vector<std::string> runtime_template_ids;
    bool dry_run = false;
};

struct setup_ledger_resource {
    std::string kind;
    std::filesystem::path path;
    bool owned = false;
    std::optional<std::string> content_sha256;

    auto operator==(const setup_ledger_resource&) const -> bool = default;
};

struct setup_ledger {
    std::uint8_t schema_version = 1;
    std::filesystem::path ledger_path;
    std::filesystem::path config_path;
    std::vector<setup_ledger_resource> resources;

    auto operator==(const setup_ledger&) const -> bool = default;
};

struct setup_cleanup_item {
    setup_ledger_resource resource;
    bool removable = false;
    bool absent = false;
    std::string reason;

    auto operator==(const setup_cleanup_item&) const -> bool = default;
};

struct setup_cleanup_plan {
    setup_ledger ledger;
    std::vector<setup_cleanup_item> items;
    bool ledger_removable = false;

    [[nodiscard]] auto blocked() const -> bool {
        return std::ranges::any_of(items, [](const auto& item) {
            return item.resource.owned && !item.removable && !item.absent;
        });
    }
};

[[nodiscard]] auto plan_setup(const setup_options& options, const environment& values)
    -> result<setup_plan>;
[[nodiscard]] auto execute_setup(const setup_plan& plan) -> result<void>;
[[nodiscard]] auto setup_ledger_path(const config& service) -> std::filesystem::path;
[[nodiscard]] auto load_setup_ledger(const std::filesystem::path& path) -> result<setup_ledger>;
[[nodiscard]] auto plan_setup_adoption(const std::filesystem::path& config_path)
    -> result<setup_ledger>;
[[nodiscard]] auto execute_setup_adoption(const setup_ledger& ledger) -> result<void>;
[[nodiscard]] auto plan_setup_cleanup(const std::filesystem::path& config_path)
    -> result<setup_cleanup_plan>;
// Deletes only resources that the ledger says setup created and whose current
// identity still matches the preview. The caller must present the exact
// ledger digest printed with the preview, preventing a stale confirmation.
[[nodiscard]] auto
execute_setup_cleanup(const setup_cleanup_plan& plan, std::string_view confirmed_ledger_sha256)
    -> result<void>;
[[nodiscard]] auto setup_ledger_sha256(const setup_ledger& ledger) -> result<std::string>;

} // namespace glove::host
