#pragma once

#include "glove/host/runtime_policy.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace glove::host::snapshot {

inline auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

inline auto ensure_protected_directory(const std::filesystem::path& path) -> result<void> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(
            std::string{"protected harness directory must be a canonical absolute non-root path"}
        );
    }
    std::filesystem::path current = path.root_path();
    for (const auto& component : path.relative_path()) {
        current /= component;
        struct stat metadata{};
        if (::lstat(current.c_str(), &metadata) == 0) {
            if (!S_ISDIR(metadata.st_mode)) {
                return std::unexpected(
                    "protected harness ancestor is not a directory: " + current.string()
                );
            }
            const bool root_sticky = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
            if (metadata.st_uid != 0 && metadata.st_uid != ::geteuid()) {
                return std::unexpected(
                    "protected harness ancestor is not owned by root or the service user: " +
                    current.string()
                );
            }
            if ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !root_sticky) {
                return std::unexpected(
                    "protected harness ancestor is writable by another principal: " +
                    current.string()
                );
            }
            continue;
        }
        if (errno != ENOENT) {
            return std::unexpected(system_error("inspect protected harness directory"));
        }
        if (::mkdir(current.c_str(), 0700) != 0) {
            return std::unexpected(system_error("create protected harness directory"));
        }
    }
    return {};
}

inline auto
path_within(const std::filesystem::path& candidate, const std::filesystem::path& root) noexcept
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

struct homebrew_keg {
    std::filesystem::path prefix;
    std::string formula;
    std::filesystem::path root;
};

struct runtime_dependency_closure {
    std::filesystem::path executable;
    std::vector<std::string> arguments;
    std::vector<std::filesystem::path> read_only_paths;
};

struct planned_runtime_snapshot {
    std::string digest;
    std::uint64_t logical_bytes = 0;
    std::uint64_t entries = 0;
    std::filesystem::path snapshot_root;
    std::filesystem::path payload_root;
    std::filesystem::path mapped_source;
    std::vector<std::filesystem::path> source_roots;
    runtime_dependency_closure closure;
};

auto homebrew_keg_for(const std::filesystem::path& path) -> std::optional<homebrew_keg>;

auto append_homebrew_runtime_closure(
    const homebrew_keg& interpreter,
    std::vector<std::filesystem::path>& paths,
    bool allow_dependency_commands
) -> result<void>;

auto minimise_roots(std::vector<std::filesystem::path> paths) -> std::vector<std::filesystem::path>;

auto append_snapshot_file_digest(
    const std::filesystem::path& path,
    std::string_view relative,
    std::string& manifest,
    std::uint64_t& total_bytes
) -> result<void>;

auto snapshot_tree_digest(
    const std::filesystem::path& root,
    std::uint64_t* logical_bytes = nullptr,
    std::uint64_t* entry_count = nullptr
) -> result<std::string>;

auto package_root_for(const std::filesystem::path& source) -> std::filesystem::path;

auto derive_runtime_dependency_closure(
    const std::filesystem::path& source_entry,
    const std::filesystem::path& source,
    bool allow_dependency_commands
) -> result<runtime_dependency_closure>;

auto path_ancestors_are_launch_trusted(const std::filesystem::path& path) -> bool;

auto closure_launch_is_trusted(const runtime_dependency_closure& closure) -> bool;

auto snapshot_payload_root(const std::filesystem::path& payload_root, std::size_t index)
    -> std::filesystem::path;

auto map_snapshot_path(
    const std::filesystem::path& source,
    std::span<const std::filesystem::path> closure_roots,
    const std::filesystem::path& payload_root
) -> result<std::filesystem::path>;

auto snapshot_closure_digest(
    std::span<const std::filesystem::path> roots,
    std::uint64_t* logical_bytes = nullptr,
    std::uint64_t* entry_count = nullptr
) -> result<std::string>;

auto materialized_snapshot_digest(const std::filesystem::path& payload_root, std::size_t root_count)
    -> result<std::string>;

auto plan_runtime_snapshot(
    const std::filesystem::path& protected_directory,
    const std::filesystem::path& source,
    const runtime_dependency_closure& closure
) -> result<planned_runtime_snapshot>;

auto protect_snapshot_tree(const std::filesystem::path& payload_root) -> result<void>;

auto materialize_runtime_snapshot(const planned_runtime_snapshot& plan) -> result<bool>;

} // namespace glove::host::snapshot
