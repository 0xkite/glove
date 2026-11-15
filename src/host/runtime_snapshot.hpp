#pragma once

#include "glove/detail/descriptor_acl.hpp"
#include "glove/host/runtime_policy.hpp"

#include <fcntl.h>
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

inline auto
ensure_protected_directory(const std::filesystem::path& path, bool private_final = false)
    -> result<void> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path ||
        path.native().size() > 4096U || path.native().contains('\0')) {
        return std::unexpected(
            std::string{
                "protected harness directory must be a bounded canonical absolute non-root path"
            }
        );
    }

    struct owned_fd {
        int value;

        explicit owned_fd(int fd) : value{fd} {}

        owned_fd(const owned_fd&) = delete;
        auto operator=(const owned_fd&) -> owned_fd& = delete;

        ~owned_fd() {
            if (value >= 0) {
                (void)::close(value);
            }
        }
    } parent{::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};

    if (parent.value < 0) {
        return std::unexpected(system_error("open protected harness root"));
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(parent.value, glove::detail::acl_scope::integrity);
        !acl) {
        return acl;
    }
    std::filesystem::path walked{"/"};
    std::size_t depth = 0;
    for (const auto& component : path.relative_path()) {
        if (++depth > 128U) {
            return std::unexpected(std::string{"protected harness directory exceeds depth bound"});
        }
        walked /= component;
        struct stat named{};
        bool created = false;
        if (::fstatat(parent.value, component.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) {
                return std::unexpected(system_error("inspect protected harness directory"));
            }
            if (::mkdirat(parent.value, component.c_str(), 0700) != 0) {
                return std::unexpected(
                    system_error("create exclusive protected harness directory")
                );
            }
            created = true;
            if (::fstatat(parent.value, component.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
                return std::unexpected(system_error("pin created protected harness directory"));
            }
        }
        const bool root_sticky = named.st_uid == 0 && (named.st_mode & S_ISVTX) != 0;
        if (!S_ISDIR(named.st_mode) || (named.st_uid != 0 && named.st_uid != ::geteuid()) ||
            ((named.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !root_sticky) ||
            ((created || (private_final && walked == path)) &&
             (named.st_uid != ::geteuid() || (named.st_mode & 07777U) != 0700U))) {
            return std::unexpected(
                std::string{"protected harness directory ownership or mode is unsafe"}
            );
        }
        owned_fd next{::openat(
            parent.value,
            component.c_str(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )};
        struct stat opened{};
        if (next.value < 0 || ::fstat(next.value, &opened) != 0 || opened.st_dev != named.st_dev ||
            opened.st_ino != named.st_ino || opened.st_uid != named.st_uid ||
            opened.st_gid != named.st_gid || opened.st_mode != named.st_mode) {
            return std::unexpected(std::string{"protected harness directory changed on open"});
        }
        if (created) {
            if (auto acl = glove::detail::clear_created_descriptor_acl(next.value); !acl) {
                return acl;
            }
        }
        const auto scope = created || (private_final && walked == path)
                               ? glove::detail::acl_scope::owner_private
                               : glove::detail::acl_scope::integrity;
        if (auto acl = glove::detail::check_descriptor_acl(next.value, scope); !acl) {
            return acl;
        }
        struct stat rebound{};
        if (::fstatat(parent.value, component.c_str(), &rebound, AT_SYMLINK_NOFOLLOW) != 0 ||
            rebound.st_dev != opened.st_dev || rebound.st_ino != opened.st_ino ||
            rebound.st_uid != opened.st_uid || rebound.st_gid != opened.st_gid ||
            rebound.st_mode != opened.st_mode) {
            return std::unexpected(std::string{"protected harness directory binding changed"});
        }
        const int previous = parent.value;
        parent.value = next.value;
        next.value = -1;
        if (::close(previous) != 0) {
            return std::unexpected(system_error("close protected harness ancestor"));
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

// A non-script returns nullopt. Script directives are bounded to 4096 bytes.
auto read_runtime_shebang(const std::filesystem::path& source)
    -> result<std::optional<std::vector<std::string>>>;

// Exclusions only: the production caller obtains home from the effective account,
// never from a launch request. Configured paths can remove authority, not grant it.
auto validate_pi_source_exclusions(
    std::span<const std::filesystem::path> roots,
    const std::filesystem::path& account_home,
    std::span<const std::filesystem::path> additional_exclusions = {}
) -> result<void>;

// Pi-only source admission shared by staging and read-only revalidation.
auto validate_pi_source_closure(
    const std::filesystem::path& source_entry,
    const std::filesystem::path& source,
    const runtime_dependency_closure& closure,
    const std::filesystem::path& protected_directory,
    std::span<const std::filesystem::path> additional_exclusions = {}
) -> result<void>;

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

// Wrapper entries do not consume the unchanged 200000-content-entry budget.
struct snapshot_tree_budget {
    std::size_t content_remaining = 200'000U;
    std::size_t wrappers_remaining = 64U + 1U;

    constexpr auto admit(bool wrapper) noexcept -> bool {
        auto& remaining = wrapper ? wrappers_remaining : content_remaining;
        if (remaining == 0) {
            return false;
        }
        --remaining;
        return true;
    }
};

// Read-only admission for a sealed, owner-owned root and its sole payload tree.
auto validate_protected_snapshot_tree(
    const std::filesystem::path& snapshot_root, std::size_t root_count
) -> result<void>;

auto protect_snapshot_tree(const std::filesystem::path& payload_root) -> result<void>;

auto materialize_runtime_snapshot(const planned_runtime_snapshot& plan) -> result<bool>;

} // namespace glove::host::snapshot

namespace glove::host::detail {

// Caller-owned deny-only policy. Public no-context validation stays strict;
// native composition supplies its admitted machine authority before any hash.
auto validate_pi_runtime_with_exclusions(
    const staged_runtime_harness& runtime,
    std::span<const std::filesystem::path> additional_exclusions
) -> result<void>;

} // namespace glove::host::detail
