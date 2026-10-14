#pragma once

#include "pi_private_files.hpp"

#include <dirent.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>

namespace glove::run::detail::private_cleanup {

using private_files::descriptor;
using private_files::directory_flags;
using private_files::failure;
using private_files::result;
using private_files::same;
using private_files::stable_bytes;
inline constexpr std::size_t recovery_entries = 4096U;

struct directory_closer {
    void operator()(DIR* stream) const noexcept { (void)::closedir(stream); }
};

using directory_stream = std::unique_ptr<DIR, directory_closer>;

// Complete a read-only admission pass before invoking a narrowing pass. Each
// opened entry is rechecked before mutation; this is not an atomic same-UID tree.
inline auto inspect_tree(int fd, dev_t device, std::size_t& entries, std::size_t depth, bool narrow)
    -> result<void> {
    descriptor enumeration{::openat(fd, ".", directory_flags)};
    if (enumeration.get() < 0) {
        return failure("open Pi cleanup preflight");
    }
    directory_stream stream{::fdopendir(enumeration.get())};
    if (!stream) {
        return failure("enumerate Pi cleanup preflight");
    }
    (void)enumeration.release();
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return failure("read Pi cleanup preflight");
            }
            break;
        }
        const auto length = ::strnlen(entry->d_name, sizeof(entry->d_name));
        if (length == sizeof(entry->d_name)) {
            return std::unexpected("unbounded Pi cleanup entry");
        }
        const std::string name{entry->d_name, length};
        if (name == "." || name == "..") {
            continue;
        }
        if (++entries > recovery_entries || depth >= 64) {
            return std::unexpected("Pi cleanup tree exceeds entry/depth bound");
        }
        struct stat before{};
        if (::fstatat(fd, name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect Pi cleanup entry");
        }
        const auto mode = before.st_mode & 07777U;
        const auto owner_mode = mode & 0700U;
        const bool directory = S_ISDIR(before.st_mode);
        if (before.st_uid != ::geteuid() || before.st_dev != device || (mode & 07000U) != 0 ||
            (directory ? (before.st_nlink == 0 || (owner_mode != 0700U && owner_mode != 0500U))
                       : (!S_ISREG(before.st_mode) || before.st_nlink != 1 ||
                          (owner_mode != 0600U && owner_mode != 0400U && owner_mode != 0700U &&
                           owner_mode != 0500U)))) {
            return std::unexpected("Pi cleanup refuses unsafe/symlink/aliased entry: " + name);
        }
        descriptor opened{::openat(
            fd,
            name.c_str(),
            directory ? directory_flags : O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )};
        struct stat actual{};
        struct stat named{};
        if (opened.get() < 0 || ::fstat(opened.get(), &actual) != 0 ||
            ::fstatat(fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("pin Pi cleanup entry");
        }
        if (!same(before, actual) || !same(actual, named) || before.st_nlink != actual.st_nlink ||
            actual.st_nlink != named.st_nlink) {
            return std::unexpected("Pi cleanup entry changed on open");
        }
        if (auto acl = glove::detail::check_descriptor_acl(
                opened.get(), glove::detail::acl_scope::owner_private
            );
            !acl) {
            return acl;
        }
        // Ordinary Node artifacts inherit the host umask (often 0644/0755).
        // Only after safe phase/lease admission, remove group/other permissions
        // from pinned, unaliased entries; never add owner rights or follow links.
        if (narrow && mode != owner_mode) {
            if (::fchmod(opened.get(), static_cast<mode_t>(owner_mode)) != 0 ||
                ::fsync(opened.get()) != 0) {
                return failure("narrow Pi cleanup artifact permissions");
            }
            struct stat narrowed{};
            if (::fstat(opened.get(), &narrowed) != 0 ||
                ::fstatat(fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
                return failure("reinspect narrowed Pi cleanup artifact");
            }
            actual.st_mode =
                (actual.st_mode & ~static_cast<mode_t>(07777U)) | static_cast<mode_t>(owner_mode);
            if (!same(actual, narrowed) || !stable_bytes(narrowed, named) ||
                narrowed.st_nlink != actual.st_nlink || narrowed.st_size != actual.st_size) {
                return std::unexpected("Pi cleanup artifact changed while narrowing permissions");
            }
        }
        if (directory) {
            if (auto checked = inspect_tree(opened.get(), device, entries, depth + 1, narrow);
                !checked) {
                return checked;
            }
        }
    }
    if (::closedir(stream.release()) != 0) {
        return failure("close Pi cleanup preflight");
    }
    return {};
}

} // namespace glove::run::detail::private_cleanup
