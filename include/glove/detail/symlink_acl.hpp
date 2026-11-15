#pragma once

#include "glove/detail/descriptor_acl.hpp"

#include <sys/stat.h>

#include <string_view>

#if defined(__APPLE__)
#    include <fcntl.h>
#    include <unistd.h>
#endif

namespace glove::detail {

// Child DELETE authority is independent of parent DELETE_CHILD. Inspect the
// link inode itself: Darwin's descriptor setter supports ACLs even where its
// link-path setter reports ENOTSUP. Never open the target or repair an ACL.
[[nodiscard]] inline auto check_symlink_acl_at(
    int parent,
    std::string_view name,
    const struct stat& expected,
    acl_scope scope = acl_scope::integrity
) -> std::expected<void, std::string> {
    if (scope != acl_scope::owner_private && scope != acl_scope::integrity) {
        return std::unexpected("unknown symlink ACL scope");
    }
#if defined(__APPLE__)
    if (parent < 0 || name.empty() || name.size() > 255U || name == "." || name == ".." ||
        name.find('/') != std::string_view::npos || name.find('\0') != std::string_view::npos ||
        !S_ISLNK(expected.st_mode) || expected.st_uid != ::geteuid() || expected.st_nlink != 1 ||
        (expected.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        return std::unexpected("invalid symlink ACL witness");
    }

    struct descriptor {
        int value;

        explicit descriptor(int fd) noexcept : value{fd} {}

        descriptor(const descriptor&) = delete;
        auto operator=(const descriptor&) -> descriptor& = delete;

        ~descriptor() {
            if (value >= 0) {
                (void)::close(value);
            }
        }
    } opened{
        ::openat(parent, std::string{name}.c_str(), O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC)
    };

    // O_SYMLINK opens the link; adding O_NOFOLLOW instead makes Darwin fail
    // with ELOOP. The pinned inode must match the caller's no-follow witness.
    if (opened.value < 0) {
        return acl_detail::failure("open symlink inode for ACL admission");
    }
    const auto same = [&](const struct stat& actual) {
        return actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino &&
               actual.st_uid == expected.st_uid && actual.st_gid == expected.st_gid &&
               actual.st_mode == expected.st_mode && actual.st_nlink == expected.st_nlink &&
               actual.st_size == expected.st_size &&
               actual.st_mtimespec.tv_sec == expected.st_mtimespec.tv_sec &&
               actual.st_mtimespec.tv_nsec == expected.st_mtimespec.tv_nsec &&
               actual.st_ctimespec.tv_sec == expected.st_ctimespec.tv_sec &&
               actual.st_ctimespec.tv_nsec == expected.st_ctimespec.tv_nsec;
    };
    struct stat actual{}, named{};
    if (::fstat(opened.value, &actual) != 0 || !same(actual)) {
        return std::unexpected("symlink ACL inode changed on open");
    }
    if (auto checked = check_descriptor_acl(opened.value, scope); !checked) {
        return checked;
    }
    if (::fstat(opened.value, &actual) != 0 ||
        ::fstatat(parent, std::string{name}.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same(actual) || !same(named)) {
        return std::unexpected("symlink ACL inode or binding changed");
    }
    const int fd = opened.value;
    opened.value = -1;
    if (::close(fd) != 0) {
        return acl_detail::failure("close symlink ACL descriptor");
    }
#else
    // No Darwin ACL claim: Linux POSIX symlink ACLs are not an authority seam
    // covered by this helper. Existing caller link/parent checks still apply.
    (void)parent;
    (void)name;
    (void)expected;
    (void)scope;
#endif
    return {};
}

} // namespace glove::detail
