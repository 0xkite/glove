#pragma once

#include <expected>
#include <string>

#if defined(__APPLE__)
#    include <sys/acl.h>
#    include <sys/stat.h>

#    include <cerrno>
#    include <system_error>
#endif

namespace glove::detail {

enum class acl_scope { owner_private, integrity };

#if defined(__APPLE__)
namespace acl_detail {
struct owned_acl {
    acl_t value;

    explicit owned_acl(acl_t input) noexcept : value{input} {}

    owned_acl(const owned_acl&) = delete;
    auto operator=(const owned_acl&) -> owned_acl& = delete;

    ~owned_acl() {
        if (value != nullptr) {
            (void)::acl_free(value);
        }
    }
};

inline auto failure(const char* operation) -> std::unexpected<std::string> {
    const int saved = errno;
    return std::unexpected(
        std::string{operation} + ": " + std::error_code{saved, std::generic_category()}.message()
    );
}
} // namespace acl_detail
#endif

// POSIX mode checks remain mandatory at the caller. Darwin allow ACEs are
// independent of chmod bits. Deny ACEs are harmless restrictions; allow ACEs
// are conservatively rejected without resolving principal/group membership.
[[nodiscard]] inline auto check_descriptor_acl(int fd, acl_scope scope)
    -> std::expected<void, std::string> {
    if (scope != acl_scope::owner_private && scope != acl_scope::integrity) {
        return std::unexpected("unknown descriptor ACL scope");
    }
#if defined(__APPLE__)
    acl_detail::owned_acl acl{::acl_get_fd_np(fd, ACL_TYPE_EXTENDED)};
    if (acl.value == nullptr) {
        // Darwin also reports ENOENT for an absent extended ACL. Distinguish
        // that from an invalid/detached descriptor; named binding checks stay
        // with the caller. Unsupported/denied retrieval is not absence.
        const int acl_error = errno;
        struct stat present{};
        if (acl_error == ENOENT && ::fstat(fd, &present) == 0 && present.st_nlink != 0) {
            return {};
        }
        errno = acl_error;
        return acl_detail::failure("read descriptor ACL");
    }
    if (::acl_valid(acl.value) != 0) {
        return acl_detail::failure("validate descriptor ACL");
    }
    constexpr acl_permset_mask_t read_only = ACL_READ_DATA | ACL_EXECUTE | ACL_READ_ATTRIBUTES |
                                             ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY |
                                             ACL_SYNCHRONIZE;
    // Darwin documents numeric entry indices and EINVAL at the end of a valid
    // ACL. The local validated copy cannot change during this bounded walk.
    for (int index = 0; index <= ACL_MAX_ENTRIES; ++index) {
        acl_entry_t entry{};
        errno = 0;
        if (::acl_get_entry(acl.value, index, &entry) != 0) {
            if (errno == EINVAL) {
                return {};
            }
            return acl_detail::failure("enumerate descriptor ACL");
        }
        if (index == ACL_MAX_ENTRIES) {
            return std::unexpected("descriptor ACL exceeds entry bound");
        }
        acl_tag_t tag{};
        if (::acl_get_tag_type(entry, &tag) != 0) {
            return acl_detail::failure("inspect descriptor ACL tag");
        }
        if (tag == ACL_EXTENDED_DENY) {
            continue;
        }
        if (tag != ACL_EXTENDED_ALLOW) {
            return std::unexpected("unknown descriptor ACL entry type");
        }
        acl_permset_mask_t permissions = 0;
        if (::acl_get_permset_mask_np(entry, &permissions) != 0) {
            return acl_detail::failure("inspect descriptor ACL permissions");
        }
        if (scope == acl_scope::owner_private || (permissions & ~read_only) != 0) {
            return std::unexpected("descriptor ACL grants additional private or write authority");
        }
    }
    return std::unexpected("descriptor ACL enumeration unresolved");
#else
    // Linux POSIX named-user/group ACL access is restricted by the group-class
    // mode mask. The caller's owner-only/no-extra-write mode checks enforce it;
    // this is not an active POSIX ACL audit or evidence for another ACL model.
    (void)fd;
    (void)scope;
    return {};
#endif
}

// ONLY for an exclusively created, descriptor-proven owned object. Existing
// unsafe entries are rejected, never silently repaired into launch authority.
[[nodiscard]] inline auto clear_created_descriptor_acl(int fd) -> std::expected<void, std::string> {
#if defined(__APPLE__)
    acl_detail::owned_acl empty{::acl_init(0)};
    if (empty.value == nullptr || ::acl_set_fd_np(fd, empty.value, ACL_TYPE_EXTENDED) != 0) {
        return acl_detail::failure("clear exclusively created descriptor ACL");
    }
    return check_descriptor_acl(fd, acl_scope::owner_private);
#else
    (void)fd;
    return {};
#endif
}

} // namespace glove::detail
