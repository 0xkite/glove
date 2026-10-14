#pragma once

#if defined(__APPLE__)
#    include <fcntl.h>
#    include <membership.h>
#    include <sys/acl.h>
#    include <unistd.h>

#    include <cerrno>
#    include <filesystem>

namespace glove::test {

// Synthetic named-UID authority only; never execute or impersonate that UID.
inline auto set_fixture_acl(
    const std::filesystem::path& path,
    bool directory,
    acl_tag_t tag = ACL_EXTENDED_ALLOW,
    bool read_only = false,
    bool symbolic_link = false
) -> bool {
    struct acl_owner {
        acl_t value = ::acl_init(1);
        acl_owner() = default;
        acl_owner(const acl_owner&) = delete;
        auto operator=(const acl_owner&) -> acl_owner& = delete;

        ~acl_owner() {
            if (value != nullptr) {
                (void)::acl_free(value);
            }
        }
    } acl;

    acl_entry_t entry{};
    uuid_t principal{};
    if (acl.value == nullptr || ::mbr_uid_to_uuid(65534, principal) != 0 ||
        ::acl_create_entry(&acl.value, &entry) != 0 || ::acl_set_tag_type(entry, tag) != 0 ||
        ::acl_set_qualifier(entry, principal) != 0) {
        return false;
    }
    acl_permset_mask_t permissions = ACL_READ_DATA | ACL_EXECUTE | ACL_READ_ATTRIBUTES |
                                     ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY;
    if (!read_only) {
        permissions |= ACL_WRITE_DATA | ACL_APPEND_DATA | ACL_DELETE | ACL_DELETE_CHILD |
                       ACL_WRITE_ATTRIBUTES | ACL_WRITE_EXTATTRIBUTES | ACL_WRITE_SECURITY |
                       ACL_CHANGE_OWNER;
    }
    if (::acl_set_permset_mask_np(entry, permissions) != 0) {
        return false;
    }
    if (directory) {
        acl_flagset_t flags{};
        if (::acl_get_flagset_np(entry, &flags) != 0 ||
            ::acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT) != 0 ||
            ::acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT) != 0) {
            return false;
        }
    }
    if (directory && symbolic_link) {
        return false;
    }
    const int fd = ::open(
        path.c_str(),
        O_RDONLY | O_CLOEXEC | O_NONBLOCK | (symbolic_link ? O_SYMLINK : O_NOFOLLOW) |
            (directory ? O_DIRECTORY : 0)
    );
    if (fd < 0) {
        return false;
    }
    const bool applied = ::acl_set_fd_np(fd, acl.value, ACL_TYPE_EXTENDED) == 0;
    return ::close(fd) == 0 && applied;
}

inline auto fixture_acl_empty(const std::filesystem::path& path, bool directory) -> bool {
    const int fd = ::open(
        path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (directory ? O_DIRECTORY : 0)
    );
    if (fd < 0) {
        return false;
    }
    errno = 0;
    acl_t acl = ::acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    bool empty = false;
    if (acl != nullptr) {
        acl_entry_t entry{};
        empty = ::acl_get_entry(acl, 0, &entry) != 0 && errno == EINVAL;
        (void)::acl_free(acl);
    } else {
        empty = errno == ENOENT;
    }
    return ::close(fd) == 0 && empty;
}

} // namespace glove::test
#endif
