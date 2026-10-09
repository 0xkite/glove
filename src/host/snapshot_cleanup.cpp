#include "snapshot_cleanup.hpp"

#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <utility>

namespace glove::host::snapshot {
namespace {

// Content entries, closure wrappers, and the payload directory; root is extra.
constexpr std::size_t max_entries = 200'000U + 64U + 1U;
constexpr std::size_t max_depth = 130U;
constexpr std::size_t max_name_bytes = 255U;
constexpr int directory_flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

struct borrowed_descriptor {
    int value;
};

class descriptor {
public:
    explicit descriptor(int value) noexcept : value_{value} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    descriptor(descriptor&& other) noexcept : value_{std::exchange(other.value_, -1)} {}

    auto operator=(descriptor&& other) noexcept -> descriptor& {
        if (this != &other) {
            descriptor previous{std::exchange(value_, std::exchange(other.value_, -1))};
        }
        return *this;
    }

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto borrow() const noexcept -> borrowed_descriptor { return {value_}; }

    auto release() noexcept -> int { return std::exchange(value_, -1); }

private:
    int value_;
};

struct directory_closer {
    void operator()(DIR* value) const noexcept { (void)::closedir(value); }
};

using directory_stream = std::unique_ptr<DIR, directory_closer>;
using identity = std::pair<dev_t, ino_t>;

auto failure(std::string_view operation) -> std::unexpected<std::string> {
    const int saved = errno;
    return std::unexpected(
        std::string{operation} + ": " + std::error_code{saved, std::generic_category()}.message()
    );
}

auto valid_name(std::string_view name) noexcept -> bool {
    return !name.empty() && name.size() <= max_name_bytes && name != "." && name != ".." &&
           name.find('/') == std::string_view::npos && name.find('\0') == std::string_view::npos;
}

auto private_directory(const struct stat& metadata, uid_t owner) noexcept -> bool {
    const auto mode = metadata.st_mode & 07777U;
    return S_ISDIR(metadata.st_mode) && metadata.st_uid == owner && metadata.st_nlink != 0 &&
           (mode == 0700U || mode == 0500U);
}

auto same_identity(const struct stat& left, const struct stat& right) noexcept -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_uid == right.st_uid && left.st_gid == right.st_gid &&
           left.st_mode == right.st_mode;
}

auto same_entry(const struct stat& left, const struct stat& right) noexcept -> bool {
    if (!same_identity(left, right) || left.st_nlink != right.st_nlink ||
        left.st_size != right.st_size) {
        return false;
    }
#if defined(__APPLE__)
    return left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
           left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
           left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
#else
    return left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
           left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
#endif
}

struct directory_frame {
    borrowed_descriptor parent;
    borrowed_descriptor directory;
    const char* name;
    struct stat expected;
    const directory_frame* ancestor;
};

struct cleanup_context {
    borrowed_descriptor parent;
    borrowed_descriptor owned_root;
    struct stat parent_identity;
    uid_t owner;
    dev_t device;
    std::size_t entries = 0;
    std::set<identity> directories;
};

auto check_parent(const cleanup_context& context) -> result<void> {
    struct stat parent{};
    if (::fstat(context.parent.value, &parent) != 0) {
        return failure("reinspect snapshot cleanup parent");
    }
    if (!same_identity(parent, context.parent_identity) ||
        !private_directory(parent, context.owner) || (parent.st_mode & 07777U) != 0700U) {
        return std::unexpected(std::string{"snapshot cleanup parent changed or is unsafe"});
    }
    return detail::check_descriptor_acl(context.parent.value, detail::acl_scope::owner_private);
}

// Directory size, timestamps, and link counts change as our children disappear.
// Every ancestor edge is rechecked so a detached subtree is not mutated merely
// because its descriptor remains usable. No check is an atomic unlink guard.
auto check_attached(const cleanup_context& context, const directory_frame& frame) -> result<void> {
    if (auto checked = check_parent(context); !checked) {
        return checked;
    }
    for (const auto* current = &frame; current != nullptr; current = current->ancestor) {
        struct stat opened{};
        struct stat named{};
        if (::fstat(current->directory.value, &opened) != 0 ||
            ::fstatat(current->parent.value, current->name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("reinspect attached snapshot cleanup directory");
        }
        if (!same_identity(current->expected, opened) || !same_identity(opened, named) ||
            !private_directory(opened, context.owner) || !private_directory(named, context.owner)) {
            return std::unexpected(std::string{"snapshot cleanup directory identity changed"});
        }
        if (auto acl = detail::check_descriptor_acl(
                current->directory.value, detail::acl_scope::integrity
            );
            !acl) {
            return acl;
        }
        if (current->ancestor == nullptr) {
            struct stat owned{};
            if (::fstat(context.owned_root.value, &owned) != 0) {
                return failure("reinspect owned snapshot cleanup root");
            }
            if (!same_identity(opened, owned) || !private_directory(owned, context.owner)) {
                return std::unexpected(std::string{"snapshot cleanup owned root changed"});
            }
            if (auto acl = detail::check_descriptor_acl(
                    context.owned_root.value, detail::acl_scope::integrity
                );
                !acl) {
                return acl;
            }
        }
    }
    return {};
}

auto open_directory(borrowed_descriptor parent, const char* name, const struct stat& expected)
    -> result<descriptor> {
    descriptor opened{::openat(parent.value, name, directory_flags)};
    if (opened.borrow().value < 0) {
        return failure("open snapshot cleanup directory without following links");
    }
    struct stat actual{};
    struct stat named{};
    if (::fstat(opened.borrow().value, &actual) != 0 ||
        ::fstatat(parent.value, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect opened snapshot cleanup directory");
    }
    if (!same_entry(expected, actual) || !same_entry(actual, named)) {
        return std::unexpected(std::string{"snapshot cleanup directory changed on open"});
    }
    return opened;
}

auto enumerate(const directory_frame& frame) -> result<directory_stream> {
    // A fresh open description avoids sharing the caller's directory offset.
    auto enumeration = open_directory(frame.directory, ".", frame.expected);
    if (!enumeration) {
        return std::unexpected(enumeration.error());
    }
    directory_stream stream{::fdopendir(enumeration->borrow().value)};
    if (!stream) {
        return failure("enumerate snapshot cleanup directory");
    }
    (void)enumeration->release();
    return stream;
}

auto check_absent(borrowed_descriptor parent, const char* name) -> result<void> {
    struct stat remaining{};
    if (::fstatat(parent.value, name, &remaining, AT_SYMLINK_NOFOLLOW) == 0) {
        return std::unexpected(std::string{"snapshot cleanup entry replaced after removal"});
    }
    if (errno != ENOENT) {
        return failure("verify snapshot cleanup entry removal");
    }
    return {};
}

auto open_leaf(
    const cleanup_context& context,
    const directory_frame& parent,
    const char* name,
    const struct stat& before
) -> result<descriptor> {
    const bool link = S_ISLNK(before.st_mode);
    const auto mode = before.st_mode & 07777U;
    // Symlink permissions do not grant target access and are commonly 0777.
    // Only the owner/single-link inode is unlinked; its target is never opened.
    if (before.st_uid != context.owner || before.st_dev != context.device || before.st_nlink != 1 ||
        (!link && (!S_ISREG(before.st_mode) ||
                   (mode != 0600U && mode != 0700U && mode != 0400U && mode != 0500U))) ||
        (link && (before.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0)) {
        return std::unexpected(std::string{"snapshot cleanup refuses unsafe or aliased entry"});
    }
    descriptor opened{
        link
            ? -1
            : ::openat(parent.directory.value, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    };
    if (!link) {
        if (opened.borrow().value < 0) {
            return failure("open snapshot cleanup file without following links");
        }
        struct stat actual{};
        if (::fstat(opened.borrow().value, &actual) != 0) {
            return failure("inspect opened snapshot cleanup file");
        }
        if (!same_entry(before, actual)) {
            return std::unexpected(std::string{"snapshot cleanup file changed on open"});
        }
    }
    return opened;
}

auto check_leaf(
    const directory_frame& parent,
    const char* name,
    const struct stat& before,
    borrowed_descriptor opened
) -> result<void> {
    if (S_ISLNK(before.st_mode)) {
        if (auto checked = detail::check_symlink_acl_at(parent.directory.value, name, before);
            !checked) {
            return checked;
        }
    } else {
        struct stat actual{};
        if (::fstat(opened.value, &actual) != 0) {
            return failure("reinspect opened snapshot cleanup file");
        }
        if (!same_entry(before, actual)) {
            return std::unexpected(std::string{"snapshot cleanup opened file changed"});
        }
        if (auto acl = detail::check_descriptor_acl(opened.value, detail::acl_scope::integrity);
            !acl) {
            return acl;
        }
    }
    struct stat named{};
    if (::fstatat(parent.directory.value, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("reinspect snapshot cleanup leaf before removal");
    }
    if (!same_entry(before, named)) {
        return std::unexpected(std::string{"snapshot cleanup leaf changed before removal"});
    }
    return {};
}

auto remove_leaf(
    const cleanup_context& context,
    const directory_frame& parent,
    const char* name,
    const struct stat& before
) -> result<void> {
    auto opened = open_leaf(context, parent, name, before);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    if (auto attached = check_attached(context, parent); !attached) {
        return attached;
    }
    if (auto checked = check_leaf(parent, name, before, opened->borrow()); !checked) {
        return checked;
    }
    if (::unlinkat(parent.directory.value, name, 0) != 0) {
        return failure("unlink snapshot cleanup leaf");
    }
    if (auto absent = check_absent(parent.directory, name); !absent) {
        return absent;
    }
    if (!S_ISLNK(before.st_mode)) {
        struct stat after{};
        if (::fstat(opened->borrow().value, &after) != 0) {
            return failure("inspect removed snapshot cleanup file");
        }
        if (!same_identity(before, after) || after.st_nlink != 0) {
            return std::unexpected(std::string{"snapshot cleanup removed file identity changed"});
        }
        if (::close(opened->release()) != 0) {
            return failure("close snapshot cleanup file");
        }
    }
    return check_attached(context, parent);
}

auto count_entry(cleanup_context& context, std::string_view name, std::size_t depth)
    -> result<void> {
    if (!valid_name(name) || depth >= max_depth || context.entries >= max_entries) {
        return std::unexpected(std::string{"snapshot cleanup exceeds entry or depth bound"});
    }
    ++context.entries;
    return {};
}

auto open_child(
    cleanup_context& context,
    const directory_frame& frame,
    const char* name,
    const struct stat& before
) -> result<descriptor> {
    if (!private_directory(before, context.owner) || before.st_dev != context.device ||
        !context.directories.emplace(before.st_dev, before.st_ino).second) {
        return std::unexpected(std::string{"snapshot cleanup refuses unsafe or aliased directory"});
    }
    return open_directory(frame.directory, name, before);
}

// Discover all existing unsafe entries before restoring modes or removing any
// sibling. This pass is read-only and uses the destructive walk's exact bounds
// and admission checks. Later rechecks detect drift, not same-UID atomicity.
auto preflight_directory(cleanup_context& context, const directory_frame& frame, std::size_t depth)
    -> result<void> {
    if (auto attached = check_attached(context, frame); !attached) {
        return attached;
    }
    auto stream = enumerate(frame);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream->get());
        if (entry == nullptr) {
            if (errno != 0) {
                return failure("read snapshot cleanup preflight directory");
            }
            break;
        }
        const auto length = ::strnlen(entry->d_name, sizeof(entry->d_name));
        if (length == sizeof(entry->d_name)) {
            return std::unexpected(std::string{"snapshot cleanup entry name is unbounded"});
        }
        const std::string_view name{entry->d_name, length};
        if (name == "." || name == "..") {
            continue;
        }
        if (auto counted = count_entry(context, name, depth); !counted) {
            return counted;
        }
        struct stat before{};
        if (::fstatat(frame.directory.value, entry->d_name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect snapshot cleanup preflight entry");
        }
        if (S_ISDIR(before.st_mode)) {
            auto child = open_child(context, frame, entry->d_name, before);
            if (!child) {
                return std::unexpected(child.error());
            }
            const directory_frame child_frame{
                frame.directory, child->borrow(), entry->d_name, before, &frame
            };
            if (auto checked = preflight_directory(context, child_frame, depth + 1U); !checked) {
                return checked;
            }
            if (::close(child->release()) != 0) {
                return failure("close snapshot cleanup preflight directory");
            }
        } else {
            auto leaf = open_leaf(context, frame, entry->d_name, before);
            if (!leaf) {
                return std::unexpected(leaf.error());
            }
            if (auto attached = check_attached(context, frame); !attached) {
                return attached;
            }
            if (auto checked = check_leaf(frame, entry->d_name, before, leaf->borrow()); !checked) {
                return checked;
            }
            if (leaf->borrow().value >= 0 && ::close(leaf->release()) != 0) {
                return failure("close snapshot cleanup preflight file");
            }
        }
    }
    if (::closedir(stream->release()) != 0) {
        return failure("close snapshot cleanup preflight enumeration");
    }
    struct stat after{};
    if (::fstat(frame.directory.value, &after) != 0) {
        return failure("reinspect snapshot cleanup preflight directory");
    }
    if (!same_entry(frame.expected, after)) {
        return std::unexpected(std::string{"snapshot cleanup directory changed during preflight"});
    }
    return check_attached(context, frame);
}

auto remove_directory(cleanup_context& context, directory_frame& frame, std::size_t depth)
    -> result<void> {
    if (auto attached = check_attached(context, frame); !attached) {
        return attached;
    }
    if ((frame.expected.st_mode & 07777U) == 0500U) {
        if (::fchmod(frame.directory.value, 0700) != 0) {
            return failure("restore snapshot cleanup owner directory permissions");
        }
        frame.expected.st_mode = (frame.expected.st_mode & ~static_cast<mode_t>(07777U)) | 0700U;
        if (auto attached = check_attached(context, frame); !attached) {
            return attached;
        }
    }
    // Refresh timestamps after our chmod, without accepting identity drift.
    struct stat writable{};
    if (::fstat(frame.directory.value, &writable) != 0) {
        return failure("inspect writable snapshot cleanup directory");
    }
    if (!same_identity(frame.expected, writable) || !private_directory(writable, context.owner)) {
        return std::unexpected(
            std::string{"snapshot cleanup directory changed before enumeration"}
        );
    }
    frame.expected = writable;
    auto stream = enumerate(frame);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream->get());
        if (entry == nullptr) {
            if (errno != 0) {
                return failure("read snapshot cleanup directory");
            }
            break;
        }
        const auto length = ::strnlen(entry->d_name, sizeof(entry->d_name));
        if (length == sizeof(entry->d_name)) {
            return std::unexpected(std::string{"snapshot cleanup entry name is unbounded"});
        }
        const std::string_view name{entry->d_name, length};
        if (name == "." || name == "..") {
            continue;
        }
        if (auto counted = count_entry(context, name, depth); !counted) {
            return counted;
        }
        // readdir storage is owned by this stream and survives child recursion.
        struct stat before{};
        if (::fstatat(frame.directory.value, entry->d_name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect snapshot cleanup entry");
        }
        if (!S_ISDIR(before.st_mode)) {
            if (auto removed = remove_leaf(context, frame, entry->d_name, before); !removed) {
                return removed;
            }
            continue;
        }
        auto child = open_child(context, frame, entry->d_name, before);
        if (!child) {
            return std::unexpected(child.error());
        }
        directory_frame child_frame{
            frame.directory, child->borrow(), entry->d_name, before, &frame
        };
        if (auto removed = remove_directory(context, child_frame, depth + 1U); !removed) {
            return removed;
        }
        if (::close(child->release()) != 0) {
            return failure("close snapshot cleanup directory");
        }
    }
    if (::closedir(stream->release()) != 0) {
        return failure("close snapshot cleanup enumeration");
    }
    if (auto attached = check_attached(context, frame); !attached) {
        return attached;
    }
    struct stat before_removal{};
    if (::fstat(frame.directory.value, &before_removal) != 0) {
        return failure("inspect snapshot cleanup directory before removal");
    }
    if (!same_identity(frame.expected, before_removal)) {
        return std::unexpected(std::string{"snapshot cleanup directory changed before removal"});
    }
    if (::unlinkat(frame.parent.value, frame.name, AT_REMOVEDIR) != 0) {
        return failure("remove snapshot cleanup directory");
    }
    if (auto absent = check_absent(frame.parent, frame.name); !absent) {
        return absent;
    }
    struct stat after{};
    if (::fstat(frame.directory.value, &after) != 0) {
        return failure("inspect removed snapshot cleanup directory");
    }
    bool removed_links = after.st_nlink == 0;
#if defined(__APPLE__)
    // Darwin retains the pre-rmdir link count on an open directory descriptor.
    // Successful rmdir and checked named absence establish namespace removal;
    // the pinned descriptor must still identify the same private directory.
    removed_links = removed_links || after.st_nlink == before_removal.st_nlink;
#endif
    if (!same_identity(frame.expected, after) || !removed_links) {
        return std::unexpected(std::string{"snapshot cleanup removed directory identity changed"});
    }
    return frame.ancestor != nullptr ? check_attached(context, *frame.ancestor)
                                     : check_parent(context);
}

} // namespace

auto remove_owned_staging_tree(int parent_fd, std::string_view name, int owned_root_fd)
    -> result<void> {
    if (parent_fd < 0 || owned_root_fd < 0 || !valid_name(name)) {
        return std::unexpected(
            std::string{"snapshot cleanup requires pinned descriptors and one name"}
        );
    }
    const std::string root_name{name};
    const borrowed_descriptor parent{parent_fd};
    const borrowed_descriptor owned_root{owned_root_fd};
    struct stat parent_metadata{};
    struct stat root_metadata{};
    struct stat named{};
    if (::fstat(parent.value, &parent_metadata) != 0 ||
        ::fstat(owned_root.value, &root_metadata) != 0 ||
        ::fstatat(parent.value, root_name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect owned snapshot cleanup root and parent");
    }
    const auto owner = ::geteuid();
    if (!private_directory(parent_metadata, owner) || (parent_metadata.st_mode & 07777U) != 0700U ||
        !private_directory(root_metadata, owner) || !same_entry(root_metadata, named) ||
        parent_metadata.st_dev != root_metadata.st_dev ||
        parent_metadata.st_ino == root_metadata.st_ino) {
        return std::unexpected(
            std::string{"snapshot cleanup root identity or private ownership is unsafe"}
        );
    }
    auto root = open_directory(parent, root_name.c_str(), root_metadata);
    if (!root) {
        return std::unexpected(root.error());
    }
    cleanup_context context{
        parent, owned_root, parent_metadata, owner, root_metadata.st_dev, 0, {}
    };
    context.directories.emplace(parent_metadata.st_dev, parent_metadata.st_ino);
    context.directories.emplace(root_metadata.st_dev, root_metadata.st_ino);
    directory_frame frame{parent, root->borrow(), root_name.c_str(), root_metadata, nullptr};
    if (auto checked = preflight_directory(context, frame, 0U); !checked) {
        return checked;
    }
    context.entries = 0;
    context.directories.clear();
    context.directories.emplace(parent_metadata.st_dev, parent_metadata.st_ino);
    context.directories.emplace(root_metadata.st_dev, root_metadata.st_ino);
    if (auto removed = remove_directory(context, frame, 0U); !removed) {
        return removed;
    }
    if (::close(root->release()) != 0) {
        return failure("close snapshot cleanup root");
    }
    return {};
}

} // namespace glove::host::snapshot
