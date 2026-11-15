#include "snapshot_copy.hpp"

#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iterator>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::host::snapshot {
namespace {

constexpr std::uint64_t max_bytes = std::uint64_t{2} * 1024U * 1024U * 1024U;
constexpr std::uint64_t max_entries = 200'000U;
constexpr std::size_t max_path_bytes = 4096U;
constexpr std::size_t max_depth = 128U;
constexpr int source_flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

class descriptor {
public:
    explicit descriptor(int value = -1) noexcept : value_{value} {}

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

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

    auto release() noexcept -> int { return std::exchange(value_, -1); }

private:
    int value_;
};

struct directory_closer {
    void operator()(DIR* value) const noexcept { (void)::closedir(value); }
};

using directory_stream = std::unique_ptr<DIR, directory_closer>;

auto failure(std::string_view operation) -> std::unexpected<std::string> {
    const int saved = errno;
    return std::unexpected(
        std::string{operation} + ": " + std::error_code{saved, std::generic_category()}.message()
    );
}

auto enumerate(int directory) -> result<directory_stream> {
    descriptor duplicate{::fcntl(directory, F_DUPFD_CLOEXEC, 3)};
    if (duplicate.get() < 0) {
        return failure("duplicate runtime snapshot directory");
    }
    directory_stream stream{::fdopendir(duplicate.get())};
    if (!stream) {
        return failure("enumerate runtime snapshot directory");
    }
    (void)duplicate.release();
    return stream;
}

auto same_object(const struct stat& left, const struct stat& right) noexcept -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
           left.st_gid == right.st_gid && left.st_nlink == right.st_nlink &&
           left.st_size == right.st_size;
}

auto same_version(const struct stat& left, const struct stat& right) noexcept -> bool {
#if defined(__APPLE__)
    return same_object(left, right) && left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
           left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
           left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
#else
    return same_object(left, right) && left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
           left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
#endif
}

auto bounded_path(const std::filesystem::path& path) -> bool {
    return !path.empty() && path.native().size() <= max_path_bytes &&
           path.native().find('\0') == std::string::npos && path.is_absolute() &&
           path != path.root_path() && path.lexically_normal() == path;
}

auto within(const std::filesystem::path& path, const std::filesystem::path& root) -> bool {
    return std::mismatch(root.begin(), root.end(), path.begin(), path.end()).first == root.end();
}

auto open_checked(int parent, const char* name, const struct stat& expected) -> result<descriptor> {
    descriptor opened{
        ::openat(parent, name, source_flags | (S_ISDIR(expected.st_mode) ? O_DIRECTORY : 0))
    };
    if (opened.get() < 0) {
        return failure("open runtime snapshot source without following links");
    }
    struct stat actual{};
    if (::fstat(opened.get(), &actual) != 0) {
        return failure("inspect opened runtime snapshot source");
    }
    if (!same_version(expected, actual)) {
        return std::unexpected(std::string{"runtime snapshot source identity changed on open"});
    }
    return opened;
}

// Walk every component, not just the final one. Source ancestors may be
// group-writable discovery input; destination ancestors must remain trusted.
auto open_parent(const std::filesystem::path& path, bool protected_destination)
    -> result<descriptor> {
    descriptor current{::open("/", source_flags | O_DIRECTORY)};
    if (current.get() < 0) {
        return failure("open runtime snapshot filesystem root");
    }
    if (protected_destination) {
        if (auto acl = glove::detail::check_descriptor_acl(
                current.get(), glove::detail::acl_scope::integrity
            );
            !acl) {
            return std::unexpected(acl.error());
        }
    }
    for (const auto& component : path.parent_path().relative_path()) {
        struct stat metadata{};
        if (::fstatat(current.get(), component.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect runtime snapshot ancestor");
        }
        const bool sticky_root = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
        if (!S_ISDIR(metadata.st_mode) ||
            (protected_destination &&
             ((metadata.st_uid != 0 && metadata.st_uid != ::geteuid()) ||
              ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !sticky_root)))) {
            return std::unexpected(std::string{"runtime snapshot ancestor is unsafe"});
        }
        auto next = open_checked(current.get(), component.c_str(), metadata);
        if (!next) {
            return std::unexpected(next.error());
        }
        if (protected_destination) {
            if (auto acl = glove::detail::check_descriptor_acl(
                    next->get(), glove::detail::acl_scope::integrity
                );
                !acl) {
                return std::unexpected(acl.error());
            }
        }
        current = std::move(*next);
    }
    return current;
}

auto create_directory(int parent, const char* name) -> result<descriptor> {
    if (auto acl =
            glove::detail::check_descriptor_acl(parent, glove::detail::acl_scope::owner_private);
        !acl) {
        return std::unexpected(acl.error());
    }
    if (::mkdirat(parent, name, 0700) != 0) {
        return failure("create exclusive runtime snapshot directory");
    }
    struct stat metadata{};
    if (::fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect created runtime snapshot directory");
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (metadata.st_mode & 07777U) != 0700U) {
        return std::unexpected(std::string{"created runtime snapshot directory is unsafe"});
    }
    auto opened = open_checked(parent, name, metadata);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    if (auto acl = glove::detail::clear_created_descriptor_acl(opened->get()); !acl) {
        return std::unexpected(acl.error());
    }
    struct stat named{};
    struct stat current{};
    if (::fstat(opened->get(), &current) != 0 ||
        ::fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_object(current, named) ||
        current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino ||
        current.st_uid != metadata.st_uid || current.st_mode != metadata.st_mode) {
        return std::unexpected(std::string{"created runtime snapshot directory binding changed"});
    }
    return opened;
}

struct budget {
    std::uint64_t bytes;
    std::uint64_t entries;
};

auto copy_file(
    int source,
    int destination_parent,
    const char* name,
    const struct stat& before,
    budget& remaining
) -> result<void> {
    if (before.st_nlink != 1 || before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > remaining.bytes) {
        return std::unexpected(
            std::string{"runtime snapshot file exceeds its budget or is aliased"}
        );
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            destination_parent, glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    descriptor destination{::openat(
        destination_parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    )};
    if (destination.get() < 0) {
        return failure("create exclusive runtime snapshot file");
    }
    struct stat created{};
    if (::fstat(destination.get(), &created) != 0) {
        return failure("inspect created runtime snapshot file");
    }
    if (!S_ISREG(created.st_mode) || created.st_uid != ::geteuid() || created.st_nlink != 1 ||
        created.st_size != 0 || (created.st_mode & 07777U) != 0600U) {
        return std::unexpected(std::string{"created runtime snapshot file is unsafe"});
    }
    struct stat named_created{};
    if (::fstatat(destination_parent, name, &named_created, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(created, named_created)) {
        return std::unexpected(std::string{"created runtime snapshot file binding changed"});
    }
    if (auto acl = glove::detail::clear_created_descriptor_acl(destination.get()); !acl) {
        return std::unexpected(acl.error());
    }
    std::array<char, 64U * 1024U> buffer{};
    auto unread = static_cast<std::uint64_t>(before.st_size);
    while (unread != 0) {
        const auto wanted =
            static_cast<std::size_t>(std::min<std::uint64_t>(unread, buffer.size()));
        const auto count = ::read(source, buffer.data(), wanted);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return failure("read runtime snapshot file");
        }
        if (count == 0) {
            return std::unexpected(std::string{"runtime snapshot file shrank during copy"});
        }
        const auto available = static_cast<std::size_t>(count);
        if (static_cast<std::uint64_t>(available) > remaining.bytes) {
            return std::unexpected(std::string{"runtime snapshot exceeds its planned byte budget"});
        }
        // Charge before writing, including partially written chunks on failure.
        remaining.bytes -= static_cast<std::uint64_t>(available);
        for (std::size_t offset = 0; offset < available;) {
            const auto written =
                ::write(destination.get(), buffer.data() + offset, available - offset);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                return failure("write runtime snapshot file");
            }
            offset += static_cast<std::size_t>(written);
        }
        unread -= static_cast<std::uint64_t>(available);
    }
    // Probe for growth, but never write bytes beyond the initial admitted size.
    ssize_t extra = 0;
    do {
        extra = ::read(source, buffer.data(), 1U);
    } while (extra < 0 && errno == EINTR);
    if (extra < 0) {
        return failure("check runtime snapshot file growth");
    }
    struct stat after{};
    if (::fstat(source, &after) != 0) {
        return failure("reinspect runtime snapshot source file");
    }
    if (extra != 0 || !S_ISREG(after.st_mode) || after.st_nlink != 1 ||
        !same_version(before, after)) {
        return std::unexpected(std::string{"runtime snapshot file changed during copy"});
    }
    if ((before.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 &&
        ::fchmod(destination.get(), 0700) != 0) {
        return failure("preserve runtime snapshot executable bit");
    }
    struct stat completed{};
    struct stat named_completed{};
    if (::fstat(destination.get(), &completed) != 0 ||
        ::fstatat(destination_parent, name, &named_completed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(completed, named_completed) || completed.st_dev != created.st_dev ||
        completed.st_ino != created.st_ino || completed.st_uid != ::geteuid() ||
        completed.st_nlink != 1 || completed.st_size != before.st_size ||
        !glove::detail::check_descriptor_acl(
            destination.get(), glove::detail::acl_scope::owner_private
        )) {
        return std::unexpected(std::string{"completed runtime snapshot file authority changed"});
    }
    if (::close(destination.release()) != 0) {
        return failure("close runtime snapshot destination file");
    }
    return {};
}

// Resolve a link's target by explicitly walking from its pinned source root.
// No kernel symlink traversal is permitted. Expand bounded link chains through
// pinned directories instead of canonicalizing mutable discovery paths.
// Process '..' before continuing the walk so
// a symlink/../ suffix cannot be normalized into apparent safety.
auto check_link_target(
    int root,
    const std::filesystem::path& relative_parent,
    const std::filesystem::path& target,
    std::size_t followed_links = 0
) -> result<void> {
    std::vector<descriptor> directories;
    descriptor duplicate{::fcntl(root, F_DUPFD_CLOEXEC, 3)};
    if (duplicate.get() < 0) {
        return failure("duplicate runtime snapshot link boundary");
    }
    directories.push_back(std::move(duplicate));
    const auto walk = relative_parent / target;
    std::filesystem::path walked;
    for (auto component = walk.begin(); component != walk.end(); ++component) {
        if (*component == "." || component->empty()) {
            continue;
        }
        if (*component == "..") {
            if (directories.size() == 1U) {
                return std::unexpected(
                    std::string{"runtime snapshot symbolic link escapes its root"}
                );
            }
            directories.pop_back();
            walked = walked.parent_path();
            continue;
        }
        struct stat metadata{};
        if (::fstatat(
                directories.back().get(), component->c_str(), &metadata, AT_SYMLINK_NOFOLLOW
            ) != 0) {
            return failure("inspect runtime snapshot symbolic link target");
        }
        if (S_ISLNK(metadata.st_mode)) {
            if (followed_links >= 32U || metadata.st_nlink != 1) {
                return std::unexpected(
                    std::string{"runtime snapshot link chain exceeds its bound or is aliased"}
                );
            }
            std::array<char, max_path_bytes + 1U> bytes{};
            const auto size = ::readlinkat(
                directories.back().get(), component->c_str(), bytes.data(), bytes.size()
            );
            if (size <= 0 || static_cast<std::size_t>(size) > max_path_bytes) {
                return std::unexpected(
                    std::string{"runtime snapshot link chain target is unbounded"}
                );
            }
            const std::string value{bytes.data(), static_cast<std::size_t>(size)};
            const std::filesystem::path link{value};
            if (link.is_absolute() || value.find('\0') != std::string::npos) {
                return std::unexpected(std::string{"runtime snapshot link chain is unsafe"});
            }
            auto expanded = walked / link;
            for (auto suffix = std::next(component); suffix != walk.end(); ++suffix) {
                expanded /= *suffix;
            }
            if (expanded.native().size() > max_path_bytes) {
                return std::unexpected(
                    std::string{"runtime snapshot expanded link exceeds its path bound"}
                );
            }
            struct stat after{};
            if (::fstatat(
                    directories.back().get(), component->c_str(), &after, AT_SYMLINK_NOFOLLOW
                ) != 0 ||
                !same_version(metadata, after)) {
                return std::unexpected(std::string{"runtime snapshot link chain changed"});
            }
            return check_link_target(root, {}, expanded, followed_links + 1U);
        }
        const bool is_directory = S_ISDIR(metadata.st_mode);
        if ((!is_directory && (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)) ||
            (!is_directory && std::next(component) != walk.end())) {
            return std::unexpected(std::string{"runtime snapshot symbolic link target is unsafe"});
        }
        auto opened = open_checked(directories.back().get(), component->c_str(), metadata);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (is_directory) {
            if (directories.size() > max_depth) {
                return std::unexpected(
                    std::string{"runtime snapshot link target exceeds depth bound"}
                );
            }
            directories.push_back(std::move(*opened));
            walked /= *component;
        }
    }
    return {};
}

auto copy_link(
    int source_parent,
    int destination_parent,
    const char* name,
    const struct stat& before,
    int root,
    const std::filesystem::path& relative_parent
) -> result<void> {
    std::array<char, max_path_bytes + 1U> bytes{};
    const auto count = ::readlinkat(source_parent, name, bytes.data(), bytes.size());
    if (count < 0) {
        return failure("read runtime snapshot symbolic link");
    }
    if (count == 0 || static_cast<std::size_t>(count) > max_path_bytes || before.st_nlink != 1) {
        return std::unexpected(
            std::string{"runtime snapshot symbolic link exceeds its bound or is aliased"}
        );
    }
    const std::string value{bytes.data(), static_cast<std::size_t>(count)};
    const std::filesystem::path target{value};
    if (value.find('\0') != std::string::npos || target.is_absolute() ||
        (relative_parent / target).native().size() > max_path_bytes) {
        return std::unexpected(std::string{"runtime snapshot symbolic link is unsafe"});
    }
    if (auto safe = check_link_target(root, relative_parent, target); !safe) {
        return std::unexpected(safe.error());
    }
    struct stat after{};
    if (::fstatat(source_parent, name, &after, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("reinspect runtime snapshot symbolic link");
    }
    if (!same_version(before, after)) {
        return std::unexpected(std::string{"runtime snapshot symbolic link changed during copy"});
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            destination_parent, glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    if (::symlinkat(value.c_str(), destination_parent, name) != 0) {
        return failure("create exclusive runtime snapshot symbolic link");
    }
    struct stat created{};
    if (::fstatat(destination_parent, name, &created, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect created runtime snapshot symbolic link");
    }
    return glove::detail::check_symlink_acl_at(
        destination_parent, name, created, glove::detail::acl_scope::owner_private
    );
}

auto copy_tree(
    int source,
    int destination,
    int root,
    const std::filesystem::path& source_path,
    const std::filesystem::path& relative,
    budget& remaining,
    std::size_t depth
) -> result<void> {
    auto directory = enumerate(source);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    for (;;) {
        errno = 0;
        const auto* item = ::readdir(directory->get());
        if (item == nullptr) {
            if (errno != 0) {
                return failure("read runtime snapshot directory");
            }
            return {};
        }
        const auto length = ::strnlen(item->d_name, sizeof(item->d_name));
        if (length == sizeof(item->d_name)) {
            return std::unexpected(std::string{"runtime snapshot entry name is unbounded"});
        }
        const std::string name{item->d_name, length};
        if (name == "." || name == "..") {
            continue;
        }
        if (name.empty() || name.find('/') != std::string::npos || depth >= max_depth ||
            (source_path / name).native().size() > max_path_bytes || remaining.entries == 0) {
            return std::unexpected(
                std::string{"runtime snapshot exceeds its entry, path, or depth budget"}
            );
        }
        --remaining.entries;
        struct stat before{};
        if (::fstatat(source, name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect runtime snapshot source entry");
        }
        if (S_ISLNK(before.st_mode)) {
            if (auto copied = copy_link(source, destination, name.c_str(), before, root, relative);
                !copied) {
                return std::unexpected(copied.error());
            }
        } else {
            const bool is_directory = S_ISDIR(before.st_mode);
            if (!is_directory && (!S_ISREG(before.st_mode) || before.st_nlink != 1)) {
                return std::unexpected(
                    std::string{"runtime snapshot contains a special or aliased file"}
                );
            }
            auto opened = open_checked(source, name.c_str(), before);
            if (!opened) {
                return std::unexpected(opened.error());
            }
            if (is_directory) {
                auto child = create_directory(destination, name.c_str());
                if (!child) {
                    return std::unexpected(child.error());
                }
                if (auto copied = copy_tree(
                        opened->get(),
                        child->get(),
                        root,
                        source_path / name,
                        relative / name,
                        remaining,
                        depth + 1U
                    );
                    !copied) {
                    return std::unexpected(copied.error());
                }
            } else if (
                auto copied =
                    copy_file(opened->get(), destination, name.c_str(), before, remaining);
                !copied
            ) {
                return std::unexpected(copied.error());
            }
            struct stat after{};
            if (::fstat(opened->get(), &after) != 0 || !same_version(before, after)) {
                return std::unexpected(
                    std::string{"opened runtime snapshot source changed during copy"}
                );
            }
        }
        struct stat named_after{};
        if (::fstatat(source, name.c_str(), &named_after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_version(before, named_after)) {
            return std::unexpected(
                std::string{"runtime snapshot source entry changed during copy"}
            );
        }
    }
}

} // namespace

auto copy_runtime_closure(
    const std::vector<std::filesystem::path>& source_roots,
    const std::filesystem::path& existing_empty_payload,
    std::uint64_t planned_bytes,
    std::uint64_t planned_entries
) -> result<void> {
    if (source_roots.empty() || source_roots.size() > 64U || planned_bytes > max_bytes ||
        planned_entries > max_entries || !bounded_path(existing_empty_payload)) {
        return std::unexpected(std::string{"runtime snapshot copy has invalid paths or budgets"});
    }
    for (const auto& source : source_roots) {
        if (!bounded_path(source) || within(source, existing_empty_payload) ||
            within(existing_empty_payload, source)) {
            return std::unexpected(
                std::string{"runtime snapshot source is unbounded or overlaps payload"}
            );
        }
    }
    auto parent = open_parent(existing_empty_payload, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    struct stat payload_metadata{};
    const auto payload_name = existing_empty_payload.filename();
    if (::fstatat(parent->get(), payload_name.c_str(), &payload_metadata, AT_SYMLINK_NOFOLLOW) !=
        0) {
        return failure("inspect existing runtime snapshot payload");
    }
    if (!S_ISDIR(payload_metadata.st_mode) || payload_metadata.st_uid != ::geteuid() ||
        (payload_metadata.st_mode & 07777U) != 0700U) {
        return std::unexpected(std::string{"runtime snapshot payload must be owner-0700"});
    }
    auto payload = open_checked(parent->get(), payload_name.c_str(), payload_metadata);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            payload->get(), glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    {
        auto directory = enumerate(payload->get());
        if (!directory) {
            return std::unexpected(directory.error());
        }
        for (;;) {
            errno = 0;
            const auto* item = ::readdir(directory->get());
            if (item == nullptr) {
                if (errno != 0) {
                    return failure("read existing runtime snapshot payload");
                }
                break;
            }
            if (std::strcmp(item->d_name, ".") != 0 && std::strcmp(item->d_name, "..") != 0) {
                return std::unexpected(std::string{"runtime snapshot payload must be empty"});
            }
        }
    }
    budget remaining{planned_bytes, planned_entries};
    for (std::size_t index = 0; index < source_roots.size(); ++index) {
        const auto& path = source_roots[index];
        auto source_parent = open_parent(path, false);
        if (!source_parent) {
            return std::unexpected(source_parent.error());
        }
        const auto name = path.filename();
        struct stat before{};
        if (::fstatat(source_parent->get(), name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect runtime snapshot source root");
        }
        const bool is_directory = S_ISDIR(before.st_mode);
        if (!is_directory && (!S_ISREG(before.st_mode) || before.st_nlink != 1)) {
            return std::unexpected(
                std::string{"runtime snapshot root must be an unaliased file or directory"}
            );
        }
        auto source = open_checked(source_parent->get(), name.c_str(), before);
        if (!source) {
            return std::unexpected(source.error());
        }
        if (!is_directory) {
            if (remaining.entries == 0 || before.st_size < 0 ||
                static_cast<std::uint64_t>(before.st_size) > remaining.bytes) {
                return std::unexpected(
                    std::string{"runtime snapshot root exceeds its planned budget"}
                );
            }
            --remaining.entries;
        }
        const auto root_name = "root-" + std::to_string(index);
        auto destination = create_directory(payload->get(), root_name.c_str());
        if (!destination) {
            return std::unexpected(destination.error());
        }
        const auto copied =
            is_directory
                ? copy_tree(
                      source->get(), destination->get(), source->get(), path, {}, remaining, 0U
                  )
                : copy_file(source->get(), destination->get(), name.c_str(), before, remaining);
        if (!copied) {
            return std::unexpected(copied.error());
        }
        struct stat opened_after{};
        struct stat named_after{};
        if (::fstat(source->get(), &opened_after) != 0 ||
            ::fstatat(source_parent->get(), name.c_str(), &named_after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_version(before, opened_after) || !same_version(before, named_after)) {
            return std::unexpected(std::string{"runtime snapshot source root changed during copy"});
        }
    }
    return {};
}

} // namespace glove::host::snapshot
