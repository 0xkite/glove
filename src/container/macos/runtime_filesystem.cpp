#include "runtime_filesystem.hpp"

#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::container::macos_detail {
namespace {

constexpr std::size_t max_roots = 64U;
constexpr std::size_t max_entries = 200'128U;
constexpr std::size_t max_depth = 128U;
// A declared snapshot payload contains one root-N wrapper above source depth128.
// External ancestry retains its independent 128-component bound.
constexpr std::size_t max_tree_depth = max_depth + 1U;
constexpr std::size_t max_path_bytes = 4096U;
constexpr std::size_t max_name_bytes = 255U;
constexpr std::size_t max_link_hops = 32U;
constexpr int source_flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

template<typename T> using result = std::expected<T, std::string>;

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
        std::string{"runtime filesystem: "} + std::string{operation} + ": " +
        std::error_code{saved, std::generic_category()}.message()
    );
}

auto rejected(std::string_view reason) -> std::unexpected<std::string> {
    return std::unexpected(std::string{"runtime filesystem: "} + std::string{reason});
}

auto same_binding(const struct stat& left, const struct stat& right) noexcept -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
           left.st_gid == right.st_gid && left.st_flags == right.st_flags &&
           left.st_gen == right.st_gen;
}

auto same_version(const struct stat& left, const struct stat& right) noexcept -> bool {
    return same_binding(left, right) && left.st_nlink == right.st_nlink &&
           left.st_size == right.st_size && left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
           left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
           left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
}

auto check_type(const struct stat& metadata, bool allow_link = false) -> result<void> {
    if (S_ISREG(metadata.st_mode)) {
        if (metadata.st_nlink != 1) {
            return rejected("regular files must be single-link");
        }
        return {};
    }
    if (S_ISDIR(metadata.st_mode)) {
        return {};
    }
    if (allow_link && S_ISLNK(metadata.st_mode)) {
        if (metadata.st_nlink != 1) {
            return rejected("symbolic links must be single-link");
        }
        return {};
    }
    return rejected("unsupported file type (only directories, regular files and safe links)");
}

auto inspect(int parent, const char* name) -> result<struct stat> {
    struct stat metadata{};
    if (::fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect named entry without following links");
    }
    return metadata;
}

auto check_named(int parent, const char* name, const struct stat& before, bool binding_only = false)
    -> result<void> {
    auto after = inspect(parent, name);
    if (!after) {
        return std::unexpected(after.error());
    }
    if (auto safe = check_type(*after, true); !safe) {
        return safe;
    }
    if (!(binding_only ? same_binding(before, *after) : same_version(before, *after))) {
        return rejected("named entry metadata or identity drift");
    }
    if (S_ISLNK(before.st_mode)) {
        if (auto acl = glove::detail::check_symlink_acl_at(parent, name, before); !acl) {
            return rejected(acl.error());
        }
    }
    return {};
}

auto check_opened(int fd, const struct stat& before, bool binding_only = false) -> result<void> {
    struct stat after{};
    if (::fstat(fd, &after) != 0) {
        return failure("inspect opened entry");
    }
    if (auto safe = check_type(after); !safe) {
        return safe;
    }
    if (!(binding_only ? same_binding(before, after) : same_version(before, after))) {
        return rejected("opened entry metadata or identity drift");
    }
    if (auto acl = glove::detail::check_descriptor_acl(fd, glove::detail::acl_scope::integrity);
        !acl) {
        return rejected(acl.error());
    }
    return {};
}

auto open_checked(
    int parent, const char* name, const struct stat& before, bool binding_only = false
) -> result<descriptor> {
    // Inspect types first: never intentionally open a FIFO, socket or device.
    if (auto safe = check_type(before); !safe) {
        return std::unexpected(safe.error());
    }
    descriptor opened{
        ::openat(parent, name, source_flags | (S_ISDIR(before.st_mode) ? O_DIRECTORY : 0))
    };
    if (opened.get() < 0) {
        return failure("open entry without following links");
    }
    if (auto stable = check_opened(opened.get(), before, binding_only); !stable) {
        return std::unexpected(stable.error());
    }
    if (auto stable = check_named(parent, name, before, binding_only); !stable) {
        return std::unexpected(stable.error());
    }
    return opened;
}

auto duplicate(int fd) -> result<descriptor> {
    descriptor copy{::fcntl(fd, F_DUPFD_CLOEXEC, 3)};
    if (copy.get() < 0) {
        return failure("duplicate pinned descriptor");
    }
    return copy;
}

auto enumerate(int fd) -> result<directory_stream> {
    auto copy = duplicate(fd);
    if (!copy) {
        return std::unexpected(copy.error());
    }
    directory_stream stream{::fdopendir(copy->get())};
    if (!stream) {
        return failure("open directory enumeration");
    }
    (void)copy->release();
    return stream;
}

auto valid_name(std::string_view name) -> bool {
    return !name.empty() && name.size() <= max_name_bytes && name != "." && name != ".." &&
           name.find('/') == std::string_view::npos && name.find('\0') == std::string_view::npos;
}

struct pinned_entry {
    descriptor fd;
    struct stat metadata;
    std::string name;
};

enum class stack_check { full, external_ancestors, binding_only };

// Keep parent descriptors until the entire walk finishes, including ancestors
// outside the runtime root. A pathname replacement must not silently retarget
// the SBPL grant after we inspected a different inode.
auto check_stack(const std::vector<pinned_entry>& entries, stack_check mode = stack_check::full)
    -> result<void> {
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        // Namespace parents and shared ancestors bind names and security metadata,
        // not unrelated entries. Scanned runtime directories retain full checks.
        const bool binding_only =
            mode == stack_check::binding_only ||
            (mode == stack_check::external_ancestors && index + 1U < entries.size());
        if (auto stable = check_opened(entry.fd.get(), entry.metadata, binding_only); !stable) {
            return stable;
        }
        if (index != 0) {
            if (auto stable = check_named(
                    entries[index - 1U].fd.get(), entry.name.c_str(), entry.metadata, binding_only
                );
                !stable) {
                return stable;
            }
        }
    }
    return {};
}

auto pin_root(const std::string& path, bool binding_only_root = false)
    -> result<std::vector<pinned_entry>> {
    descriptor floor{::open("/", source_flags | O_DIRECTORY)};
    if (floor.get() < 0) {
        return failure("open filesystem root");
    }
    struct stat metadata{};
    if (::fstat(floor.get(), &metadata) != 0) {
        return failure("inspect filesystem root");
    }
    std::vector<pinned_entry> entries;
    entries.push_back({std::move(floor), metadata, {}});
    const std::filesystem::path root{path};
    const auto relative = root.relative_path();
    for (auto component = relative.begin(); component != relative.end(); ++component) {
        const auto name = component->string();
        if (!valid_name(name) || entries.size() > max_depth) {
            return rejected("root component exceeds name or depth bound");
        }
        auto before = inspect(entries.back().fd.get(), name.c_str());
        if (!before) {
            return std::unexpected(before.error());
        }
        if (std::next(component) != relative.end() && !S_ISDIR(before->st_mode)) {
            return rejected("root ancestor is not a directory");
        }
        auto opened = open_checked(
            entries.back().fd.get(),
            name.c_str(),
            *before,
            binding_only_root || std::next(component) != relative.end()
        );
        if (!opened) {
            return std::unexpected(opened.error());
        }
        entries.push_back({std::move(*opened), *before, name});
    }
    return entries;
}

auto pin_constraint_parent(const profile& p, const std::string& parent, bool private_parent)
    -> result<std::vector<pinned_entry>> {
    if (parent.empty() || parent.size() > max_path_bytes ||
        parent.find('\0') != std::string::npos) {
        return rejected("launch constraint parent exceeds path bounds");
    }
    const std::filesystem::path path{parent};
    if (!path.is_absolute() || path == path.root_path() ||
        path.lexically_normal().string() != parent) {
        return rejected("launch constraint parent must already be canonical and absolute");
    }
    bool exact_grant = false;
    for (const auto& rule : p.filesystem) {
        if (!rule.writable) {
            continue;
        }
        if (rule.path == parent) {
            exact_grant = true;
            continue;
        }
        const std::filesystem::path root{rule.path};
        const auto mismatch = std::mismatch(root.begin(), root.end(), path.begin(), path.end());
        if (mismatch.first == root.end()) {
            return rejected("launch constraint parent is replaceable through an ancestor grant");
        }
    }
    if (!exact_grant) {
        return rejected("launch constraint parent must exactly match a writable filesystem rule");
    }
    // Even the last directory is namespace-only: unrelated lock or workspace
    // entries may change directory size, link count and timestamps during admission.
    auto pinned = pin_root(parent, true);
    if (!pinned) {
        return std::unexpected(pinned.error());
    }
    const auto& metadata = pinned->back().metadata;
    if (!S_ISDIR(metadata.st_mode)) {
        return rejected("launch constraint parent must be a directory");
    }
    if (private_parent && (metadata.st_uid != ::getuid() || (metadata.st_mode & 07777) != 0700)) {
        return rejected("immutable file parent must be current-user owned and mode 0700");
    }
    if (private_parent) {
        if (auto acl = glove::detail::check_descriptor_acl(
                pinned->back().fd.get(), glove::detail::acl_scope::owner_private
            );
            !acl) {
            return rejected(acl.error());
        }
    }
    if (auto stable = check_stack(*pinned, stack_check::binding_only); !stable) {
        return std::unexpected(stable.error());
    }
    return pinned;
}

auto check_reserved_absent(int parent, const std::string& name) -> result<void> {
    struct stat metadata{};
    if (::fstatat(parent, name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) == 0) {
        return rejected("reserved entry already exists");
    }
    if (errno != ENOENT) {
        return failure("inspect reserved entry without following links");
    }
    // Exact lookup is insufficient on case-sensitive volumes. Inspect only
    // direct names, with a fixed bound, matching the generated ASCII-fold rule.
    auto stream = enumerate(parent);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    ::rewinddir(stream->get());
    std::size_t remaining = 65536U;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream->get());
        if (entry == nullptr) {
            if (errno != 0) {
                return failure("enumerate reserved namespace");
            }
            if (::closedir(stream->release()) != 0) {
                return failure("close reserved enumeration");
            }
            return {};
        }
        if (remaining-- == 0) {
            return rejected("reserved namespace enumeration bound exceeded");
        }
        const auto length = ::strnlen(entry->d_name, sizeof(entry->d_name));
        if (length == sizeof(entry->d_name)) {
            return rejected("reserved namespace name bound exceeded");
        }
        if (length != name.size()) {
            continue;
        }
        const auto folded = [](char c) {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
        };
        bool matches = true;
        for (std::size_t index = 0; index != length; ++index) {
            matches = matches && folded(entry->d_name[index]) == folded(name[index]);
        }
        if (matches) {
            return rejected("reserved entry ASCII case alias already exists");
        }
    }
}

struct immutable_witness {
    std::vector<pinned_entry> parent;
    pinned_entry file;
};

struct reserved_witness {
    std::vector<pinned_entry> parent;
    std::string name;
};

auto read_link(int parent, const char* name, const struct stat& before) -> result<std::string> {
    if (auto safe = check_type(before, true); !safe) {
        return std::unexpected(safe.error());
    }
    if (auto acl = glove::detail::check_symlink_acl_at(parent, name, before); !acl) {
        return rejected(acl.error());
    }
    std::array<char, max_path_bytes + 1U> bytes{};
    const auto count = ::readlinkat(parent, name, bytes.data(), bytes.size());
    if (count < 0) {
        return failure("read symbolic link target");
    }
    if (count == 0 || static_cast<std::size_t>(count) > max_path_bytes) {
        return rejected("symbolic link target exceeds path bound or is empty");
    }
    std::string target{bytes.data(), static_cast<std::size_t>(count)};
    if (target.front() == '/' || target.find('\0') != std::string::npos) {
        return rejected("symbolic link target must be relative");
    }
    if (auto stable = check_named(parent, name, before); !stable) {
        return std::unexpected(stable.error());
    }
    return target;
}

struct link_witness {
    descriptor parent;
    struct stat metadata;
    std::string name;
};

// No kernel link following or lexical normalization. In particular, a/../b
// first resolves a (including its links), and only then pops a pinned directory.
// The root descriptor is a floor: '..' can never reach another admitted root.
auto resolve_link(int root, std::size_t root_bytes, std::string pending) -> result<void> {
    auto floor = duplicate(root);
    if (!floor) {
        return std::unexpected(floor.error());
    }
    struct stat metadata{};
    if (::fstat(floor->get(), &metadata) != 0) {
        return failure("inspect symbolic link boundary");
    }
    std::vector<pinned_entry> directories;
    directories.push_back({std::move(*floor), metadata, {}});
    std::vector<link_witness> links;
    std::size_t walked_bytes = root_bytes;
    while (!pending.empty()) {
        if (walked_bytes + 1U + pending.size() > max_path_bytes) {
            return rejected("expanded symbolic link exceeds path bound");
        }
        const auto slash = pending.find('/');
        const auto name = pending.substr(0, slash);
        const bool needs_directory = slash != std::string::npos;
        pending = needs_directory ? pending.substr(slash + 1U) : std::string{};
        if (name.empty() || name == ".") {
            continue;
        }
        if (name == "..") {
            if (directories.size() == 1U) {
                return rejected("symbolic link escapes its pinned root");
            }
            if (auto stable = check_stack(directories); !stable) {
                return stable;
            }
            walked_bytes -= directories.back().name.size() + 1U;
            directories.pop_back();
            continue;
        }
        if (!valid_name(name) || directories.size() > max_tree_depth) {
            return rejected("symbolic link component exceeds name or depth bound");
        }
        const int parent = directories.back().fd.get();
        auto before = inspect(parent, name.c_str());
        if (!before) {
            return std::unexpected(before.error());
        }
        if (S_ISLNK(before->st_mode)) {
            if (links.size() >= max_link_hops) {
                return rejected("symbolic link chain is cyclic or exceeds 32-hop bound");
            }
            auto target = read_link(parent, name.c_str(), *before);
            if (!target) {
                return std::unexpected(target.error());
            }
            // Preserve even a trailing slash: a regular file followed by '/'
            // must fail, rather than turn into an apparently valid leaf.
            const auto extra = needs_directory ? 1U + pending.size() : 0U;
            if (walked_bytes + 1U + target->size() + extra > max_path_bytes) {
                return rejected("expanded symbolic link exceeds path bound");
            }
            auto pinned_parent = duplicate(parent);
            if (!pinned_parent) {
                return std::unexpected(pinned_parent.error());
            }
            links.push_back({std::move(*pinned_parent), *before, name});
            pending = *target + (needs_directory ? "/" + pending : std::string{});
            continue;
        }
        if (needs_directory && !S_ISDIR(before->st_mode)) {
            return rejected("symbolic link traverses a non-directory");
        }
        auto opened = open_checked(parent, name.c_str(), *before);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (S_ISDIR(before->st_mode)) {
            walked_bytes += name.size() + 1U;
            directories.push_back({std::move(*opened), *before, name});
        } else {
            if (auto stable = check_opened(opened->get(), *before); !stable) {
                return stable;
            }
            if (auto stable = check_named(parent, name.c_str(), *before); !stable) {
                return stable;
            }
        }
    }
    for (const auto& link : links) {
        if (auto stable = check_named(link.parent.get(), link.name.c_str(), link.metadata);
            !stable) {
            return stable;
        }
    }
    return check_stack(directories);
}

// Only the physical directory walk enumerates subtrees. Symlinks validate a
// target's metadata but never recursively scan it, so directory aliases do not
// multiply the entry budget or recurse back into an already scanned subtree.
auto scan_tree(
    int source,
    const struct stat& directory_metadata,
    int root,
    std::size_t root_bytes,
    const std::string& relative,
    std::size_t depth,
    std::size_t& remaining
) -> result<void> {
    auto stream = enumerate(source);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    for (;;) {
        errno = 0;
        const auto* item = ::readdir(stream->get());
        if (item == nullptr) {
            if (errno != 0) {
                return failure("read directory enumeration");
            }
            if (::closedir(stream->release()) != 0) {
                return failure("close directory enumeration");
            }
            return check_opened(source, directory_metadata);
        }
        const auto length = ::strnlen(item->d_name, sizeof(item->d_name));
        if (length == sizeof(item->d_name) || length > max_name_bytes) {
            return rejected("directory entry exceeds fixed name bound");
        }
        std::array<char, max_name_bytes + 1U> leaf{};
        std::memcpy(leaf.data(), item->d_name, length);
        const std::string_view name{leaf.data(), length};
        if (name == "." || name == "..") {
            continue;
        }
        const auto relative_bytes = relative.empty() ? length : relative.size() + 1U + length;
        if (!valid_name(name) || depth >= max_tree_depth || remaining == 0 ||
            root_bytes + 1U + relative_bytes > max_path_bytes) {
            return rejected("tree exceeds entry, name, depth or path bound");
        }
        --remaining;
        const auto child_path =
            relative.empty() ? std::string{name} : relative + "/" + std::string{name};
        auto before = inspect(source, leaf.data());
        if (!before) {
            return std::unexpected(before.error());
        }
        if (S_ISLNK(before->st_mode)) {
            if (auto safe = resolve_link(root, root_bytes, child_path); !safe) {
                return safe;
            }
        } else {
            auto opened = open_checked(source, leaf.data(), *before);
            if (!opened) {
                return std::unexpected(opened.error());
            }
            if (S_ISDIR(before->st_mode)) {
                if (auto safe = scan_tree(
                        opened->get(), *before, root, root_bytes, child_path, depth + 1U, remaining
                    );
                    !safe) {
                    return safe;
                }
            }
            if (auto stable = check_opened(opened->get(), *before); !stable) {
                return stable;
            }
        }
        if (auto stable = check_named(source, leaf.data(), *before); !stable) {
            return stable;
        }
    }
}

} // namespace

auto validate_runtime_filesystem(const std::vector<fs_rule>& roots)
    -> std::expected<void, std::string> {
    if (roots.size() > max_roots) {
        return rejected("root count exceeds 64-root bound");
    }
    std::size_t remaining = max_entries;
    for (const auto& rule : roots) {
        if (rule.writable || rule.path.empty() || rule.path.size() > max_path_bytes ||
            rule.path.find('\0') != std::string::npos) {
            return rejected("root must be a bounded read-only canonical path");
        }
        const std::filesystem::path path{rule.path};
        if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
            return rejected("root must be a non-root canonical absolute path");
        }
        if (remaining == 0) {
            return rejected("tree exceeds total entry bound");
        }
        --remaining; // Root files and directories count too, across all roots.
        auto pinned = pin_root(rule.path);
        if (!pinned) {
            return std::unexpected(pinned.error());
        }
        const auto& root = pinned->back();
        if (S_ISDIR(root.metadata.st_mode)) {
            if (auto safe = scan_tree(
                    root.fd.get(), root.metadata, root.fd.get(), rule.path.size(), {}, 0U, remaining
                );
                !safe) {
                return safe;
            }
        }
        if (auto stable = check_stack(*pinned, stack_check::external_ancestors); !stable) {
            return stable;
        }
    }
    return {};
}

auto validate_launch_constraints(const profile& p) -> std::expected<void, std::string> {
    if (p.immutable_files.size() > 16U || p.reserved_entries.size() > 4U) {
        return rejected("launch constraints exceed file or reserved count bound");
    }
    std::vector<immutable_witness> files;
    files.reserve(p.immutable_files.size());
    for (const auto& file : p.immutable_files) {
        if (file.empty() || file.size() > max_path_bytes || file.find('\0') != std::string::npos) {
            return rejected("immutable file exceeds path bounds");
        }
        const std::filesystem::path path{file};
        if (!path.is_absolute() || path.lexically_normal().string() != file) {
            return rejected("immutable file must already be canonical and absolute");
        }
        const auto name = path.filename().string();
        if (!valid_name(name)) {
            return rejected("immutable file has invalid leaf name");
        }
        auto pinned = pin_constraint_parent(p, path.parent_path().string(), true);
        if (!pinned) {
            return std::unexpected(pinned.error());
        }
        const int parent = pinned->back().fd.get();
        auto before = inspect(parent, name.c_str());
        if (!before) {
            return std::unexpected(before.error());
        }
        if (!S_ISREG(before->st_mode) || before->st_nlink != 1) {
            return rejected("immutable file must be a single-link regular file");
        }
        const auto permissions = before->st_mode & 07777;
        if (before->st_uid != ::getuid() || (permissions != 0600 && permissions != 0400)) {
            return rejected("immutable file must be current-user owned and mode 0600 or 0400");
        }
        auto opened = open_checked(parent, name.c_str(), *before);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (auto acl = glove::detail::check_descriptor_acl(
                opened->get(), glove::detail::acl_scope::owner_private
            );
            !acl) {
            return rejected(acl.error());
        }
        files.push_back({std::move(*pinned), {std::move(*opened), *before, name}});
    }
    std::vector<reserved_witness> reserved;
    reserved.reserve(p.reserved_entries.size());
    for (const auto& entry : p.reserved_entries) {
        if (!valid_name(entry.name) || entry.name.size() > 64U ||
            !std::ranges::all_of(entry.name, [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                       c == '-' || c == '_' || c == '.';
            })) {
            return rejected("reserved entry has invalid name");
        }
        auto pinned = pin_constraint_parent(p, entry.parent, false);
        if (!pinned) {
            return std::unexpected(pinned.error());
        }
        if (auto absent = check_reserved_absent(pinned->back().fd.get(), entry.name); !absent) {
            return absent;
        }
        reserved.push_back({std::move(*pinned), entry.name});
    }
    // Retain every witness until all constraints have been inspected. Files
    // keep full version checks; directory namespaces keep security/binding checks.
    for (const auto& witness : files) {
        if (auto stable = check_stack(witness.parent, stack_check::binding_only); !stable) {
            return stable;
        }
        const auto& file = witness.file;
        if (auto acl = glove::detail::check_descriptor_acl(
                witness.parent.back().fd.get(), glove::detail::acl_scope::owner_private
            );
            !acl) {
            return rejected(acl.error());
        }
        if (auto acl = glove::detail::check_descriptor_acl(
                file.fd.get(), glove::detail::acl_scope::owner_private
            );
            !acl) {
            return rejected(acl.error());
        }
        if (auto stable = check_opened(file.fd.get(), file.metadata); !stable) {
            return stable;
        }
        if (auto stable =
                check_named(witness.parent.back().fd.get(), file.name.c_str(), file.metadata);
            !stable) {
            return stable;
        }
        if (auto stable = check_stack(witness.parent, stack_check::binding_only); !stable) {
            return stable;
        }
    }
    for (const auto& witness : reserved) {
        if (auto stable = check_stack(witness.parent, stack_check::binding_only); !stable) {
            return stable;
        }
        if (auto absent = check_reserved_absent(witness.parent.back().fd.get(), witness.name);
            !absent) {
            return absent;
        }
        if (auto stable = check_stack(witness.parent, stack_check::binding_only); !stable) {
            return stable;
        }
    }
    return {};
}

} // namespace glove::container::macos_detail
