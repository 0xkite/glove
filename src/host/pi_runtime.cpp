#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "runtime_snapshot.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <ranges>
#include <utility>

namespace glove::host {
namespace {

constexpr std::size_t max_path_bytes = 4096U;
// Source depth remains 128; snapshot root->payload->root-N adds two levels.
constexpr std::size_t max_tree_depth = 128U + 2U;

class descriptor {
public:
    explicit descriptor(int value = -1) : value_{value} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    descriptor(descriptor&& other) noexcept : value_{std::exchange(other.value_, -1)} {}

    auto operator=(descriptor&& other) noexcept -> descriptor& {
        if (this != &other) {
            if (value_ >= 0) {
                (void)::close(value_);
            }
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_;
};

auto bounded_path(const std::filesystem::path& path) -> bool {
    const auto& bytes = path.native();
    return !bytes.empty() && bytes.size() <= max_path_bytes &&
           bytes.find('\0') == std::string::npos && path.is_absolute() &&
           path.lexically_normal() == path && path != path.root_path();
}

auto lower_hex_digest(std::string_view digest) -> bool {
    return digest.size() == 64U && std::ranges::all_of(digest, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto canonical_matches(const std::filesystem::path& path) -> bool {
    std::error_code error;
    return std::filesystem::canonical(path, error) == path && !error;
}

auto same_object(const struct stat& left, const struct stat& right) -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_uid == right.st_uid && left.st_mode == right.st_mode &&
           left.st_nlink == right.st_nlink && left.st_size == right.st_size;
}

// No creation and no following directory aliases, including intermediate
// components. Root-owned sticky temporary ancestors are not launch grants.
auto open_protected_directory(const std::filesystem::path& path, mode_t final_mode)
    -> result<descriptor> {
    descriptor current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (current.get() < 0) {
        return std::unexpected(snapshot::system_error("open Pi store root ancestor"));
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(current.get(), glove::detail::acl_scope::integrity);
        !acl) {
        return std::unexpected(acl.error());
    }
    std::filesystem::path walked{"/"};
    for (const auto& component : path.relative_path()) {
        walked /= component;
        descriptor next{::openat(
            current.get(), component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )};
        struct stat metadata{};
        if (next.get() < 0 || ::fstat(next.get(), &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
            return std::unexpected(std::string{"Pi protected store has an unsafe directory"});
        }
        const bool sticky_root = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
        if ((metadata.st_uid != 0 && metadata.st_uid != ::geteuid()) ||
            ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !sticky_root) ||
            (walked == path &&
             (metadata.st_uid != ::geteuid() || (metadata.st_mode & 07777U) != final_mode))) {
            return std::unexpected(std::string{"Pi protected store ownership or mode is unsafe"});
        }
        const auto scope = walked == path && final_mode == 0700
                               ? glove::detail::acl_scope::owner_private
                               : glove::detail::acl_scope::integrity;
        if (auto acl = glove::detail::check_descriptor_acl(next.get(), scope); !acl) {
            return std::unexpected(acl.error());
        }
        current = std::move(next);
    }
    return current;
}

struct directory_closer {
    void operator()(DIR* directory) const noexcept { (void)::closedir(directory); }
};

// Bound enumeration before hashing. Each directory is opened relative to its
// already checked parent, and regular files may not share writable hardlinks.
auto check_tree(
    int directory_fd,
    const std::filesystem::path& path,
    const std::filesystem::path& boundary,
    snapshot::snapshot_tree_budget& entries,
    std::size_t depth,
    const std::vector<std::string>* permitted_children = nullptr
) -> result<void> {
    if (depth > max_tree_depth) {
        return std::unexpected(std::string{"Pi snapshot exceeds its directory depth bound"});
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(directory_fd, glove::detail::acl_scope::integrity);
        !acl) {
        return std::unexpected(acl.error());
    }
    const int duplicate = ::fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        return std::unexpected(snapshot::system_error("duplicate Pi snapshot directory"));
    }
    std::unique_ptr<DIR, directory_closer> directory{::fdopendir(duplicate)};
    if (!directory) {
        (void)::close(duplicate);
        return std::unexpected(snapshot::system_error("enumerate Pi snapshot directory"));
    }
    std::size_t children = 0;
    for (;;) {
        errno = 0;
        const auto* item = ::readdir(directory.get());
        if (item == nullptr) {
            if (errno != 0) {
                return std::unexpected(snapshot::system_error("read Pi snapshot directory"));
            }
            break;
        }
        const std::string name{item->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        const auto child_path = path / name;
        const bool wrapper = child_path == boundary || path == boundary;
        if (!entries.admit(wrapper) ||
            (permitted_children != nullptr &&
             std::ranges::find(*permitted_children, name) == permitted_children->end())) {
            return std::unexpected(std::string{"Pi snapshot has excess or unknown entries"});
        }
        ++children;
        if (!bounded_path(child_path)) {
            return std::unexpected(std::string{"Pi snapshot path exceeds its bound"});
        }
        struct stat metadata{};
        if (::fstatat(directory_fd, name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
            metadata.st_uid != ::geteuid()) {
            return std::unexpected(std::string{"Pi snapshot entry is not owner-owned"});
        }
        if (S_ISLNK(metadata.st_mode)) {
            if (auto checked = glove::detail::check_symlink_acl_at(directory_fd, name, metadata);
                !checked) {
                return checked;
            }
            std::array<char, max_path_bytes + 1U> target{};
            const auto size =
                ::readlinkat(directory_fd, name.c_str(), target.data(), target.size());
            if (size <= 0 || static_cast<std::size_t>(size) > max_path_bytes || target[0] == '/' ||
                metadata.st_nlink != 1) {
                return std::unexpected(std::string{"Pi snapshot has an unsafe symbolic link"});
            }
            const std::string link{target.data(), static_cast<std::size_t>(size)};
            std::error_code error;
            const auto resolved = std::filesystem::canonical(child_path, error);
            struct stat after{};
            if (link.find('\0') != std::string::npos || error || !bounded_path(resolved) ||
                !snapshot::path_within(resolved, boundary) ||
                ::fstatat(directory_fd, name.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 ||
                !same_object(metadata, after)) {
                return std::unexpected(std::string{"Pi snapshot symbolic link escapes or changed"});
            }
            continue;
        }
        const bool is_directory = S_ISDIR(metadata.st_mode);
        const auto mode = metadata.st_mode & 07777U;
        if ((!is_directory && !S_ISREG(metadata.st_mode)) ||
            (is_directory ? mode != 0500U : (mode != 0400U && mode != 0500U)) ||
            (!is_directory && metadata.st_nlink != 1)) {
            return std::unexpected(std::string{"Pi snapshot type, mode, or link count is unsafe"});
        }
        descriptor child{::openat(
            directory_fd,
            name.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | (is_directory ? O_DIRECTORY : 0)
        )};
        struct stat opened{};
        if (child.get() < 0 || ::fstat(child.get(), &opened) != 0 ||
            !same_object(metadata, opened)) {
            return std::unexpected(std::string{"Pi snapshot entry identity changed"});
        }
        if (auto acl = glove::detail::check_descriptor_acl(
                child.get(), glove::detail::acl_scope::integrity
            );
            !acl) {
            return std::unexpected(acl.error());
        }
        if (is_directory) {
            auto checked = check_tree(child.get(), child_path, boundary, entries, depth + 1U);
            if (!checked) {
                return std::unexpected(checked.error());
            }
        }
        struct stat after{};
        if (::fstatat(directory_fd, name.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_object(opened, after) ||
            !glove::detail::check_descriptor_acl(
                child.get(), glove::detail::acl_scope::integrity
            )) {
            return std::unexpected(std::string{"Pi snapshot entry changed during validation"});
        }
    }
    if (permitted_children != nullptr && children != permitted_children->size()) {
        return std::unexpected(std::string{"Pi snapshot is missing expected payload roots"});
    }
    return glove::detail::check_descriptor_acl(directory_fd, glove::detail::acl_scope::integrity);
}

auto broad_source_root(const std::filesystem::path& root, const std::filesystem::path& home)
    -> bool {
    for (const auto* restricted : {"/opt/homebrew", "/usr/local", "/home", "/Users"}) {
        if (snapshot::path_within(std::filesystem::path{restricted}, root)) {
            return true;
        }
    }
    return snapshot::path_within(home, root);
}

// Component strings alone do not identify authority on case-folding or
// normalization-aware filesystems. Compare ancestor objects in both directions.
auto exclusion_overlaps_by_identity(
    const std::filesystem::path& root, const std::filesystem::path& excluded
) -> result<bool> {
    const auto ancestor_matches = [](std::filesystem::path path,
                                     const struct stat& target) -> result<bool> {
        std::size_t depth = 0;
        for (;;) {
            if (++depth > 128U) {
                return std::unexpected(std::string{"Pi source exclusion ancestry exceeds bound"});
            }
            struct stat metadata{};
            if (::stat(path.c_str(), &metadata) == 0) {
                if (metadata.st_dev == target.st_dev && metadata.st_ino == target.st_ino) {
                    return true;
                }
            } else if (errno != ENOENT && errno != ENOTDIR) {
                return std::unexpected(std::string{"Pi source exclusion ancestry is unavailable"});
            }
            if (path == path.root_path()) {
                return false;
            }
            path = path.parent_path();
        }
    };
    struct stat root_metadata{};
    if (::stat(root.c_str(), &root_metadata) != 0) {
        return std::unexpected(std::string{"Pi source exclusion root is unavailable"});
    }
    auto contains = ancestor_matches(excluded, root_metadata);
    if (!contains || *contains) {
        return contains;
    }
    struct stat excluded_metadata{};
    if (::stat(excluded.c_str(), &excluded_metadata) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return false;
        }
        return std::unexpected(std::string{"Pi source exclusion identity is unavailable"});
    }
    return ancestor_matches(root, excluded_metadata);
}

} // namespace

namespace snapshot {

auto validate_pi_source_exclusions(
    std::span<const std::filesystem::path> roots,
    const std::filesystem::path& account_home,
    std::span<const std::filesystem::path> additional_exclusions
) -> result<void> {
    if (additional_exclusions.size() > 64U ||
        !std::ranges::all_of(additional_exclusions, bounded_path)) {
        return std::unexpected(std::string{"Pi additional source exclusions exceed bounds"});
    }
    if (!bounded_path(account_home) || roots.empty() || roots.size() > 64U ||
        !std::ranges::all_of(roots, bounded_path)) {
        return std::unexpected(std::string{"Pi source exclusion paths are invalid"});
    }
    std::vector<std::filesystem::path> excluded;
    const std::array authority_suffixes{
        ".pi",
        ".codex",
        ".claude",
        ".config",
        ".ssh",
        ".aws",
        ".gnupg",
        ".netrc",
        ".npmrc",
        ".local/share/glove",
        ".local/state/glove",
        ".cache/glove"
    };
    for (const auto* suffix : authority_suffixes) {
        excluded.push_back(account_home / suffix);
    }
    // The host resolver can select a HOME distinct from the effective account.
    // Its known state removes authority too; it never replaces account exclusions.
    if (const auto* value = ::getenv("HOME"); value != nullptr && value[0] != '\0') {
        const auto length = ::strnlen(value, max_path_bytes + 1U);
        if (length > max_path_bytes) {
            return std::unexpected(std::string{"Pi configured source exclusion exceeds bound"});
        }
        const std::filesystem::path home{std::string_view{value, length}};
        if (!bounded_path(home)) {
            return std::unexpected(std::string{"Pi configured source exclusion is invalid"});
        }
        for (const auto* suffix : authority_suffixes) {
            excluded.push_back(home / suffix);
        }
    }
    // These inputs are deny-only. In particular a configured agent home must
    // never become a runtime grant merely because Node is installed beside it.
    for (const auto& [name, suffix] : std::array{
             std::pair{"PI_CODING_AGENT_DIR", ""},
             std::pair{"XDG_CONFIG_HOME", ""},
             std::pair{"XDG_DATA_HOME", "glove"},
             std::pair{"XDG_STATE_HOME", "glove"},
             std::pair{"XDG_CACHE_HOME", "glove"},
         }) {
        const auto* value = ::getenv(name);
        if (value == nullptr || value[0] == '\0') {
            continue;
        }
        const auto length = ::strnlen(value, max_path_bytes + 1U);
        if (length > max_path_bytes) {
            return std::unexpected(std::string{"Pi configured source exclusion exceeds bound"});
        }
        std::filesystem::path path{std::string_view{value, length}};
        if (!bounded_path(path)) {
            return std::unexpected(std::string{"Pi configured source exclusion is invalid"});
        }
        if (suffix[0] != '\0') {
            path /= suffix;
        }
        excluded.push_back(std::move(path));
    }
    // At most 29 fixed/configured locations plus 64 additional deny-only paths;
    // the independent 64-root content budget is unchanged.
    excluded.insert(excluded.end(), additional_exclusions.begin(), additional_exclusions.end());
    for (const auto& path : excluded) {
        std::error_code error;
        // Missing optional state still reserves its lexical location. Resolve
        // existing aliases too, without opening or decoding any credential file.
        const auto resolved = std::filesystem::weakly_canonical(path, error);
        if (!bounded_path(path) || error || !bounded_path(resolved)) {
            return std::unexpected(std::string{"Pi source exclusion cannot be resolved"});
        }
        for (const auto& root : roots) {
            if (path_within(root, path) || path_within(path, root) || path_within(root, resolved) ||
                path_within(resolved, root)) {
                return std::unexpected(std::string{"Pi source closure overlaps operator state"});
            }
            auto same_authority = exclusion_overlaps_by_identity(root, resolved);
            if (!same_authority) {
                return std::unexpected(same_authority.error());
            }
            if (*same_authority) {
                return std::unexpected(std::string{"Pi source closure overlaps operator state"});
            }
        }
    }
    return {};
}

auto validate_protected_snapshot_tree(
    const std::filesystem::path& snapshot_root, std::size_t root_count
) -> result<void> {
    if (!bounded_path(snapshot_root) || root_count == 0 || root_count > 64U) {
        return std::unexpected(std::string{"invalid protected snapshot tree path"});
    }
    auto root = open_protected_directory(snapshot_root, 0500);
    if (!root) {
        return std::unexpected(root.error());
    }
    snapshot_tree_budget entries;
    const std::vector<std::string> children{"payload"};
    const auto payload_path = snapshot_root / "payload";
    if (auto checked = check_tree(root->get(), snapshot_root, payload_path, entries, 0U, &children);
        !checked) {
        return checked;
    }
    auto payload = open_protected_directory(payload_path, 0500);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    std::vector<std::string> roots;
    for (std::size_t index = 0; index < root_count; ++index) {
        roots.push_back("root-" + std::to_string(index));
    }
    entries = {};
    return check_tree(payload->get(), payload_path, payload_path, entries, 0U, &roots);
}

auto validate_pi_source_closure(
    const std::filesystem::path& source_entry,
    const std::filesystem::path& source,
    const runtime_dependency_closure& closure,
    const std::filesystem::path& protected_directory,
    std::span<const std::filesystem::path> additional_exclusions
) -> result<void> {
    if (!bounded_path(source_entry) || !bounded_path(source) || !bounded_path(closure.executable) ||
        !bounded_path(protected_directory) || closure.read_only_paths.empty() ||
        closure.read_only_paths.size() > 64U ||
        !std::ranges::all_of(closure.read_only_paths, bounded_path) ||
        minimise_roots(closure.read_only_paths) != closure.read_only_paths ||
        closure.arguments != std::vector<std::string>{source.string()}) {
        return std::unexpected(
            std::string{"Pi source closure paths or script binding are invalid"}
        );
    }
    std::error_code error;
    if (std::filesystem::canonical(source_entry, error) != source || error ||
        !canonical_matches(source) || !canonical_matches(closure.executable)) {
        return std::unexpected(std::string{"Pi original source or interpreter identity changed"});
    }
    std::array<char, 16384U> account_buffer{};
    struct passwd account{};
    struct passwd* found = nullptr;
    if (::getpwuid_r(::geteuid(), &account, account_buffer.data(), account_buffer.size(), &found) !=
            0 ||
        found == nullptr || account.pw_dir == nullptr) {
        return std::unexpected(std::string{"cannot resolve Pi source home exclusion"});
    }
    const auto home = std::filesystem::canonical(account.pw_dir, error);
    if (error || !bounded_path(home)) {
        return std::unexpected(std::string{"Pi source home exclusion is invalid"});
    }
    if (auto excluded =
            validate_pi_source_exclusions(closure.read_only_paths, home, additional_exclusions);
        !excluded) {
        return excluded;
    }
    for (const auto& root : closure.read_only_paths) {
        if (broad_source_root(root, home) || path_within(root, protected_directory) ||
            path_within(protected_directory, root) || !canonical_matches(root)) {
            return std::unexpected(
                std::string{"Pi source closure is broad, aliased, or overlaps its protected store"}
            );
        }
    }
    // The top-level source alias is also discovery input, not part of the copy.
    if (path_within(source_entry, protected_directory) ||
        path_within(protected_directory, source_entry)) {
        return std::unexpected(std::string{"Pi source entry overlaps its protected store"});
    }
    auto directive = read_runtime_shebang(source);
    if (!directive || !*directive) {
        return std::unexpected(
            directive ? std::string{"Pi requires a Node script"} : directive.error()
        );
    }
    const auto& fields = **directive;
    std::filesystem::path interpreter;
    if (fields == std::vector<std::string>{"/usr/bin/env", "node"}) {
        interpreter = source_entry.parent_path() / "node";
    } else if (
        fields.size() == 1U && bounded_path(std::filesystem::path{fields.front()}) &&
        std::filesystem::path{fields.front()}.filename() == "node"
    ) {
        interpreter = fields.front();
    } else {
        return std::unexpected(
            std::string{"Pi requires a bounded absolute Node directive or env node"}
        );
    }
    const auto resolved = std::filesystem::canonical(interpreter, error);
    struct stat metadata{};
    if (error || resolved != closure.executable || ::stat(resolved.c_str(), &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || (metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        return std::unexpected(std::string{"Pi adjacent Node alias or interpreter changed"});
    }
    return {};
}

} // namespace snapshot

auto detail::validate_pi_runtime_with_exclusions(
    const staged_runtime_harness& runtime,
    std::span<const std::filesystem::path> additional_exclusions
) -> result<void> {
    if (runtime.runtime_id != "pi" || runtime.executable_name != "pi" ||
        !lower_hex_digest(runtime.snapshot_digest) ||
        !lower_hex_digest(runtime.adoption_manifest_digest) ||
        !bounded_path(runtime.protected_entry_point) ||
        runtime.protected_entry_point.filename() != "pi" ||
        !bounded_path(runtime.launch_executable) || runtime.launch_arguments.size() != 1U ||
        runtime.launch_arguments.front().size() > max_path_bytes ||
        runtime.launch_arguments.front().find('\0') != std::string::npos ||
        !bounded_path(std::filesystem::path{runtime.launch_arguments.front()}) ||
        runtime.read_only_paths.size() != 1U || !bounded_path(runtime.read_only_paths.front()) ||
        !bounded_path(runtime.source_executable) ||
        !bounded_path(runtime.canonical_source_executable) ||
        !bounded_path(runtime.source_launch_executable) || runtime.source_read_only_paths.empty() ||
        runtime.source_read_only_paths.size() > 64U ||
        !std::ranges::all_of(runtime.source_read_only_paths, bounded_path)) {
        return std::unexpected(std::string{"Pi staged runtime binding is invalid"});
    }
    const auto adapter = supervisor::native_skill_runtime_adapter_for("pi");
    if (!adapter || !adapter->adoption_manifest || !adapter->adoption_manifest->require_snapshot) {
        return std::unexpected(std::string{"Pi snapshot adoption adapter is unavailable"});
    }
    auto adoption = supervisor::native_harness_adoption_manifest_digest(*adapter);
    if (!adoption || *adoption != runtime.adoption_manifest_digest) {
        return std::unexpected(std::string{"Pi adapter adoption digest changed"});
    }
    const auto store = runtime.protected_entry_point.parent_path();
    const snapshot::runtime_dependency_closure original{
        .executable = runtime.source_launch_executable,
        .arguments = {runtime.canonical_source_executable.string()},
        .read_only_paths = runtime.source_read_only_paths,
    };
    if (auto valid = snapshot::validate_pi_source_closure(
            runtime.source_executable,
            runtime.canonical_source_executable,
            original,
            store,
            additional_exclusions
        );
        !valid) {
        return std::unexpected(valid.error());
    }
    const auto snapshot_root = store / "snapshots" / runtime.snapshot_digest;
    const auto payload = snapshot_root / "payload";
    if (runtime.read_only_paths.front() != payload) {
        return std::unexpected(std::string{"Pi requires its sole exact snapshot payload grant"});
    }
    auto mapped_source = snapshot::map_snapshot_path(
        runtime.canonical_source_executable, runtime.source_read_only_paths, payload
    );
    auto mapped_interpreter = snapshot::map_snapshot_path(
        runtime.source_launch_executable, runtime.source_read_only_paths, payload
    );
    if (!mapped_source || !mapped_interpreter || !bounded_path(*mapped_source) ||
        !bounded_path(*mapped_interpreter) ||
        runtime.launch_arguments.front() != mapped_source->string() ||
        runtime.launch_executable != *mapped_interpreter) {
        return std::unexpected(
            std::string{"Pi launch paths differ from the approved snapshot mapping"}
        );
    }
    auto store_fd = open_protected_directory(store, 0700);
    auto snapshots_fd = open_protected_directory(snapshot_root.parent_path(), 0700);
    auto root_fd = open_protected_directory(snapshot_root, 0500);
    auto payload_fd = open_protected_directory(payload, 0500);
    if (!store_fd || !snapshots_fd || !root_fd || !payload_fd) {
        return std::unexpected(std::string{"Pi snapshot directories are not owner-protected"});
    }
    struct stat entry{};
    if (::fstatat(store_fd->get(), "pi", &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(entry.st_mode) || entry.st_uid != ::geteuid() || entry.st_nlink != 1) {
        return std::unexpected(std::string{"Pi protected entry must be an owner-owned symlink"});
    }
    if (auto checked = glove::detail::check_symlink_acl_at(store_fd->get(), "pi", entry);
        !checked) {
        return std::unexpected(checked.error());
    }
    std::error_code error;
    if (std::filesystem::canonical(runtime.protected_entry_point, error) != *mapped_source ||
        error || !canonical_matches(*mapped_source) || !canonical_matches(*mapped_interpreter)) {
        return std::unexpected(std::string{"Pi protected entry or launch path changed"});
    }
    snapshot::snapshot_tree_budget entries;
    const std::vector<std::string> root_children{"payload"};
    if (auto checked =
            check_tree(root_fd->get(), snapshot_root, payload, entries, 0, &root_children);
        !checked) {
        return std::unexpected(checked.error());
    }
    std::vector<std::string> payload_children;
    for (std::size_t index = 0; index < runtime.source_read_only_paths.size(); ++index) {
        payload_children.push_back("root-" + std::to_string(index));
    }
    entries = {};
    if (auto checked =
            check_tree(payload_fd->get(), payload, payload, entries, 0, &payload_children);
        !checked) {
        return std::unexpected(checked.error());
    }
    std::uint64_t source_bytes = 0;
    std::uint64_t source_entries = 0;
    auto source_digest = snapshot::snapshot_closure_digest(
        runtime.source_read_only_paths, &source_bytes, &source_entries
    );
    std::vector<std::filesystem::path> copied_roots;
    for (std::size_t index = 0; index < runtime.source_read_only_paths.size(); ++index) {
        copied_roots.push_back(snapshot::snapshot_payload_root(payload, index));
    }
    std::uint64_t copied_bytes = 0;
    std::uint64_t copied_entries = 0;
    auto copied_digest =
        snapshot::snapshot_closure_digest(copied_roots, &copied_bytes, &copied_entries);
    if (!source_digest || !copied_digest || *source_digest != runtime.snapshot_digest ||
        *copied_digest != runtime.snapshot_digest ||
        source_bytes != runtime.snapshot_logical_bytes ||
        source_entries != runtime.snapshot_entries || copied_bytes != source_bytes ||
        copied_entries != source_entries) {
        return std::unexpected(
            std::string{"Pi source or copied closure no longer matches its approved digest"}
        );
    }
    // Hash helpers reopen paths; retain the checked directory descriptors and
    // reject a topology replacement around that read-only hashing interval.
    for (const auto& [path, pinned] : std::array{
             std::pair{store, store_fd->get()},
             std::pair{snapshot_root.parent_path(), snapshots_fd->get()},
             std::pair{snapshot_root, root_fd->get()},
             std::pair{payload, payload_fd->get()},
         }) {
        struct stat before{};
        struct stat current{};
        auto reopened = open_protected_directory(
            path, path == store || path == snapshot_root.parent_path() ? 0700 : 0500
        );
        if (!reopened || ::fstat(pinned, &before) != 0 || ::fstat(reopened->get(), &current) != 0 ||
            !same_object(before, current) ||
            !glove::detail::check_descriptor_acl(
                pinned,
                path == store || path == snapshot_root.parent_path()
                    ? glove::detail::acl_scope::owner_private
                    : glove::detail::acl_scope::integrity
            )) {
            return std::unexpected(std::string{"Pi snapshot topology changed during hashing"});
        }
    }
    if (auto valid = snapshot::validate_pi_source_closure(
            runtime.source_executable,
            runtime.canonical_source_executable,
            original,
            store,
            additional_exclusions
        );
        !valid) {
        return std::unexpected(valid.error());
    }
    struct stat after{};
    if (::fstatat(store_fd->get(), "pi", &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(entry, after)) {
        return std::unexpected(std::string{"Pi protected entry changed during validation"});
    }
    if (auto checked = glove::detail::check_symlink_acl_at(store_fd->get(), "pi", entry);
        !checked) {
        return std::unexpected(checked.error());
    }
    return {};
}

auto validate_pi_runtime_harness(const staged_runtime_harness& runtime) -> result<void> {
    return detail::validate_pi_runtime_with_exclusions(runtime, {});
}

} // namespace glove::host
