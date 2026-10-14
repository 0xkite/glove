#include "native_library_environment.hpp"

#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <deque>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace fs = std::filesystem;

namespace {

struct owned_directory {
    int fd;

    explicit owned_directory(int value) noexcept : fd{value} {}

    owned_directory(owned_directory&& other) noexcept : fd{std::exchange(other.fd, -1)} {}

    owned_directory(const owned_directory&) = delete;
    auto operator=(const owned_directory&) -> owned_directory& = delete;

    ~owned_directory() {
        if (fd >= 0) {
            (void)::close(fd);
        }
    }
};

auto canonical_spelling(const fs::path& path) -> bool {
    const auto& value = path.native();
    return path.is_absolute() && path != path.root_path() && value.size() <= 4096 &&
           value == path.lexically_normal().native() && value.find('\0') == std::string::npos &&
           value.find(':') == std::string::npos && value.find("//") == std::string::npos &&
           value.back() != '/';
}

auto same_version(const struct stat& before, const struct stat& after) -> bool {
#if defined(__APPLE__)
    const bool times = before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
                       before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
                       before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
                       before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    const bool times = before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
                       before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
                       before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
                       before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
    return times && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
           before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
           before.st_size == after.st_size;
}

auto sealed_directory(int fd, struct stat& identity) -> bool {
    return ::fstat(fd, &identity) == 0 && S_ISDIR(identity.st_mode) &&
           identity.st_uid == ::geteuid() && identity.st_nlink != 0 &&
           (identity.st_mode & 0222U) == 0 &&
           glove::detail::check_descriptor_acl(fd, glove::detail::acl_scope::integrity).has_value();
}

auto recheck_directory(int fd, int parent, const char* name, const struct stat& identity) -> bool {
    struct stat opened{};
    struct stat named{};
    return sealed_directory(fd, opened) && same_version(identity, opened) &&
           ::fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 && same_version(opened, named);
}

// Bounded resolution never follows an arbitrary supplied environment path.
// It starts from the admitted snapshot descriptor and rechecks every visited
// object/link and parent. The original approved projection spelling is retained.

auto inspect_library_path(int payload, std::string_view root_name)
    -> std::expected<bool, std::string> {
    const auto refused = [] {
        return std::unexpected(std::string{"invalid native library projection"});
    };

    struct entry_witness {
        owned_directory descriptor;
        struct stat identity;
        std::size_t parent;
        std::string name;
    };

    struct link_witness {
        std::size_t parent;
        std::string name;
        struct stat identity;
        std::string target;
    };

    std::vector<entry_witness> entries;
    std::vector<link_witness> links;
    std::vector<std::size_t> stack;
    entries.reserve(257);
    links.reserve(40);
    stack.reserve(129);
    owned_directory anchor{::fcntl(payload, F_DUPFD_CLOEXEC, 3)};
    struct stat anchor_identity{};
    if (!sealed_directory(anchor.fd, anchor_identity)) {
        return refused();
    }
    entries.push_back({std::move(anchor), anchor_identity, 0, {}});
    stack.push_back(0);
    std::deque<std::string> pending{std::string{root_name}, "lib"};
    std::size_t queued_bytes = root_name.size() + 3;
    bool directory = true;
    unsigned visits = 0;
    std::vector<std::pair<std::size_t, std::string>> absences;
    while (!pending.empty()) {
        if (++visits > 256 || pending.size() > 128) {
            return refused();
        }
        auto name = std::move(pending.front());
        pending.pop_front();
        queued_bytes -= name.size();
        if (name.empty() || name == ".") {
            continue;
        }
        if (name == "..") {
            if (stack.size() == 1) {
                return refused();
            }
            // Pop the physical parent AFTER earlier aliases have been resolved.
            // Keep its descriptor/name witness in entries for final rechecks.
            stack.pop_back();
            continue;
        }
        if (name.size() > 255 || name.find('/') != std::string::npos ||
            name.find('\0') != std::string::npos) {
            return refused();
        }
        const auto parent_index = stack.back();
        const int parent = entries[parent_index].descriptor.fd;
        constexpr int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        owned_directory child{::openat(parent, name.c_str(), flags)};
        const int opened_error = errno;
        if (child.fd >= 0) {
            struct stat identity{};
            struct stat named{};
            if (::fstat(child.fd, &identity) != 0 || identity.st_uid != ::geteuid() ||
                (identity.st_mode & 0222U) != 0 || identity.st_nlink == 0 ||
                (!S_ISDIR(identity.st_mode) &&
                 (!S_ISREG(identity.st_mode) || identity.st_nlink != 1)) ||
                ::fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
                !same_version(identity, named) ||
                !glove::detail::check_descriptor_acl(
                    child.fd, glove::detail::acl_scope::integrity
                )) {
                return refused();
            }
            const bool is_directory = S_ISDIR(identity.st_mode);
            if (entries.size() == 257 || (is_directory && stack.size() == 129)) {
                return refused();
            }
            entries.push_back({std::move(child), identity, parent_index, name});
            if (is_directory) {
                stack.push_back(entries.size() - 1);
            } else {
                if (!pending.empty()) {
                    return refused();
                }
                directory = false;
            }
        } else if (opened_error == ELOOP) {
            struct stat link{};
            if (links.size() == 40 ||
                ::fstatat(parent, name.c_str(), &link, AT_SYMLINK_NOFOLLOW) != 0 ||
                !glove::detail::check_symlink_acl_at(parent, name, link)) {
                return refused();
            }
            std::array<char, 4097> bytes{};
            const auto count = ::readlinkat(parent, name.c_str(), bytes.data(), bytes.size());
            if (count <= 0 || count > 4096) {
                return refused();
            }
            std::string target{bytes.data(), static_cast<std::size_t>(count)};
            const fs::path target_path{target};
            if (target_path.is_absolute() || target.find('\0') != std::string::npos) {
                return refused();
            }
            std::vector<std::string> components;
            std::size_t extra_bytes = 0;
            for (const auto& component : target_path) {
                auto part = component.string();
                if (part.size() > 255 || part.size() > 4096 - extra_bytes ||
                    components.size() == 128) {
                    return refused();
                }
                extra_bytes += part.size();
                components.push_back(std::move(part));
            }
            if (extra_bytes > 4096 - queued_bytes || components.size() > 128 - pending.size()) {
                return refused();
            }
            for (auto it = components.rbegin(); it != components.rend(); ++it) {
                pending.push_front(*it);
            }
            queued_bytes += extra_bytes;
            links.push_back({parent_index, name, link, std::move(target)});
        } else if (opened_error == ENOENT) {
            struct stat absent{};
            if (::fstatat(parent, name.c_str(), &absent, AT_SYMLINK_NOFOLLOW) == 0 ||
                errno != ENOENT) {
                return refused();
            }
            absences.emplace_back(parent_index, name);
            directory = false;
            break;
        } else {
            return refused();
        }
    }
    const auto recheck_entries = [&] {
        for (std::size_t index = 0; index < entries.size(); ++index) {
            const auto& entry = entries[index];
            struct stat actual{};
            struct stat named{};
            if (::fstat(entry.descriptor.fd, &actual) != 0 ||
                !same_version(entry.identity, actual) ||
                !glove::detail::check_descriptor_acl(
                    entry.descriptor.fd, glove::detail::acl_scope::integrity
                )) {
                return false;
            }
            if (index != 0 && (::fstatat(
                                   entries[entry.parent].descriptor.fd,
                                   entry.name.c_str(),
                                   &named,
                                   AT_SYMLINK_NOFOLLOW
                               ) != 0 ||
                               !same_version(actual, named))) {
                return false;
            }
        }
        return true;
    };
    if (!recheck_entries()) {
        return refused();
    }
    for (const auto& link : links) {
        const int parent = entries[link.parent].descriptor.fd;
        struct stat actual{};
        std::array<char, 4097> target{};
        const auto count = ::readlinkat(parent, link.name.c_str(), target.data(), target.size());
        if (count < 0 || static_cast<std::size_t>(count) != link.target.size() ||
            std::string_view{target.data(), static_cast<std::size_t>(count)} != link.target ||
            ::fstatat(parent, link.name.c_str(), &actual, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_version(link.identity, actual) ||
            !glove::detail::check_symlink_acl_at(parent, link.name, actual)) {
            return refused();
        }
    }
    for (const auto& [parent, name] : absences) {
        struct stat actual{};
        if (::fstatat(entries[parent].descriptor.fd, name.c_str(), &actual, AT_SYMLINK_NOFOLLOW) ==
                0 ||
            errno != ENOENT) {
            return refused();
        }
    }
    if (!recheck_entries()) {
        return refused();
    }
    return directory;
}

} // namespace

auto validate_native_library_environment(
    const host::staged_runtime_harness& runtime, std::span<const std::string> environment
) -> std::expected<void, std::string> {
    constexpr std::string_view prefix = "DYLD_LIBRARY_PATH=";
    const auto refused = [] {
        return std::unexpected(std::string{"invalid native library projection"});
    };
    if (environment.size() > 1 || runtime.read_only_paths.empty() ||
        runtime.source_read_only_paths.size() > 64) {
        return refused();
    }
    std::string_view supplied;
    if (!environment.empty()) {
        const auto& entry = environment.front();
        if (entry.size() > native_library_max_bytes || !entry.starts_with(prefix) ||
            entry.size() == prefix.size() || entry.find('\0') != std::string::npos) {
            return refused();
        }
        supplied = std::string_view{entry}.substr(prefix.size());
        std::set<std::string_view> components;
        auto remaining = supplied;
        while (true) {
            const auto colon = remaining.find(':');
            const auto component = remaining.substr(0, colon);
            if (component.empty() || component.size() > 4096 || components.size() == 64 ||
                !canonical_spelling(fs::path{component}) || !components.insert(component).second) {
                return refused();
            }
            if (colon == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(colon + 1);
        }
    }
    const auto& payload = runtime.read_only_paths.front();
    if (!canonical_spelling(payload)) {
        return refused();
    }
    constexpr int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    owned_directory opened_payload{::open(payload.c_str(), flags)};
    struct stat payload_identity{};
    struct stat payload_named{};
    if (!sealed_directory(opened_payload.fd, payload_identity) ||
        ::lstat(payload.c_str(), &payload_named) != 0 ||
        !same_version(payload_identity, payload_named)) {
        return refused();
    }
    std::string projected;
    for (std::size_t index = 0; index < runtime.source_read_only_paths.size(); ++index) {
        const auto name = "root-" + std::to_string(index);
        owned_directory root{::openat(opened_payload.fd, name.c_str(), flags)};
        struct stat root_identity{};
        if (!sealed_directory(root.fd, root_identity) ||
            !recheck_directory(root.fd, opened_payload.fd, name.c_str(), root_identity)) {
            return refused();
        }
        auto directory = inspect_library_path(opened_payload.fd, name);
        if (!directory ||
            !recheck_directory(root.fd, opened_payload.fd, name.c_str(), root_identity)) {
            return refused();
        }
        if (!*directory) {
            continue;
        }
        const auto path = payload / name / "lib";
        const auto value = path.string();
        if (!canonical_spelling(path)) {
            return refused();
        }
        const std::size_t separator = projected.empty() ? 0U : 1U;
        constexpr auto value_budget = native_library_max_bytes - prefix.size();
        if (projected.size() > value_budget || separator > value_budget - projected.size() ||
            value.size() > value_budget - projected.size() - separator) {
            return refused();
        }
        if (separator != 0) {
            projected.push_back(':');
        }
        projected += value;
    }
    struct stat final_payload{};
    if (!sealed_directory(opened_payload.fd, final_payload) ||
        !same_version(payload_identity, final_payload) ||
        ::lstat(payload.c_str(), &payload_named) != 0 ||
        !same_version(final_payload, payload_named) || supplied != projected ||
        (projected.empty() != environment.empty())) {
        return refused();
    }
    return {};
}

} // namespace glove::run::detail
