#include "pi_catalog.hpp"

#include "glove/detail/descriptor_acl.hpp"
#include "glove/detail/symlink_acl.hpp"

#include "../host/runtime_snapshot.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <deque>
#include <optional>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace {

constexpr std::size_t max_path_bytes = 4096U;
constexpr std::size_t max_depth = 128U;
// Payload-relative lookup includes root-N above the source depth128 budget.
constexpr std::size_t max_payload_depth = max_depth + 1U;
constexpr std::size_t max_catalog_bytes = 1024U * 1024U;
constexpr int open_flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;

template<typename Operation> auto bounded_call(Operation operation) -> decltype(operation()) {
    for (unsigned attempt = 0; attempt < 8U; ++attempt) {
        const auto result = operation();
        if (result >= 0 || errno != EINTR) {
            return result;
        }
    }
    return -1;
}

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

    auto get() const noexcept -> int { return value_; }

    // Do not retry close: on some platforms an interrupted close consumed fd.
    auto close_checked() -> bool {
        const int value = std::exchange(value_, -1);
        return value < 0 || ::close(value) == 0;
    }

private:
    int value_;
};

auto same_security(const struct stat& a, const struct stat& b) -> bool {
    bool same = a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
                a.st_uid == b.st_uid && a.st_gid == b.st_gid;
#if defined(__APPLE__)
    same = same && a.st_flags == b.st_flags && a.st_gen == b.st_gen;
#endif
    return same;
}

auto same_version(const struct stat& a, const struct stat& b) -> bool {
    if (!same_security(a, b) || a.st_nlink != b.st_nlink || a.st_size != b.st_size) {
        return false;
    }
#if defined(__APPLE__)
    return a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
           a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
           a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec &&
           a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
#else
    return a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
           a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
#endif
}

auto protected_object(const struct stat& metadata) -> bool {
    const auto mode = metadata.st_mode & 07777U;
    return metadata.st_uid == ::geteuid() &&
           (S_ISDIR(metadata.st_mode) ? mode == 0500U
                                      : S_ISREG(metadata.st_mode) && metadata.st_nlink == 1 &&
                                            (mode == 0400U || mode == 0500U));
}

auto safe_ancestor(const struct stat& metadata) -> bool {
    const bool sticky_root = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
    return S_ISDIR(metadata.st_mode) && (metadata.st_uid == 0 || metadata.st_uid == ::geteuid()) &&
           ((metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0 || sticky_root);
}

auto read_link(int parent, const std::string& name) -> std::optional<std::string> {
    std::array<char, max_path_bytes + 1U> buffer{};
    const auto count = bounded_call([&] {
        return ::readlinkat(parent, name.c_str(), buffer.data(), buffer.size());
    });
    if (count <= 0 || static_cast<std::size_t>(count) > max_path_bytes) {
        return std::nullopt;
    }
    std::string target{buffer.data(), static_cast<std::size_t>(count)};
    if (target.front() == '/' || target.find('\0') != std::string::npos) {
        return std::nullopt;
    }
    return target;
}

struct pin {
    descriptor fd;
    std::size_t parent;
    std::string name;
    struct stat metadata{};
    bool versioned = true;
    std::optional<std::string> link;
};

// Indices, not raw references, survive vector growth. All visited components
// remain pinned even when '..' or package discovery pops the logical stack.
class pinned_payload {
public:
    auto open_root(const std::filesystem::path& payload) -> bool {
        if (!payload.is_absolute() || payload == payload.root_path() ||
            payload.lexically_normal() != payload || payload.native().size() > max_path_bytes ||
            payload.native().find('\0') != std::string::npos) {
            return false;
        }
        descriptor root{bounded_call([] { return ::open("/", open_flags | O_DIRECTORY); })};
        struct stat metadata{};
        struct stat named{};
        if (root.get() < 0 || ::fstat(root.get(), &metadata) != 0 || ::lstat("/", &named) != 0 ||
            !same_security(metadata, named) || !safe_ancestor(metadata) ||
            !glove::detail::check_descriptor_acl(root.get(), glove::detail::acl_scope::integrity)) {
            return false;
        }
        pins_.push_back({std::move(root), 0U, {}, metadata, false, std::nullopt});
        std::size_t parent = 0;
        std::size_t depth = 0;
        for (const auto& component : payload.relative_path()) {
            if (++depth > max_depth) {
                return false;
            }
            auto child = open_child(parent, component.string(), false);
            if (!child || !safe_ancestor(pins_[*child].metadata)) {
                return false;
            }
            parent = *child;
        }
        if (!protected_object(pins_[parent].metadata)) {
            return false;
        }
        pins_[parent].versioned = true;
        payload_ = parent;
        return true;
    }

    struct resolved {
        std::size_t object;
        std::vector<std::size_t> directories;
    };

    auto resolve(std::vector<std::size_t> stack, std::string_view path) -> std::optional<resolved> {
        if (stack.empty() || stack.front() != payload_ || path.empty() || path.front() == '/' ||
            path.size() > max_path_bytes || path.find('\0') != std::string_view::npos) {
            return std::nullopt;
        }
        std::deque<std::string> remaining;
        append_components(remaining, path);
        std::size_t bytes = path.size();
        unsigned hops = 0;
        std::set<std::pair<dev_t, ino_t>> links;
        while (!remaining.empty()) {
            auto name = std::move(remaining.front());
            remaining.pop_front();
            if (name == "." || name.empty()) {
                continue;
            }
            if (name == "..") {
                if (stack.size() == 1U) {
                    return std::nullopt;
                }
                stack.pop_back();
                continue;
            }
            if (stack.size() > max_payload_depth) {
                return std::nullopt;
            }
            const auto parent = stack.back();
            // Attempt a no-follow open first, including for links and FIFOs.
            auto child = open_child(parent, name, true);
            if (!child) {
                struct stat metadata{};
                if (::fstatat(fd(parent), name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !S_ISLNK(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
                    metadata.st_nlink != 1 || ++hops > 32U ||
                    !links.emplace(metadata.st_dev, metadata.st_ino).second) {
                    return std::nullopt;
                }
                if (!glove::detail::check_symlink_acl_at(fd(parent), name, metadata)) {
                    return std::nullopt;
                }
                auto target = read_link(fd(parent), name);
                struct stat after{};
                if (!target || bytes + target->size() > max_path_bytes ||
                    ::fstatat(fd(parent), name.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !same_version(metadata, after)) {
                    return std::nullopt;
                }
                bytes += target->size();
                pins_.push_back({descriptor{}, parent, name, metadata, true, target});
                std::deque<std::string> expanded;
                append_components(expanded, *target);
                expanded.insert(expanded.end(), remaining.begin(), remaining.end());
                remaining = std::move(expanded);
                continue;
            }
            if (remaining.empty()) {
                return resolved{*child, std::move(stack)};
            }
            if (!S_ISDIR(pins_[*child].metadata.st_mode)) {
                return std::nullopt;
            }
            stack.push_back(*child);
        }
        return resolved{stack.back(), std::move(stack)};
    }

    auto nearest_package(std::vector<std::size_t> stack)
        -> std::optional<std::vector<std::size_t>> {
        for (std::size_t depth = 0; !stack.empty() && depth < max_payload_depth; ++depth) {
            auto manifest = open_child(stack.back(), "package.json", true);
            if (manifest) {
                if (!S_ISREG(pins_[*manifest].metadata.st_mode)) {
                    return std::nullopt;
                }
                return stack;
            }
            // Only absence permits moving up. A link, special file, unsafe
            // mode or changed nearest manifest is not a fallback opportunity.
            struct stat named{};
            if (::fstatat(fd(stack.back()), "package.json", &named, AT_SYMLINK_NOFOLLOW) == 0 ||
                errno != ENOENT) {
                return std::nullopt;
            }
            stack.pop_back();
        }
        return std::nullopt;
    }

    auto revalidate() const -> bool {
        for (std::size_t index = 0; index < pins_.size(); ++index) {
            const auto& item = pins_[index];
            struct stat named{};
            const int status =
                index == 0U
                    ? ::lstat("/", &named)
                    : ::fstatat(fd(item.parent), item.name.c_str(), &named, AT_SYMLINK_NOFOLLOW);
            const auto matches = [&](const struct stat& value) {
                return item.versioned ? same_version(item.metadata, value)
                                      : same_security(item.metadata, value);
            };
            if (status != 0 || !matches(named)) {
                return false;
            }
            if (item.link) {
                if (!glove::detail::check_symlink_acl_at(
                        fd(item.parent), item.name, item.metadata
                    ) ||
                    read_link(fd(item.parent), item.name) != item.link) {
                    return false;
                }
            } else {
                struct stat opened{};
                if (::fstat(item.fd.get(), &opened) != 0 || !matches(opened) ||
                    !glove::detail::check_descriptor_acl(
                        item.fd.get(), glove::detail::acl_scope::integrity
                    )) {
                    return false;
                }
            }
        }
        return true;
    }

    auto close_checked() -> bool {
        bool okay = true;
        for (auto& item : pins_) {
            if (!item.fd.close_checked()) {
                okay = false;
            }
        }
        return okay;
    }

    auto fd(std::size_t index) const -> int { return pins_[index].fd.get(); }

    auto metadata(std::size_t index) const -> const struct stat& { return pins_[index].metadata; }

    auto root_stack() const -> std::vector<std::size_t> { return {payload_}; }

private:
    static void append_components(std::deque<std::string>& output, std::string_view path) {
        while (!path.empty()) {
            const auto separator = path.find('/');
            const auto part = path.substr(0, separator);
            if (!part.empty()) {
                output.emplace_back(part);
            }
            if (separator == std::string_view::npos) {
                break;
            }
            path.remove_prefix(separator + 1U);
        }
    }

    auto open_child(std::size_t parent, const std::string& name, bool versioned)
        -> std::optional<std::size_t> {
        if (!glove::detail::check_descriptor_acl(fd(parent), glove::detail::acl_scope::integrity)) {
            return std::nullopt;
        }
        descriptor child{bounded_call([&] {
            return ::openat(fd(parent), name.c_str(), open_flags);
        })};
        struct stat opened{};
        struct stat named{};
        if (child.get() < 0 || ::fstat(child.get(), &opened) != 0 ||
            ::fstatat(fd(parent), name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            (versioned ? !same_version(opened, named) : !same_security(opened, named)) ||
            (versioned ? !protected_object(opened) : !safe_ancestor(opened)) ||
            !glove::detail::check_descriptor_acl(
                child.get(), glove::detail::acl_scope::integrity
            )) {
            return std::nullopt;
        }
        const auto index = pins_.size();
        pins_.push_back({std::move(child), parent, name, opened, versioned, std::nullopt});
        return index;
    }

    std::vector<pin> pins_;
    std::size_t payload_ = 0;
};

} // namespace

auto load_pi_builtin_catalog(
    const pi_runtime_selection& selection,
    pi_provider provider,
    std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::string, std::string> {
    std::string_view filename;
    switch (provider) {
    case pi_provider::openai:
        filename = "openai.json";
        break;
    case pi_provider::anthropic:
        filename = "anthropic.json";
        break;
    default:
        return std::unexpected(std::string{"Pi catalog provider is unsupported"});
    }
    const auto& runtime = selection.runtime;
    if (auto valid = host::detail::validate_pi_runtime_with_exclusions(runtime, source_exclusions);
        !valid) {
        return std::unexpected(valid.error());
    }
    const auto& payload = runtime.read_only_paths.front();
    const std::filesystem::path script{runtime.launch_arguments.front()};
    const auto relative = script.lexically_relative(payload);
    if (relative.empty() || relative.is_absolute()) {
        return std::unexpected(std::string{"Pi script is outside its approved payload"});
    }
    pinned_payload pinned;
    if (!pinned.open_root(payload)) {
        return std::unexpected(std::string{"Pi catalog payload ancestry is unsafe"});
    }
    auto mapped = pinned.resolve(pinned.root_stack(), relative.native());
    if (!mapped || !S_ISREG(pinned.metadata(mapped->object).st_mode)) {
        return std::unexpected(std::string{"Pi catalog script binding is unsafe"});
    }
    auto package = pinned.nearest_package(std::move(mapped->directories));
    if (!package) {
        return std::unexpected(
            std::string{"Pi copied script has no safe nearest package manifest"}
        );
    }
    const std::string suffix =
        "node_modules/@earendil-works/pi-ai/dist/providers/data/" + std::string{filename};
    auto catalog = pinned.resolve(std::move(*package), suffix);
    if (!catalog) {
        return std::unexpected(std::string{"Pi approved catalog path is missing or unsafe"});
    }
    const auto& metadata = pinned.metadata(catalog->object);
    if (!S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        static_cast<std::uintmax_t>(metadata.st_size) > max_catalog_bytes || !pinned.revalidate()) {
        return std::unexpected(std::string{"Pi catalog type, size, or topology is unsafe"});
    }
    std::string bytes(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto count = bounded_call([&] {
            return ::read(
                pinned.fd(catalog->object), bytes.data() + consumed, bytes.size() - consumed
            );
        });
        if (count <= 0) {
            return std::unexpected(std::string{"Pi catalog read failed or truncated"});
        }
        consumed += static_cast<std::size_t>(count);
    }
    char trailing{};
    if (bounded_call([&] { return ::read(pinned.fd(catalog->object), &trailing, 1U); }) != 0 ||
        !pinned.revalidate()) {
        return std::unexpected(std::string{"Pi catalog grew or changed while reading"});
    }
    // Whole-runtime hashing reopens paths. Keep every catalog/component pin
    // alive across it, then check those pins again. This is drift detection,
    // not an atomic integrity guarantee against another same-UID process.
    if (auto valid = host::detail::validate_pi_runtime_with_exclusions(runtime, source_exclusions);
        !valid) {
        return std::unexpected(valid.error());
    }
    if (!pinned.revalidate() || !pinned.close_checked()) {
        return std::unexpected(std::string{"Pi catalog changed or failed to close"});
    }
    return bytes;
}

} // namespace glove::run::detail
