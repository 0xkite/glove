#include "glove/supervisor/harness_adoption.hpp"

#include "glove/container/digest.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace adoption_wire {

struct pi_generated_settings {
    std::vector<std::string> packages;
    bool enableSkillCommands = false;
};

struct pi_adoption_manifest {
    std::uint32_t schema_version = 0;
    std::string runtime_id;
    std::string manifest_digest;
    std::string snapshot_digest;
    std::vector<std::string> packages;
    pi_generated_settings generated_settings;
};

} // namespace adoption_wire

namespace {

constexpr std::uint64_t max_manifest_bytes = std::uint64_t{1024} * 1024U;
constexpr std::uint64_t max_payload_bytes = std::uint64_t{2} * 1024U * 1024U * 1024U;
constexpr std::size_t max_payload_entries = 200'000U;
constexpr std::size_t max_payload_roots = 64U;
constexpr std::size_t max_relative_path_bytes = 4'096U;
constexpr std::size_t copy_buffer_bytes = std::size_t{64} * 1024U;
constexpr auto permission_mask = 0777U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

    void reset(int descriptor = -1) noexcept {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

class unique_directory {
public:
    explicit unique_directory(::DIR* directory = nullptr) noexcept : directory_{directory} {}

    unique_directory(const unique_directory&) = delete;
    auto operator=(const unique_directory&) -> unique_directory& = delete;
    unique_directory(unique_directory&&) = delete;
    auto operator=(unique_directory&&) -> unique_directory& = delete;

    ~unique_directory() {
        if (directory_ != nullptr) {
            static_cast<void>(::closedir(directory_));
        }
    }

    [[nodiscard]] auto get() const noexcept -> ::DIR* { return directory_; }

private:
    ::DIR* directory_ = nullptr;
};

struct file_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    std::uint64_t owner = 0;
    std::uint64_t links = 0;
    std::uint32_t mode = 0;
    std::int64_t modified_seconds = 0;
    std::int64_t changed_seconds = 0;
    std::int64_t modified_nanoseconds = 0;
    std::int64_t changed_nanoseconds = 0;

    auto operator==(const file_identity&) const -> bool = default;
};

struct manifest_document {
    std::string generated_settings_json;
    std::size_t payload_count = 0;
};

struct tree_digest {
    std::string digest;
    std::uint64_t bytes = 0;
    std::uint64_t entries = 0;
};

struct tree_state {
    std::string manifest;
    std::uint64_t bytes = 0;
    std::uint64_t entries = 0;
};

struct copy_state {
    std::uint64_t bytes = 0;
    std::uint64_t entries = 0;
};

auto errno_message(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_pi_package_id(std::string_view value) -> bool {
    if (value.empty() || value.size() > 214U || value.starts_with('.') || value.contains("..") ||
        std::ranges::any_of(value, [](unsigned char byte) {
            return !(
                std::isalnum(byte) != 0 || byte == '@' || byte == '/' || byte == '-' ||
                byte == '_' || byte == '.'
            );
        })) {
        return false;
    }
    const auto slash = value.find('/');
    if (value.starts_with('@')) {
        return slash != std::string_view::npos && slash > 1U && slash + 1U < value.size() &&
               value.find('/', slash + 1U) == std::string_view::npos;
    }
    return slash == std::string_view::npos;
}

auto valid_relative_component(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 255U && value != "." && value != ".." &&
           value.find('/') == std::string_view::npos && value.find('\0') == std::string_view::npos;
}

auto same_file_identity(const struct stat& before, const struct stat& after) -> bool {
#if defined(__APPLE__)
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

auto make_file_identity(const struct stat& metadata) -> file_identity {
#if defined(__APPLE__)
    return {
        .device = static_cast<std::uint64_t>(metadata.st_dev),
        .inode = static_cast<std::uint64_t>(metadata.st_ino),
        .size = static_cast<std::uint64_t>(metadata.st_size),
        .owner = static_cast<std::uint64_t>(metadata.st_uid),
        .links = static_cast<std::uint64_t>(metadata.st_nlink),
        .mode = static_cast<std::uint32_t>(metadata.st_mode),
        .modified_seconds = metadata.st_mtimespec.tv_sec,
        .changed_seconds = metadata.st_ctimespec.tv_sec,
        .modified_nanoseconds = metadata.st_mtimespec.tv_nsec,
        .changed_nanoseconds = metadata.st_ctimespec.tv_nsec,
    };
#else
    return {
        .device = static_cast<std::uint64_t>(metadata.st_dev),
        .inode = static_cast<std::uint64_t>(metadata.st_ino),
        .size = static_cast<std::uint64_t>(metadata.st_size),
        .owner = static_cast<std::uint64_t>(metadata.st_uid),
        .links = static_cast<std::uint64_t>(metadata.st_nlink),
        .mode = static_cast<std::uint32_t>(metadata.st_mode),
        .modified_seconds = metadata.st_mtim.tv_sec,
        .changed_seconds = metadata.st_ctim.tv_sec,
        .modified_nanoseconds = metadata.st_mtim.tv_nsec,
        .changed_nanoseconds = metadata.st_ctim.tv_nsec,
    };
#endif
}

auto same_file_identity(const struct stat& metadata, const file_identity& expected) -> bool {
    return make_file_identity(metadata) == expected;
}

auto owner_only_directory(const struct stat& metadata, mode_t expected_mode) -> bool {
    return S_ISDIR(metadata.st_mode) && metadata.st_uid == ::geteuid() &&
           (metadata.st_mode & permission_mask) == expected_mode;
}

auto protected_snapshot_directory(const struct stat& metadata) -> bool {
    return S_ISDIR(metadata.st_mode) && metadata.st_uid == ::geteuid() &&
           (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (metadata.st_mode & (S_IRUSR | S_IXUSR)) == (S_IRUSR | S_IXUSR);
}

auto immutable_payload_directory(const struct stat& metadata) -> bool {
    return S_ISDIR(metadata.st_mode) && metadata.st_uid == ::geteuid() &&
           (metadata.st_mode & permission_mask) == 0500U &&
           (metadata.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) == 0;
}

auto immutable_payload_file(const struct stat& metadata) -> bool {
    const auto mode = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    return S_ISREG(metadata.st_mode) && metadata.st_uid == ::geteuid() && metadata.st_nlink == 1 &&
           (mode == 0400U || mode == 0500U) &&
           (metadata.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) == 0 && metadata.st_size >= 0;
}

auto open_absolute_directory_no_follow(std::string_view raw)
    -> std::expected<unique_fd, std::string> {
    const std::filesystem::path path{raw};
    if (raw.empty() || raw.size() > max_relative_path_bytes ||
        raw.find('\0') != std::string_view::npos || !path.is_absolute() ||
        path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"adoption manifest root is invalid"});
    }
    unique_fd current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (current.get() < 0) {
        return std::unexpected(errno_message("open adoption filesystem root"));
    }
    for (const auto& component : path.relative_path()) {
        const auto name = component.string();
        if (!valid_relative_component(name)) {
            return std::unexpected(std::string{"adoption manifest root has an invalid component"});
        }
        unique_fd next{
            ::openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (next.get() < 0) {
            return std::unexpected(errno_message("resolve adoption manifest root"));
        }
        current = std::move(next);
    }
    return current;
}

auto open_directory_at(int parent_fd, std::string_view name)
    -> std::expected<unique_fd, std::string> {
    if (parent_fd < 0 || !valid_relative_component(name)) {
        return std::unexpected(std::string{"adoption directory component is invalid"});
    }
    unique_fd descriptor{::openat(
        parent_fd, std::string{name}.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (descriptor.get() < 0) {
        return std::unexpected(errno_message("open adoption directory"));
    }
    return descriptor;
}

auto directory_entries(int descriptor, std::size_t maximum)
    -> std::expected<std::vector<std::string>, std::string> {
    if (descriptor < 0 || maximum == 0) {
        return std::unexpected(std::string{"adoption directory iterator is invalid"});
    }
    unique_fd duplicate{::fcntl(descriptor, F_DUPFD_CLOEXEC, 0)};
    if (duplicate.get() < 0) {
        return std::unexpected(errno_message("duplicate adoption directory"));
    }
    ::DIR* raw = ::fdopendir(duplicate.get());
    if (raw == nullptr) {
        return std::unexpected(errno_message("iterate adoption directory"));
    }
    static_cast<void>(duplicate.release());
    unique_directory directory{raw};
    // Duplicated directory descriptors share the open-file description and
    // therefore its iteration offset. Rewind the duplicate before every
    // bounded traversal so a prior identity check cannot make a valid payload
    // appear empty during a later revalidation.
    ::rewinddir(directory.get());
    std::vector<std::string> entries;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(errno_message("read adoption directory"));
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (!valid_relative_component(name) || entries.size() >= maximum) {
            return std::unexpected(std::string{"adoption payload directory exceeds its bound"});
        }
        entries.emplace_back(name);
    }
    std::ranges::sort(entries);
    return entries;
}

auto append(std::string& destination, std::string_view value) -> std::expected<void, std::string> {
    constexpr std::size_t max_tree_manifest_bytes = std::size_t{64} * 1024U * 1024U;
    if (destination.size() > max_tree_manifest_bytes ||
        value.size() > max_tree_manifest_bytes - destination.size()) {
        return std::unexpected(std::string{"adoption snapshot manifest exceeds its bound"});
    }
    destination.append(value);
    return {};
}

auto append_nul(std::string& destination) -> std::expected<void, std::string> {
    return append(destination, std::string_view{"\0", 1U});
}

auto hash_payload_file(
    int parent_fd, std::string_view name, std::string_view relative, tree_state& state
) -> std::expected<void, std::string> {
    unique_fd descriptor{
        ::openat(parent_fd, std::string{name}.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (descriptor.get() < 0) {
        return std::unexpected(errno_message("open adoption payload file"));
    }
    struct stat before{};
    if (::fstat(descriptor.get(), &before) != 0 || !immutable_payload_file(before)) {
        return std::unexpected(std::string{"adoption payload file metadata is unsafe"});
    }
    const auto size = static_cast<std::uint64_t>(before.st_size);
    if (size > max_payload_bytes - state.bytes) {
        return std::unexpected(std::string{"adoption payload exceeds its byte bound"});
    }
    auto digest = container::sha256_fd_hex(descriptor.get(), std::max<std::uint64_t>(size, 1U));
    struct stat after{};
    if (!digest || ::fstat(descriptor.get(), &after) != 0 || !same_file_identity(before, after)) {
        return std::unexpected(
            digest ? std::string{"adoption payload file changed while hashing"}
                   : std::string{"hash adoption payload file: "} + digest.error()
        );
    }
    if (auto appended = append(state.manifest, "f"); !appended) {
        return appended;
    }
    if (auto appended = append_nul(state.manifest); !appended) {
        return appended;
    }
    if (auto appended = append(state.manifest, relative); !appended) {
        return appended;
    }
    if (auto appended = append_nul(state.manifest); !appended) {
        return appended;
    }
    if (auto appended = append(state.manifest, (before.st_mode & 0111U) != 0 ? "x" : "-");
        !appended) {
        return appended;
    }
    if (auto appended = append_nul(state.manifest); !appended) {
        return appended;
    }
    if (auto appended = append(state.manifest, std::to_string(size)); !appended) {
        return appended;
    }
    if (auto appended = append_nul(state.manifest); !appended) {
        return appended;
    }
    if (auto appended = append(state.manifest, *digest); !appended) {
        return appended;
    }
    if (auto appended = append_nul(state.manifest); !appended) {
        return appended;
    }
    state.bytes += size;
    return {};
}

auto snapshot_tree_digest_at(int descriptor, std::string_view prefix, tree_state& state)
    -> std::expected<void, std::string> {
    auto entries = directory_entries(descriptor, max_payload_entries - state.entries);
    if (!entries) {
        return std::unexpected(entries.error());
    }
    for (const auto& name : *entries) {
        if (state.entries == max_payload_entries) {
            return std::unexpected(std::string{"adoption payload exceeds its entry bound"});
        }
        const std::string relative =
            prefix.empty() ? name : std::string{prefix} + "/" + std::string{name};
        if (relative.size() > max_relative_path_bytes) {
            return std::unexpected(std::string{"adoption payload path exceeds its bound"});
        }
        struct stat metadata{};
        if (::fstatat(descriptor, name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(errno_message("inspect adoption payload entry"));
        }
        ++state.entries;
        if (S_ISDIR(metadata.st_mode)) {
            if (!immutable_payload_directory(metadata)) {
                return std::unexpected(std::string{"adoption payload directory is unsafe"});
            }
            auto child = open_directory_at(descriptor, name);
            if (!child) {
                return std::unexpected(child.error());
            }
            if (auto appended = append(state.manifest, "d"); !appended) {
                return appended;
            }
            if (auto appended = append_nul(state.manifest); !appended) {
                return appended;
            }
            if (auto appended = append(state.manifest, relative); !appended) {
                return appended;
            }
            if (auto appended = append_nul(state.manifest); !appended) {
                return appended;
            }
            if (auto nested = snapshot_tree_digest_at(child->get(), relative, state); !nested) {
                return nested;
            }
            continue;
        }
        if (S_ISREG(metadata.st_mode)) {
            if (auto hashed = hash_payload_file(descriptor, name, relative, state); !hashed) {
                return hashed;
            }
            continue;
        }
        return std::unexpected(
            S_ISLNK(metadata.st_mode)
                ? std::string{"adoption payload symbolic links are not supported"}
                : std::string{"adoption payload contains an unsupported file type"}
        );
    }
    return {};
}

auto snapshot_tree_digest_at(int descriptor) -> std::expected<tree_digest, std::string> {
    struct stat root{};
    if (descriptor < 0 || ::fstat(descriptor, &root) != 0 || !immutable_payload_directory(root)) {
        return std::unexpected(std::string{"adoption payload root is unsafe"});
    }
    tree_state state;
    if (auto scanned = snapshot_tree_digest_at(descriptor, {}, state); !scanned) {
        return std::unexpected(scanned.error());
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(state.manifest.data()), state.manifest.size()
    };
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash adoption payload tree: "} + digest.error());
    }
    return tree_digest{
        .digest = std::move(*digest),
        .bytes = state.bytes,
        .entries = state.entries,
    };
}

auto payload_snapshot_digest(int payload_fd, std::size_t payload_count)
    -> std::expected<std::string, std::string> {
    struct stat payload{};
    if (payload_fd < 0 || payload_count == 0 || payload_count > max_payload_roots ||
        ::fstat(payload_fd, &payload) != 0 || !immutable_payload_directory(payload)) {
        return std::unexpected(std::string{"adoption snapshot payload is unsafe"});
    }
    auto entries = directory_entries(payload_fd, max_payload_roots + 1U);
    if (!entries) {
        return std::unexpected(entries.error());
    }
    std::vector<std::string> expected;
    expected.reserve(payload_count);
    for (std::size_t index = 0; index < payload_count; ++index) {
        expected.push_back("root-" + std::to_string(index));
    }
    if (*entries != expected) {
        return std::unexpected(std::string{"adoption snapshot payload layout is invalid"});
    }

    std::string manifest{"glove.runtime-snapshot.v2"};
    std::uint64_t total_bytes = 0;
    std::uint64_t total_entries = 0;
    for (const auto& name : expected) {
        auto root = open_directory_at(payload_fd, name);
        if (!root) {
            return std::unexpected(root.error());
        }
        auto tree = snapshot_tree_digest_at(root->get());
        if (!tree) {
            return std::unexpected(tree.error());
        }
        if (tree->bytes > max_payload_bytes - total_bytes ||
            tree->entries > max_payload_entries - total_entries) {
            return std::unexpected(std::string{"adoption snapshot exceeds its aggregate bound"});
        }
        total_bytes += tree->bytes;
        total_entries += tree->entries;
        if (auto appended = append_nul(manifest); !appended) {
            return std::unexpected(appended.error());
        }
        if (auto appended = append(manifest, tree->digest); !appended) {
            return std::unexpected(appended.error());
        }
    }
    const auto bytes =
        std::span{reinterpret_cast<const unsigned char*>(manifest.data()), manifest.size()};
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash adoption snapshot: "} + digest.error());
    }
    return *digest;
}

auto read_manifest(int descriptor)
    -> std::expected<std::pair<std::string, file_identity>, std::string> {
    struct stat before{};
    if (descriptor < 0 || ::fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        (before.st_mode & permission_mask) != 0600U || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > max_manifest_bytes ||
        static_cast<std::uint64_t>(before.st_size) >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::unexpected(std::string{"adoption manifest metadata is unsafe"});
    }
    std::string contents(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const auto read = ::pread(
            descriptor,
            contents.data() + offset,
            contents.size() - offset,
            static_cast<off_t>(offset)
        );
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(
                read < 0 ? errno_message("read adoption manifest")
                         : std::string{"adoption manifest ended unexpectedly"}
            );
        }
        offset += static_cast<std::size_t>(read);
    }
    struct stat after{};
    if (::fstat(descriptor, &after) != 0 || !same_file_identity(before, after)) {
        return std::unexpected(std::string{"adoption manifest changed while reading"});
    }
    return std::pair{std::move(contents), make_file_identity(after)};
}

auto decode_pi_manifest(
    const std::string& contents,
    const native_harness_adoption_policy& policy,
    std::string_view expected_runtime_id
) -> std::expected<manifest_document, std::string> {
    adoption_wire::pi_adoption_manifest manifest;
    std::string parse_buffer{contents};
    if (const auto error = glz::read<strict_read_options>(manifest, parse_buffer); error) {
        return std::unexpected(
            std::string{"decode adoption manifest: "} + glz::format_error(error, parse_buffer)
        );
    }
    auto canonical = glz::write_json(manifest);
    if (!canonical || *canonical != contents) {
        return std::unexpected(std::string{"adoption manifest is not canonical"});
    }
    if (manifest.schema_version != 1 || manifest.runtime_id != expected_runtime_id ||
        manifest.manifest_digest != policy.manifest_digest ||
        manifest.snapshot_digest != policy.snapshot_digest || manifest.packages.empty() ||
        manifest.packages.size() > max_payload_roots ||
        !manifest.generated_settings.enableSkillCommands) {
        return std::unexpected(std::string{"adoption manifest binding is invalid"});
    }
    for (std::size_t index = 0; index < manifest.packages.size(); ++index) {
        if (!valid_pi_package_id(manifest.packages[index]) ||
            (index != 0 && manifest.packages[index - 1U] >= manifest.packages[index])) {
            return std::unexpected(std::string{"adoption manifest package selectors are invalid"});
        }
    }
    auto settings = pi_adoption_settings_json(manifest.packages.size());
    if (!settings) {
        return std::unexpected(settings.error());
    }
    if (manifest.generated_settings.packages.size() != manifest.packages.size()) {
        return std::unexpected(std::string{"adoption manifest generated settings are invalid"});
    }
    for (std::size_t index = 0; index < manifest.generated_settings.packages.size(); ++index) {
        const std::string expected = "./extensions/" + std::to_string(index);
        if (manifest.generated_settings.packages[index] != expected) {
            return std::unexpected(std::string{"adoption manifest generated settings escape home"});
        }
    }
    auto digest = native_harness_adoption_document_digest(
        manifest.snapshot_digest, std::span<const std::string>{manifest.packages}
    );
    if (!digest || *digest != manifest.manifest_digest) {
        return std::unexpected(
            digest ? std::string{"adoption manifest digest mismatch"}
                   : std::string{"derive adoption manifest digest: "} + digest.error()
        );
    }
    return manifest_document{
        .generated_settings_json = std::move(*settings),
        .payload_count = manifest.packages.size(),
    };
}

auto make_private_directory_at(int parent_fd, std::string_view name)
    -> std::expected<unique_fd, std::string> {
    if (parent_fd < 0 || !valid_relative_component(name)) {
        return std::unexpected(std::string{"adoption private-home component is invalid"});
    }
    if (::mkdirat(parent_fd, std::string{name}.c_str(), 0700) != 0 && errno != EEXIST) {
        return std::unexpected(errno_message("create adoption private-home directory"));
    }
    auto directory = open_directory_at(parent_fd, name);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    struct stat metadata{};
    if (::fstat(directory->get(), &metadata) != 0 || !owner_only_directory(metadata, 0700U)) {
        return std::unexpected(std::string{"adoption private-home directory is unsafe"});
    }
    return directory;
}

auto write_all(int descriptor, const unsigned char* bytes, std::size_t size)
    -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < size) {
        const auto written = ::write(descriptor, bytes + offset, size - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return std::unexpected(errno_message("write adoption private payload"));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto reserve_copy_entry(copy_state& state) -> std::expected<void, std::string> {
    if (state.entries == max_payload_entries) {
        return std::unexpected(std::string{"adoption private payload exceeds its entry bound"});
    }
    ++state.entries;
    return {};
}

auto copy_payload_tree(int source_fd, int destination_fd, copy_state& state)
    -> std::expected<void, std::string> {
    auto entries = directory_entries(source_fd, max_payload_entries - state.entries);
    if (!entries) {
        return std::unexpected(entries.error());
    }
    for (const auto& name : *entries) {
        if (auto reserved = reserve_copy_entry(state); !reserved) {
            return reserved;
        }
        struct stat metadata{};
        if (::fstatat(source_fd, name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(errno_message("inspect adoption payload for copy"));
        }
        if (S_ISDIR(metadata.st_mode)) {
            if (!immutable_payload_directory(metadata) ||
                ::mkdirat(destination_fd, name.c_str(), 0700) != 0) {
                return std::unexpected(
                    S_ISDIR(metadata.st_mode) ? errno_message("create adopted payload directory")
                                              : std::string{"adoption payload directory is unsafe"}
                );
            }
            auto source = open_directory_at(source_fd, name);
            auto destination = open_directory_at(destination_fd, name);
            if (!source || !destination) {
                return std::unexpected(source ? destination.error() : source.error());
            }
            struct stat destination_metadata{};
            if (::fstat(destination->get(), &destination_metadata) != 0 ||
                !owner_only_directory(destination_metadata, 0700U)) {
                return std::unexpected(std::string{"adopted payload directory is unsafe"});
            }
            if (auto copied = copy_payload_tree(source->get(), destination->get(), state);
                !copied) {
                return copied;
            }
            if (::fchmod(destination->get(), 0500) != 0 || ::fsync(destination->get()) != 0) {
                return std::unexpected(errno_message("finalize adopted payload directory"));
            }
            continue;
        }
        if (!S_ISREG(metadata.st_mode) || !immutable_payload_file(metadata)) {
            return std::unexpected(
                S_ISLNK(metadata.st_mode)
                    ? std::string{"adoption payload symbolic links are not supported"}
                    : std::string{"adoption payload file is unsafe"}
            );
        }
        const auto size = static_cast<std::uint64_t>(metadata.st_size);
        if (size > max_payload_bytes - state.bytes) {
            return std::unexpected(std::string{"adoption private payload exceeds its byte bound"});
        }
        unique_fd source{::openat(source_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
        unique_fd destination{::openat(
            destination_fd,
            name.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            (metadata.st_mode & 0111U) != 0 ? 0500 : 0400
        )};
        if (source.get() < 0 || destination.get() < 0) {
            return std::unexpected(
                source.get() < 0 ? errno_message("open adoption payload file")
                                 : errno_message("create adopted payload file")
            );
        }
        struct stat source_before{};
        if (::fstat(source.get(), &source_before) != 0 ||
            !same_file_identity(source_before, metadata)) {
            return std::unexpected(std::string{"adoption payload file changed before copy"});
        }
        std::array<unsigned char, copy_buffer_bytes> buffer{};
        std::uint64_t offset = 0;
        while (offset < size) {
            const auto requested =
                static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - offset));
            const auto read =
                ::pread(source.get(), buffer.data(), requested, static_cast<off_t>(offset));
            if (read < 0 && errno == EINTR) {
                continue;
            }
            if (read <= 0) {
                return std::unexpected(errno_message("read adoption payload file"));
            }
            if (auto written =
                    write_all(destination.get(), buffer.data(), static_cast<std::size_t>(read));
                !written) {
                return written;
            }
            offset += static_cast<std::uint64_t>(read);
        }
        struct stat source_after{};
        struct stat destination_after{};
        if (::fstat(source.get(), &source_after) != 0 ||
            !same_file_identity(source_before, source_after) || ::fsync(destination.get()) != 0 ||
            ::fstat(destination.get(), &destination_after) != 0 ||
            !immutable_payload_file(destination_after) ||
            static_cast<std::uint64_t>(destination_after.st_size) != size) {
            return std::unexpected(std::string{"adoption payload file changed during copy"});
        }
        state.bytes += size;
    }
    return {};
}

} // namespace

struct resolved_native_harness_adoption::implementation {
    unique_fd root_descriptor;
    unique_fd manifest_descriptor;
    unique_fd payload_descriptor;
    file_identity root_identity;
    file_identity manifest_identity;
    file_identity payload_identity;
    native_harness_adoption_identity identity;
    std::string runtime_id;
    std::string generated_settings_json;
    std::size_t payload_count = 0;
};

resolved_native_harness_adoption::resolved_native_harness_adoption(
    std::unique_ptr<implementation> state
) noexcept
    : state_{std::move(state)} {}

resolved_native_harness_adoption::resolved_native_harness_adoption(
    resolved_native_harness_adoption&& other
) noexcept = default;

auto resolved_native_harness_adoption::operator=(resolved_native_harness_adoption&& other) noexcept
    -> resolved_native_harness_adoption& = default;

resolved_native_harness_adoption::~resolved_native_harness_adoption() = default;

auto resolved_native_harness_adoption::runtime_id() const noexcept -> std::string_view {
    return state_ ? std::string_view{state_->runtime_id} : std::string_view{};
}

auto resolved_native_harness_adoption::identity() const noexcept
    -> native_harness_adoption_identity {
    return state_ ? state_->identity : native_harness_adoption_identity{};
}

auto resolved_native_harness_adoption::generated_settings_json() const noexcept
    -> std::string_view {
    return state_ ? std::string_view{state_->generated_settings_json} : std::string_view{};
}

auto resolved_native_harness_adoption::payload_count() const noexcept -> std::size_t {
    return state_ ? state_->payload_count : 0U;
}

auto resolved_native_harness_adoption::verify_identity() const -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"adoption manifest state is unavailable"});
    }
    struct stat root{};
    struct stat manifest{};
    struct stat payload{};
    if (::fstat(state_->root_descriptor.get(), &root) != 0 || !owner_only_directory(root, 0700U) ||
        !same_file_identity(root, state_->root_identity) ||
        ::fstat(state_->manifest_descriptor.get(), &manifest) != 0 ||
        !same_file_identity(manifest, state_->manifest_identity) ||
        ::fstat(state_->payload_descriptor.get(), &payload) != 0 ||
        !same_file_identity(payload, state_->payload_identity)) {
        return std::unexpected(std::string{"adoption manifest identity changed"});
    }
    auto manifest_contents = read_manifest(state_->manifest_descriptor.get());
    if (!manifest_contents || manifest_contents->second != state_->manifest_identity) {
        return std::unexpected(
            manifest_contents ? std::string{"adoption manifest identity changed"}
                              : manifest_contents.error()
        );
    }
    const native_harness_adoption_policy policy{
        .manifest_root = "/descriptor-pinned",
        .manifest_digest = state_->identity.manifest_digest,
        .snapshot_digest = state_->identity.snapshot_digest,
    };
    auto document = decode_pi_manifest(manifest_contents->first, policy, state_->runtime_id);
    if (!document || document->generated_settings_json != state_->generated_settings_json ||
        document->payload_count != state_->payload_count) {
        return std::unexpected(
            document ? std::string{"adoption manifest content changed"} : document.error()
        );
    }
    auto snapshot =
        payload_snapshot_digest(state_->payload_descriptor.get(), state_->payload_count);
    if (!snapshot || *snapshot != state_->identity.snapshot_digest) {
        return std::unexpected(
            snapshot ? std::string{"adoption snapshot digest mismatch"} : snapshot.error()
        );
    }
    return {};
}

auto validate_native_harness_adoption_policy(const native_harness_adoption_policy& policy)
    -> std::expected<void, std::string> {
    const std::filesystem::path root{policy.manifest_root};
    if (policy.manifest_root.empty() || policy.manifest_root.size() > max_relative_path_bytes ||
        policy.manifest_root.find('\0') != std::string::npos || !root.is_absolute() ||
        root == root.root_path() || root.lexically_normal() != root ||
        !valid_digest(policy.manifest_digest) || !valid_digest(policy.snapshot_digest)) {
        return std::unexpected(std::string{"native harness adoption policy is invalid"});
    }
    return {};
}

auto pi_adoption_settings_json(std::size_t payload_count)
    -> std::expected<std::string, std::string> {
    if (payload_count == 0 || payload_count > max_payload_roots) {
        return std::unexpected(std::string{"Pi adoption payload count is invalid"});
    }
    std::string settings{"{\"packages\":["};
    for (std::size_t index = 0; index < payload_count; ++index) {
        if (index != 0U) {
            settings.push_back(',');
        }
        settings += "\"./extensions/" + std::to_string(index) + "\"";
    }
    settings += "],\"enableSkillCommands\":true}\n";
    return settings;
}

auto native_harness_adoption_document_digest(
    std::string_view snapshot_digest, std::span<const std::string> payload_ids
) -> std::expected<std::string, std::string> {
    if (!valid_digest(snapshot_digest) || payload_ids.empty() ||
        payload_ids.size() > max_payload_roots) {
        return std::unexpected(std::string{"native harness adoption document is invalid"});
    }
    for (std::size_t index = 0; index < payload_ids.size(); ++index) {
        if (!valid_pi_package_id(payload_ids[index]) ||
            (index != 0U && payload_ids[index - 1U] >= payload_ids[index])) {
            return std::unexpected(
                std::string{"native harness adoption payload selectors are invalid"}
            );
        }
    }
    auto settings = pi_adoption_settings_json(payload_ids.size());
    if (!settings) {
        return std::unexpected(settings.error());
    }
    std::string material{"glove.pi-adoption-manifest-v1"};
    material.push_back('\0');
    material.append(snapshot_digest);
    material.push_back('\0');
    for (const auto& id : payload_ids) {
        material.append(id);
        material.push_back('\0');
    }
    material.append(*settings);
    const auto bytes =
        std::span{reinterpret_cast<const unsigned char*>(material.data()), material.size()};
    return container::sha256_hex(bytes);
}

auto resolve_native_harness_adoption(
    const native_harness_adoption_policy& policy, std::string_view expected_runtime_id
) -> std::expected<resolved_native_harness_adoption, std::string> {
    if (auto valid = validate_native_harness_adoption_policy(policy); !valid) {
        return std::unexpected(valid.error());
    }
    if (expected_runtime_id != "pi") {
        return std::unexpected(std::string{"native harness adoption projector is unsupported"});
    }
    auto root = open_absolute_directory_no_follow(policy.manifest_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    struct stat root_metadata{};
    if (::fstat(root->get(), &root_metadata) != 0 || !owner_only_directory(root_metadata, 0700U)) {
        return std::unexpected(std::string{"adoption manifest root is unsafe"});
    }
    auto manifests = open_directory_at(root->get(), "manifests");
    auto snapshots = open_directory_at(root->get(), "snapshots");
    if (!manifests || !snapshots) {
        return std::unexpected(manifests ? snapshots.error() : manifests.error());
    }
    struct stat manifests_metadata{};
    struct stat snapshots_metadata{};
    if (::fstat(manifests->get(), &manifests_metadata) != 0 ||
        !owner_only_directory(manifests_metadata, 0700U) ||
        ::fstat(snapshots->get(), &snapshots_metadata) != 0 ||
        !owner_only_directory(snapshots_metadata, 0700U)) {
        return std::unexpected(std::string{"adoption manifest store is unsafe"});
    }

    const std::string manifest_name = policy.manifest_digest + ".json";
    unique_fd manifest{
        ::openat(manifests->get(), manifest_name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (manifest.get() < 0) {
        return std::unexpected(errno_message("open adoption manifest"));
    }
    auto contents = read_manifest(manifest.get());
    if (!contents) {
        return std::unexpected(contents.error());
    }
    auto document = decode_pi_manifest(contents->first, policy, expected_runtime_id);
    if (!document) {
        return std::unexpected(document.error());
    }

    auto snapshot = open_directory_at(snapshots->get(), policy.snapshot_digest);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    struct stat snapshot_metadata{};
    if (::fstat(snapshot->get(), &snapshot_metadata) != 0 ||
        !protected_snapshot_directory(snapshot_metadata)) {
        return std::unexpected(std::string{"adoption snapshot directory is unsafe"});
    }
    auto payload = open_directory_at(snapshot->get(), "payload");
    if (!payload) {
        return std::unexpected(payload.error());
    }
    struct stat payload_metadata{};
    if (::fstat(payload->get(), &payload_metadata) != 0 ||
        !immutable_payload_directory(payload_metadata)) {
        return std::unexpected(std::string{"adoption snapshot payload is unsafe"});
    }
    auto snapshot_digest = payload_snapshot_digest(payload->get(), document->payload_count);
    if (!snapshot_digest || *snapshot_digest != policy.snapshot_digest) {
        return std::unexpected(
            snapshot_digest ? std::string{"adoption snapshot digest mismatch"}
                            : snapshot_digest.error()
        );
    }
    auto state = std::make_unique<resolved_native_harness_adoption::implementation>();
    state->root_descriptor = std::move(*root);
    state->manifest_descriptor = std::move(manifest);
    state->payload_descriptor = std::move(*payload);
    state->root_identity = make_file_identity(root_metadata);
    state->manifest_identity = std::move(contents->second);
    state->payload_identity = make_file_identity(payload_metadata);
    state->identity = {
        .manifest_digest = policy.manifest_digest,
        .snapshot_digest = policy.snapshot_digest,
    };
    state->runtime_id = std::string{expected_runtime_id};
    state->generated_settings_json = std::move(document->generated_settings_json);
    state->payload_count = document->payload_count;
    return resolved_native_harness_adoption{std::move(state)};
}

auto materialize_native_harness_adoption_projection(
    int private_home_fd,
    std::string_view runtime_id,
    const resolved_native_harness_adoption& adoption
) -> std::expected<void, std::string> {
    if (private_home_fd < 0 || runtime_id != "pi" || adoption.runtime_id() != runtime_id ||
        adoption.payload_count() == 0 || adoption.payload_count() > max_payload_roots) {
        return std::unexpected(std::string{"native harness adoption projection is invalid"});
    }
    if (auto verified = adoption.verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    auto pi = make_private_directory_at(private_home_fd, ".pi");
    if (!pi) {
        return std::unexpected(pi.error());
    }
    auto agent = make_private_directory_at(pi->get(), "agent");
    if (!agent) {
        return std::unexpected(agent.error());
    }
    auto extensions = make_private_directory_at(agent->get(), "extensions");
    if (!extensions) {
        return std::unexpected(extensions.error());
    }
    copy_state copied;
    for (std::size_t index = 0; index < adoption.payload_count(); ++index) {
        const std::string source_name = "root-" + std::to_string(index);
        const std::string destination_name = std::to_string(index);
        auto source = open_directory_at(adoption.state_->payload_descriptor.get(), source_name);
        if (!source) {
            return std::unexpected(source.error());
        }
        struct stat source_metadata{};
        if (::fstat(source->get(), &source_metadata) != 0 ||
            !immutable_payload_directory(source_metadata) ||
            ::mkdirat(extensions->get(), destination_name.c_str(), 0700) != 0) {
            return std::unexpected(
                source_metadata.st_mode != 0 && !immutable_payload_directory(source_metadata)
                    ? std::string{"adoption payload root is unsafe"}
                    : errno_message("create adopted extension root")
            );
        }
        auto destination = open_directory_at(extensions->get(), destination_name);
        if (!destination) {
            return std::unexpected(destination.error());
        }
        struct stat destination_metadata{};
        if (::fstat(destination->get(), &destination_metadata) != 0 ||
            !owner_only_directory(destination_metadata, 0700U)) {
            return std::unexpected(std::string{"adopted extension root is unsafe"});
        }
        if (auto copied_tree = copy_payload_tree(source->get(), destination->get(), copied);
            !copied_tree) {
            return copied_tree;
        }
        if (::fchmod(destination->get(), 0500) != 0 || ::fsync(destination->get()) != 0) {
            return std::unexpected(errno_message("finalize adopted extension root"));
        }
    }
    if (::fsync(extensions->get()) != 0 || ::fsync(agent->get()) != 0 || ::fsync(pi->get()) != 0) {
        return std::unexpected(errno_message("sync adopted extension projection"));
    }
    if (auto verified = adoption.verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    return {};
}

} // namespace glove::supervisor
