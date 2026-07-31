#include "glove/supervisor/library_bundle.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace glove::supervisor {

namespace {

constexpr auto permission_mask = 0777U;

auto system_error(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto valid_digest(std::string_view digest) -> bool {
    if (digest.size() != 64U) {
        return false;
    }
    for (const char character : digest) {
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

auto same_change_times(const struct stat& left, const struct stat& right) -> bool {
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

auto inspect_bundle(int descriptor, std::string_view digest)
    -> std::expected<struct stat, std::string> {
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(system_error("inspect library bundle"));
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (metadata.st_mode & permission_mask) != 0600U || metadata.st_nlink != 1 ||
        metadata.st_size <= 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_library_bundle_bytes) {
        return std::unexpected(std::string{"library bundle metadata is unsafe"});
    }
    auto actual = container::sha256_fd_hex(descriptor, max_library_bundle_bytes);
    if (!actual || *actual != digest) {
        return std::unexpected(std::string{"library bundle content digest mismatch"});
    }
    struct stat after{};
    if (::fstat(descriptor, &after) != 0) {
        return std::unexpected(system_error("reinspect library bundle"));
    }
    if (after.st_dev != metadata.st_dev || after.st_ino != metadata.st_ino ||
        after.st_mode != metadata.st_mode || after.st_uid != metadata.st_uid ||
        after.st_nlink != metadata.st_nlink || after.st_size != metadata.st_size ||
        !same_change_times(after, metadata)) {
        return std::unexpected(std::string{"library bundle changed while hashing"});
    }
    return metadata;
}

} // namespace

resolved_library_bundle::resolved_library_bundle(
    int descriptor,
    std::string digest,
    std::uint64_t device,
    std::uint64_t inode,
    std::uint64_t size_bytes,
    std::uint64_t mode,
    std::uint64_t owner
) noexcept
    : descriptor_{descriptor},
      digest_{std::move(digest)},
      device_{device},
      inode_{inode},
      size_bytes_{size_bytes},
      mode_{mode},
      owner_{owner} {}

resolved_library_bundle::resolved_library_bundle(resolved_library_bundle&& other) noexcept
    : descriptor_{std::exchange(other.descriptor_, -1)},
      digest_{std::move(other.digest_)},
      device_{other.device_},
      inode_{other.inode_},
      size_bytes_{other.size_bytes_},
      mode_{other.mode_},
      owner_{other.owner_} {}

resolved_library_bundle::~resolved_library_bundle() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

auto resolved_library_bundle::verify_identity() const -> std::expected<void, std::string> {
    if (descriptor_ < 0) {
        return std::unexpected(std::string{"library bundle descriptor is unavailable"});
    }

    auto metadata = inspect_bundle(descriptor_, digest_);
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    if (static_cast<std::uint64_t>(metadata->st_dev) != device_ ||
        static_cast<std::uint64_t>(metadata->st_ino) != inode_ ||
        static_cast<std::uint64_t>(metadata->st_size) != size_bytes_ ||
        static_cast<std::uint64_t>(metadata->st_mode) != mode_ ||
        static_cast<std::uint64_t>(metadata->st_uid) != owner_) {
        return std::unexpected(std::string{"library bundle identity changed"});
    }
    return {};
}

auto resolved_library_bundle::read_bytes(std::uint64_t max_bytes) const
    -> std::expected<std::vector<unsigned char>, std::string> {
    if (descriptor_ < 0 || max_bytes == 0 || size_bytes_ == 0 || size_bytes_ > max_bytes ||
        size_bytes_ > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(std::string{"library bundle read bound is invalid"});
    }
    if (auto verified = verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size_bytes_));
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto result = ::pread(
            descriptor_,
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(system_error("read library bundle"));
        }
        consumed += static_cast<std::size_t>(result);
    }
    if (auto verified = verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    return bytes;
}

library_bundle_store::library_bundle_store(
    std::filesystem::path root,
    int descriptor,
    std::uint64_t device,
    std::uint64_t inode,
    std::uint64_t owner
) noexcept
    : root_{std::move(root)},
      descriptor_{descriptor},
      device_{device},
      inode_{inode},
      owner_{owner} {}

library_bundle_store::library_bundle_store(library_bundle_store&& other) noexcept
    : root_{std::move(other.root_)},
      descriptor_{std::exchange(other.descriptor_, -1)},
      device_{other.device_},
      inode_{other.inode_},
      owner_{other.owner_} {}

library_bundle_store::~library_bundle_store() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

auto library_bundle_store::open(const std::filesystem::path& root)
    -> std::expected<library_bundle_store, std::string> {
    if (!root.is_absolute()) {
        return std::unexpected(std::string{"library bundle root must be absolute"});
    }
    const int descriptor = ::open(root.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) {
        return std::unexpected(system_error("open library bundle root"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || (metadata.st_mode & permission_mask) != 0700U) {
        ::close(descriptor);
        return std::unexpected(std::string{"library bundle root metadata is unsafe"});
    }
    library_bundle_store store{
        root,
        descriptor,
        static_cast<std::uint64_t>(metadata.st_dev),
        static_cast<std::uint64_t>(metadata.st_ino),
        static_cast<std::uint64_t>(metadata.st_uid),
    };
    if (auto verified = store.verify_root_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    return store;
}

auto library_bundle_store::verify_root_identity() const -> std::expected<void, std::string> {
    struct stat descriptor_metadata{};
    struct stat path_metadata{};
    if (descriptor_ < 0 || ::fstat(descriptor_, &descriptor_metadata) != 0 ||
        ::lstat(root_.c_str(), &path_metadata) != 0) {
        return std::unexpected(system_error("verify library bundle root"));
    }
    if (!S_ISDIR(descriptor_metadata.st_mode) || !S_ISDIR(path_metadata.st_mode) ||
        S_ISLNK(path_metadata.st_mode) ||
        static_cast<std::uint64_t>(descriptor_metadata.st_dev) != device_ ||
        static_cast<std::uint64_t>(descriptor_metadata.st_ino) != inode_ ||
        static_cast<std::uint64_t>(descriptor_metadata.st_uid) != owner_ ||
        (descriptor_metadata.st_mode & permission_mask) != 0700U ||
        path_metadata.st_dev != descriptor_metadata.st_dev ||
        path_metadata.st_ino != descriptor_metadata.st_ino ||
        path_metadata.st_uid != descriptor_metadata.st_uid ||
        path_metadata.st_mode != descriptor_metadata.st_mode) {
        return std::unexpected(std::string{"library bundle root identity changed"});
    }
    return {};
}

auto library_bundle_store::resolve(std::string_view content_digest) const
    -> std::expected<resolved_library_bundle, std::string> {
    if (!valid_digest(content_digest)) {
        return std::unexpected(std::string{"library bundle digest is invalid"});
    }
    if (auto verified = verify_root_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    const std::string filename = std::string{content_digest} + ".json";
    const int descriptor =
        ::openat(descriptor_, filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return std::unexpected(system_error("open library bundle"));
    }
    auto metadata = inspect_bundle(descriptor, content_digest);
    if (!metadata) {
        ::close(descriptor);
        return std::unexpected(metadata.error());
    }
    if (auto verified = verify_root_identity(); !verified) {
        ::close(descriptor);
        return std::unexpected(verified.error());
    }
    return resolved_library_bundle{
        descriptor,
        std::string{content_digest},
        static_cast<std::uint64_t>(metadata->st_dev),
        static_cast<std::uint64_t>(metadata->st_ino),
        static_cast<std::uint64_t>(metadata->st_size),
        static_cast<std::uint64_t>(metadata->st_mode),
        static_cast<std::uint64_t>(metadata->st_uid),
    };
}

auto library_bundle_store::resolve_projections(
    const std::vector<resolved_library_projection_target>& projections
) const -> std::expected<std::vector<resolved_library_projection>, std::string> {
    std::set<std::string> targets;
    std::vector<resolved_library_projection> resolved;
    resolved.reserve(projections.size());
    for (const auto& requested : projections) {
        const std::filesystem::path destination{requested.target_path};
        if (!destination.is_absolute() || destination == destination.root_path() ||
            destination.lexically_normal() != destination) {
            return std::unexpected(std::string{"library projection target is invalid"});
        }
        const std::filesystem::path target =
            destination / (requested.projection.content_digest + ".json");
        const std::string target_text = target.string();
        if (!targets.insert(target_text).second) {
            return std::unexpected(std::string{"library projection target is duplicated"});
        }
        auto bundle = resolve(requested.projection.content_digest);
        if (!bundle) {
            return std::unexpected(bundle.error());
        }
        resolved.push_back({
            .projection_id = requested.projection.projection_id,
            .destination_alias = requested.projection.destination_alias,
            .target_path = target_text,
            .bundle = std::move(*bundle),
        });
    }
    return resolved;
}

} // namespace glove::supervisor
