#include "glove/container/digest.hpp"
#include "glove/supervisor/linux_ephemeral_copy.hpp"

#include "persistent_quota_image.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <linux/mount.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace glove::supervisor::linux_detail {

namespace {

constexpr std::uint64_t max_copy_entries = 100'000;
constexpr unsigned int max_copy_depth = 64;
constexpr std::size_t copy_buffer_bytes = std::size_t{64} * 1024U;
constexpr std::size_t max_recovery_metadata_bytes = std::size_t{16} * 1024U * 1024U;
constexpr long tmpfs_magic = 0x01021994;
constexpr long ext4_magic = 0xEF53;
constexpr std::string_view regular_file_payload = ".glove-payload";
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

} // namespace

struct wire_snapshot_entry {
    std::string path;
    std::string content_digest;
    std::uint64_t bytes = 0;
    std::uint32_t mode = 0;
    bool directory = false;
};

struct retained_recovery_body {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::vector<wire_snapshot_entry> baseline;
};

struct retained_recovery_envelope {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::vector<wire_snapshot_entry> baseline;
    std::string metadata_digest;
};

struct retained_recovery_metadata {
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    bool directory = false;
    std::vector<path_snapshot_entry> baseline;
};

namespace {

class unique_fd {
public:
    explicit unique_fd(int fd = -1) noexcept : fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(fd_, -1); }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
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
            ::closedir(directory_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> ::DIR* { return directory_; }

private:
    ::DIR* directory_;
};

struct copy_state {
    std::uint64_t max_bytes = 0;
    std::uint64_t logical_bytes = 0;
    std::uint64_t regular_files = 0;
    std::uint64_t directories = 0;
    std::uint64_t entries = 0;
};

auto errno_message(int error) -> std::string {
    return std::error_code{error, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 64 && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' || character == '.';
    });
}

auto valid_recovery_directory_name(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 255U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' || character == '.';
    });
}

result<unique_fd> open_absolute_directory_no_follow(std::string_view raw) {
    const std::filesystem::path path{raw};
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"invalid materialization root"});
    }
    unique_fd current{::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(std::string{"open materialization root: "} + errno_message(errno));
    }
    for (const auto& component : path.relative_path()) {
        const std::string name = component.string();
        unique_fd next{
            ::openat(current.get(), name.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (next.get() < 0) {
            return std::unexpected(
                std::string{"resolve materialization root: "} + errno_message(errno)
            );
        }
        current = std::move(next);
    }
    unique_fd usable{::openat(current.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    struct ::stat status = {};
    if (usable.get() < 0 || ::fstat(usable.get(), &status) < 0) {
        return std::unexpected(
            std::string{"inspect materialization root: "} + errno_message(errno)
        );
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"materialization root must be an owner-only directory"});
    }
    return usable;
}

auto mount_target_path(int root_fd, std::string_view directory_name) -> std::string {
    return "/proc/self/fd/" + std::to_string(root_fd) + "/" + std::string{directory_name};
}

// Owns the namespace side effects between mkdirat/move_mount and the
// materialization object's noexcept adoption. The caller allocates both
// strings before the first side effect, so rollback cannot allocate.
class pending_materialization {
public:
    pending_materialization(
        int root_fd, const char* directory_name, const char* mount_path
    ) noexcept
        : root_fd_{root_fd}, directory_name_{directory_name}, mount_path_{mount_path} {}

    pending_materialization(const pending_materialization&) = delete;
    auto operator=(const pending_materialization&) -> pending_materialization& = delete;
    pending_materialization(pending_materialization&&) = delete;
    auto operator=(pending_materialization&&) -> pending_materialization& = delete;

    ~pending_materialization() {
        if (mounted_) {
            static_cast<void>(::umount2(mount_path_, MNT_DETACH));
        }
        if (directory_created_) {
            static_cast<void>(::unlinkat(root_fd_, directory_name_, AT_REMOVEDIR));
        }
    }

    void mark_directory_created() noexcept { directory_created_ = true; }

    void mark_mounted() noexcept { mounted_ = true; }

    void release() noexcept {
        mounted_ = false;
        directory_created_ = false;
    }

private:
    int root_fd_;
    const char* directory_name_;
    const char* mount_path_;
    bool directory_created_ = false;
    bool mounted_ = false;
};

auto mount_unavailable(int error) -> bool {
    return error == EACCES || error == ENOSYS || error == EOPNOTSUPP || error == EPERM;
}

auto mount_quota_tmpfs(int target_fd, std::uint64_t max_bytes) -> result<void> {
    unique_fd context{static_cast<int>(::syscall(SYS_fsopen, "tmpfs", FSOPEN_CLOEXEC))};
    if (context.get() < 0) {
        const int saved = errno;
        const auto prefix = mount_unavailable(saved) ? "quota-backed tmpfs mount unavailable: "
                                                     : "open tmpfs mount context: ";
        return std::unexpected(std::string{prefix} + errno_message(saved));
    }
    const std::string size = std::to_string(max_bytes);
    if (::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_STRING, "size", size.c_str(), 0) < 0 ||
        ::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_STRING, "mode", "0700", 0) < 0 ||
        ::syscall(SYS_fsconfig, context.get(), FSCONFIG_CMD_CREATE, nullptr, nullptr, 0) < 0) {
        return std::unexpected(
            std::string{"configure quota-backed tmpfs: "} + errno_message(errno)
        );
    }
    unique_fd detached{static_cast<int>(::syscall(
        SYS_fsmount,
        context.get(),
        FSMOUNT_CLOEXEC,
        static_cast<unsigned int>(MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
    ))};
    if (detached.get() < 0) {
        return std::unexpected(std::string{"create quota-backed tmpfs: "} + errno_message(errno));
    }
    constexpr unsigned int move_flags = MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH;
    if (::syscall(SYS_move_mount, detached.get(), "", target_fd, "", move_flags) < 0) {
        return std::unexpected(std::string{"attach quota-backed tmpfs: "} + errno_message(errno));
    }
    return {};
}

auto stable_metadata(const struct ::stat& before, const struct ::stat& after) -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

auto require_exact_quota_granularity(std::uint64_t max_bytes) -> result<void> {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return std::unexpected(std::string{"cannot determine filesystem quota granularity"});
    }
    const auto page_bytes = static_cast<std::uint64_t>(page_size);
    if (max_bytes < page_bytes || max_bytes % page_bytes != 0) {
        return std::unexpected(std::string{"materialization quota must be a page multiple"});
    }
    return {};
}

auto reserve_bytes(copy_state& state, std::size_t bytes) -> result<void> {
    const auto count = static_cast<std::uint64_t>(bytes);
    if (state.logical_bytes > state.max_bytes || count > state.max_bytes - state.logical_bytes) {
        return std::unexpected(std::string{"materialization quota exceeded while copying"});
    }
    state.logical_bytes += count;
    return {};
}

auto write_all(int fd, const char* data, std::size_t size) -> result<void> {
    std::size_t offset = 0;
    while (offset < size) {
        const ::ssize_t written = ::write(fd, data + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EDQUOT || errno == ENOSPC) {
                return std::unexpected(std::string{"materialization filesystem quota exceeded"});
            }
            return std::unexpected(std::string{"write materialized file: "} + errno_message(errno));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

auto retained_metadata_name(std::string_view session_id, std::string_view exposure_id)
    -> std::string {
    return "glove-retained-meta-s" + std::to_string(session_id.size()) + "-" +
           std::string{session_id} + "-a" + std::to_string(exposure_id.size()) + "-" +
           std::string{exposure_id} + ".json";
}

auto encode_recovery_metadata(
    std::string_view session_id,
    std::string_view exposure_id,
    std::uint64_t generation,
    std::string_view scope_digest,
    std::string_view source_identity_digest,
    std::uint64_t max_bytes,
    bool directory,
    const std::vector<path_snapshot_entry>& baseline
) -> result<std::string> {
    std::vector<wire_snapshot_entry> encoded;
    encoded.reserve(baseline.size());
    for (const auto& entry : baseline) {
        encoded.push_back({
            .path = entry.path,
            .content_digest = entry.content_digest,
            .bytes = entry.bytes,
            .mode = entry.mode,
            .directory = entry.directory,
        });
    }
    retained_recovery_body body{
        .session_id = std::string{session_id},
        .exposure_id = std::string{exposure_id},
        .generation = generation,
        .scope_digest = std::string{scope_digest},
        .source_identity_digest = std::string{source_identity_digest},
        .max_bytes = max_bytes,
        .directory = directory,
        .baseline = std::move(encoded),
    };
    auto body_json = glz::write_json(body);
    if (!body_json) {
        return std::unexpected(std::string{"encode retained recovery metadata"});
    }
    auto digest = container::sha256_hex(
        std::span{reinterpret_cast<const unsigned char*>(body_json->data()), body_json->size()}
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    retained_recovery_envelope envelope{
        .schema_version = body.schema_version,
        .session_id = std::move(body.session_id),
        .exposure_id = std::move(body.exposure_id),
        .generation = body.generation,
        .scope_digest = std::move(body.scope_digest),
        .source_identity_digest = std::move(body.source_identity_digest),
        .max_bytes = body.max_bytes,
        .directory = body.directory,
        .baseline = std::move(body.baseline),
        .metadata_digest = std::move(*digest),
    };
    auto json = glz::write_json(envelope);
    if (!json || json->empty() || json->size() > max_recovery_metadata_bytes) {
        return std::unexpected(std::string{"encode retained recovery envelope"});
    }
    return *json;
}

auto persist_recovery_metadata(
    int root_fd,
    std::string_view session_id,
    std::string_view exposure_id,
    std::uint64_t generation,
    std::string_view scope_digest,
    std::string_view source_identity_digest,
    std::uint64_t max_bytes,
    bool directory,
    const std::vector<path_snapshot_entry>& baseline
) -> result<std::string> {
    auto json = encode_recovery_metadata(
        session_id,
        exposure_id,
        generation,
        scope_digest,
        source_identity_digest,
        max_bytes,
        directory,
        baseline
    );
    if (!json) {
        return std::unexpected(json.error());
    }
    const auto name = retained_metadata_name(session_id, exposure_id);
    const auto pending_name = name + ".pending";
    struct stat existing{};
    if (::fstatat(root_fd, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        return std::unexpected(std::string{"retained recovery metadata already exists"});
    }
    unique_fd file{::openat(
        root_fd, pending_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    )};
    if (file.get() < 0) {
        return std::unexpected(
            std::string{"create retained recovery metadata: "} + errno_message(errno)
        );
    }
    const auto cleanup = [&] { static_cast<void>(::unlinkat(root_fd, pending_name.c_str(), 0)); };
    if (auto written = write_all(file.get(), json->data(), json->size()); !written) {
        cleanup();
        return std::unexpected(written.error());
    }
    if (::fsync(file.get()) != 0 ||
        ::renameat(root_fd, pending_name.c_str(), root_fd, name.c_str()) != 0 ||
        ::fsync(root_fd) != 0) {
        const auto message =
            std::string{"publish retained recovery metadata: "} + errno_message(errno);
        cleanup();
        return std::unexpected(message);
    }
    return name;
}

auto read_bounded_file(int descriptor, std::size_t max_bytes) -> result<std::string> {
    struct stat status{};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_size <= 0 || static_cast<std::uint64_t>(status.st_size) > max_bytes) {
        return std::unexpected(std::string{"retained recovery metadata file is invalid"});
    }
    std::string contents(static_cast<std::size_t>(status.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const auto count = ::pread(
            descriptor,
            contents.data() + offset,
            contents.size() - offset,
            static_cast<off_t>(offset)
        );
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(
                std::string{"read retained recovery metadata: "} + errno_message(errno)
            );
        }
        offset += static_cast<std::size_t>(count);
    }
    return contents;
}

auto load_recovery_metadata(
    int root_fd, std::string_view session_id, std::string_view exposure_id, std::uint64_t max_bytes
) -> result<std::optional<retained_recovery_metadata>> {
    const auto name = retained_metadata_name(session_id, exposure_id);
    unique_fd file{::openat(root_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (file.get() < 0) {
        if (errno == ENOENT) {
            return std::optional<retained_recovery_metadata>{};
        }
        return std::unexpected(
            std::string{"open retained recovery metadata: "} + errno_message(errno)
        );
    }
    auto json = read_bounded_file(file.get(), max_recovery_metadata_bytes);
    if (!json) {
        return std::unexpected(json.error());
    }
    retained_recovery_envelope envelope;
    if (const auto error = glz::read<strict_read_options>(envelope, *json);
        error || envelope.schema_version != 1 || envelope.session_id != session_id ||
        envelope.exposure_id != exposure_id || envelope.generation == 0 ||
        !valid_digest(envelope.scope_digest) || !valid_digest(envelope.source_identity_digest) ||
        envelope.max_bytes != max_bytes || envelope.baseline.size() > max_copy_entries ||
        !valid_digest(envelope.metadata_digest)) {
        return std::unexpected(std::string{"retained recovery metadata schema is invalid"});
    }
    retained_recovery_body body{
        .schema_version = envelope.schema_version,
        .session_id = envelope.session_id,
        .exposure_id = envelope.exposure_id,
        .generation = envelope.generation,
        .scope_digest = envelope.scope_digest,
        .source_identity_digest = envelope.source_identity_digest,
        .max_bytes = envelope.max_bytes,
        .directory = envelope.directory,
        .baseline = envelope.baseline,
    };
    auto body_json = glz::write_json(body);
    auto digest =
        body_json
            ? container::sha256_hex(
                  std::span{
                      reinterpret_cast<const unsigned char*>(body_json->data()), body_json->size()
                  }
              )
            : result<std::string>{std::unexpected(std::string{"encode recovery metadata"})};
    auto canonical = glz::write_json(envelope);
    if (!digest || *digest != envelope.metadata_digest || !canonical || *canonical != *json) {
        return std::unexpected(std::string{"retained recovery metadata digest is invalid"});
    }
    std::vector<path_snapshot_entry> baseline;
    baseline.reserve(envelope.baseline.size());
    std::uint64_t total_bytes = 0;
    for (auto& entry : envelope.baseline) {
        if (entry.bytes > max_bytes - total_bytes) {
            return std::unexpected(std::string{"retained recovery baseline exceeds quota"});
        }
        total_bytes += entry.bytes;
        baseline.push_back({
            .path = std::move(entry.path),
            .content_digest = std::move(entry.content_digest),
            .bytes = entry.bytes,
            .mode = entry.mode,
            .directory = entry.directory,
        });
    }
    if (!path_snapshot_digest(baseline) ||
        envelope.directory != (baseline.empty() || baseline.front().path != ".")) {
        return std::unexpected(std::string{"retained recovery baseline is invalid"});
    }
    return retained_recovery_metadata{
        .generation = envelope.generation,
        .scope_digest = std::move(envelope.scope_digest),
        .source_identity_digest = std::move(envelope.source_identity_digest),
        .directory = envelope.directory,
        .baseline = std::move(baseline),
    };
}

auto owner_only_regular_entry_exists(int root_fd, std::string_view raw_name) -> result<bool> {
    if (!valid_recovery_directory_name(raw_name)) {
        return std::unexpected(std::string{"invalid retained recovery sidecar name"});
    }
    const std::string name{raw_name};
    struct stat status{};
    if (::fstatat(root_fd, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return false;
        }
        return std::unexpected(
            std::string{"inspect retained recovery sidecar: "} + errno_message(errno)
        );
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1 || status.st_uid != ::geteuid() ||
        (status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"retained recovery sidecar metadata is invalid"});
    }
    return true;
}

auto remove_incomplete_recovery_metadata(
    int root_fd, std::string_view session_id, std::string_view exposure_id
) -> result<void> {
    const auto pending_name = retained_metadata_name(session_id, exposure_id) + ".pending";
    auto exists = owner_only_regular_entry_exists(root_fd, pending_name);
    if (!exists) {
        return std::unexpected(exists.error());
    }
    if (*exists && ::unlinkat(root_fd, pending_name.c_str(), 0) != 0) {
        return std::unexpected(
            std::string{"remove incomplete retained recovery metadata: "} + errno_message(errno)
        );
    }
    if (*exists && ::fsync(root_fd) != 0) {
        return std::unexpected(
            std::string{"sync incomplete retained recovery cleanup: "} + errno_message(errno)
        );
    }
    return {};
}

auto published_stage_matches(
    int root_fd, std::string_view stage_name, const retained_change_manifest& expected
) -> result<bool> {
    const std::string name{stage_name};
    unique_fd stage{
        ::openat(root_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (stage.get() < 0) {
        if (errno == ENOENT) {
            return false;
        }
        return std::unexpected(
            std::string{"open published retained stage: "} + errno_message(errno)
        );
    }
    unique_fd manifest_file{
        ::openat(stage.get(), "manifest.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (manifest_file.get() < 0) {
        return std::unexpected(
            std::string{"open published retained manifest: "} + errno_message(errno)
        );
    }
    auto json = read_bounded_file(manifest_file.get(), max_recovery_metadata_bytes);
    auto manifest = json ? decode_retained_change_manifest_json(*json)
                         : result<retained_change_manifest>{std::unexpected(json.error())};
    if (!manifest || manifest->manifest_digest != expected.manifest_digest ||
        manifest->canonical_json != expected.canonical_json) {
        return std::unexpected(
            manifest ? std::string{"published retained manifest mismatch"} : manifest.error()
        );
    }
    unique_fd content{
        ::openat(stage.get(), "content", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (content.get() < 0) {
        return std::unexpected(
            std::string{"open published retained content: "} + errno_message(errno)
        );
    }
    unique_fd payload;
    int descriptor = content.get();
    if (!manifest->directory) {
        payload = unique_fd{
            ::openat(content.get(), regular_file_payload.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (payload.get() < 0) {
            return std::unexpected(
                std::string{"open published retained payload: "} + errno_message(errno)
            );
        }
        descriptor = payload.get();
    }
    auto snapshot = snapshot_path_tree(descriptor, manifest->max_bytes);
    auto digest = snapshot ? path_snapshot_digest(*snapshot)
                           : result<std::string>{std::unexpected(snapshot.error())};
    if (!digest || *digest != manifest->staged_tree_digest) {
        return std::unexpected(
            digest ? std::string{"published retained content mismatch"} : digest.error()
        );
    }
    return true;
}

auto copy_file_descriptor(int source_fd, int destination_fd, copy_state& state) -> result<void> {
    struct ::stat before = {};
    if (::fstat(source_fd, &before) < 0 || !S_ISREG(before.st_mode)) {
        return std::unexpected(std::string{"materialization source file changed type"});
    }
    if (before.st_nlink != 1) {
        return std::unexpected(std::string{"materialization source contains a hardlinked file"});
    }
    std::array<char, copy_buffer_bytes> buffer{};
    for (;;) {
        const ::ssize_t count = ::read(source_fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                std::string{"read materialization source: "} + errno_message(errno)
            );
        }
        if (count == 0) {
            break;
        }
        const auto size = static_cast<std::size_t>(count);
        if (auto reserved = reserve_bytes(state, size); !reserved) {
            return reserved;
        }
        if (auto written = write_all(destination_fd, buffer.data(), size); !written) {
            return written;
        }
    }
    struct ::stat after = {};
    if (::fstat(source_fd, &after) < 0 || !stable_metadata(before, after)) {
        return std::unexpected(std::string{"materialization source changed while copying"});
    }
    ++state.regular_files;
    return {};
}

auto open_pinned_source(int descriptor_fd, int flags) -> result<unique_fd> {
    const std::string path = "/proc/self/fd/" + std::to_string(descriptor_fd);
    unique_fd source{::open(path.c_str(), flags | O_CLOEXEC)};
    if (source.get() < 0) {
        return std::unexpected(
            std::string{"reopen pinned materialization source: "} + errno_message(errno)
        );
    }
    return source;
}

auto safe_file_mode(::mode_t source_mode) -> ::mode_t {
    return static_cast<::mode_t>((source_mode & 0555U) | 0600U);
}

auto safe_directory_mode(::mode_t source_mode) -> ::mode_t {
    return static_cast<::mode_t>((source_mode & 0555U) | 0700U);
}

auto copy_regular_entry(
    int source_parent,
    int destination_parent,
    const char* name,
    const struct ::stat& expected,
    copy_state& state
) -> result<void> {
    unique_fd source{::openat(source_parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (source.get() < 0) {
        return std::unexpected(
            std::string{"open materialization source file: "} + errno_message(errno)
        );
    }
    struct ::stat opened = {};
    if (::fstat(source.get(), &opened) < 0 || !S_ISREG(opened.st_mode) ||
        !stable_metadata(expected, opened)) {
        return std::unexpected(std::string{"materialization source entry changed before copy"});
    }
    if (opened.st_nlink != 1) {
        return std::unexpected(std::string{"materialization source contains a hardlinked file"});
    }
    unique_fd destination{::openat(
        destination_parent,
        name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        safe_file_mode(opened.st_mode)
    )};
    if (destination.get() < 0) {
        return std::unexpected(std::string{"create materialized file: "} + errno_message(errno));
    }
    if (::fchmod(destination.get(), safe_file_mode(opened.st_mode)) < 0) {
        return std::unexpected(std::string{"set materialized file mode: "} + errno_message(errno));
    }
    if (auto copied = copy_file_descriptor(source.get(), destination.get(), state); !copied) {
        return copied;
    }
    if (::fsync(destination.get()) != 0) {
        return std::unexpected(std::string{"sync materialized file: "} + errno_message(errno));
    }
    return {};
}

auto copy_directory_contents(
    int source_fd, int destination_fd, copy_state& state, unsigned int depth
) -> result<void> {
    if (depth > max_copy_depth) {
        return std::unexpected(std::string{"materialization directory depth exceeds bound"});
    }
    struct ::stat before = {};
    if (::fstat(source_fd, &before) < 0 || !S_ISDIR(before.st_mode)) {
        return std::unexpected(std::string{"materialization source directory changed type"});
    }
    unique_fd iterator_fd{::fcntl(source_fd, F_DUPFD_CLOEXEC, 0)};
    if (iterator_fd.get() < 0) {
        return std::unexpected(
            std::string{"duplicate materialization directory: "} + errno_message(errno)
        );
    }
    ::DIR* raw_directory = ::fdopendir(iterator_fd.get());
    if (raw_directory == nullptr) {
        return std::unexpected(
            std::string{"iterate materialization directory: "} + errno_message(errno)
        );
    }
    static_cast<void>(iterator_fd.release());
    unique_directory directory{raw_directory};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(
                    std::string{"read materialization directory entry: "} + errno_message(errno)
                );
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (++state.entries > max_copy_entries) {
            return std::unexpected(std::string{"materialization entry count exceeds bound"});
        }
        struct ::stat entry_status = {};
        if (::fstatat(source_fd, entry->d_name, &entry_status, AT_SYMLINK_NOFOLLOW) < 0) {
            return std::unexpected(
                std::string{"inspect materialization source entry: "} + errno_message(errno)
            );
        }
        if (S_ISREG(entry_status.st_mode)) {
            if (auto copied = copy_regular_entry(
                    source_fd, destination_fd, entry->d_name, entry_status, state
                );
                !copied) {
                return copied;
            }
            continue;
        }
        if (!S_ISDIR(entry_status.st_mode)) {
            return std::unexpected(
                std::string{"materialization source contains a symlink or special file"}
            );
        }
        unique_fd source_child{
            ::openat(source_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (source_child.get() < 0) {
            return std::unexpected(
                std::string{"open materialization source directory: "} + errno_message(errno)
            );
        }
        struct ::stat opened = {};
        if (::fstat(source_child.get(), &opened) < 0 || !stable_metadata(entry_status, opened)) {
            return std::unexpected(
                std::string{"materialization source directory changed before copy"}
            );
        }
        if (::mkdirat(destination_fd, entry->d_name, 0700) < 0) {
            return std::unexpected(
                std::string{"create materialized directory: "} + errno_message(errno)
            );
        }
        unique_fd destination_child{
            ::openat(destination_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (destination_child.get() < 0) {
            return std::unexpected(
                std::string{"open materialized directory: "} + errno_message(errno)
            );
        }
        ++state.directories;
        if (auto copied = copy_directory_contents(
                source_child.get(), destination_child.get(), state, depth + 1
            );
            !copied) {
            return copied;
        }
        if (::fchmod(destination_child.get(), safe_directory_mode(opened.st_mode)) < 0) {
            return std::unexpected(
                std::string{"set materialized directory mode: "} + errno_message(errno)
            );
        }
    }
    struct ::stat after = {};
    if (::fstat(source_fd, &after) < 0 || !stable_metadata(before, after)) {
        return std::unexpected(std::string{"materialization source changed while copying"});
    }
    if (::fsync(destination_fd) != 0) {
        return std::unexpected(std::string{"sync materialized directory: "} + errno_message(errno));
    }
    return {};
}

auto remove_directory_contents(int descriptor, unsigned int depth) -> result<void> {
    if (depth > max_copy_depth) {
        return std::unexpected(std::string{"retained stage cleanup depth exceeds bound"});
    }
    unique_fd iterator_fd{
        ::openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (iterator_fd.get() < 0) {
        return std::unexpected(
            std::string{"open retained stage cleanup iterator: "} + errno_message(errno)
        );
    }
    DIR* raw = ::fdopendir(iterator_fd.get());
    if (raw == nullptr) {
        return std::unexpected(
            std::string{"iterate retained stage cleanup: "} + errno_message(errno)
        );
    }
    static_cast<void>(iterator_fd.release());
    unique_directory directory{raw};
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(
                    std::string{"read retained stage cleanup: "} + errno_message(errno)
                );
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        struct stat status{};
        if (::fstatat(descriptor, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(
                std::string{"inspect retained stage cleanup entry: "} + errno_message(errno)
            );
        }
        if (S_ISDIR(status.st_mode)) {
            unique_fd child{
                ::openat(descriptor, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            };
            if (child.get() < 0) {
                return std::unexpected(
                    std::string{"open retained stage cleanup directory: "} + errno_message(errno)
                );
            }
            if (auto removed = remove_directory_contents(child.get(), depth + 1U); !removed) {
                return removed;
            }
            if (::unlinkat(descriptor, entry->d_name, AT_REMOVEDIR) != 0) {
                return std::unexpected(
                    std::string{"remove retained stage directory: "} + errno_message(errno)
                );
            }
        } else if (S_ISREG(status.st_mode)) {
            if (::unlinkat(descriptor, entry->d_name, 0) != 0) {
                return std::unexpected(
                    std::string{"remove retained stage file: "} + errno_message(errno)
                );
            }
        } else {
            return std::unexpected(
                std::string{"retained stage cleanup encountered an unsupported type"}
            );
        }
    }
    return {};
}

struct filesystem_usage {
    std::uint64_t used_bytes = 0;
    std::uint64_t capacity_bytes = 0;
};

auto checked_filesystem_usage(int fd, bool persistent, std::uint64_t quota_bytes)
    -> result<filesystem_usage> {
    struct ::statfs status = {};
    if (::fstatfs(fd, &status) < 0) {
        return std::unexpected(
            std::string{"observe materialization filesystem: "} + errno_message(errno)
        );
    }
    const auto expected_magic = persistent ? ext4_magic : tmpfs_magic;
    if (status.f_type != expected_magic || status.f_blocks < status.f_bfree ||
        status.f_bsize <= 0) {
        return std::unexpected(std::string{"materialization filesystem identity is invalid"});
    }
    const auto blocks = static_cast<std::uint64_t>(status.f_blocks);
    const auto used_blocks = static_cast<std::uint64_t>(status.f_blocks - status.f_bfree);
    const auto block_size = static_cast<std::uint64_t>(status.f_bsize);
    if (blocks > std::numeric_limits<std::uint64_t>::max() / block_size ||
        (persistent && blocks * block_size > quota_bytes)) {
        return std::unexpected(std::string{"materialization usage exceeds receipt representation"});
    }
    return filesystem_usage{
        .used_bytes = used_blocks * block_size,
        .capacity_bytes = persistent ? quota_bytes : blocks * block_size,
    };
}

} // namespace

ephemeral_copy_materialization::ephemeral_copy_materialization(
    int root_fd,
    int mount_root_fd,
    std::string directory_name,
    std::string mount_path,
    std::string target_path,
    std::string alias,
    std::uint64_t quota_bytes,
    bool cleanup_on_destroy
) noexcept
    : root_fd_{root_fd},
      mount_root_fd_{mount_root_fd},
      directory_name_{std::move(directory_name)},
      mount_path_{std::move(mount_path)},
      target_path_{std::move(target_path)},
      alias_{std::move(alias)},
      quota_bytes_{quota_bytes},
      mounted_{true},
      cleanup_on_destroy_{cleanup_on_destroy} {}

ephemeral_copy_materialization::ephemeral_copy_materialization(
    ephemeral_copy_materialization&& other
) noexcept
    : root_fd_{std::exchange(other.root_fd_, -1)},
      mount_root_fd_{std::exchange(other.mount_root_fd_, -1)},
      content_fd_{std::exchange(other.content_fd_, -1)},
      directory_name_{std::move(other.directory_name_)},
      mount_path_{std::move(other.mount_path_)},
      target_path_{std::move(other.target_path_)},
      alias_{std::move(other.alias_)},
      quota_bytes_{other.quota_bytes_},
      logical_bytes_{other.logical_bytes_},
      regular_files_{other.regular_files_},
      directories_{other.directories_},
      source_identity_{other.source_identity_},
      session_id_{std::move(other.session_id_)},
      exposure_generation_{other.exposure_generation_},
      exposure_scope_digest_{std::move(other.exposure_scope_digest_)},
      source_identity_digest_{std::move(other.source_identity_digest_)},
      baseline_{std::move(other.baseline_)},
      retained_manifest_{std::move(other.retained_manifest_)},
      retained_metadata_name_{std::move(other.retained_metadata_name_)},
      persistent_image_name_{std::move(other.persistent_image_name_)},
      is_directory_{other.is_directory_},
      persistent_{other.persistent_},
      mounted_{std::exchange(other.mounted_, false)},
      cleanup_on_destroy_{std::exchange(other.cleanup_on_destroy_, false)} {}

ephemeral_copy_materialization::~ephemeral_copy_materialization() {
    if (cleanup_on_destroy_) {
        cleanup_noexcept();
        return;
    }
    close_content_descriptors();
    close_root_descriptor();
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create_mounted(
    std::string_view materialization_root,
    std::string directory_name,
    std::string target_path,
    std::string alias,
    std::uint64_t quota_bytes,
    bool persistent
) {
    if (auto granularity = require_exact_quota_granularity(quota_bytes); !granularity) {
        return std::unexpected(granularity.error());
    }
    if (persistent && quota_bytes < minimum_persistent_quota_bytes) {
        return std::unexpected(std::string{"retained quota is below the persistent image minimum"});
    }
    auto root = open_absolute_directory_no_follow(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    std::string mount_path = mount_target_path(root->get(), directory_name);
    pending_materialization pending{root->get(), directory_name.c_str(), mount_path.c_str()};
    if (::mkdirat(root->get(), directory_name.c_str(), 0700) < 0) {
        return std::unexpected(
            std::string{"create materialization directory: "} + errno_message(errno)
        );
    }
    pending.mark_directory_created();
    unique_fd target{
        ::openat(root->get(), directory_name.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (target.get() < 0) {
        return std::unexpected(
            std::string{"open materialization directory: "} + errno_message(errno)
        );
    }
    std::string persistent_image_name;
    if (persistent) {
        auto image =
            create_persistent_quota_image(root->get(), directory_name, mount_path, quota_bytes);
        if (!image) {
            return std::unexpected(image.error());
        }
        persistent_image_name = std::move(*image);
    } else if (auto mounted = mount_quota_tmpfs(target.get(), quota_bytes); !mounted) {
        return std::unexpected(mounted.error());
    }
    pending.mark_mounted();
    unique_fd mounted_root{::openat(
        root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (mounted_root.get() < 0) {
        if (!persistent_image_name.empty()) {
            static_cast<void>(remove_persistent_quota_image(root->get(), persistent_image_name));
        }
        return std::unexpected(
            std::string{"open mounted materialization: "} + errno_message(errno)
        );
    }
    if (::fchmod(mounted_root.get(), 0700) != 0 ||
        (persistent && ::unlinkat(mounted_root.get(), "lost+found", AT_REMOVEDIR) != 0)) {
        const auto message =
            std::string{"initialize mounted materialization: "} + errno_message(errno);
        if (!persistent_image_name.empty()) {
            static_cast<void>(remove_persistent_quota_image(root->get(), persistent_image_name));
        }
        return std::unexpected(message);
    }
    pending.release();
    ephemeral_copy_materialization materialization{
        root->release(),
        mounted_root.release(),
        std::move(directory_name),
        std::move(mount_path),
        std::move(target_path),
        std::move(alias),
        quota_bytes,
        true,
    };
    materialization.persistent_ = persistent;
    materialization.persistent_image_name_ = std::move(persistent_image_name);
    auto initial_filesystem = checked_filesystem_usage(
        materialization.mount_root_fd_, materialization.persistent_, quota_bytes
    );
    if (!initial_filesystem || initial_filesystem->capacity_bytes != quota_bytes) {
        return std::unexpected(
            initial_filesystem ? std::string{"materialization quota capacity mismatch"}
                               : initial_filesystem.error()
        );
    }
    return materialization;
}

result<std::optional<ephemeral_copy_materialization>>
ephemeral_copy_materialization::adopt_recovered(
    std::string_view materialization_root,
    std::string_view session_id,
    std::string directory_name,
    std::string alias,
    std::uint64_t quota_bytes
) {
    if (!valid_identifier(session_id) || !valid_recovery_directory_name(directory_name) ||
        !valid_recovery_directory_name(alias)) {
        return std::unexpected(std::string{"invalid recovered materialization identity"});
    }
    if (auto granularity = require_exact_quota_granularity(quota_bytes); !granularity) {
        return std::unexpected(granularity.error());
    }
    auto root = open_absolute_directory_no_follow(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    auto metadata = load_recovery_metadata(root->get(), session_id, alias, quota_bytes);
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    const bool persistent = metadata->has_value();
    const auto mount_path = mount_target_path(root->get(), directory_name);
    unique_fd mounted_root{::openat(
        root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (mounted_root.get() < 0) {
        if (errno == ENOENT) {
            if (persistent) {
                return std::unexpected(std::string{"retained recovery mountpoint is unavailable"});
            }
            return std::optional<ephemeral_copy_materialization>{};
        }
        return std::unexpected(
            std::string{"open recovered materialization: "} + errno_message(errno)
        );
    }
    struct stat root_status{};
    struct stat materialization_status{};
    if (::fstat(root->get(), &root_status) != 0 ||
        ::fstat(mounted_root.get(), &materialization_status) != 0) {
        return std::unexpected(
            std::string{"inspect recovered materialization mount: "} + errno_message(errno)
        );
    }
    const bool mounted = root_status.st_dev != materialization_status.st_dev;
    std::string persistent_image_name;
    if (persistent) {
        persistent_image_name = persistent_quota_image_name(directory_name);
        if (auto valid =
                validate_persistent_quota_image(root->get(), persistent_image_name, quota_bytes);
            !valid) {
            return std::unexpected(valid.error());
        }
        if (!mounted) {
            mounted_root.reset();
            if (auto recovered = recover_persistent_quota_image(
                    root->get(), persistent_image_name, mount_path, quota_bytes
                );
                !recovered) {
                return std::unexpected(recovered.error());
            }
            mounted_root.reset(
                ::openat(
                    root->get(),
                    directory_name.c_str(),
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            );
            if (mounted_root.get() < 0) {
                return std::unexpected(
                    std::string{"open remounted retained materialization: "} + errno_message(errno)
                );
            }
        }
    } else if (!mounted) {
        mounted_root.reset();
        if (::unlinkat(root->get(), directory_name.c_str(), AT_REMOVEDIR) != 0) {
            return std::unexpected(
                std::string{"remove lost volatile materialization: "} + errno_message(errno)
            );
        }
        return std::optional<ephemeral_copy_materialization>{};
    }
    auto filesystem = checked_filesystem_usage(mounted_root.get(), persistent, quota_bytes);
    if (!filesystem || filesystem->capacity_bytes != quota_bytes) {
        return std::unexpected(
            filesystem ? std::string{"recovered materialization quota mismatch"}
                       : filesystem.error()
        );
    }
    ephemeral_copy_materialization recovered{
        root->release(),
        mounted_root.release(),
        std::move(directory_name),
        std::move(mount_path),
        std::string{},
        std::move(alias),
        quota_bytes,
        false
    };
    recovered.persistent_ = persistent;
    recovered.persistent_image_name_ = std::move(persistent_image_name);
    if (*metadata) {
        recovered.session_id_ = std::string{session_id};
        recovered.exposure_generation_ = (*metadata)->generation;
        recovered.exposure_scope_digest_ = std::move((*metadata)->scope_digest);
        recovered.source_identity_digest_ = std::move((*metadata)->source_identity_digest);
        recovered.baseline_ = std::move((*metadata)->baseline);
        recovered.is_directory_ = (*metadata)->directory;
        recovered.retained_metadata_name_ = retained_metadata_name(session_id, recovered.alias_);
        if (recovered.is_directory_) {
            recovered.content_fd_ = ::fcntl(recovered.mount_root_fd_, F_DUPFD_CLOEXEC, 0);
        } else {
            recovered.content_fd_ = ::openat(
                recovered.mount_root_fd_,
                regular_file_payload.data(),
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            );
        }
        if (recovered.content_fd_ < 0) {
            return std::unexpected(
                std::string{"open recovered retained content: "} + errno_message(errno)
            );
        }
    }
    return std::optional<ephemeral_copy_materialization>{std::move(recovered)};
}

result<std::optional<retained_change_manifest>> ephemeral_copy_materialization::recover_orphaned(
    std::string_view materialization_root,
    std::string_view session_id,
    std::string directory_name,
    std::string alias
) {
    if (!valid_identifier(session_id) || !valid_recovery_directory_name(directory_name) ||
        !valid_recovery_directory_name(alias)) {
        return std::unexpected(std::string{"invalid orphaned materialization identity"});
    }
    auto root = open_absolute_directory_no_follow(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    const auto metadata_name = retained_metadata_name(session_id, alias);
    auto metadata_exists = owner_only_regular_entry_exists(root->get(), metadata_name);
    if (!metadata_exists) {
        return std::unexpected(metadata_exists.error());
    }
    const auto pending_name = metadata_name + ".pending";
    auto pending_exists = owner_only_regular_entry_exists(root->get(), pending_name);
    if (!pending_exists) {
        return std::unexpected(pending_exists.error());
    }
    if (*metadata_exists && *pending_exists) {
        return std::unexpected(std::string{"retained recovery metadata publication is ambiguous"});
    }

    const auto image_name = persistent_quota_image_name(directory_name);
    struct stat image_status{};
    const bool image_exists =
        ::fstatat(root->get(), image_name.c_str(), &image_status, AT_SYMLINK_NOFOLLOW) == 0;
    if (!image_exists && errno != ENOENT) {
        return std::unexpected(
            std::string{"inspect orphaned retained image: "} + errno_message(errno)
        );
    }
    if (*metadata_exists && !image_exists) {
        return std::unexpected(std::string{"retained recovery metadata has no quota image"});
    }

    if (image_exists) {
        auto quota_bytes = persistent_quota_image_size(root->get(), image_name);
        if (!quota_bytes) {
            return std::unexpected(quota_bytes.error());
        }
        struct stat directory_status{};
        if (::fstatat(
                root->get(), directory_name.c_str(), &directory_status, AT_SYMLINK_NOFOLLOW
            ) != 0) {
            if (errno != ENOENT) {
                return std::unexpected(
                    std::string{"inspect orphaned retained mountpoint: "} + errno_message(errno)
                );
            }
            if (*metadata_exists) {
                if (::mkdirat(root->get(), directory_name.c_str(), 0700) != 0 ||
                    ::fsync(root->get()) != 0) {
                    return std::unexpected(
                        std::string{"restore retained recovery mountpoint: "} + errno_message(errno)
                    );
                }
            } else {
                if (auto removed = remove_persistent_quota_image(root->get(), image_name);
                    !removed) {
                    return std::unexpected(removed.error());
                }
                if (auto removed =
                        remove_incomplete_recovery_metadata(root->get(), session_id, alias);
                    !removed) {
                    return std::unexpected(removed.error());
                }
                return std::optional<retained_change_manifest>{};
            }
        } else if (!S_ISDIR(directory_status.st_mode) || directory_status.st_uid != ::geteuid()) {
            return std::unexpected(std::string{"orphaned retained mountpoint is invalid"});
        }

        if (*metadata_exists) {
            auto adopted = adopt_recovered(
                materialization_root, session_id, directory_name, alias, *quota_bytes
            );
            if (!adopted || !*adopted) {
                return std::unexpected(
                    adopted ? std::string{"retained orphan disappeared during recovery"}
                            : adopted.error()
                );
            }
            auto manifest = (**adopted).finalize_retained();
            if (!manifest) {
                return std::unexpected(manifest.error());
            }
            (**adopted).arm_recovered_cleanup();
            if (auto cleaned = (**adopted).cleanup(); !cleaned) {
                return std::unexpected(cleaned.error());
            }
            return *manifest;
        }

        const auto mount_path = mount_target_path(root->get(), directory_name);
        unique_fd mounted_root{::openat(
            root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )};
        if (mounted_root.get() < 0) {
            return std::unexpected(
                std::string{"open incomplete retained mountpoint: "} + errno_message(errno)
            );
        }
        struct stat root_status{};
        struct stat mounted_status{};
        if (::fstat(root->get(), &root_status) != 0 ||
            ::fstat(mounted_root.get(), &mounted_status) != 0) {
            return std::unexpected(
                std::string{"inspect incomplete retained mount: "} + errno_message(errno)
            );
        }
        const bool mounted = root_status.st_dev != mounted_status.st_dev;
        if (mounted) {
            auto usage = checked_filesystem_usage(mounted_root.get(), true, *quota_bytes);
            if (!usage || usage->capacity_bytes != *quota_bytes) {
                return std::unexpected(
                    usage ? std::string{"incomplete retained quota mismatch"} : usage.error()
                );
            }
            mounted_root.reset();
            if (::umount2(mount_path.c_str(), 0) != 0) {
                return std::unexpected(
                    std::string{"unmount incomplete retained materialization: "} +
                    errno_message(errno)
                );
            }
        } else {
            mounted_root.reset();
        }
        if (::unlinkat(root->get(), directory_name.c_str(), AT_REMOVEDIR) != 0) {
            return std::unexpected(
                std::string{"remove incomplete retained mountpoint: "} + errno_message(errno)
            );
        }
        if (auto removed = remove_persistent_quota_image(root->get(), image_name); !removed) {
            return std::unexpected(removed.error());
        }
        if (auto removed = remove_incomplete_recovery_metadata(root->get(), session_id, alias);
            !removed) {
            return std::unexpected(removed.error());
        }
        return std::optional<retained_change_manifest>{};
    }

    unique_fd mounted_root{::openat(
        root->get(), directory_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (mounted_root.get() < 0) {
        if (errno == ENOENT) {
            if (auto removed = remove_incomplete_recovery_metadata(root->get(), session_id, alias);
                !removed) {
                return std::unexpected(removed.error());
            }
            return std::optional<retained_change_manifest>{};
        }
        return std::unexpected(
            std::string{"open orphaned volatile materialization: "} + errno_message(errno)
        );
    }
    struct stat root_status{};
    struct stat mounted_status{};
    if (::fstat(root->get(), &root_status) != 0 ||
        ::fstat(mounted_root.get(), &mounted_status) != 0) {
        return std::unexpected(
            std::string{"inspect orphaned volatile mount: "} + errno_message(errno)
        );
    }
    if (root_status.st_dev == mounted_status.st_dev) {
        mounted_root.reset();
        if (::unlinkat(root->get(), directory_name.c_str(), AT_REMOVEDIR) != 0) {
            return std::unexpected(
                std::string{"remove lost volatile mountpoint: "} + errno_message(errno)
            );
        }
        if (auto removed = remove_incomplete_recovery_metadata(root->get(), session_id, alias);
            !removed) {
            return std::unexpected(removed.error());
        }
        return std::optional<retained_change_manifest>{};
    }
    auto usage = checked_filesystem_usage(mounted_root.get(), false, 0);
    if (!usage || usage->capacity_bytes == 0) {
        return std::unexpected(
            usage ? std::string{"orphaned volatile quota is invalid"} : usage.error()
        );
    }
    mounted_root.reset();
    auto adopted = adopt_recovered(
        materialization_root,
        session_id,
        std::move(directory_name),
        std::move(alias),
        usage->capacity_bytes
    );
    if (!adopted) {
        return std::unexpected(adopted.error());
    }
    if (*adopted) {
        (**adopted).arm_recovered_cleanup();
        if (auto cleaned = (**adopted).cleanup(); !cleaned) {
            return std::unexpected(cleaned.error());
        }
    }
    return std::optional<retained_change_manifest>{};
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create_empty_session_scratch(
    std::string_view materialization_root, std::string_view session_id, std::uint64_t quota_bytes
) {
    if (!valid_identifier(session_id)) {
        return std::unexpected(std::string{"invalid session filesystem identifier"});
    }
    std::string name =
        "glove-sessionfs-s" + std::to_string(session_id.size()) + "-" + std::string{session_id};
    auto materialization = create_mounted(
        materialization_root, std::move(name), std::string{}, "__scratch", quota_bytes, false
    );
    if (!materialization) {
        return std::unexpected(materialization.error());
    }
    for (const auto* directory : {"tmp", "var-tmp"}) {
        if (::mkdirat(materialization->mount_root_fd_, directory, 0700) < 0) {
            return std::unexpected(
                std::string{"create session scratch directory: "} + errno_message(errno)
            );
        }
    }
    materialization->content_fd_ = ::fcntl(materialization->mount_root_fd_, F_DUPFD_CLOEXEC, 0);
    if (materialization->content_fd_ < 0) {
        return std::unexpected(
            std::string{"duplicate session scratch descriptor: "} + errno_message(errno)
        );
    }
    materialization->directories_ = 3;
    materialization->is_directory_ = true;
    return materialization;
}

result<ephemeral_copy_materialization> ephemeral_copy_materialization::create(
    std::string_view materialization_root,
    std::string_view session_id,
    const resolved_path_grant& grant
) {
    if (!valid_identifier(session_id) || !valid_identifier(grant.alias())) {
        return std::unexpected(std::string{"invalid materialization identifier"});
    }
    const bool ephemeral = grant.access() == path_access::ephemeral_write &&
                           grant.cleanup_policy() == path_cleanup_policy::remove;
    const bool retained =
        grant.access() == path_access::retained_write &&
        grant.cleanup_policy() == path_cleanup_policy::retain && grant.exposure_generation() != 0 &&
        !grant.exposure_scope_digest().empty() && !grant.source_identity_digest().empty();
    if ((!ephemeral && !retained) || grant.materialization() != path_materialization::copy ||
        grant.max_bytes() == 0) {
        return std::unexpected(std::string{"grant is not a supported copy materialization"});
    }
    if (auto identity = grant.verify_identity(); !identity) {
        return std::unexpected(identity.error());
    }
    std::string name = "glove-mat-s" + std::to_string(session_id.size()) + "-" +
                       std::string{session_id} + "-a" + std::to_string(grant.alias().size()) + "-" +
                       std::string{grant.alias()};
    auto mounted = create_mounted(
        materialization_root,
        std::move(name),
        std::string{grant.target_path()},
        std::string{grant.alias()},
        grant.max_bytes(),
        retained
    );
    if (!mounted) {
        return std::unexpected(mounted.error());
    }
    auto materialization = std::move(*mounted);

    struct ::stat source_status = {};
    if (::fstat(grant.descriptor_fd(), &source_status) < 0) {
        return std::unexpected(
            std::string{"inspect pinned materialization source: "} + errno_message(errno)
        );
    }
    copy_state state{.max_bytes = grant.max_bytes()};
    if (S_ISDIR(source_status.st_mode)) {
        auto source = open_pinned_source(grant.descriptor_fd(), O_RDONLY | O_DIRECTORY);
        if (!source) {
            return std::unexpected(source.error());
        }
        state.directories = 1;
        if (auto copied =
                copy_directory_contents(source->get(), materialization.mount_root_fd_, state, 0);
            !copied) {
            return std::unexpected(copied.error());
        }
        materialization.content_fd_ = ::fcntl(materialization.mount_root_fd_, F_DUPFD_CLOEXEC, 0);
        materialization.is_directory_ = true;
    } else if (S_ISREG(source_status.st_mode)) {
        auto source = open_pinned_source(grant.descriptor_fd(), O_RDONLY);
        if (!source) {
            return std::unexpected(source.error());
        }
        unique_fd destination{::openat(
            materialization.mount_root_fd_,
            regular_file_payload.data(),
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            safe_file_mode(source_status.st_mode)
        )};
        if (destination.get() < 0) {
            return std::unexpected(
                std::string{"create materialized payload: "} + errno_message(errno)
            );
        }
        if (auto copied = copy_file_descriptor(source->get(), destination.get(), state); !copied) {
            return std::unexpected(copied.error());
        }
        if (::lseek(destination.get(), 0, SEEK_SET) < 0) {
            return std::unexpected(
                std::string{"rewind materialized payload: "} + errno_message(errno)
            );
        }
        materialization.content_fd_ = destination.release();
        materialization.is_directory_ = false;
    } else {
        return std::unexpected(std::string{"materialization source changed type"});
    }
    if (materialization.content_fd_ < 0) {
        return std::unexpected(std::string{"duplicate materialized content descriptor failed"});
    }
    if (auto identity = grant.verify_identity(); !identity) {
        return std::unexpected(identity.error());
    }
    materialization.logical_bytes_ = state.logical_bytes;
    materialization.regular_files_ = state.regular_files;
    materialization.directories_ = state.directories;
    materialization.source_identity_ = grant.identity();
    if (retained) {
        materialization.session_id_ = std::string{session_id};
        materialization.exposure_generation_ = grant.exposure_generation();
        materialization.exposure_scope_digest_ = std::string{grant.exposure_scope_digest()};
        materialization.source_identity_digest_ = std::string{grant.source_identity_digest()};
        auto baseline =
            snapshot_path_tree(materialization.content_fd_, materialization.quota_bytes_);
        if (!baseline) {
            return std::unexpected(baseline.error());
        }
        materialization.baseline_ = std::move(*baseline);
        auto metadata = persist_recovery_metadata(
            materialization.root_fd_,
            materialization.session_id_,
            materialization.alias_,
            materialization.exposure_generation_,
            materialization.exposure_scope_digest_,
            materialization.source_identity_digest_,
            materialization.quota_bytes_,
            materialization.is_directory_,
            materialization.baseline_
        );
        if (!metadata) {
            return std::unexpected(metadata.error());
        }
        materialization.retained_metadata_name_ = std::move(*metadata);
    }
    if (auto usage = materialization.observe(); !usage) {
        return std::unexpected(usage.error());
    }
    return materialization;
}

result<std::optional<retained_change_manifest>>
ephemeral_copy_materialization::finalize_retained() {
    if (retained_manifest_) {
        return retained_manifest_;
    }
    if (baseline_.empty() && exposure_generation_ == 0) {
        return std::optional<retained_change_manifest>{};
    }
    if (content_fd_ < 0 || session_id_.empty() || exposure_generation_ == 0) {
        return std::unexpected(std::string{"retained materialization identity is incomplete"});
    }
    auto current = snapshot_path_tree(content_fd_, quota_bytes_);
    if (!current) {
        return std::unexpected(current.error());
    }
    auto manifest = build_retained_change_manifest(
        session_id_,
        alias_,
        exposure_generation_,
        exposure_scope_digest_,
        source_identity_digest_,
        quota_bytes_,
        baseline_,
        *current
    );
    if (!manifest) {
        return std::unexpected(manifest.error());
    }
    const std::string final_name = "glove-retained-s" + std::to_string(session_id_.size()) + "-" +
                                   session_id_ + "-a" + std::to_string(alias_.size()) + "-" +
                                   alias_;
    const std::string pending_name = final_name + ".pending";
    struct stat existing{};
    if (::fstatat(root_fd_, final_name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        auto matches = published_stage_matches(root_fd_, final_name, *manifest);
        if (!matches || !*matches) {
            return std::unexpected(
                matches ? std::string{"retained stage destination conflicts"} : matches.error()
            );
        }
        if (!retained_metadata_name_.empty() &&
            ::unlinkat(root_fd_, retained_metadata_name_.c_str(), 0) != 0 && errno != ENOENT) {
            return std::unexpected(
                std::string{"remove retained recovery metadata: "} + errno_message(errno)
            );
        }
        if (::fsync(root_fd_) != 0) {
            return std::unexpected(
                std::string{"sync retained metadata removal: "} + errno_message(errno)
            );
        }
        retained_metadata_name_.clear();
        retained_manifest_ = std::move(*manifest);
        return retained_manifest_;
    }
    if (errno != ENOENT) {
        return std::unexpected(
            std::string{"inspect retained stage destination: "} + errno_message(errno)
        );
    }
    if (::mkdirat(root_fd_, pending_name.c_str(), 0700) != 0) {
        return std::unexpected(std::string{"create retained stage: "} + errno_message(errno));
    }
    unique_fd pending{
        ::openat(root_fd_, pending_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    const auto cleanup_pending = [&]() noexcept {
        if (pending.get() >= 0) {
            static_cast<void>(remove_directory_contents(pending.get(), 0));
        }
        static_cast<void>(::unlinkat(root_fd_, pending_name.c_str(), AT_REMOVEDIR));
    };
    if (pending.get() < 0 || ::mkdirat(pending.get(), "content", 0700) != 0) {
        const auto message = std::string{"prepare retained stage: "} + errno_message(errno);
        cleanup_pending();
        return std::unexpected(message);
    }
    unique_fd destination{
        ::openat(pending.get(), "content", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (destination.get() < 0) {
        const auto message = std::string{"open retained stage content: "} + errno_message(errno);
        cleanup_pending();
        return std::unexpected(message);
    }
    copy_state exported{.max_bytes = quota_bytes_};
    if (is_directory_) {
        if (auto copied = copy_directory_contents(content_fd_, destination.get(), exported, 0);
            !copied) {
            const auto message = copied.error();
            cleanup_pending();
            return std::unexpected(message);
        }
    } else {
        auto source = open_pinned_source(content_fd_, O_RDONLY);
        unique_fd output{::openat(
            destination.get(),
            regular_file_payload.data(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600
        )};
        if (!source || output.get() < 0) {
            const auto message =
                source ? std::string{"create retained stage payload: "} + errno_message(errno)
                       : source.error();
            cleanup_pending();
            return std::unexpected(message);
        }
        if (auto copied = copy_file_descriptor(source->get(), output.get(), exported); !copied) {
            const auto message = copied.error();
            cleanup_pending();
            return std::unexpected(message);
        }
        if (::fsync(output.get()) != 0) {
            const auto message =
                std::string{"sync retained stage payload: "} + errno_message(errno);
            cleanup_pending();
            return std::unexpected(message);
        }
    }
    unique_fd manifest_file{::openat(
        pending.get(), "manifest.json", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    )};
    if (manifest_file.get() < 0) {
        const auto message =
            std::string{"persist retained stage manifest: "} + errno_message(errno);
        cleanup_pending();
        return std::unexpected(message);
    }
    if (auto written = write_all(
            manifest_file.get(), manifest->canonical_json.data(), manifest->canonical_json.size()
        );
        !written) {
        const auto message = written.error();
        cleanup_pending();
        return std::unexpected(message);
    }
    if (::fsync(manifest_file.get()) != 0 || ::fsync(destination.get()) != 0 ||
        ::fsync(pending.get()) != 0) {
        const auto message = std::string{"sync retained stage: "} + errno_message(errno);
        cleanup_pending();
        return std::unexpected(message);
    }
    if (::renameat(root_fd_, pending_name.c_str(), root_fd_, final_name.c_str()) != 0 ||
        ::fsync(root_fd_) != 0) {
        const auto message = std::string{"publish retained stage: "} + errno_message(errno);
        cleanup_pending();
        return std::unexpected(message);
    }
    if (!retained_metadata_name_.empty() &&
        ::unlinkat(root_fd_, retained_metadata_name_.c_str(), 0) != 0 && errno != ENOENT) {
        return std::unexpected(
            std::string{"remove retained recovery metadata: "} + errno_message(errno)
        );
    }
    if (::fsync(root_fd_) != 0) {
        return std::unexpected(
            std::string{"sync retained metadata removal: "} + errno_message(errno)
        );
    }
    retained_metadata_name_.clear();
    retained_manifest_ = std::move(*manifest);
    return retained_manifest_;
}

result<materialization_usage> ephemeral_copy_materialization::observe() const {
    if (!mounted_ || mount_root_fd_ < 0) {
        return std::unexpected(std::string{"materialization is not mounted"});
    }
    auto filesystem = checked_filesystem_usage(mount_root_fd_, persistent_, quota_bytes_);
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    if (filesystem->capacity_bytes != quota_bytes_) {
        return std::unexpected(std::string{"materialization quota capacity changed"});
    }
    return materialization_usage{
        .logical_bytes = logical_bytes_,
        .filesystem_bytes = filesystem->used_bytes,
        .quota_bytes = quota_bytes_,
        .regular_files = regular_files_,
        .directories = directories_,
    };
}

void ephemeral_copy_materialization::close_content_descriptors() noexcept {
    if (content_fd_ >= 0) {
        ::close(content_fd_);
        content_fd_ = -1;
    }
    if (mount_root_fd_ >= 0) {
        ::close(mount_root_fd_);
        mount_root_fd_ = -1;
    }
}

void ephemeral_copy_materialization::close_root_descriptor() noexcept {
    if (root_fd_ >= 0) {
        ::close(root_fd_);
        root_fd_ = -1;
    }
}

void ephemeral_copy_materialization::cleanup_noexcept() noexcept {
    if (!retained_metadata_name_.empty() && !retained_manifest_) {
        try {
            if (auto finalized = finalize_retained(); !finalized) {
                close_content_descriptors();
                close_root_descriptor();
                return;
            }
        } catch (...) {
            close_content_descriptors();
            close_root_descriptor();
            return;
        }
    }
    close_content_descriptors();
    if (root_fd_ >= 0 && !directory_name_.empty()) {
        if (mounted_) {
            static_cast<void>(::umount2(mount_path_.c_str(), MNT_DETACH));
            mounted_ = false;
        }
        static_cast<void>(::unlinkat(root_fd_, directory_name_.c_str(), AT_REMOVEDIR));
    }
    if (root_fd_ >= 0 && !persistent_image_name_.empty()) {
        static_cast<void>(remove_persistent_quota_image(root_fd_, persistent_image_name_));
    }
    directory_name_.clear();
    mount_path_.clear();
    persistent_image_name_.clear();
    close_root_descriptor();
}

result<void> ephemeral_copy_materialization::cleanup() {
    close_content_descriptors();
    if (root_fd_ < 0) {
        return {};
    }
    if (mounted_ && !directory_name_.empty()) {
        if (::umount2(mount_path_.c_str(), 0) < 0) {
            return std::unexpected(std::string{"unmount materialization: "} + errno_message(errno));
        }
        mounted_ = false;
    }
    if (!directory_name_.empty() &&
        ::unlinkat(root_fd_, directory_name_.c_str(), AT_REMOVEDIR) < 0 && errno != ENOENT) {
        return std::unexpected(
            std::string{"remove materialization directory: "} + errno_message(errno)
        );
    }
    directory_name_.clear();
    mount_path_.clear();
    if (!persistent_image_name_.empty()) {
        if (auto removed = remove_persistent_quota_image(root_fd_, persistent_image_name_);
            !removed) {
            return std::unexpected(removed.error());
        }
        persistent_image_name_.clear();
    }
    close_root_descriptor();
    return {};
}

} // namespace glove::supervisor::linux_detail
