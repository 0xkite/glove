#include "glove/supervisor/linux_session_filesystem.hpp"

#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <limits>
#include <set>
#include <system_error>
#include <utility>

namespace glove::supervisor::linux_detail {

namespace {

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto valid_target(std::string_view raw) -> bool {
    const std::filesystem::path target{raw};
    if (!target.is_absolute() || target == target.root_path() ||
        target.lexically_normal() != target) {
        return false;
    }
    constexpr std::array<std::string_view, 3> reserved_targets = {"/proc", "/tmp", "/var/tmp"};
    const bool overlaps_reserved = std::ranges::any_of(reserved_targets, [&](auto reserved) {
        const std::filesystem::path reserved_path{reserved};
        return path_within(target, reserved_path) || path_within(reserved_path, target);
    });
    return !overlaps_reserved;
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' ||
               character == ':' || character == '.';
    });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

auto checked_add(std::uint64_t& total, std::uint64_t value) -> bool {
    if (value > std::numeric_limits<std::uint64_t>::max() - total) {
        return false;
    }
    total += value;
    return true;
}

auto valid_recovery_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 64U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' || character == '.';
    });
}

auto scratch_directory_name(std::string_view session_id) -> std::string {
    return "glove-sessionfs-s" + std::to_string(session_id.size()) + "-" + std::string{session_id};
}

auto partition_directory_name(std::string_view session_id, std::string_view alias) -> std::string {
    return "glove-mat-s" + std::to_string(session_id.size()) + "-" + std::string{session_id} +
           "-a" + std::to_string(alias.size()) + "-" + std::string{alias};
}

auto errno_message(int error) -> std::string {
    return std::error_code{error, std::generic_category()}.message();
}

constexpr std::size_t max_orphan_entries = 10'000U;

struct materialization_identity {
    std::string session_id;
    std::string alias;

    auto operator<=>(const materialization_identity&) const = default;
};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            if (descriptor_ >= 0) {
                ::close(descriptor_);
            }
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    int descriptor_ = -1;
};

class unique_directory {
public:
    explicit unique_directory(::DIR* directory = nullptr) noexcept : directory_{directory} {}

    unique_directory(const unique_directory&) = delete;
    auto operator=(const unique_directory&) -> unique_directory& = delete;

    ~unique_directory() {
        if (directory_ != nullptr) {
            ::closedir(directory_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> ::DIR* { return directory_; }

private:
    ::DIR* directory_;
};

result<unique_fd> open_owner_only_root(std::string_view raw) {
    const std::filesystem::path path{raw};
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"invalid materialization root"});
    }
    unique_fd current{::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(std::string{"open materialization root: "} + errno_message(errno));
    }
    for (const auto& component : path.relative_path()) {
        const auto name = component.string();
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
    unique_fd root{::openat(current.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    struct stat status{};
    if (root.get() < 0 || ::fstat(root.get(), &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"materialization root must be an owner-only directory"});
    }
    return root;
}

auto parse_size(std::string_view value) -> std::optional<std::size_t> {
    if (value.empty() || (value.size() > 1U && value.front() == '0')) {
        return std::nullopt;
    }
    std::size_t parsed = 0;
    const auto conversion = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (conversion.ec != std::errc{} || conversion.ptr != value.data() + value.size() ||
        parsed == 0 || parsed > 64U) {
        return std::nullopt;
    }
    return parsed;
}

auto consume_length_prefixed(std::string_view& input, char marker) -> std::optional<std::string> {
    if (input.size() < 3U || input.front() != marker) {
        return std::nullopt;
    }
    input.remove_prefix(1);
    const auto separator = input.find('-');
    if (separator == std::string_view::npos) {
        return std::nullopt;
    }
    auto length = parse_size(input.substr(0, separator));
    if (!length) {
        return std::nullopt;
    }
    input.remove_prefix(separator + 1U);
    if (input.size() < *length) {
        return std::nullopt;
    }
    std::string value{input.substr(0, *length)};
    input.remove_prefix(*length);
    if (!valid_recovery_identifier(value)) {
        return std::nullopt;
    }
    return value;
}

auto parse_partition_name(std::string_view name) -> std::optional<materialization_identity> {
    constexpr std::string_view prefix = "glove-mat-";
    if (!name.starts_with(prefix)) {
        return std::nullopt;
    }
    name.remove_prefix(prefix.size());
    auto session_id = consume_length_prefixed(name, 's');
    if (!session_id || !name.starts_with("-a")) {
        return std::nullopt;
    }
    name.remove_prefix(1);
    auto alias = consume_length_prefixed(name, 'a');
    if (!alias || !name.empty()) {
        return std::nullopt;
    }
    return materialization_identity{std::move(*session_id), std::move(*alias)};
}

auto parse_scratch_name(std::string_view name) -> std::optional<materialization_identity> {
    constexpr std::string_view prefix = "glove-sessionfs-";
    if (!name.starts_with(prefix)) {
        return std::nullopt;
    }
    name.remove_prefix(prefix.size());
    auto session_id = consume_length_prefixed(name, 's');
    if (!session_id || !name.empty()) {
        return std::nullopt;
    }
    return materialization_identity{std::move(*session_id), "__scratch"};
}

auto parse_metadata_name(std::string_view name) -> std::optional<materialization_identity> {
    if (name.ends_with(".pending")) {
        name.remove_suffix(std::string_view{".pending"}.size());
    }
    constexpr std::string_view suffix = ".json";
    constexpr std::string_view prefix = "glove-retained-meta-";
    if (!name.starts_with(prefix) || !name.ends_with(suffix)) {
        return std::nullopt;
    }
    name.remove_prefix(prefix.size());
    name.remove_suffix(suffix.size());
    auto session_id = consume_length_prefixed(name, 's');
    if (!session_id || !name.starts_with("-a")) {
        return std::nullopt;
    }
    name.remove_prefix(1);
    auto alias = consume_length_prefixed(name, 'a');
    if (!alias || !name.empty()) {
        return std::nullopt;
    }
    return materialization_identity{std::move(*session_id), std::move(*alias)};
}

auto list_root_entries(int root_fd) -> result<std::vector<std::string>> {
    unique_fd iterator_fd{::fcntl(root_fd, F_DUPFD_CLOEXEC, 0)};
    if (iterator_fd.get() < 0) {
        return std::unexpected(
            std::string{"duplicate materialization root: "} + errno_message(errno)
        );
    }
    ::DIR* raw = ::fdopendir(iterator_fd.get());
    if (raw == nullptr) {
        return std::unexpected(
            std::string{"iterate materialization root: "} + errno_message(errno)
        );
    }
    static_cast<void>(iterator_fd.release());
    unique_directory directory{raw};
    std::vector<std::string> entries;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(
                    std::string{"read materialization root: "} + errno_message(errno)
                );
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (entries.size() >= max_orphan_entries) {
            return std::unexpected(std::string{"materialization root entry bound exceeded"});
        }
        entries.emplace_back(name);
    }
    std::ranges::sort(entries);
    return entries;
}

auto clone_mount_descriptor(int source_fd) -> result<int> {
    const int descriptor = static_cast<int>(
        // Linux has no typed libc wrapper for open_tree(2).
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::syscall(SYS_open_tree, source_fd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
    );
    if (descriptor < 0) {
        return std::unexpected(
            std::string{"clone session mount descriptor: "} + errno_message(errno)
        );
    }
    return descriptor;
}

void close_mount_records(std::vector<session_mount>& mounts) noexcept {
    for (auto& mount : mounts) {
        if (mount.descriptor_fd >= 0) {
            ::close(mount.descriptor_fd);
            mount.descriptor_fd = -1;
        }
    }
    mounts.clear();
}

auto validate_grants(
    const std::vector<resolved_path_grant>& grants,
    const std::vector<resolved_library_projection>& library_projections,
    std::uint64_t page_bytes
) -> result<std::uint64_t> {
    std::uint64_t allocated = 0;
    std::set<std::string> aliases;
    std::vector<std::filesystem::path> targets;
    targets.reserve(grants.size());
    for (const auto& grant : grants) {
        const bool read_bind = grant.access() == path_access::read &&
                               grant.materialization() == path_materialization::bind &&
                               grant.cleanup_policy() == path_cleanup_policy::retain &&
                               grant.max_bytes() == 0;
        const bool ephemeral_copy = grant.access() == path_access::ephemeral_write &&
                                    grant.materialization() == path_materialization::copy &&
                                    grant.cleanup_policy() == path_cleanup_policy::remove &&
                                    grant.max_bytes() != 0 && grant.max_bytes() % page_bytes == 0;
        const bool retained_copy = grant.access() == path_access::retained_write &&
                                   grant.materialization() == path_materialization::copy &&
                                   grant.cleanup_policy() == path_cleanup_policy::retain &&
                                   grant.max_bytes() != 0 && grant.max_bytes() % page_bytes == 0 &&
                                   grant.exposure_generation() != 0 &&
                                   !grant.exposure_scope_digest().empty();
        if ((!read_bind && !ephemeral_copy && !retained_copy) ||
            !valid_target(grant.target_path()) ||
            !aliases.insert(std::string{grant.alias()}).second ||
            ((ephemeral_copy || retained_copy) && !checked_add(allocated, grant.max_bytes()))) {
            return std::unexpected(std::string{"invalid session filesystem grant set"});
        }
        const std::filesystem::path target{grant.target_path()};
        for (const auto& existing : targets) {
            if (path_within(target, existing) || path_within(existing, target)) {
                return std::unexpected(std::string{"overlapping session filesystem targets"});
            }
        }
        targets.push_back(target);
    }
    std::set<std::string> projection_ids;
    for (const auto& projection : library_projections) {
        const std::filesystem::path target{projection.target_path};
        const auto expected_filename = std::string{projection.bundle.content_digest()} + ".json";
        if (!valid_identifier(projection.projection_id) ||
            !valid_identifier(projection.destination_alias) ||
            !projection_ids.insert(projection.projection_id).second ||
            !valid_digest(projection.bundle.content_digest()) ||
            !valid_target(projection.target_path) || target.filename() != expected_filename ||
            !projection.bundle.verify_identity()) {
            return std::unexpected(std::string{"invalid session library projection set"});
        }
        if (std::ranges::any_of(targets, [&](const auto& existing) {
                return path_within(target, existing) || path_within(existing, target);
            })) {
            return std::unexpected(std::string{"overlapping session filesystem targets"});
        }
        targets.push_back(target);
    }
    return allocated;
}

auto scratch_mount(int source_fd, std::string target, std::string alias, std::uint64_t quota)
    -> result<session_mount> {
    auto descriptor = clone_mount_descriptor(source_fd);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    return session_mount{
        .descriptor_fd = *descriptor,
        .target_path = std::move(target),
        .alias = std::move(alias),
        .quota_partition = "__scratch",
        .quota_bytes = quota,
        .source_identity = std::nullopt,
        .source_content_digest = std::nullopt,
        .projection_id = std::nullopt,
        .projection_destination_alias = std::nullopt,
        .runtime_adapter_id = std::nullopt,
        .runtime_context_digest = std::nullopt,
        .writable = true,
        .directory = true,
    };
}

auto create_scratch_mounts(
    int tmp_fd, int var_tmp_fd, std::uint64_t quota, std::size_t total_mounts
) -> result<std::vector<session_mount>> {
    std::vector<session_mount> mounts;
    mounts.reserve(total_mounts);
    auto tmp = scratch_mount(tmp_fd, "/tmp", "__scratch_tmp", quota);
    if (!tmp) {
        return std::unexpected(tmp.error());
    }
    mounts.push_back(std::move(*tmp));
    auto var_tmp = scratch_mount(var_tmp_fd, "/var/tmp", "__scratch_var_tmp", quota);
    if (!var_tmp) {
        close_mount_records(mounts);
        return std::unexpected(var_tmp.error());
    }
    mounts.push_back(std::move(*var_tmp));
    return mounts;
}

auto append_native_skill_runtime_home(
    const native_skill_runtime_adapter& adapter,
    int scratch_fd,
    std::uint64_t scratch_quota,
    const std::vector<resolved_library_projection>& library_projections,
    std::vector<session_mount>& mounts
) -> result<void> {
    auto projection = resolve_native_skill_runtime_projection(adapter, library_projections);
    if (!projection) {
        return std::unexpected(projection.error());
    }
    auto context_digest = native_skill_runtime_projection_digest(adapter, *projection);
    if (!context_digest) {
        return std::unexpected(context_digest.error());
    }
    if (::mkdirat(scratch_fd, "agent-home", 0700) != 0) {
        return std::unexpected(
            std::string{"create native skill private home: "} + errno_message(errno)
        );
    }
    unique_fd home_fd{::openat(
        scratch_fd, "agent-home", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (home_fd.get() < 0) {
        return std::unexpected(
            std::string{"open native skill private home: "} + errno_message(errno)
        );
    }
    if (auto materialized = materialize_native_skill_runtime_projection(
            home_fd.get(), adapter, *projection
        );
        !materialized) {
        return std::unexpected(materialized.error());
    }
    auto mount = scratch_mount(
        home_fd.get(), "/home/agent", adapter.home_mount_alias, scratch_quota
    );
    if (!mount) {
        return std::unexpected(mount.error());
    }
    mount->runtime_adapter_id = adapter.runtime_id;
    mount->runtime_context_digest = std::move(*context_digest);
    mounts.push_back(std::move(*mount));
    return {};
}

auto append_read_mount(const resolved_path_grant& grant, std::vector<session_mount>& mounts)
    -> result<void> {
    if (auto verified = grant.verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    const auto identity = grant.identity();
    const auto mode = static_cast<mode_t>(identity.mode);
    session_mount mount{
        .target_path = std::string{grant.target_path()},
        .alias = std::string{grant.alias()},
        .quota_partition = "",
        .quota_bytes = 0,
        .source_identity = identity,
        .source_content_digest = std::nullopt,
        .projection_id = std::nullopt,
        .projection_destination_alias = std::nullopt,
        .runtime_adapter_id = std::nullopt,
        .runtime_context_digest = std::nullopt,
        .writable = false,
        .directory = static_cast<bool>(S_ISDIR(mode)),
    };
    auto descriptor = clone_mount_descriptor(grant.descriptor_fd());
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    if (auto verified = grant.verify_identity(); !verified) {
        ::close(*descriptor);
        return std::unexpected(verified.error());
    }
    mount.descriptor_fd = *descriptor;
    mounts.push_back(std::move(mount));
    return {};
}

auto append_ephemeral_mount(
    std::string_view materialization_root,
    std::string_view session_id,
    const resolved_path_grant& grant,
    std::vector<ephemeral_copy_materialization>& materializations,
    std::vector<session_mount>& mounts
) -> result<void> {
    auto materialized =
        ephemeral_copy_materialization::create(materialization_root, session_id, grant);
    if (!materialized) {
        return std::unexpected(materialized.error());
    }
    session_mount mount{
        .target_path = std::string{materialized->target_path()},
        .alias = std::string{materialized->alias()},
        .quota_partition = std::string{materialized->alias()},
        .quota_bytes = materialized->quota_bytes(),
        .source_identity = materialized->source_identity(),
        .source_content_digest = std::nullopt,
        .projection_id = std::nullopt,
        .projection_destination_alias = std::nullopt,
        .runtime_adapter_id = std::nullopt,
        .runtime_context_digest = std::nullopt,
        .writable = true,
        .directory = materialized->is_directory(),
    };
    auto descriptor = clone_mount_descriptor(materialized->content_fd());
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    mount.descriptor_fd = *descriptor;
    mounts.push_back(std::move(mount));
    materializations.push_back(std::move(*materialized));
    return {};
}

auto append_library_mounts(
    const std::vector<resolved_library_projection>& projections, std::vector<session_mount>& mounts
) -> result<void> {
    for (const auto& projection : projections) {
        if (auto verified = projection.bundle.verify_identity(); !verified) {
            return std::unexpected(verified.error());
        }
        const auto bundle_identity = projection.bundle.identity();
        session_mount mount{
            .target_path = projection.target_path,
            .alias = "library:" + projection.projection_id,
            .quota_partition = "",
            .quota_bytes = 0,
            .source_identity =
                path_identity{
                    .device = bundle_identity.device,
                    .inode = bundle_identity.inode,
                    .mode = bundle_identity.mode,
                },
            .source_content_digest = std::string{projection.bundle.content_digest()},
            .projection_id = projection.projection_id,
            .projection_destination_alias = projection.destination_alias,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .writable = false,
            .directory = false,
        };
        auto descriptor = clone_mount_descriptor(projection.bundle.descriptor_fd());
        if (!descriptor) {
            return std::unexpected(descriptor.error());
        }
        if (auto verified = projection.bundle.verify_identity(); !verified) {
            ::close(*descriptor);
            return std::unexpected(verified.error());
        }
        mount.descriptor_fd = *descriptor;
        mounts.push_back(std::move(mount));
    }
    return {};
}

auto append_grant_mounts(
    std::string_view materialization_root,
    std::string_view session_id,
    const std::vector<resolved_path_grant>& grants,
    std::vector<ephemeral_copy_materialization>& materializations,
    std::vector<session_mount>& mounts
) -> result<void> {
    for (const auto& grant : grants) {
        auto appended = grant.access() == path_access::read
                            ? append_read_mount(grant, mounts)
                            : append_ephemeral_mount(
                                  materialization_root, session_id, grant, materializations, mounts
                              );
        if (!appended) {
            return appended;
        }
    }
    return {};
}

} // namespace

linux_session_filesystem::linux_session_filesystem(
    std::uint64_t disk_limit_bytes,
    ephemeral_copy_materialization scratch,
    int tmp_fd,
    int var_tmp_fd,
    std::vector<ephemeral_copy_materialization> materializations,
    std::vector<session_mount> mounts
) noexcept
    : disk_limit_bytes_{disk_limit_bytes},
      scratch_{std::move(scratch)},
      tmp_fd_{tmp_fd},
      var_tmp_fd_{var_tmp_fd},
      materializations_{std::move(materializations)},
      mounts_{std::move(mounts)} {}

linux_session_filesystem::linux_session_filesystem(linux_session_filesystem&& other) noexcept
    : disk_limit_bytes_{other.disk_limit_bytes_},
      scratch_{std::move(other.scratch_)},
      tmp_fd_{std::exchange(other.tmp_fd_, -1)},
      var_tmp_fd_{std::exchange(other.var_tmp_fd_, -1)},
      materializations_{std::move(other.materializations_)},
      mounts_{std::exchange(other.mounts_, {})},
      active_{std::exchange(other.active_, false)} {}

linux_session_filesystem::~linux_session_filesystem() {
    close_mount_descriptors();
    close_scratch_descriptors();
}

result<linux_session_filesystem> linux_session_filesystem::create(
    std::string_view materialization_root,
    std::string_view session_id,
    std::uint64_t disk_limit_bytes,
    std::vector<resolved_path_grant>&& grants,
    std::vector<resolved_library_projection>&& library_projections,
    std::string_view runtime_id
) {
    auto owned_grants = std::move(grants);
    auto owned_library_projections = std::move(library_projections);
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return std::unexpected(std::string{"cannot determine session filesystem granularity"});
    }
    const auto page_bytes = static_cast<std::uint64_t>(page_size);
    if (disk_limit_bytes < page_bytes || disk_limit_bytes % page_bytes != 0) {
        return std::unexpected(std::string{"session disk limit must be a page multiple"});
    }

    auto allocated = validate_grants(owned_grants, owned_library_projections, page_bytes);
    if (!allocated) {
        return std::unexpected(allocated.error());
    }
    if (*allocated >= disk_limit_bytes || disk_limit_bytes - *allocated < page_bytes) {
        return std::unexpected(std::string{"session filesystem requires a scratch quota"});
    }
    const std::uint64_t scratch_quota = disk_limit_bytes - *allocated;
    auto scratch = ephemeral_copy_materialization::create_empty_session_scratch(
        materialization_root, session_id, scratch_quota
    );
    if (!scratch) {
        return std::unexpected(scratch.error());
    }
    unique_fd tmp_fd{::openat( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        scratch->content_fd(),
        "tmp",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (tmp_fd.get() < 0) {
        return std::unexpected(std::string{"open session /tmp: "} + errno_message(errno));
    }
    unique_fd var_tmp_fd{::openat( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        scratch->content_fd(),
        "var-tmp",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    )};
    if (var_tmp_fd.get() < 0) {
        const int saved = errno;
        return std::unexpected(std::string{"open session /var/tmp: "} + errno_message(saved));
    }

    std::vector<ephemeral_copy_materialization> materializations;
    materializations.reserve(owned_grants.size());
    auto mounts = create_scratch_mounts(
        tmp_fd.get(),
        var_tmp_fd.get(),
        scratch_quota,
        owned_grants.size() + owned_library_projections.size() + 3U
    );
    if (!mounts) {
        return std::unexpected(mounts.error());
    }
    if (const auto adapter = native_skill_runtime_adapter_for(runtime_id)) {
        if (auto appended = append_native_skill_runtime_home(
                *adapter,
                scratch->content_fd(),
                scratch_quota,
                owned_library_projections,
                *mounts
            );
            !appended) {
            close_mount_records(*mounts);
            return std::unexpected(appended.error());
        }
    }
    if (auto appended = append_grant_mounts(
            materialization_root, session_id, owned_grants, materializations, *mounts
        );
        !appended) {
        close_mount_records(*mounts);
        return std::unexpected(appended.error());
    }
    if (auto appended = append_library_mounts(owned_library_projections, *mounts); !appended) {
        close_mount_records(*mounts);
        return std::unexpected(appended.error());
    }
    linux_session_filesystem filesystem{
        disk_limit_bytes,
        std::move(*scratch),
        tmp_fd.release(),
        var_tmp_fd.release(),
        std::move(materializations),
        std::move(*mounts),
    };
    auto usage = filesystem.observe();
    if (!usage || usage->quota_bytes != disk_limit_bytes) {
        return std::unexpected(
            usage ? std::string{"session filesystem quota partition mismatch"} : usage.error()
        );
    }
    return filesystem;
}

result<void> linux_session_filesystem::cleanup_recovered(
    std::string_view materialization_root,
    std::string_view session_id,
    std::uint64_t disk_limit_bytes,
    const std::vector<recovered_quota_partition>& partitions
) {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return std::unexpected(std::string{"cannot determine recovery quota granularity"});
    }
    const auto page_bytes = static_cast<std::uint64_t>(page_size);
    if (!valid_recovery_identifier(session_id) || partitions.size() > 128U ||
        disk_limit_bytes < page_bytes || disk_limit_bytes % page_bytes != 0) {
        return std::unexpected(std::string{"invalid recovered session filesystem identity"});
    }
    std::uint64_t allocated = 0;
    std::set<std::string> aliases;
    for (const auto& partition : partitions) {
        if (!valid_recovery_identifier(partition.alias) || partition.quota_bytes == 0 ||
            partition.quota_bytes % page_bytes != 0 || !aliases.insert(partition.alias).second ||
            !checked_add(allocated, partition.quota_bytes)) {
            return std::unexpected(std::string{"invalid recovered quota partition set"});
        }
    }
    if (allocated >= disk_limit_bytes || disk_limit_bytes - allocated < page_bytes) {
        return std::unexpected(std::string{"recovered session scratch quota is invalid"});
    }

    std::vector<ephemeral_copy_materialization> recovered;
    recovered.reserve(partitions.size() + 1U);
    for (const auto& partition : partitions) {
        auto adopted = ephemeral_copy_materialization::adopt_recovered(
            materialization_root,
            session_id,
            partition_directory_name(session_id, partition.alias),
            partition.alias,
            partition.quota_bytes
        );
        if (!adopted) {
            return std::unexpected(adopted.error());
        }
        if (*adopted) {
            recovered.push_back(std::move(**adopted));
        }
    }
    auto scratch = ephemeral_copy_materialization::adopt_recovered(
        materialization_root,
        session_id,
        scratch_directory_name(session_id),
        "__scratch",
        disk_limit_bytes - allocated
    );
    if (!scratch) {
        return std::unexpected(scratch.error());
    }
    if (*scratch) {
        recovered.push_back(std::move(**scratch));
    }
    std::string first_error;
    for (auto& materialization : recovered) {
        auto finalized = materialization.finalize_retained();
        if (!finalized) {
            if (first_error.empty()) {
                first_error = finalized.error();
            }
            continue;
        }
        materialization.arm_recovered_cleanup();
        if (auto cleaned = materialization.cleanup(); !cleaned && first_error.empty()) {
            first_error = cleaned.error();
        }
    }
    if (!first_error.empty()) {
        return std::unexpected(std::move(first_error));
    }
    return {};
}

result<orphaned_materialization_report> linux_session_filesystem::sweep_orphaned(
    std::string_view materialization_root, const std::vector<std::string>& protected_session_ids
) {
    std::set<std::string> protected_sessions;
    for (const auto& session_id : protected_session_ids) {
        if (!valid_recovery_identifier(session_id) ||
            !protected_sessions.insert(session_id).second) {
            return std::unexpected(std::string{"invalid protected session inventory"});
        }
    }
    auto root = open_owner_only_root(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    auto entries = list_root_entries(root->get());
    if (!entries) {
        return std::unexpected(entries.error());
    }

    orphaned_materialization_report report;
    std::set<materialization_identity> processed;
    const auto recover = [&](const materialization_identity& identity,
                             std::string directory_name) -> result<void> {
        if (protected_sessions.contains(identity.session_id) || processed.contains(identity)) {
            return {};
        }
        auto recovered = ephemeral_copy_materialization::recover_orphaned(
            materialization_root, identity.session_id, std::move(directory_name), identity.alias
        );
        if (!recovered) {
            return std::unexpected(recovered.error());
        }
        processed.insert(identity);
        ++report.inspected;
        if (*recovered) {
            report.recovered_retained_changes.push_back(std::move(**recovered));
        } else {
            ++report.removed_without_stage;
        }
        return {};
    };

    for (const auto& name : *entries) {
        auto identity = parse_partition_name(name);
        if (!identity) {
            identity = parse_scratch_name(name);
        }
        if (!identity || protected_sessions.contains(identity->session_id)) {
            continue;
        }
        struct stat status{};
        if (::fstatat(root->get(), name.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            return std::unexpected(
                std::string{"inspect orphaned materialization: "} + errno_message(errno)
            );
        }
        if (!S_ISDIR(status.st_mode) || status.st_uid != ::geteuid()) {
            return std::unexpected(std::string{"orphaned materialization entry is invalid"});
        }
        if (auto recovered = recover(*identity, name); !recovered) {
            return std::unexpected(recovered.error());
        }
    }

    // A crash can occur after creating the persistent sidecars but before or
    // after publishing the mountpoint. A second pass covers those exact cases.
    entries = list_root_entries(root->get());
    if (!entries) {
        return std::unexpected(entries.error());
    }
    for (const auto& name : *entries) {
        std::optional<materialization_identity> identity;
        if (std::string_view{name}.ends_with(".ext4")) {
            identity = parse_partition_name(
                std::string_view{name}.substr(0, name.size() - std::string_view{".ext4"}.size())
            );
        } else {
            identity = parse_metadata_name(name);
        }
        if (!identity || protected_sessions.contains(identity->session_id) ||
            processed.contains(*identity)) {
            continue;
        }
        const auto directory_name = partition_directory_name(identity->session_id, identity->alias);
        if (auto recovered = recover(*identity, directory_name); !recovered) {
            return std::unexpected(recovered.error());
        }
    }
    std::ranges::sort(
        report.recovered_retained_changes, {}, &retained_change_manifest::exposure_id
    );
    return report;
}

auto linux_session_filesystem::mounts() const -> std::vector<session_mount> {
    if (!active_ || mounts_.size() < 2U ||
        std::ranges::any_of(mounts_, [](const auto& mount) { return mount.descriptor_fd < 0; })) {
        return {};
    }
    return mounts_;
}

auto linux_session_filesystem::recovery_partitions() const
    -> std::vector<recovered_quota_partition> {
    if (!active_) {
        return {};
    }
    std::vector<recovered_quota_partition> partitions;
    partitions.reserve(materializations_.size());
    for (const auto& materialization : materializations_) {
        partitions.push_back({
            .alias = std::string{materialization.alias()},
            .quota_bytes = materialization.quota_bytes(),
        });
    }
    std::ranges::sort(partitions, {}, &recovered_quota_partition::alias);
    return partitions;
}

result<session_filesystem_usage> linux_session_filesystem::observe() const {
    if (!active_) {
        return std::unexpected(std::string{"session filesystem is not active"});
    }
    auto scratch = scratch_.observe();
    if (!scratch) {
        return std::unexpected(scratch.error());
    }
    session_filesystem_usage usage{
        .filesystem_bytes = scratch->filesystem_bytes,
        .quota_bytes = scratch->quota_bytes,
        .materializations = materializations_.size(),
        .limit_hit = scratch->filesystem_bytes >= scratch->quota_bytes,
    };
    for (const auto& materialization : materializations_) {
        auto observed = materialization.observe();
        if (!observed) {
            return std::unexpected(observed.error());
        }
        if (!checked_add(usage.filesystem_bytes, observed->filesystem_bytes) ||
            !checked_add(usage.quota_bytes, observed->quota_bytes)) {
            return std::unexpected(std::string{"session filesystem usage overflow"});
        }
        usage.limit_hit = usage.limit_hit || observed->filesystem_bytes >= observed->quota_bytes;
    }
    if (usage.quota_bytes != disk_limit_bytes_ || usage.filesystem_bytes > usage.quota_bytes) {
        return std::unexpected(std::string{"session filesystem quota evidence mismatch"});
    }
    return usage;
}

result<std::vector<retained_change_manifest>>
linux_session_filesystem::finalize_retained_changes() {
    if (!active_) {
        return std::unexpected(std::string{"session filesystem is not active"});
    }
    if (!retained_manifests_.empty()) {
        return retained_manifests_;
    }
    std::vector<retained_change_manifest> finalized_manifests;
    finalized_manifests.reserve(materializations_.size());
    for (auto& materialization : materializations_) {
        auto manifest = materialization.finalize_retained();
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        if (*manifest) {
            finalized_manifests.push_back(std::move(**manifest));
        }
    }
    std::ranges::sort(finalized_manifests, {}, &retained_change_manifest::exposure_id);
    retained_manifests_ = std::move(finalized_manifests);
    return retained_manifests_;
}

void linux_session_filesystem::close_scratch_descriptors() noexcept {
    if (tmp_fd_ >= 0) {
        ::close(tmp_fd_);
        tmp_fd_ = -1;
    }
    if (var_tmp_fd_ >= 0) {
        ::close(var_tmp_fd_);
        var_tmp_fd_ = -1;
    }
}

void linux_session_filesystem::close_mount_descriptors() noexcept {
    close_mount_records(mounts_);
}

result<void> linux_session_filesystem::cleanup() {
    close_mount_descriptors();
    close_scratch_descriptors();
    if (!active_) {
        return {};
    }
    if (auto finalized = finalize_retained_changes(); !finalized) {
        return std::unexpected(finalized.error());
    }
    std::string first_error;
    for (auto& materialization : materializations_) {
        if (auto cleaned = materialization.cleanup(); !cleaned && first_error.empty()) {
            first_error = cleaned.error();
        }
    }
    if (auto cleaned = scratch_.cleanup(); !cleaned && first_error.empty()) {
        first_error = cleaned.error();
    }
    if (!first_error.empty()) {
        return std::unexpected(std::move(first_error));
    }
    active_ = false;
    return {};
}

} // namespace glove::supervisor::linux_detail
