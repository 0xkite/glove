#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "../sha256.hpp"
#include "linux_managed_session.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace glove::container::linux_detail {

namespace {

constexpr std::size_t max_launch_fields = 256;
constexpr std::size_t max_launch_string_bytes = std::size_t{64} * 1024U;
constexpr std::uint64_t max_executable_bytes = std::uint64_t{512} * 1024U * 1024U;

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char character) {
               return std::isdigit(static_cast<unsigned char>(character)) != 0 ||
                      (character >= 'a' && character <= 'f');
           });
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 256U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' ||
               character == ':' || character == '.';
    });
}

auto valid_string(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_launch_string_bytes &&
           value.find('\0') == std::string_view::npos;
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

struct executable_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t mode = 0;
    std::uint64_t size = 0;
    std::uint64_t modified_seconds = 0;
    std::uint32_t modified_nanoseconds = 0;
    std::uint64_t changed_seconds = 0;
    std::uint32_t changed_nanoseconds = 0;
    std::string content_digest;
};

auto inspect_executable(int descriptor) -> std::expected<executable_identity, std::string> {
    if (descriptor < 0) {
        return std::unexpected(std::string{"managed launch executable descriptor is closed"});
    }

    struct ::stat status{};

    if (::fstat(descriptor, &status) < 0) {
        return std::unexpected(
            std::string{"inspect managed launch executable: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    if (!S_ISREG(status.st_mode) || (status.st_mode & 0111U) == 0 || status.st_size < 0 ||
        status.st_mtim.tv_sec < 0 || status.st_mtim.tv_nsec < 0 || status.st_ctim.tv_sec < 0 ||
        status.st_ctim.tv_nsec < 0) {
        return std::unexpected(std::string{"invalid managed launch executable identity"});
    }
    if (static_cast<std::uint64_t>(status.st_size) > max_executable_bytes) {
        return std::unexpected(std::string{"managed launch executable exceeds its hash bound"});
    }
    auto content_digest = detail::sha256_fd_hex(descriptor, max_executable_bytes);

    struct ::stat after{};

    const int reinspected = ::fstat(descriptor, &after);
    const int saved_error = errno;
    if (!content_digest) {
        return std::unexpected(content_digest.error());
    }
    if (reinspected < 0) {
        return std::unexpected(
            std::string{"reinspect managed launch executable: "} +
            std::error_code{saved_error, std::generic_category()}.message()
        );
    }
    if (status.st_dev != after.st_dev || status.st_ino != after.st_ino ||
        status.st_mode != after.st_mode || status.st_size != after.st_size ||
        status.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        status.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        status.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        status.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        return std::unexpected(std::string{"managed launch executable changed while hashing"});
    }
    using unsigned_device = std::make_unsigned_t<decltype(status.st_dev)>;
    using unsigned_inode = std::make_unsigned_t<decltype(status.st_ino)>;
    using unsigned_size = std::make_unsigned_t<decltype(status.st_size)>;
    static_assert(sizeof(unsigned_device) <= sizeof(std::uint64_t));
    static_assert(sizeof(unsigned_inode) <= sizeof(std::uint64_t));
    static_assert(sizeof(unsigned_size) <= sizeof(std::uint64_t));
    static_assert(sizeof(status.st_mode) <= sizeof(std::uint32_t));
    return executable_identity{
        .device = static_cast<std::uint64_t>(static_cast<unsigned_device>(status.st_dev)),
        .inode = static_cast<std::uint64_t>(static_cast<unsigned_inode>(status.st_ino)),
        .mode = static_cast<std::uint32_t>(status.st_mode),
        .size = static_cast<std::uint64_t>(static_cast<unsigned_size>(status.st_size)),
        .modified_seconds = static_cast<std::uint64_t>(status.st_mtim.tv_sec),
        .modified_nanoseconds = static_cast<std::uint32_t>(status.st_mtim.tv_nsec),
        .changed_seconds = static_cast<std::uint64_t>(status.st_ctim.tv_sec),
        .changed_nanoseconds = static_cast<std::uint32_t>(status.st_ctim.tv_nsec),
        .content_digest = std::move(*content_digest),
    };
}

struct mount_projection_state {
    std::set<std::string> aliases;
    std::set<std::string> targets;
    std::vector<std::filesystem::path> target_paths;
    std::map<std::string, std::uint64_t> quota_partitions;
    std::size_t scratch_mounts = 0;
    std::size_t runtime_home_mounts = 0;
    std::optional<std::string> runtime_home_path;
    std::optional<std::string> runtime_adapter_id;
    std::optional<std::string> runtime_context_digest;
};

auto valid_mount_source_identity(const supervisor::linux_detail::session_mount& mount) -> bool {
    if (!mount.source_identity) {
        return false;
    }
    const auto mode = static_cast<mode_t>(mount.source_identity->mode);
    return (S_ISDIR(mode) || S_ISREG(mode)) && mount.directory == static_cast<bool>(S_ISDIR(mode));
}

auto reserve_mount_projection(
    const supervisor::linux_detail::session_mount& mount, mount_projection_state& state
) -> std::expected<void, std::string> {
    const std::filesystem::path target{mount.target_path};
    if (!valid_identifier(mount.alias) || !valid_string(mount.target_path) ||
        !target.is_absolute() || target == target.root_path() ||
        target.lexically_normal() != target || !state.aliases.insert(mount.alias).second ||
        !state.targets.insert(mount.target_path).second) {
        return std::unexpected(std::string{"invalid managed launch mount projection"});
    }
    const bool overlaps = std::ranges::any_of(state.target_paths, [&](const auto& existing) {
        return path_within(target, existing) || path_within(existing, target);
    });
    if (overlaps) {
        return std::unexpected(std::string{"overlapping managed launch mount projection"});
    }
    state.target_paths.push_back(target);
    return {};
}

auto validate_read_only_mount(const supervisor::linux_detail::session_mount& mount)
    -> std::expected<void, std::string> {
    if (!mount.quota_partition.empty() || mount.quota_bytes != 0 ||
        !valid_mount_source_identity(mount) || mount.runtime_adapter_id ||
        mount.runtime_context_digest) {
        return std::unexpected(std::string{"invalid managed launch read-only projection"});
    }
    const bool has_projection_evidence = mount.source_content_digest.has_value() ||
                                         mount.projection_id.has_value() ||
                                         mount.projection_destination_alias.has_value();
    if (has_projection_evidence) {
        const auto mode = static_cast<mode_t>(mount.source_identity->mode);
        const std::filesystem::path target{mount.target_path};
        if (!mount.source_content_digest || !mount.projection_id ||
            !mount.projection_destination_alias || !valid_digest(*mount.source_content_digest) ||
            !valid_identifier(*mount.projection_id) ||
            !valid_identifier(*mount.projection_destination_alias) || !S_ISREG(mode) ||
            mount.directory || mount.alias != "library:" + *mount.projection_id ||
            target.filename() != *mount.source_content_digest + ".json") {
            return std::unexpected(std::string{"invalid managed launch library projection"});
        }
    }
    return {};
}

auto validate_writable_mount(
    const supervisor::linux_detail::session_mount& mount, mount_projection_state& state
) -> std::expected<void, std::string> {
    if (!valid_identifier(mount.quota_partition) || mount.quota_bytes == 0) {
        return std::unexpected(std::string{"invalid managed launch writable projection"});
    }
    if (mount.source_content_digest || mount.projection_id || mount.projection_destination_alias) {
        return std::unexpected(
            std::string{"writable managed launch projection has content digest"}
        );
    }
    const bool has_runtime_context =
        mount.runtime_adapter_id.has_value() || mount.runtime_context_digest.has_value();
    if (has_runtime_context) {
        const auto adapter =
            mount.runtime_adapter_id
                ? supervisor::native_skill_runtime_adapter_for(*mount.runtime_adapter_id)
                : std::nullopt;
        if (!mount.runtime_adapter_id || !mount.runtime_context_digest || !adapter ||
            !valid_digest(*mount.runtime_context_digest) || mount.quota_partition != "__scratch" ||
            mount.alias != adapter->home_mount_alias || mount.target_path != "/home/agent" ||
            mount.source_identity || !mount.directory || state.runtime_home_mounts != 0U) {
            return std::unexpected(std::string{"invalid managed runtime home projection"});
        }
        ++state.runtime_home_mounts;
        state.runtime_home_path = mount.target_path;
        state.runtime_adapter_id = *mount.runtime_adapter_id;
        state.runtime_context_digest = *mount.runtime_context_digest;
        const auto [partition, inserted] =
            state.quota_partitions.emplace(mount.quota_partition, mount.quota_bytes);
        if (!inserted && partition->second != mount.quota_bytes) {
            return std::unexpected(std::string{"managed launch quota partition is inconsistent"});
        }
        return {};
    }
    const auto [partition, inserted] =
        state.quota_partitions.emplace(mount.quota_partition, mount.quota_bytes);
    if (!inserted && partition->second != mount.quota_bytes) {
        return std::unexpected(std::string{"managed launch quota partition is inconsistent"});
    }
    if (mount.quota_partition == "__scratch") {
        const bool tmp = mount.alias == "__scratch_tmp" && mount.target_path == "/tmp";
        const bool var_tmp = mount.alias == "__scratch_var_tmp" && mount.target_path == "/var/tmp";
        if ((!tmp && !var_tmp) || mount.source_identity || !mount.directory) {
            return std::unexpected(std::string{"invalid managed launch scratch projection"});
        }
        ++state.scratch_mounts;
        return {};
    }
    if (mount.quota_partition != mount.alias || !valid_mount_source_identity(mount)) {
        return std::unexpected(std::string{"managed launch mount identity is missing"});
    }
    return {};
}

auto validate_mount_projection_entry(
    const supervisor::linux_detail::session_mount& mount, mount_projection_state& state
) -> std::expected<void, std::string> {
    if (auto reserved = reserve_mount_projection(mount, state); !reserved) {
        return reserved;
    }
    return mount.writable ? validate_writable_mount(mount, state) : validate_read_only_mount(mount);
}

auto validate_mount_projection(
    std::span<const supervisor::linux_detail::session_mount> mounts,
    const resource_limits& limits,
    const std::optional<std::string>& managed_home_dir
) -> std::expected<void, std::string> {
    if (mounts.size() < 2U || mounts.size() > max_launch_fields + 3U) {
        return std::unexpected(std::string{"managed launch has an invalid mount count"});
    }
    mount_projection_state state;
    for (const auto& mount : mounts) {
        if (auto valid = validate_mount_projection_entry(mount, state); !valid) {
            return valid;
        }
    }
    if (state.scratch_mounts != 2U ||
        (managed_home_dir.has_value() != (state.runtime_home_mounts == 1U)) ||
        (managed_home_dir &&
         (*managed_home_dir != "/home/agent" || state.runtime_home_path != managed_home_dir))) {
        return std::unexpected(std::string{"managed launch requires exact scratch projections"});
    }
    std::uint64_t quota_total = 0;
    for (const auto& [name, bytes] : state.quota_partitions) {
        static_cast<void>(name);
        if (bytes > std::numeric_limits<std::uint64_t>::max() - quota_total) {
            return std::unexpected(std::string{"managed launch quota total overflow"});
        }
        quota_total += bytes;
    }
    if (quota_total != limits.disk_bytes) {
        return std::unexpected(std::string{"managed launch quota total mismatch"});
    }
    return {};
}

class canonical_encoder {
public:
    void append_u8(std::uint8_t value) { bytes_.push_back(value); }

    void append_u32(std::uint32_t value) {
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_u64(std::uint64_t value) {
        for (const unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_bool(bool value) { append_u8(static_cast<std::uint8_t>(value ? 1U : 0U)); }

    void append_string(std::string_view value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            valid_ = false;
            return;
        }
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value.size() >> shift));
        }
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }
    [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }

private:
    std::vector<unsigned char> bytes_;
    bool valid_ = true;
};

void append_limits(canonical_encoder& encoder, const resource_limits& limits) {
    encoder.append_u64(limits.cpu_time_ms);
    encoder.append_u64(limits.memory_bytes);
    encoder.append_u32(limits.pids);
    encoder.append_u64(limits.wall_time_ms);
    encoder.append_u64(limits.disk_bytes);
    encoder.append_u64(limits.terminal_output_bytes);
}

} // namespace

auto managed_session_capabilities() noexcept -> resource_enforcement_capabilities {
    return {
        .cpu_time = enforcement_mechanism::cgroup_v2,
        .memory = enforcement_mechanism::cgroup_v2,
        .pids = enforcement_mechanism::cgroup_v2,
        .wall_time = enforcement_mechanism::watchdog,
        .disk = enforcement_mechanism::filesystem_quota,
        .terminal_output = enforcement_mechanism::byte_counter,
        .receipt_schema_version = 1,
    };
}

auto bind_managed_launch_projection_from_fd(
    const profile& prof,
    const std::vector<std::string>& resolved_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    std::string_view controller_plan_digest,
    int executable_fd
) -> std::expected<managed_launch_binding, std::string> {
    if (!valid_digest(controller_plan_digest)) {
        return std::unexpected(std::string{"invalid controller plan digest"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (!checked->required_limits) {
        return std::unexpected(std::string{"managed launch requires resource limits"});
    }
    if (!checked->filesystem.empty() || checked->home_dir || checked->temp_dir ||
        checked->work_dir || std::ranges::any_of(checked->runtime_filesystem, [](const auto& rule) {
            return rule.writable;
        })) {
        return std::unexpected(
            std::string{"managed session paths must come from the lifecycle mount set"}
        );
    }
    if (checked->proxy) {
        return std::unexpected(
            std::string{"Linux egress proxy transport is not implemented; refusing network grant"}
        );
    }
    if (resolved_argv.empty() || resolved_argv.size() > max_launch_fields ||
        std::ranges::any_of(resolved_argv, [](const auto& value) {
            return !valid_string(value);
        })) {
        return std::unexpected(std::string{"invalid resolved managed launch argv"});
    }
    const std::filesystem::path executable{resolved_argv.front()};
    if (!executable.is_absolute() || executable.lexically_normal() != executable) {
        return std::unexpected(std::string{"managed launch executable is not resolved"});
    }
    auto executable_metadata = inspect_executable(executable_fd);
    if (!executable_metadata) {
        return std::unexpected(executable_metadata.error());
    }
    if (checked->environment.size() > max_launch_fields ||
        std::ranges::any_of(checked->environment, [](const auto& value) {
            return !valid_string(value);
        })) {
        return std::unexpected(std::string{"managed launch environment exceeds its bound"});
    }
    const resource_limits limits = checked->required_limits.value_or(resource_limits{});
    if (auto valid = validate_mount_projection(mounts, limits, checked->managed_home_dir); !valid) {
        return std::unexpected(valid.error());
    }

    auto environment = checked->environment;
    std::ranges::sort(environment);
    std::vector<supervisor::linux_detail::session_mount> ordered_mounts{
        mounts.begin(), mounts.end()
    };
    std::ranges::sort(ordered_mounts, [](const auto& left, const auto& right) {
        return std::tie(left.alias, left.target_path) < std::tie(right.alias, right.target_path);
    });

    canonical_encoder encoder;
    encoder.append_string("glove.managed-launch-profile");
    encoder.append_u8(std::uint8_t{1});
    encoder.append_string(controller_plan_digest);
    encoder.append_u64(executable_metadata->device);
    encoder.append_u64(executable_metadata->inode);
    encoder.append_u32(executable_metadata->mode);
    encoder.append_u64(executable_metadata->size);
    encoder.append_u64(executable_metadata->modified_seconds);
    encoder.append_u32(executable_metadata->modified_nanoseconds);
    encoder.append_u64(executable_metadata->changed_seconds);
    encoder.append_u32(executable_metadata->changed_nanoseconds);
    encoder.append_string(executable_metadata->content_digest);
    append_limits(encoder, limits);
    encoder.append_u32(static_cast<std::uint32_t>(environment.size()));
    for (const auto& entry : environment) {
        encoder.append_string(entry);
    }
    encoder.append_u32(static_cast<std::uint32_t>(checked->runtime_filesystem.size()));
    for (const auto& rule : checked->runtime_filesystem) {
        encoder.append_string(rule.path);
        encoder.append_bool(rule.writable);
    }
    encoder.append_bool(checked->managed_home_dir.has_value());
    if (checked->managed_home_dir) {
        encoder.append_string(*checked->managed_home_dir);
    }
    encoder.append_u32(static_cast<std::uint32_t>(resolved_argv.size()));
    for (const auto& argument : resolved_argv) {
        encoder.append_string(argument);
    }
    encoder.append_u32(static_cast<std::uint32_t>(ordered_mounts.size()));
    for (const auto& mount : ordered_mounts) {
        encoder.append_string(mount.alias);
        encoder.append_string(mount.target_path);
        encoder.append_string(mount.quota_partition);
        encoder.append_u64(mount.quota_bytes);
        encoder.append_bool(mount.writable);
        encoder.append_bool(mount.directory);
        encoder.append_bool(mount.source_identity.has_value());
        if (mount.source_identity) {
            encoder.append_u64(mount.source_identity->device);
            encoder.append_u64(mount.source_identity->inode);
            encoder.append_u32(mount.source_identity->mode);
        }
        encoder.append_bool(mount.source_content_digest.has_value());
        if (mount.source_content_digest) {
            encoder.append_string(*mount.source_content_digest);
            encoder.append_string(*mount.projection_id);
            encoder.append_string(*mount.projection_destination_alias);
        }
        encoder.append_bool(mount.runtime_adapter_id.has_value());
        if (mount.runtime_adapter_id) {
            encoder.append_string(*mount.runtime_adapter_id);
            encoder.append_string(*mount.runtime_context_digest);
        }
    }
    if (!encoder.valid()) {
        return std::unexpected(std::string{"managed launch field exceeds canonical encoding limit"});
    }
    auto digest = detail::sha256_hex(encoder.bytes());
    if (!digest) {
        return std::unexpected(digest.error());
    }
    std::vector<library_projection_receipt> library_projections;
    for (const auto& mount : ordered_mounts) {
        if (mount.source_content_digest) {
            library_projections.push_back({
                .projection_id = *mount.projection_id,
                .destination_alias = *mount.projection_destination_alias,
                .target_path = mount.target_path,
                .content_digest = *mount.source_content_digest,
            });
        }
    }
    return managed_launch_binding{
        .controller_plan_digest = std::string{controller_plan_digest},
        .profile_digest = std::move(*digest),
        .library_projections = std::move(library_projections),
    };
}

auto bind_managed_launch_projection(
    const profile& prof,
    const std::vector<std::string>& resolved_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    std::string_view controller_plan_digest
) -> std::expected<managed_launch_binding, std::string> {
    if (resolved_argv.empty()) {
        return std::unexpected(std::string{"invalid resolved managed launch argv"});
    }
    const int executable_fd = ::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        resolved_argv.front().c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if (executable_fd < 0) {
        return std::unexpected(
            std::string{"open managed launch executable: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    auto binding = bind_managed_launch_projection_from_fd(
        prof, resolved_argv, mounts, controller_plan_digest, executable_fd
    );
    ::close(executable_fd);
    return binding;
}

} // namespace glove::container::linux_detail
