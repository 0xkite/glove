#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "../sha256.hpp"
#include "linux_managed_session.hpp"

#include <fcntl.h>
#include <sys/socket.h>
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
    std::optional<std::string> runtime_adoption_manifest_digest;
    std::optional<std::string> runtime_adoption_snapshot_digest;
    std::optional<std::string> service_proxy_manifest_digest;
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
    state.target_paths.push_back(target);
    return {};
}

auto allowed_secret_home_overlap(
    const supervisor::linux_detail::session_mount& first,
    const supervisor::linux_detail::session_mount& second
) -> bool {
    const auto* home = &first;
    const auto* secret = &second;
    if (second.runtime_adapter_id && first.secret_handle) {
        home = &second;
        secret = &first;
    }
    if (!home->runtime_adapter_id || !secret->secret_handle || !secret->secret_runtime_id ||
        home->target_path != "/home/agent" ||
        *home->runtime_adapter_id != *secret->secret_runtime_id) {
        return false;
    }
    const std::filesystem::path home_path{home->target_path};
    const std::filesystem::path secret_path{secret->target_path};
    return secret_path != home_path && path_within(secret_path, home_path);
}

auto validate_secret_mount(const supervisor::linux_detail::session_mount& mount)
    -> std::expected<void, std::string> {
    const std::filesystem::path target{mount.target_path};
    const std::filesystem::path managed_home{"/home/agent"};
    if (!mount.secret_handle || !mount.secret_runtime_id ||
        !valid_identifier(*mount.secret_handle) || !valid_identifier(*mount.secret_runtime_id) ||
        mount.alias != "secret:" + *mount.secret_handle || target.lexically_normal() != target ||
        target == managed_home || !path_within(target, managed_home) ||
        !valid_mount_source_identity(mount) || mount.source_content_digest || mount.projection_id ||
        mount.projection_destination_alias || mount.runtime_adapter_id ||
        mount.runtime_context_digest || mount.runtime_adoption_manifest_digest ||
        mount.runtime_adoption_snapshot_digest || mount.service_proxy_manifest_digest ||
        !mount.quota_partition.empty() || mount.quota_bytes != 0 || mount.directory) {
        return std::unexpected(std::string{"invalid managed launch secret projection"});
    }
    return {};
}

auto validate_read_only_mount(
    const supervisor::linux_detail::session_mount& mount, mount_projection_state& state
) -> std::expected<void, std::string> {
    if (!mount.quota_partition.empty() || mount.quota_bytes != 0 ||
        !valid_mount_source_identity(mount) || mount.runtime_adapter_id ||
        mount.runtime_context_digest || mount.runtime_adoption_manifest_digest ||
        mount.runtime_adoption_snapshot_digest) {
        return std::unexpected(std::string{"invalid managed launch read-only projection"});
    }
    const bool has_secret = mount.secret_handle.has_value() || mount.secret_runtime_id.has_value();
    if (has_secret) {
        return validate_secret_mount(mount);
    }
    if (mount.service_proxy_manifest_digest) {
        const auto mode = static_cast<mode_t>(mount.source_identity->mode);
        if (state.service_proxy_manifest_digest ||
            !valid_digest(*mount.service_proxy_manifest_digest) ||
            mount.alias != "local-services" || mount.target_path != "/run/glove-services/local" ||
            !mount.directory || !S_ISDIR(mode) || mount.source_content_digest ||
            mount.projection_id || mount.projection_destination_alias) {
            return std::unexpected(std::string{"invalid managed local service projection"});
        }
        state.service_proxy_manifest_digest = *mount.service_proxy_manifest_digest;
        return {};
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
    const bool has_secret = mount.secret_handle.has_value() || mount.secret_runtime_id.has_value();
    if (has_secret) {
        return validate_secret_mount(mount);
    }
    if (!valid_identifier(mount.quota_partition) || mount.quota_bytes == 0) {
        return std::unexpected(std::string{"invalid managed launch writable projection"});
    }
    if (mount.source_content_digest || mount.projection_id || mount.projection_destination_alias ||
        mount.secret_handle || mount.secret_runtime_id || mount.service_proxy_manifest_digest) {
        return std::unexpected(
            std::string{"writable managed launch projection has content digest"}
        );
    }
    const bool has_runtime_context =
        mount.runtime_adapter_id.has_value() || mount.runtime_context_digest.has_value();
    const bool has_adoption_identity = mount.runtime_adoption_manifest_digest.has_value() ||
                                       mount.runtime_adoption_snapshot_digest.has_value();
    if (has_runtime_context) {
        const auto adapter =
            mount.runtime_adapter_id
                ? supervisor::native_skill_runtime_adapter_for(*mount.runtime_adapter_id)
                : std::nullopt;
        if (!mount.runtime_adapter_id || !mount.runtime_context_digest || !adapter ||
            !valid_digest(*mount.runtime_context_digest) ||
            (has_adoption_identity &&
             (!mount.runtime_adoption_manifest_digest || !mount.runtime_adoption_snapshot_digest ||
              adapter->runtime_id != "pi" ||
              !valid_digest(*mount.runtime_adoption_manifest_digest) ||
              !valid_digest(*mount.runtime_adoption_snapshot_digest))) ||
            mount.quota_partition != "__scratch" || mount.alias != adapter->home_mount_alias ||
            mount.target_path != "/home/agent" || mount.source_identity || !mount.directory ||
            state.runtime_home_mounts != 0U) {
            return std::unexpected(std::string{"invalid managed runtime home projection"});
        }
        ++state.runtime_home_mounts;
        state.runtime_home_path = mount.target_path;
        state.runtime_adapter_id = *mount.runtime_adapter_id;
        state.runtime_context_digest = *mount.runtime_context_digest;
        state.runtime_adoption_manifest_digest = mount.runtime_adoption_manifest_digest;
        state.runtime_adoption_snapshot_digest = mount.runtime_adoption_snapshot_digest;
        const auto [partition, inserted] =
            state.quota_partitions.emplace(mount.quota_partition, mount.quota_bytes);
        if (!inserted && partition->second != mount.quota_bytes) {
            return std::unexpected(std::string{"managed launch quota partition is inconsistent"});
        }
        return {};
    }
    if (has_adoption_identity) {
        return std::unexpected(std::string{"adoption identity requires a managed runtime home"});
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
    return mount.writable ? validate_writable_mount(mount, state)
                          : validate_read_only_mount(mount, state);
}

auto validate_mount_projection(
    std::span<const supervisor::linux_detail::session_mount> mounts,
    const resource_limits& limits,
    const std::optional<std::string>& managed_home_dir
) -> std::expected<void, std::string> {
    if (mounts.size() < 2U || mounts.size() > max_launch_fields + 35U) {
        return std::unexpected(std::string{"managed launch has an invalid mount count"});
    }
    mount_projection_state state;
    for (const auto& mount : mounts) {
        if (auto valid = validate_mount_projection_entry(mount, state); !valid) {
            return valid;
        }
    }
    for (std::size_t index = 0; index < mounts.size(); ++index) {
        const std::filesystem::path target{mounts[index].target_path};
        for (std::size_t other = index + 1U; other < mounts.size(); ++other) {
            const std::filesystem::path other_target{mounts[other].target_path};
            if ((path_within(target, other_target) || path_within(other_target, target)) &&
                !allowed_secret_home_overlap(mounts[index], mounts[other])) {
                return std::unexpected(std::string{"overlapping managed launch mount projection"});
            }
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

auto inherited_environment(std::span<const inherited_stream_descriptor> streams) -> std::string {
    std::string result{"GLOVE_LOCAL_SERVICE_FDS_V1={"};
    for (std::size_t index = 0; index < streams.size(); ++index) {
        if (index != 0U) {
            result.push_back(',');
        }
        result += "\"" + streams[index].alias + "\":" + std::to_string(streams[index].child_fd);
    }
    result.push_back('}');
    return result;
}

auto validate_inherited_streams(
    std::span<const inherited_stream_descriptor> streams,
    std::span<const std::string> environment,
    std::size_t service_mounts
) -> std::expected<std::optional<std::string>, std::string> {
    const auto fd_environment = std::ranges::count_if(environment, [](const auto& entry) {
        return entry.starts_with("GLOVE_LOCAL_SERVICE_FDS_V1=");
    });
    const auto path_environment =
        std::ranges::count(environment, "GLOVE_LOCAL_SERVICE_DIR=/run/glove-services/local");
    if (streams.empty()) {
        if (fd_environment != 0U) {
            return std::unexpected(std::string{"inherited stream environment lacks descriptors"});
        }
        return std::nullopt;
    }
    if (service_mounts != 0U || path_environment != 0U || fd_environment != 1U ||
        !std::ranges::is_sorted(streams, {}, &inherited_stream_descriptor::alias) ||
        !std::ranges::contains(environment, inherited_environment(streams))) {
        return std::unexpected(std::string{"invalid managed inherited stream projection"});
    }
    std::set<int> descriptor_fds;
    std::string_view previous_alias;
    std::string_view manifest;
    for (std::size_t index = 0; index < streams.size(); ++index) {
        const auto& stream = streams[index];
        struct stat status{};
        int domain = 0;
        int type = 0;
        socklen_t length = sizeof(int);
        if (!valid_identifier(stream.alias) ||
            (!previous_alias.empty() && previous_alias >= stream.alias) ||
            stream.descriptor_fd < 3 || stream.child_fd != static_cast<int>(index + 3U) ||
            !descriptor_fds.insert(stream.descriptor_fd).second ||
            ::fstat(stream.descriptor_fd, &status) != 0 || !S_ISSOCK(status.st_mode) ||
            static_cast<std::uint64_t>(status.st_dev) != stream.device ||
            static_cast<std::uint64_t>(status.st_ino) != stream.inode ||
            static_cast<std::uint32_t>(status.st_uid) != stream.uid ||
            static_cast<std::uint32_t>(status.st_mode) != stream.mode ||
            static_cast<std::uint64_t>(status.st_nlink) != stream.links || stream.links != 1U ||
            stream.peer_device == 0U || stream.peer_inode == 0U ||
            stream.peer_uid != static_cast<std::uint32_t>(::geteuid()) ||
            !S_ISSOCK(static_cast<mode_t>(stream.peer_mode)) || stream.peer_links != 1U ||
            (stream.peer_mode & 0777U) != 0600U ||
            ::getsockopt(stream.descriptor_fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) != 0 ||
            domain != AF_UNIX ||
            ::getsockopt(stream.descriptor_fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
            type != SOCK_STREAM || !valid_digest(stream.manifest_digest) ||
            (index != 0U && stream.manifest_digest != manifest)) {
            return std::unexpected(std::string{"invalid managed inherited stream descriptor"});
        }
        previous_alias = stream.alias;
        manifest = stream.manifest_digest;
    }
    return std::optional<std::string>{std::string{manifest}};
}

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
    int executable_fd,
    std::span<const inherited_stream_descriptor> inherited_streams
) -> std::expected<managed_launch_binding, std::string> {
    if (!valid_digest(controller_plan_digest)) {
        return std::unexpected(std::string{"invalid controller plan digest"});
    }
    auto profile_without_managed_work_dir = prof;
    const auto managed_work_dir = profile_without_managed_work_dir.work_dir;
    profile_without_managed_work_dir.work_dir.reset();
    auto checked = validate(profile_without_managed_work_dir);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (managed_work_dir && *managed_work_dir != "/workspace" &&
        (*managed_work_dir != "/home/agent" ||
         checked->managed_home_dir != std::optional<std::string>{"/home/agent"})) {
        return std::unexpected(
            std::string{"managed session work directory must be /workspace or its private home"}
        );
    }
    checked->work_dir = managed_work_dir;
    if (!checked->required_limits) {
        return std::unexpected(std::string{"managed launch requires resource limits"});
    }
    if (!checked->filesystem.empty() || checked->home_dir || checked->temp_dir ||
        std::ranges::any_of(checked->runtime_filesystem, [](const auto& rule) {
            return rule.writable;
        })) {
        return std::unexpected(
            std::string{"managed session paths must come from the lifecycle mount set"}
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
    constexpr std::string_view local_service_environment =
        "GLOVE_LOCAL_SERVICE_DIR=/run/glove-services/local";
    const auto service_mounts = std::ranges::count_if(mounts, [](const auto& mount) {
        return mount.service_proxy_manifest_digest.has_value();
    });
    const auto service_environment =
        std::ranges::count(checked->environment, local_service_environment);
    auto inherited_manifest = validate_inherited_streams(
        inherited_streams, checked->environment, static_cast<std::size_t>(service_mounts)
    );
    if (!inherited_manifest) {
        return std::unexpected(inherited_manifest.error());
    }
    if (service_mounts != service_environment || service_mounts > 1 ||
        (service_mounts != 0 && inherited_manifest->has_value())) {
        return std::unexpected(
            std::string{"managed local service mount and environment must be paired"}
        );
    }
    if (checked->work_dir && std::ranges::none_of(mounts, [&](const auto& mount) {
            return path_within(
                std::filesystem::path{mount.target_path}, std::filesystem::path{*checked->work_dir}
            );
        })) {
        return std::unexpected(
            std::string{"managed session work directory is not backed by a lifecycle mount"}
        );
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
    if (checked->work_dir) {
        encoder.append_string("glove.managed-launch-work-dir");
        encoder.append_string(*checked->work_dir);
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
        encoder.append_bool(mount.runtime_adoption_manifest_digest.has_value());
        if (mount.runtime_adoption_manifest_digest) {
            encoder.append_string(*mount.runtime_adoption_manifest_digest);
            encoder.append_string(*mount.runtime_adoption_snapshot_digest);
        }
        if (mount.secret_handle) {
            encoder.append_string("glove.managed-launch-secret");
            encoder.append_string(*mount.secret_handle);
            encoder.append_string(*mount.secret_runtime_id);
        }
        if (mount.service_proxy_manifest_digest) {
            encoder.append_string("glove.managed-launch-local-service");
            encoder.append_string(*mount.service_proxy_manifest_digest);
        }
    }
    if (!inherited_streams.empty()) {
        encoder.append_string("glove.managed-launch-inherited-stream");
        encoder.append_string("inherited-stream-v1");
        encoder.append_u32(static_cast<std::uint32_t>(inherited_streams.size()));
        for (const auto& stream : inherited_streams) {
            encoder.append_string(stream.alias);
            encoder.append_u32(static_cast<std::uint32_t>(stream.child_fd));
            encoder.append_u64(stream.device);
            encoder.append_u64(stream.inode);
            encoder.append_u32(stream.uid);
            encoder.append_u32(stream.mode);
            encoder.append_u64(stream.links);
            encoder.append_u64(stream.peer_device);
            encoder.append_u64(stream.peer_inode);
            encoder.append_u32(stream.peer_uid);
            encoder.append_u32(stream.peer_mode);
            encoder.append_u64(stream.peer_links);
            encoder.append_string(stream.manifest_digest);
        }
    }
    // Preserve the version-1 digest for offline launches while binding the
    // exact ephemeral proxy capability whenever egress is present. This
    // prevents a controller-approved offline projection from being replayed
    // with an uncommitted network grant.
    if (checked->proxy) {
        encoder.append_string("glove.managed-launch-egress");
        encoder.append_u32(checked->proxy->port);
        encoder.append_string(checked->proxy->url);
    }
    if (!encoder.valid()) {
        return std::unexpected(
            std::string{"managed launch field exceeds canonical encoding limit"}
        );
    }
    auto digest = detail::sha256_hex(encoder.bytes());
    if (!digest) {
        return std::unexpected(digest.error());
    }
    std::vector<library_projection_receipt> library_projections;
    std::optional<std::string> service_proxy_manifest_digest =
        inherited_manifest->has_value() ? *inherited_manifest : std::nullopt;
    for (const auto& mount : ordered_mounts) {
        if (mount.service_proxy_manifest_digest) {
            service_proxy_manifest_digest = mount.service_proxy_manifest_digest;
        }
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
        .service_proxy_manifest_digest = std::move(service_proxy_manifest_digest),
    };
}

auto bind_managed_launch_projection(
    const profile& prof,
    const std::vector<std::string>& resolved_argv,
    std::span<const supervisor::linux_detail::session_mount> mounts,
    std::string_view controller_plan_digest,
    std::span<const inherited_stream_descriptor> inherited_streams
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
        prof, resolved_argv, mounts, controller_plan_digest, executable_fd, inherited_streams
    );
    ::close(executable_fd);
    return binding;
}

} // namespace glove::container::linux_detail
