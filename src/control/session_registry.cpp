#include "glove/control/session_registry.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace glove::control {

namespace wire {

struct persisted_session {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string operation;
    std::string idempotency_key;
    std::string session_id;
    std::string controller_plan_digest;
    std::string request_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::string authorization_id;
    std::uint64_t authorized_at_ms = 0;
    std::uint64_t authorization_expires_at_ms = 0;
    std::string launch_profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::uint8_t process_identity_schema_version = 0;
    std::uint32_t process_pid = 0;
    std::string process_boot_id;
    std::uint64_t process_start_time_ticks = 0;
    std::uint64_t process_cgroup_device = 0;
    std::uint64_t process_cgroup_inode = 0;
    std::string process_cgroup_path_digest;
    std::optional<linux_cgroup_recovery_identity> cgroup_identity;
    std::optional<linux_filesystem_recovery_identity> filesystem_identity;
    std::optional<managed_runtime_recovery_identity> managed_runtime_identity;
    std::string failure_code;
    std::uint64_t finished_at_ms = 0;
    std::uint64_t receipt_started_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_previous_hmac;
    std::string receipt_hmac;
    std::string termination_cause;
    std::optional<int> exit_code;
    std::string canonical_plan_json;
    std::string previous_hash;
    std::string this_hash;
};

} // namespace wire

namespace {

constexpr std::array<unsigned char, 8> registry_magic = {'G', 'L', 'V', 'S', 'E', 'S', '0', '5'};
constexpr std::size_t digest_hex_bytes = 64U;
constexpr std::uint64_t min_registry_bytes = 1'024U;
constexpr std::uint64_t max_record_payload_bytes = std::uint64_t{1024} * 1024U;
constexpr std::size_t max_records = 10'000U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::uint64_t max_start_authorization_ttl_ms = 120'000U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            if (descriptor_ >= 0) {
                (void)::close(descriptor_);
            }
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

struct opened_registry {
    unique_fd parent;
    unique_fd file;
    std::string name;
    bool created = false;
};

struct registry_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    auto operator==(const registry_identity&) const -> bool = default;
};

auto failure(session_registry_error_code code, std::string message) -> session_registry_error {
    return {.code = code, .message = std::move(message)};
}

auto storage_failure(std::string message) -> session_registry_error {
    return failure(session_registry_error_code::storage, std::move(message));
}

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_boot_id(std::string_view value) noexcept -> bool {
    if (value.size() != 36U) {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto separator = index == 8U || index == 13U || index == 18U || index == 23U;
        if (separator) {
            if (value[index] != '-') {
                return false;
            }
            continue;
        }
        const auto byte = static_cast<unsigned char>(value[index]);
        const bool is_lowercase_hex = (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
        if (!is_lowercase_hex) {
            return false;
        }
    }
    return true;
}

auto valid_process_identity(const linux_process_identity& identity) noexcept -> bool {
    const auto max_pid = static_cast<std::uint64_t>(std::numeric_limits<::pid_t>::max());
    return identity.schema_version == 1 && identity.pid != 0 && identity.pid <= max_pid &&
           valid_boot_id(identity.boot_id) && identity.start_time_ticks != 0 &&
           identity.cgroup_device != 0 && identity.cgroup_inode != 0 &&
           valid_digest(identity.cgroup_path_digest);
}

auto valid_filesystem_identity(const linux_filesystem_recovery_identity& identity) noexcept
    -> bool {
    if (identity.schema_version != 1 || identity.disk_limit_bytes == 0 ||
        identity.partitions.size() > 128U) {
        return false;
    }
    std::uint64_t allocated = 0;
    std::string_view previous_alias;
    for (const auto& partition : identity.partitions) {
        if (!valid_identifier(partition.alias) || partition.quota_bytes == 0 ||
            (!previous_alias.empty() && partition.alias <= previous_alias) ||
            partition.quota_bytes > identity.disk_limit_bytes - allocated) {
            return false;
        }
        allocated += partition.quota_bytes;
        previous_alias = partition.alias;
    }
    return allocated < identity.disk_limit_bytes;
}

auto valid_cgroup_identity(const linux_cgroup_recovery_identity& identity) noexcept -> bool {
    return identity.schema_version == 1 && identity.device != 0 && identity.inode != 0;
}

auto valid_managed_runtime_identity(const managed_runtime_recovery_identity& identity) noexcept
    -> bool {
    return identity.schema_version == 1 && identity.backend == "apple_container" &&
           valid_identifier(identity.instance_id) &&
           valid_digest(identity.launch_identity_digest);
}

auto no_process_identity(const wire::persisted_session& record) noexcept -> bool {
    return record.process_identity_schema_version == 0 && record.process_pid == 0 &&
           record.process_boot_id.empty() && record.process_start_time_ticks == 0 &&
           record.process_cgroup_device == 0 && record.process_cgroup_inode == 0 &&
           record.process_cgroup_path_digest.empty();
}

auto no_resource_identity(const wire::persisted_session& record) noexcept -> bool {
    return no_process_identity(record) && !record.cgroup_identity && !record.filesystem_identity &&
           !record.managed_runtime_identity;
}

auto process_identity_from_wire(const wire::persisted_session& record)
    -> std::optional<linux_process_identity> {
    linux_process_identity identity{
        .schema_version = record.process_identity_schema_version,
        .pid = record.process_pid,
        .boot_id = record.process_boot_id,
        .start_time_ticks = record.process_start_time_ticks,
        .cgroup_device = record.process_cgroup_device,
        .cgroup_inode = record.process_cgroup_inode,
        .cgroup_path_digest = record.process_cgroup_path_digest,
    };
    if (!valid_process_identity(identity)) {
        return std::nullopt;
    }
    return identity;
}

auto same_process_identity(
    const wire::persisted_session& left, const wire::persisted_session& right
) noexcept -> bool {
    return left.process_identity_schema_version == right.process_identity_schema_version &&
           left.process_pid == right.process_pid && left.process_boot_id == right.process_boot_id &&
           left.process_start_time_ticks == right.process_start_time_ticks &&
           left.process_cgroup_device == right.process_cgroup_device &&
           left.process_cgroup_inode == right.process_cgroup_inode &&
           left.process_cgroup_path_digest == right.process_cgroup_path_digest;
}

auto same_process_identity(
    const wire::persisted_session& record, const linux_process_identity& identity
) noexcept -> bool {
    return record.process_identity_schema_version == identity.schema_version &&
           record.process_pid == identity.pid && record.process_boot_id == identity.boot_id &&
           record.process_start_time_ticks == identity.start_time_ticks &&
           record.process_cgroup_device == identity.cgroup_device &&
           record.process_cgroup_inode == identity.cgroup_inode &&
           record.process_cgroup_path_digest == identity.cgroup_path_digest;
}

auto append_u32(std::vector<unsigned char>& output, std::uint32_t value) -> void {
    output.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

auto append_u64(std::vector<unsigned char>& output, std::uint64_t value) -> void {
    output.push_back(static_cast<unsigned char>((value >> 56U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 48U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 40U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 32U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

auto append_string(std::vector<unsigned char>& output, std::string_view value) -> bool {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
}

auto append_filesystem_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_filesystem_recovery_identity>& identity
) -> std::expected<void, std::string> {
    output.push_back(identity.has_value() ? 1U : 0U);
    if (!identity) {
        return {};
    }
    output.push_back(identity->schema_version);
    append_u64(output, identity->disk_limit_bytes);
    append_u32(output, static_cast<std::uint32_t>(identity->partitions.size()));
    for (const auto& partition : identity->partitions) {
        if (!append_string(output, partition.alias)) {
            return std::unexpected(std::string{"filesystem recovery alias exceeds its hash bound"});
        }
        append_u64(output, partition.quota_bytes);
    }
    return {};
}

auto append_cgroup_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_cgroup_recovery_identity>& identity
) -> void {
    output.push_back(identity.has_value() ? 1U : 0U);
    if (!identity) {
        return;
    }
    output.push_back(identity->schema_version);
    append_u64(output, identity->device);
    append_u64(output, identity->inode);
}

auto append_managed_runtime_identity(
    std::vector<unsigned char>& output,
    const std::optional<managed_runtime_recovery_identity>& identity
) -> std::expected<void, std::string> {
    if (!identity) {
        return {};
    }
    constexpr std::string_view extension_domain = "glove.managed-runtime-identity.v1";
    output.push_back(1U);
    if (!append_string(output, extension_domain)) {
        return std::unexpected(std::string{"managed runtime hash domain is invalid"});
    }
    output.push_back(identity->schema_version);
    for (const auto value : {
             std::string_view{identity->backend},
             std::string_view{identity->instance_id},
             std::string_view{identity->launch_identity_digest},
         }) {
        if (!append_string(output, value)) {
            return std::unexpected(std::string{"managed runtime identity exceeds its hash bound"});
        }
    }
    return {};
}

auto decode_u32(std::span<const unsigned char, 4> input) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) | static_cast<std::uint32_t>(input[3]);
}

template<typename Byte, std::size_t Extent>
    requires(sizeof(Byte) == 1)
auto read_at(int descriptor, std::span<Byte, Extent> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - consumed) {
            return std::unexpected(std::string{"session registry offset exceeds platform range"});
        }
        const auto result = ::pread(
            descriptor,
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(offset + consumed)
        );
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error("read session registry"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"session registry ended unexpectedly"});
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto write_at(int descriptor, std::span<const unsigned char> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t written = 0;
    while (written < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - written) {
            return std::unexpected(std::string{"session registry offset exceeds platform range"});
        }
        const auto result = ::pwrite(
            descriptor,
            bytes.data() + written,
            bytes.size() - written,
            static_cast<off_t>(offset + written)
        );
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error("write session registry"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"session registry write made no progress"});
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

auto sync_descriptor(int descriptor, std::string_view operation)
    -> std::expected<void, std::string> {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error(operation));
    }
    return {};
}

auto inspect_file(int descriptor) -> std::expected<std::uint64_t, std::string> {
    struct stat metadata{};

    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(system_error("inspect session registry"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        permissions != owner_permissions || metadata.st_nlink != 1) {
        return std::unexpected(
            std::string{"session registry must be an owner-only, single-link regular file"}
        );
    }
    if (metadata.st_size < 0) {
        return std::unexpected(std::string{"session registry has a negative size"});
    }
    return static_cast<std::uint64_t>(metadata.st_size);
}

auto capture_identity(int descriptor) -> std::expected<registry_identity, std::string> {
    struct stat metadata{};

    if (::fstat(descriptor, &metadata) != 0 || metadata.st_size < 0) {
        return std::unexpected(system_error("capture session registry identity"));
    }
#if defined(__APPLE__)
    const auto changed = metadata.st_ctimespec;
#else
    const auto changed = metadata.st_ctim;
#endif
    return registry_identity{
        .device = static_cast<std::uint64_t>(metadata.st_dev),
        .inode = static_cast<std::uint64_t>(metadata.st_ino),
        .size = static_cast<std::uint64_t>(metadata.st_size),
        .change_seconds = static_cast<std::int64_t>(changed.tv_sec),
        .change_nanoseconds = static_cast<std::int64_t>(changed.tv_nsec),
    };
}

auto open_registry(const std::filesystem::path& path)
    -> std::expected<opened_registry, std::string> {
    const auto name = path.filename().string();
    if (name.empty() || name == "." || name == "..") {
        return std::unexpected(std::string{"session registry path requires a bounded filename"});
    }
    auto parent_path = path.parent_path();
    if (parent_path.empty()) {
        parent_path = ".";
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd parent{::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (parent.get() < 0) {
        return std::unexpected(system_error("open session registry parent"));
    }

    struct stat parent_metadata{};

    if (::fstat(parent.get(), &parent_metadata) != 0) {
        return std::unexpected(system_error("inspect session registry parent"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0700U;
    const auto parent_permissions =
        static_cast<unsigned int>(parent_metadata.st_mode) & permission_mask;
    if (!S_ISDIR(parent_metadata.st_mode) || parent_metadata.st_uid != ::geteuid() ||
        parent_permissions != owner_permissions) {
        return std::unexpected(std::string{"session registry parent must be owner-only"});
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd file{::openat(parent.get(), name.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW)};
    bool created = false;
    if (file.get() < 0 && errno == ENOENT) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        file = unique_fd{::openat(
            parent.get(), name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        )};
        created = file.get() >= 0;
    }
    if (file.get() < 0) {
        return std::unexpected(system_error("open session registry"));
    }
    if (auto valid = inspect_file(file.get()); !valid) {
        return std::unexpected(valid.error());
    }
    while (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error("lock session registry"));
    }
    return opened_registry{
        .parent = std::move(parent),
        .file = std::move(file),
        .name = name,
        .created = created,
    };
}

auto record_material(const wire::persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string> {
    std::vector<unsigned char> material;
    material.reserve(record.canonical_plan_json.size() + 512U);
    constexpr std::string_view domain = "glove.session-registry.record";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"session registry hash domain is invalid"});
    }
    material.push_back(record.schema_version);
    append_u64(material, record.sequence);
    for (const auto value : {
             std::string_view{record.operation},
             std::string_view{record.idempotency_key},
             std::string_view{record.session_id},
             std::string_view{record.controller_plan_digest},
             std::string_view{record.request_digest},
             std::string_view{record.plan_content_digest},
             std::string_view{record.state},
             std::string_view{record.authorization_id},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"session registry hash field exceeds its bound"});
        }
    }
    append_u64(material, record.policy_revision);
    append_u64(material, record.expires_at_ms);
    append_u64(material, record.created_at_ms);
    append_u64(material, record.authorized_at_ms);
    append_u64(material, record.authorization_expires_at_ms);
    if (record.state == "starting" || record.state == "running" || record.state == "stopping" ||
        record.state == "exited" || record.state == "failed") {
        if (!append_string(material, record.launch_profile_digest)) {
            return std::unexpected(
                std::string{"session registry launch profile exceeds its hash bound"}
            );
        }
        append_u64(material, record.starting_at_ms);
        append_cgroup_identity(material, record.cgroup_identity);
        if (auto appended = append_filesystem_identity(material, record.filesystem_identity);
            !appended) {
            return std::unexpected(appended.error());
        }
        if (auto appended =
                append_managed_runtime_identity(material, record.managed_runtime_identity);
            !appended) {
            return std::unexpected(appended.error());
        }
    }
    if (record.state == "running" || record.state == "stopping" || record.state == "exited" ||
        record.state == "failed") {
        append_u64(material, record.running_at_ms);
        material.push_back(record.process_identity_schema_version);
        append_u32(material, record.process_pid);
        if (!append_string(material, record.process_boot_id)) {
            return std::unexpected(
                std::string{"session registry process boot identity exceeds its hash bound"}
            );
        }
        append_u64(material, record.process_start_time_ticks);
        append_u64(material, record.process_cgroup_device);
        append_u64(material, record.process_cgroup_inode);
        if (!append_string(material, record.process_cgroup_path_digest)) {
            return std::unexpected(
                std::string{"session registry process cgroup identity exceeds its hash bound"}
            );
        }
    }
    if (record.state == "stopping" || record.state == "exited" || record.state == "failed") {
        append_u64(material, record.stopping_at_ms);
    }
    if (record.state == "failed") {
        if (!append_string(material, record.failure_code)) {
            return std::unexpected(
                std::string{"session registry failure code exceeds its hash bound"}
            );
        }
        append_u64(material, record.finished_at_ms);
    }
    if (record.state == "exited") {
        for (const auto value : {
                 std::string_view{record.receipt_key_id},
                 std::string_view{record.receipt_digest},
                 std::string_view{record.receipt_previous_hmac},
                 std::string_view{record.receipt_hmac},
                 std::string_view{record.termination_cause},
             }) {
            if (!append_string(material, value)) {
                return std::unexpected(
                    std::string{"session registry terminal field exceeds its hash bound"}
                );
            }
        }
        append_u64(material, record.receipt_sequence);
        append_u64(material, record.receipt_started_at_ms);
        append_u64(material, record.finished_at_ms);
        material.push_back(record.exit_code.has_value() ? 1U : 0U);
        if (record.exit_code) {
            append_u32(material, static_cast<std::uint32_t>(*record.exit_code));
        }
    }
    if (!append_string(material, record.canonical_plan_json) ||
        !append_string(material, record.previous_hash)) {
        return std::unexpected(std::string{"session registry plan exceeds its hash bound"});
    }
    return material;
}

auto hash_record(const wire::persisted_session& record) -> std::expected<std::string, std::string> {
    auto material = record_material(record);
    if (!material) {
        return std::unexpected(material.error());
    }
    return container::sha256_hex(*material);
}

auto hash_plan(std::string_view plan) -> std::expected<std::string, std::string> {
    return container::sha256_hex(
        std::span<const unsigned char>{
            std::bit_cast<const unsigned char*>(plan.data()), plan.size()
        }
    );
}

auto hash_start_authorization(const session_start_authorization& authorization)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-start-authorization";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"start authorization hash domain is invalid"});
    }
    material.push_back(authorization.schema_version);
    for (const auto value : {
             std::string_view{authorization.authorization_id},
             std::string_view{authorization.session_id},
             std::string_view{authorization.controller_plan_digest},
             std::string_view{authorization.plan_content_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"start authorization field exceeds its bound"});
        }
    }
    append_u64(material, authorization.approved_at_ms);
    append_u64(material, authorization.expires_at_ms);
    return container::sha256_hex(material);
}

auto hash_execution_binding(const session_execution_binding& binding)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-execution-binding";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"execution binding hash domain is invalid"});
    }
    material.push_back(binding.schema_version);
    for (const auto value : {
             std::string_view{binding.session_id},
             std::string_view{binding.controller_plan_digest},
             std::string_view{binding.plan_content_digest},
             std::string_view{binding.authorization_id},
             std::string_view{binding.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"execution binding field exceeds its bound"});
        }
    }
    append_cgroup_identity(material, binding.cgroup_identity);
    if (auto appended = append_filesystem_identity(material, binding.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_running_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-running-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"running commitment hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"running commitment field exceeds its bound"});
        }
    }
    material.push_back(running.process_identity.schema_version);
    append_u32(material, running.process_identity.pid);
    if (!append_string(material, running.process_identity.boot_id)) {
        return std::unexpected(std::string{"running process boot identity exceeds its bound"});
    }
    append_u64(material, running.process_identity.start_time_ticks);
    append_u64(material, running.process_identity.cgroup_device);
    append_u64(material, running.process_identity.cgroup_inode);
    if (!append_string(material, running.process_identity.cgroup_path_digest)) {
        return std::unexpected(std::string{"running process cgroup identity exceeds its bound"});
    }
    if (auto appended = append_filesystem_identity(material, running.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_stopping_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-stopping-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"stopping commitment hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"stopping commitment field exceeds its bound"});
        }
    }
    material.push_back(running.process_identity.schema_version);
    append_u32(material, running.process_identity.pid);
    if (!append_string(material, running.process_identity.boot_id)) {
        return std::unexpected(std::string{"stopping process boot identity exceeds its bound"});
    }
    append_u64(material, running.process_identity.start_time_ticks);
    append_u64(material, running.process_identity.cgroup_device);
    append_u64(material, running.process_identity.cgroup_inode);
    if (!append_string(material, running.process_identity.cgroup_path_digest)) {
        return std::unexpected(std::string{"stopping process cgroup identity exceeds its bound"});
    }
    if (auto appended = append_filesystem_identity(material, running.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_managed_execution_binding(const managed_session_execution_binding& binding)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.managed-session-execution-binding";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"managed execution binding hash domain is invalid"});
    }
    material.push_back(binding.schema_version);
    for (const auto value : {
             std::string_view{binding.session_id},
             std::string_view{binding.controller_plan_digest},
             std::string_view{binding.plan_content_digest},
             std::string_view{binding.authorization_id},
             std::string_view{binding.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(
                std::string{"managed execution binding field exceeds its bound"}
            );
        }
    }
    if (auto appended = append_managed_runtime_identity(material, binding.runtime_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_managed_running_commitment(
    const managed_session_running_commitment& running, std::string_view domain
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"managed lifecycle hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"managed lifecycle field exceeds its bound"});
        }
    }
    if (auto appended = append_managed_runtime_identity(material, running.runtime_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto termination_cause_name(container::resource_termination_cause cause) -> std::string_view {
    switch (cause) {
    case container::resource_termination_cause::exited:
        return "exited";
    case container::resource_termination_cause::signaled:
        return "signaled";
    case container::resource_termination_cause::cpu_time_limit:
        return "cpu_time_limit";
    case container::resource_termination_cause::memory_limit:
        return "memory_limit";
    case container::resource_termination_cause::pid_limit:
        return "pid_limit";
    case container::resource_termination_cause::wall_time_limit:
        return "wall_time_limit";
    case container::resource_termination_cause::disk_limit:
        return "disk_limit";
    case container::resource_termination_cause::terminal_output_limit:
        return "terminal_output_limit";
    case container::resource_termination_cause::supervisor_error:
        return "supervisor_error";
    }
    return {};
}

auto termination_cause_from_wire(std::string_view value)
    -> std::optional<container::resource_termination_cause> {
    using cause = container::resource_termination_cause;
    if (value == "exited") {
        return cause::exited;
    }
    if (value == "signaled") {
        return cause::signaled;
    }
    if (value == "cpu_time_limit") {
        return cause::cpu_time_limit;
    }
    if (value == "memory_limit") {
        return cause::memory_limit;
    }
    if (value == "pid_limit") {
        return cause::pid_limit;
    }
    if (value == "wall_time_limit") {
        return cause::wall_time_limit;
    }
    if (value == "disk_limit") {
        return cause::disk_limit;
    }
    if (value == "terminal_output_limit") {
        return cause::terminal_output_limit;
    }
    if (value == "supervisor_error") {
        return cause::supervisor_error;
    }
    return std::nullopt;
}

struct terminal_reference {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string_view key_id;
    std::string_view session_id;
    std::string_view controller_plan_digest;
    std::string_view profile_digest;
    std::string_view receipt_digest;
    std::string_view previous_hmac;
    std::string_view this_hmac;
    container::resource_termination_cause termination_cause =
        container::resource_termination_cause::supervisor_error;
    std::uint64_t started_at_ms = 0;
    std::uint64_t finished_at_ms = 0;
    std::optional<int> exit_code;
};

auto hash_terminal_reference(const terminal_reference& terminal)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(768U);
    constexpr std::string_view domain = "glove.session-terminal-envelope";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"terminal envelope hash domain is invalid"});
    }
    material.push_back(terminal.schema_version);
    append_u64(material, terminal.sequence);
    for (const auto value : {
             terminal.key_id,
             terminal.session_id,
             terminal.controller_plan_digest,
             terminal.profile_digest,
             terminal.receipt_digest,
             terminal.previous_hmac,
             terminal.this_hmac,
             termination_cause_name(terminal.termination_cause),
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"terminal envelope hash field exceeds its bound"});
        }
    }
    append_u64(material, terminal.started_at_ms);
    append_u64(material, terminal.finished_at_ms);
    material.push_back(terminal.exit_code.has_value() ? 1U : 0U);
    if (terminal.exit_code) {
        append_u32(material, static_cast<std::uint32_t>(*terminal.exit_code));
    }
    return container::sha256_hex(material);
}

auto hash_terminal_envelope(const container::authenticated_resource_enforcement_receipt& terminal)
    -> std::expected<std::string, std::string> {
    return hash_terminal_reference(
        terminal_reference{
            .schema_version = terminal.schema_version,
            .sequence = terminal.sequence,
            .key_id = terminal.key_id,
            .session_id = terminal.session_id,
            .controller_plan_digest = terminal.controller_plan_digest,
            .profile_digest = terminal.receipt.profile_digest,
            .receipt_digest = terminal.receipt_digest,
            .previous_hmac = terminal.previous_hmac,
            .this_hmac = terminal.this_hmac,
            .termination_cause = terminal.receipt.termination_cause,
            .started_at_ms = terminal.receipt.started_at_ms,
            .finished_at_ms = terminal.receipt.finished_at_ms,
            .exit_code = terminal.receipt.exit_code,
        }
    );
}

auto failure_code_name(session_failure_code code) -> std::string_view {
    switch (code) {
    case session_failure_code::authorization_expired:
        return "authorization_expired";
    case session_failure_code::launch_failed:
        return "launch_failed";
    case session_failure_code::supervisor_error:
        return "supervisor_error";
    case session_failure_code::recovered_without_process:
        return "recovered_without_process";
    case session_failure_code::recovered_terminated:
        return "recovered_terminated";
    }
    return "supervisor_error";
}

auto failure_code_from_wire(std::string_view value) -> std::optional<session_failure_code> {
    if (value == "authorization_expired") {
        return session_failure_code::authorization_expired;
    }
    if (value == "launch_failed") {
        return session_failure_code::launch_failed;
    }
    if (value == "supervisor_error") {
        return session_failure_code::supervisor_error;
    }
    if (value == "recovered_without_process") {
        return session_failure_code::recovered_without_process;
    }
    if (value == "recovered_terminated") {
        return session_failure_code::recovered_terminated;
    }
    return std::nullopt;
}

auto hash_failure_commitment(const session_failure_commitment& failure)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-failure-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"failure commitment hash domain is invalid"});
    }
    material.push_back(failure.schema_version);
    for (const auto value : {
             std::string_view{failure.session_id},
             std::string_view{failure.controller_plan_digest},
             std::string_view{failure.plan_content_digest},
             std::string_view{failure.authorization_id},
             std::string_view{failure.profile_digest},
             failure_code_name(failure.code),
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"failure commitment field exceeds its bound"});
        }
    }
    return container::sha256_hex(material);
}

auto state_from_wire(std::string_view state) -> std::optional<session_state> {
    if (state == "created") {
        return session_state::created;
    }
    if (state == "preparing") {
        return session_state::preparing;
    }
    if (state == "starting") {
        return session_state::starting;
    }
    if (state == "running") {
        return session_state::running;
    }
    if (state == "stopping") {
        return session_state::stopping;
    }
    if (state == "exited") {
        return session_state::exited;
    }
    if (state == "failed") {
        return session_state::failed;
    }
    return std::nullopt;
}

auto public_record(const wire::persisted_session& record) -> session_record {
    const auto state = state_from_wire(record.state);
    return {
        .schema_version = record.schema_version,
        .session_id = record.session_id,
        .controller_plan_digest = record.controller_plan_digest,
        .plan_content_digest = record.plan_content_digest,
        .state = state.value_or(session_state::created),
        .policy_revision = record.policy_revision,
        .expires_at_ms = record.expires_at_ms,
        .created_at_ms = record.created_at_ms,
    };
}

auto valid_record_shape(const wire::persisted_session& record, std::uint64_t sequence) -> bool {
    const bool common =
        record.schema_version == 1 && record.sequence == sequence &&
        valid_identifier(record.operation) && valid_identifier(record.idempotency_key) &&
        valid_identifier(record.session_id) && valid_digest(record.controller_plan_digest) &&
        valid_digest(record.request_digest) && valid_digest(record.plan_content_digest) &&
        state_from_wire(record.state).has_value() && record.policy_revision != 0 &&
        record.expires_at_ms != 0 && record.created_at_ms != 0 &&
        !record.canonical_plan_json.empty() &&
        record.canonical_plan_json.size() <= max_record_payload_bytes &&
        valid_digest(record.previous_hash) && valid_digest(record.this_hash);
    if (!common) {
        return false;
    }
    const bool no_terminal_receipt =
        record.receipt_started_at_ms == 0 && record.receipt_key_id.empty() &&
        record.receipt_sequence == 0 && record.receipt_digest.empty() &&
        record.receipt_previous_hmac.empty() && record.receipt_hmac.empty() &&
        record.termination_cause.empty() && !record.exit_code;
    const bool no_stop_intent = record.stopping_at_ms == 0;
    if (record.operation == "create" && record.state == "created") {
        return record.authorization_id.empty() && record.authorized_at_ms == 0 &&
               record.authorization_expires_at_ms == 0 && record.launch_profile_digest.empty() &&
               record.starting_at_ms == 0 && record.running_at_ms == 0 && no_stop_intent &&
               no_resource_identity(record) && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const bool authorization = valid_identifier(record.authorization_id) &&
                               record.authorized_at_ms != 0 &&
                               record.authorization_expires_at_ms > record.authorized_at_ms &&
                               record.authorization_expires_at_ms - record.authorized_at_ms <=
                                   max_start_authorization_ttl_ms &&
                               record.authorization_expires_at_ms <= record.expires_at_ms;
    if (record.operation == "reserve_start" && record.state == "preparing") {
        return authorization && record.launch_profile_digest.empty() &&
               record.starting_at_ms == 0 && record.running_at_ms == 0 && no_stop_intent &&
               no_resource_identity(record) && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const bool started = authorization && valid_digest(record.launch_profile_digest) &&
                         record.starting_at_ms >= record.authorized_at_ms &&
                         record.starting_at_ms < record.authorization_expires_at_ms;
    const bool prepared_resources =
        record.cgroup_identity && valid_cgroup_identity(*record.cgroup_identity) &&
        record.filesystem_identity && valid_filesystem_identity(*record.filesystem_identity) &&
        !record.managed_runtime_identity;
    const bool managed_resources =
        no_process_identity(record) && !record.cgroup_identity && !record.filesystem_identity &&
        record.managed_runtime_identity &&
        valid_managed_runtime_identity(*record.managed_runtime_identity);
    if (record.operation == "mark_starting" && record.state == "starting") {
        return started && record.running_at_ms == 0 && no_stop_intent &&
               no_process_identity(record) && prepared_resources && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    if (record.operation == "mark_managed_starting" && record.state == "starting") {
        return started && record.running_at_ms == 0 && no_stop_intent && managed_resources &&
               record.failure_code.empty() && record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const auto process_identity = process_identity_from_wire(record);
    const bool running = record.running_at_ms >= record.starting_at_ms &&
                         record.running_at_ms < record.authorization_expires_at_ms &&
                         process_identity.has_value() && prepared_resources &&
                         process_identity->cgroup_device == record.cgroup_identity->device &&
                         process_identity->cgroup_inode == record.cgroup_identity->inode;
    if (record.operation == "mark_running" && record.state == "running") {
        return started && running && no_stop_intent && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const bool managed_running =
        record.running_at_ms >= record.starting_at_ms &&
        record.running_at_ms < record.authorization_expires_at_ms && managed_resources;
    if (record.operation == "mark_managed_running" && record.state == "running") {
        return started && managed_running && no_stop_intent && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const bool stopping = running && record.stopping_at_ms >= record.running_at_ms;
    if (record.operation == "mark_stopping" && record.state == "stopping") {
        return started && stopping && record.failure_code.empty() && record.finished_at_ms == 0 &&
               no_terminal_receipt;
    }
    const bool managed_stopping =
        managed_running && record.stopping_at_ms >= record.running_at_ms;
    if (record.operation == "mark_managed_stopping" && record.state == "stopping") {
        return started && managed_stopping && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const auto termination = termination_cause_from_wire(record.termination_cause);
    const bool valid_exit_code =
        termination &&
        ((*termination == container::resource_termination_cause::exited && record.exit_code &&
          *record.exit_code >= 0 && *record.exit_code <= 255) ||
         (*termination != container::resource_termination_cause::exited && !record.exit_code));
    if (record.operation == "mark_exited" && record.state == "exited") {
        return started && running &&
               (no_stop_intent || record.stopping_at_ms >= record.running_at_ms) &&
               record.failure_code.empty() && record.receipt_started_at_ms != 0 &&
               record.receipt_started_at_ms <= record.running_at_ms &&
               record.finished_at_ms >=
                   (no_stop_intent ? record.running_at_ms : record.stopping_at_ms) &&
               valid_digest(record.receipt_key_id) && record.receipt_sequence != 0 &&
               valid_digest(record.receipt_digest) && valid_digest(record.receipt_previous_hmac) &&
               valid_digest(record.receipt_hmac) && valid_exit_code;
    }
    if (record.operation == "mark_managed_exited" && record.state == "exited") {
        return started && managed_running &&
               (no_stop_intent || record.stopping_at_ms >= record.running_at_ms) &&
               record.failure_code.empty() && record.receipt_started_at_ms != 0 &&
               record.receipt_started_at_ms <= record.running_at_ms &&
               record.finished_at_ms >=
                   (no_stop_intent ? record.running_at_ms : record.stopping_at_ms) &&
               valid_digest(record.receipt_key_id) && record.receipt_sequence != 0 &&
               valid_digest(record.receipt_digest) && valid_digest(record.receipt_previous_hmac) &&
               valid_digest(record.receipt_hmac) && valid_exit_code;
    }
    const auto failure = failure_code_from_wire(record.failure_code);
    const bool prelaunch_failure =
        record.running_at_ms == 0 && no_process_identity(record) && prepared_resources;
    const bool valid_failure_origin =
        (prelaunch_failure && no_stop_intent) ||
        (running && (no_stop_intent || stopping) && failure &&
         (*failure == session_failure_code::supervisor_error ||
          *failure == session_failure_code::recovered_without_process ||
          *failure == session_failure_code::recovered_terminated));
    const bool valid_managed_failure_origin =
        managed_resources &&
        ((record.running_at_ms == 0 && no_stop_intent) ||
         (record.running_at_ms != 0 &&
          (no_stop_intent || record.stopping_at_ms >= record.running_at_ms) && failure &&
          (*failure == session_failure_code::supervisor_error ||
           *failure == session_failure_code::recovered_without_process ||
           *failure == session_failure_code::recovered_terminated)));
    if (record.operation == "mark_managed_failed" && record.state == "failed") {
        return started && failure && valid_managed_failure_origin && no_terminal_receipt &&
               record.finished_at_ms >=
                   (record.stopping_at_ms != 0
                        ? record.stopping_at_ms
                        : (record.running_at_ms != 0 ? record.running_at_ms
                                                     : record.starting_at_ms));
    }
    return record.operation == "mark_failed" && record.state == "failed" && started && failure &&
           valid_failure_origin && no_terminal_receipt &&
           record.finished_at_ms >=
               (stopping ? record.stopping_at_ms
                         : (running ? record.running_at_ms : record.starting_at_ms));
}

auto encode_record(const wire::persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string> {
    auto payload = glz::write_json(record);
    if (!payload) {
        return std::unexpected(std::string{"encode session registry record failed"});
    }
    if (payload->empty() || payload->size() > max_record_payload_bytes) {
        return std::unexpected(std::string{"session registry record exceeds its bound"});
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(payload->size() + 8U);
    append_u32(bytes, static_cast<std::uint32_t>(payload->size()));
    bytes.insert(bytes.end(), payload->begin(), payload->end());
    append_u32(bytes, static_cast<std::uint32_t>(payload->size()));
    return bytes;
}

auto decode_record(std::string_view payload)
    -> std::expected<wire::persisted_session, std::string> {
    wire::persisted_session record;
    if (const auto error = glz::read<strict_read_options>(record, payload); error) {
        return std::unexpected(std::string{"decode session registry record failed"});
    }
    return record;
}

} // namespace

struct session_registry::implementation {
    opened_registry opened;
    std::shared_ptr<const supervisor::session_plan_validator> validator;
    std::shared_ptr<const supervisor::library_bundle_store> library_bundles;
    std::uint64_t max_bytes = 0;
    std::uint64_t durable_bytes = registry_magic.size();
    registry_identity identity;
    bool poisoned = false;
    std::vector<wire::persisted_session> records;
    std::unordered_map<std::string, std::size_t> sessions;
    std::unordered_map<std::string, std::size_t> requests;
    mutable std::mutex mutex;
};

namespace {

auto initialize_empty(session_registry::implementation& state) -> std::expected<void, std::string> {
    auto written = write_at(state.opened.file.get(), registry_magic, 0);
    if (!written) {
        return written;
    }
    if (auto synced = sync_descriptor(state.opened.file.get(), "sync session registry"); !synced) {
        return synced;
    }
    return sync_descriptor(state.opened.parent.get(), "sync session registry directory");
}

struct decoded_persisted_record {
    wire::persisted_session record;
    std::uint64_t next_offset = 0;
};

auto read_persisted_record(int descriptor, std::uint64_t file_size, std::uint64_t offset)
    -> std::expected<decoded_persisted_record, std::string> {
    if (file_size - offset < 8U) {
        return std::unexpected(std::string{"session registry record boundary is invalid"});
    }
    std::array<unsigned char, 4> prefix{};
    if (auto read = read_at(descriptor, std::span{prefix}, offset); !read) {
        return std::unexpected(read.error());
    }
    const auto payload_size = static_cast<std::uint64_t>(decode_u32(prefix));
    if (payload_size == 0 || payload_size > max_record_payload_bytes ||
        payload_size > file_size - offset - 8U) {
        return std::unexpected(std::string{"session registry record length is invalid"});
    }
    std::string payload(static_cast<std::size_t>(payload_size), '\0');
    if (auto read =
            read_at(descriptor, std::span<char>{payload.data(), payload.size()}, offset + 4U);
        !read) {
        return std::unexpected(read.error());
    }
    std::array<unsigned char, 4> suffix{};
    if (auto read = read_at(descriptor, std::span{suffix}, offset + 4U + payload_size); !read) {
        return std::unexpected(read.error());
    }
    if (decode_u32(suffix) != payload_size) {
        return std::unexpected(std::string{"session registry record footer mismatch"});
    }
    auto record = decode_record(payload);
    if (!record) {
        return std::unexpected(record.error());
    }
    return decoded_persisted_record{
        .record = std::move(*record),
        .next_offset = offset + payload_size + 8U,
    };
}

auto accept_recovered_record(
    session_registry::implementation& state,
    wire::persisted_session record,
    std::string_view previous_hash
) -> std::expected<void, std::string> {
    const auto sequence = static_cast<std::uint64_t>(state.records.size()) + 1U;
    if (!valid_record_shape(record, sequence) || record.previous_hash != previous_hash ||
        state.requests.contains(record.idempotency_key)) {
        return std::unexpected(std::string{"session registry record is invalid"});
    }
    const auto existing = state.sessions.find(record.session_id);
    if (record.state == "created") {
        if (existing != state.sessions.end()) {
            return std::unexpected(std::string{"session registry create transition is invalid"});
        }
    } else if (record.state == "preparing") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry start transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "created" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.canonical_plan_json != record.canonical_plan_json ||
            record.authorized_at_ms < record.created_at_ms) {
            return std::unexpected(std::string{"session registry start transition is invalid"});
        }
        const session_start_authorization authorization{
            .schema_version = record.schema_version,
            .authorization_id = record.authorization_id,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .plan_content_digest = record.plan_content_digest,
            .approved_at_ms = record.authorized_at_ms,
            .expires_at_ms = record.authorization_expires_at_ms,
        };
        auto authorization_digest = hash_start_authorization(authorization);
        if (!authorization_digest || *authorization_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry start authorization commitment mismatch"}
            );
        }
    } else if (record.state == "starting") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry starting transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "preparing" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry starting transition is invalid"});
        }
        std::expected<std::string, std::string> binding_digest =
            std::unexpected(std::string{"unknown starting operation"});
        if (record.operation == "mark_managed_starting" && record.managed_runtime_identity) {
            binding_digest = hash_managed_execution_binding(managed_session_execution_binding{
                .schema_version = record.schema_version,
                .session_id = record.session_id,
                .controller_plan_digest = record.controller_plan_digest,
                .plan_content_digest = record.plan_content_digest,
                .authorization_id = record.authorization_id,
                .profile_digest = record.launch_profile_digest,
                .runtime_identity = *record.managed_runtime_identity,
            });
        } else if (record.operation == "mark_starting" && record.cgroup_identity &&
                   record.filesystem_identity) {
            binding_digest = hash_execution_binding(session_execution_binding{
                .schema_version = record.schema_version,
                .session_id = record.session_id,
                .controller_plan_digest = record.controller_plan_digest,
                .plan_content_digest = record.plan_content_digest,
                .authorization_id = record.authorization_id,
                .profile_digest = record.launch_profile_digest,
                .cgroup_identity = *record.cgroup_identity,
                .filesystem_identity = *record.filesystem_identity,
            });
        }
        if (!binding_digest || *binding_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry execution binding commitment mismatch"}
            );
        }
    } else if (record.state == "running") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry running transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "starting" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry running transition is invalid"});
        }
        std::expected<std::string, std::string> running_digest =
            std::unexpected(std::string{"unknown running operation"});
        if (record.operation == "mark_managed_running" && record.managed_runtime_identity) {
            running_digest = hash_managed_running_commitment(
                managed_session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .runtime_identity = *record.managed_runtime_identity,
                },
                "glove.managed-session-running-commitment"
            );
        } else if (record.operation == "mark_running" && record.filesystem_identity) {
            auto process_identity = process_identity_from_wire(record);
            if (process_identity) {
                running_digest = hash_running_commitment(session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .process_identity = std::move(*process_identity),
                    .filesystem_identity = *record.filesystem_identity,
                });
            }
        }
        if (!running_digest || *running_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry running commitment mismatch"});
        }
    } else if (record.state == "stopping") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry stopping transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if (prior.state != "running" || prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms || !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry stopping transition is invalid"});
        }
        std::expected<std::string, std::string> stopping_digest =
            std::unexpected(std::string{"unknown stopping operation"});
        if (record.operation == "mark_managed_stopping" && record.managed_runtime_identity) {
            stopping_digest = hash_managed_running_commitment(
                managed_session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .runtime_identity = *record.managed_runtime_identity,
                },
                "glove.managed-session-stopping-commitment"
            );
        } else if (record.operation == "mark_stopping" && record.filesystem_identity) {
            auto process_identity = process_identity_from_wire(record);
            if (process_identity) {
                stopping_digest = hash_stopping_commitment(session_running_commitment{
                    .schema_version = record.schema_version,
                    .session_id = record.session_id,
                    .controller_plan_digest = record.controller_plan_digest,
                    .plan_content_digest = record.plan_content_digest,
                    .authorization_id = record.authorization_id,
                    .profile_digest = record.launch_profile_digest,
                    .process_identity = std::move(*process_identity),
                    .filesystem_identity = *record.filesystem_identity,
                });
            }
        }
        if (!stopping_digest || *stopping_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry stopping commitment mismatch"});
        }
    } else if (record.state == "exited") {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry exit transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if ((prior.state != "running" && prior.state != "stopping") ||
            prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms ||
            prior.stopping_at_ms != record.stopping_at_ms ||
            !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry exit transition is invalid"});
        }
        const auto termination = termination_cause_from_wire(record.termination_cause);
        if (!termination) {
            return std::unexpected(std::string{"session registry terminal cause is invalid"});
        }
        const terminal_reference terminal{
            .schema_version = 1,
            .sequence = record.receipt_sequence,
            .key_id = record.receipt_key_id,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .profile_digest = record.launch_profile_digest,
            .receipt_digest = record.receipt_digest,
            .previous_hmac = record.receipt_previous_hmac,
            .this_hmac = record.receipt_hmac,
            .termination_cause = *termination,
            .started_at_ms = record.receipt_started_at_ms,
            .finished_at_ms = record.finished_at_ms,
            .exit_code = record.exit_code,
        };
        auto terminal_digest = hash_terminal_reference(terminal);
        if (!terminal_digest || *terminal_digest != record.request_digest) {
            return std::unexpected(
                std::string{"session registry terminal envelope commitment mismatch"}
            );
        }
    } else {
        if (existing == state.sessions.end()) {
            return std::unexpected(std::string{"session registry failure transition is orphaned"});
        }
        const auto& prior = state.records[existing->second];
        if ((prior.state != "starting" && prior.state != "running" && prior.state != "stopping") ||
            prior.session_id != record.session_id ||
            prior.controller_plan_digest != record.controller_plan_digest ||
            prior.plan_content_digest != record.plan_content_digest ||
            prior.policy_revision != record.policy_revision ||
            prior.expires_at_ms != record.expires_at_ms ||
            prior.created_at_ms != record.created_at_ms ||
            prior.authorization_id != record.authorization_id ||
            prior.authorized_at_ms != record.authorized_at_ms ||
            prior.authorization_expires_at_ms != record.authorization_expires_at_ms ||
            prior.launch_profile_digest != record.launch_profile_digest ||
            prior.starting_at_ms != record.starting_at_ms ||
            prior.running_at_ms != record.running_at_ms ||
            prior.stopping_at_ms != record.stopping_at_ms ||
            !same_process_identity(prior, record) ||
            prior.cgroup_identity != record.cgroup_identity ||
            prior.filesystem_identity != record.filesystem_identity ||
            prior.managed_runtime_identity != record.managed_runtime_identity ||
            prior.canonical_plan_json != record.canonical_plan_json) {
            return std::unexpected(std::string{"session registry failure transition is invalid"});
        }
        const auto code = failure_code_from_wire(record.failure_code);
        if (!code) {
            return std::unexpected(std::string{"session registry failure code is invalid"});
        }
        const session_failure_commitment failure{
            .schema_version = record.schema_version,
            .session_id = record.session_id,
            .controller_plan_digest = record.controller_plan_digest,
            .plan_content_digest = record.plan_content_digest,
            .authorization_id = record.authorization_id,
            .profile_digest = record.launch_profile_digest,
            .code = *code,
        };
        auto failure_digest = hash_failure_commitment(failure);
        if (!failure_digest || *failure_digest != record.request_digest) {
            return std::unexpected(std::string{"session registry failure commitment mismatch"});
        }
    }
    auto plan_digest = hash_plan(record.canonical_plan_json);
    auto record_hash = hash_record(record);
    if (!plan_digest || !record_hash || *plan_digest != record.plan_content_digest ||
        *record_hash != record.this_hash) {
        return std::unexpected(std::string{"session registry content commitment mismatch"});
    }
    const auto index = state.records.size();
    state.sessions.insert_or_assign(record.session_id, index);
    state.requests.emplace(record.idempotency_key, index);
    state.records.push_back(std::move(record));
    return {};
}

auto recover(session_registry::implementation& state) -> std::expected<void, std::string> {
    auto size = inspect_file(state.opened.file.get());
    if (!size || *size < registry_magic.size() || *size > state.max_bytes) {
        return std::unexpected(std::string{"session registry size is invalid"});
    }
    std::array<unsigned char, registry_magic.size()> header{};
    if (auto read = read_at(state.opened.file.get(), std::span{header}, 0); !read) {
        return read;
    }
    if (header != registry_magic) {
        return std::unexpected(std::string{"session registry header mismatch"});
    }

    std::uint64_t offset = registry_magic.size();
    std::string previous_hash(digest_hex_bytes, '0');
    while (offset < *size) {
        if (state.records.size() >= max_records) {
            return std::unexpected(std::string{"session registry record capacity is invalid"});
        }
        auto decoded = read_persisted_record(state.opened.file.get(), *size, offset);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        const auto next_hash = decoded->record.this_hash;
        if (auto accepted =
                accept_recovered_record(state, std::move(decoded->record), previous_hash);
            !accepted) {
            return accepted;
        }
        previous_hash = next_hash;
        offset = decoded->next_offset;
    }
    state.durable_bytes = offset;
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != state.durable_bytes) {
        return std::unexpected(std::string{"session registry identity changed during recovery"});
    }
    state.identity = *identity;
    return {};
}

auto verify_identity(session_registry::implementation& state) -> bool {
    auto identity = capture_identity(state.opened.file.get());

    struct stat path_metadata{};

    const auto path_result = ::fstatat(
        state.opened.parent.get(), state.opened.name.c_str(), &path_metadata, AT_SYMLINK_NOFOLLOW
    );
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto path_permissions =
        static_cast<unsigned int>(path_metadata.st_mode) & permission_mask;
    const bool path_matches =
        path_result == 0 && S_ISREG(path_metadata.st_mode) && path_metadata.st_uid == ::geteuid() &&
        path_permissions == owner_permissions && path_metadata.st_nlink == 1 && identity &&
        static_cast<std::uint64_t>(path_metadata.st_dev) == identity->device &&
        static_cast<std::uint64_t>(path_metadata.st_ino) == identity->inode;
    if (!path_matches || *identity != state.identity || identity->size != state.durable_bytes) {
        state.poisoned = true;
        return false;
    }
    return true;
}

auto rollback_append(session_registry::implementation& state, std::uint64_t original_size) -> bool {
    while (::ftruncate(state.opened.file.get(), static_cast<off_t>(original_size)) != 0) {
        if (errno == EINTR) {
            continue;
        }
        state.poisoned = true;
        return false;
    }
    if (!sync_descriptor(state.opened.file.get(), "sync session registry rollback")) {
        state.poisoned = true;
        return false;
    }
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != original_size) {
        state.poisoned = true;
        return false;
    }
    state.identity = *identity;
    return true;
}

struct replay_lookup {
    bool found = false;
    session_record record;
};

struct start_replay_lookup {
    bool found = false;
    session_start_reservation reservation;
};

struct starting_replay_lookup {
    bool found = false;
    session_starting_record record;
};

struct running_replay_lookup {
    bool found = false;
    session_running_record record;
};

struct stopping_replay_lookup {
    bool found = false;
    session_stopping_record record;
};

struct exited_replay_lookup {
    bool found = false;
    session_exited_record record;
};

struct failure_replay_lookup {
    bool found = false;
    session_failed_record record;
};

auto start_reservation_from_record(
    session_registry::implementation& state, const wire::persisted_session& record
) -> session_registry_result<session_start_reservation> {
    // This reconstructs the exact historical idempotent response, not current
    // launch authority. Callers must still enforce authorization_expires_at_ms
    // before the later process-start transition.
    auto launch = state.validator->resolve_runtime_launch_json(
        record.canonical_plan_json, record.authorized_at_ms
    );
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves to a runtime launch: " + launch.error()
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }
    return session_start_reservation{
        .session = public_record(record),
        .launch = std::move(*launch),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
    };
}

auto starting_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_starting_record> {
    if (record.state != "starting" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || !record.cgroup_identity ||
        !valid_cgroup_identity(*record.cgroup_identity) || !record.filesystem_identity ||
        !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable starting commitment"
        ));
    }
    return session_starting_record{
        .session = public_record(record),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .cgroup_identity = *record.cgroup_identity,
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto running_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_running_record> {
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "running" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        !process_identity || !record.cgroup_identity ||
        !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable running commitment"
        ));
    }
    return session_running_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto stopping_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_stopping_record> {
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "stopping" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        record.stopping_at_ms < record.running_at_ms || !process_identity ||
        !record.cgroup_identity || !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable stopping commitment"
        ));
    }
    return session_stopping_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
    };
}

auto exited_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_exited_record> {
    const auto termination = termination_cause_from_wire(record.termination_cause);
    auto process_identity = process_identity_from_wire(record);
    if (record.state != "exited" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 || record.running_at_ms < record.starting_at_ms ||
        !process_identity ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0 ? record.running_at_ms : record.stopping_at_ms) ||
        !record.cgroup_identity || !valid_cgroup_identity(*record.cgroup_identity) ||
        process_identity->cgroup_device != record.cgroup_identity->device ||
        process_identity->cgroup_inode != record.cgroup_identity->inode ||
        !record.filesystem_identity || !valid_filesystem_identity(*record.filesystem_identity) ||
        !valid_digest(record.receipt_key_id) || record.receipt_sequence == 0 ||
        !valid_digest(record.receipt_digest) || !valid_digest(record.receipt_hmac) ||
        !termination) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable terminal receipt"
        ));
    }
    return session_exited_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = *record.filesystem_identity,
        .finished_at_ms = record.finished_at_ms,
        .receipt_key_id = record.receipt_key_id,
        .receipt_sequence = record.receipt_sequence,
        .receipt_digest = record.receipt_digest,
        .receipt_hmac = record.receipt_hmac,
        .termination_cause = *termination,
        .exit_code = record.exit_code,
    };
}

auto failed_record_from_wire(const wire::persisted_session& record)
    -> session_registry_result<session_failed_record> {
    const auto code = failure_code_from_wire(record.failure_code);
    auto process_identity = process_identity_from_wire(record);
    const bool prepared_resources =
        record.cgroup_identity && valid_cgroup_identity(*record.cgroup_identity) &&
        record.filesystem_identity && valid_filesystem_identity(*record.filesystem_identity);
    const bool process_matches_cgroup =
        process_identity && prepared_resources &&
        process_identity->cgroup_device == record.cgroup_identity->device &&
        process_identity->cgroup_inode == record.cgroup_identity->inode;
    if (record.state != "failed" || !valid_digest(record.launch_profile_digest) ||
        record.starting_at_ms == 0 ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0
                 ? (record.running_at_ms == 0 ? record.starting_at_ms : record.running_at_ms)
                 : record.stopping_at_ms) ||
        !code ||
        (record.running_at_ms == 0 && (!no_process_identity(record) || !prepared_resources)) ||
        (record.running_at_ms != 0 && !process_matches_cgroup)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session has no durable failure commitment"
        ));
    }
    return session_failed_record{
        .session = public_record(record),
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .process_identity = std::move(process_identity),
        .cgroup_identity = record.cgroup_identity,
        .filesystem_identity = record.filesystem_identity,
        .failed_at_ms = record.finished_at_ms,
        .code = *code,
    };
}

auto managed_lifecycle_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_lifecycle_record> {
    if ((record.state != "starting" && record.state != "running" &&
         record.state != "stopping" && record.state != "exited" && record.state != "failed") ||
        !valid_digest(record.launch_profile_digest) || record.starting_at_ms == 0 ||
        (record.running_at_ms != 0 && record.running_at_ms < record.starting_at_ms) ||
        (record.stopping_at_ms != 0 && record.stopping_at_ms < record.running_at_ms) ||
        !no_process_identity(record) || record.cgroup_identity || record.filesystem_identity ||
        !record.managed_runtime_identity ||
        !valid_managed_runtime_identity(*record.managed_runtime_identity)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed runtime commitment"
        ));
    }
    return managed_session_lifecycle_record{
        .session = public_record(record),
        .authorization_id = record.authorization_id,
        .authorization_expires_at_ms = record.authorization_expires_at_ms,
        .profile_digest = record.launch_profile_digest,
        .starting_at_ms = record.starting_at_ms,
        .running_at_ms = record.running_at_ms,
        .stopping_at_ms = record.stopping_at_ms,
        .runtime_identity = *record.managed_runtime_identity,
    };
}

auto managed_exited_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_exited_record> {
    auto lifecycle = managed_lifecycle_from_wire(record);
    const auto termination = termination_cause_from_wire(record.termination_cause);
    if (!lifecycle || record.state != "exited" || record.running_at_ms == 0 ||
        record.finished_at_ms <
            (record.stopping_at_ms == 0 ? record.running_at_ms : record.stopping_at_ms) ||
        !valid_digest(record.receipt_key_id) || record.receipt_sequence == 0 ||
        !valid_digest(record.receipt_digest) || !valid_digest(record.receipt_hmac) ||
        !termination) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed terminal receipt"
        ));
    }
    return managed_session_exited_record{
        .lifecycle = std::move(*lifecycle),
        .finished_at_ms = record.finished_at_ms,
        .receipt_key_id = record.receipt_key_id,
        .receipt_sequence = record.receipt_sequence,
        .receipt_digest = record.receipt_digest,
        .receipt_hmac = record.receipt_hmac,
        .termination_cause = *termination,
        .exit_code = record.exit_code,
    };
}

auto managed_failed_from_wire(const wire::persisted_session& record)
    -> session_registry_result<managed_session_failed_record> {
    auto lifecycle = managed_lifecycle_from_wire(record);
    const auto code = failure_code_from_wire(record.failure_code);
    if (!lifecycle || record.state != "failed" || !code ||
        record.finished_at_ms <
            (record.stopping_at_ms != 0
                 ? record.stopping_at_ms
                 : (record.running_at_ms != 0 ? record.running_at_ms : record.starting_at_ms))) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session has no durable managed failure commitment"
        ));
    }
    return managed_session_failed_record{
        .lifecycle = std::move(*lifecycle),
        .failed_at_ms = record.finished_at_ms,
        .code = *code,
    };
}

auto find_create_replay_locked(
    session_registry::implementation& state,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "create" || record.session_id != session_id ||
        record.controller_plan_digest != controller_plan_digest ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session create idempotency payload changed"
        ));
    }
    return replay_lookup{.found = true, .record = public_record(record)};
}

auto find_start_replay_locked(
    session_registry::implementation& state,
    const session_start_authorization& authorization,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<start_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return start_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "reserve_start" || record.session_id != authorization.session_id ||
        record.controller_plan_digest != authorization.controller_plan_digest ||
        record.plan_content_digest != authorization.plan_content_digest ||
        record.authorization_id != authorization.authorization_id ||
        record.authorized_at_ms != authorization.approved_at_ms ||
        record.authorization_expires_at_ms != authorization.expires_at_ms ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session start idempotency payload changed"
        ));
    }
    auto reservation = start_reservation_from_record(state, record);
    if (!reservation) {
        return std::unexpected(reservation.error());
    }
    return start_replay_lookup{.found = true, .reservation = std::move(*reservation)};
}

auto find_starting_replay_locked(
    session_registry::implementation& state,
    const session_execution_binding& binding,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<starting_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return starting_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_starting" || record.session_id != binding.session_id ||
        record.controller_plan_digest != binding.controller_plan_digest ||
        record.plan_content_digest != binding.plan_content_digest ||
        record.authorization_id != binding.authorization_id ||
        record.launch_profile_digest != binding.profile_digest ||
        record.cgroup_identity != binding.cgroup_identity ||
        record.filesystem_identity != binding.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session starting idempotency payload changed"
        ));
    }
    auto starting = starting_record_from_wire(record);
    if (!starting) {
        return std::unexpected(starting.error());
    }
    return starting_replay_lookup{.found = true, .record = std::move(*starting)};
}

auto find_running_replay_locked(
    session_registry::implementation& state,
    const session_running_commitment& running_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<running_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return running_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_running" || record.session_id != running_commitment.session_id ||
        record.controller_plan_digest != running_commitment.controller_plan_digest ||
        record.plan_content_digest != running_commitment.plan_content_digest ||
        record.authorization_id != running_commitment.authorization_id ||
        record.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(record, running_commitment.process_identity) ||
        record.filesystem_identity != running_commitment.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session running idempotency payload changed"
        ));
    }
    auto running = running_record_from_wire(record);
    if (!running) {
        return std::unexpected(running.error());
    }
    return running_replay_lookup{.found = true, .record = std::move(*running)};
}

auto find_stopping_replay_locked(
    session_registry::implementation& state,
    const session_running_commitment& running_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<stopping_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return stopping_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_stopping" || record.session_id != running_commitment.session_id ||
        record.controller_plan_digest != running_commitment.controller_plan_digest ||
        record.plan_content_digest != running_commitment.plan_content_digest ||
        record.authorization_id != running_commitment.authorization_id ||
        record.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(record, running_commitment.process_identity) ||
        record.filesystem_identity != running_commitment.filesystem_identity ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session stopping idempotency payload changed"
        ));
    }
    auto stopping = stopping_record_from_wire(record);
    if (!stopping) {
        return std::unexpected(stopping.error());
    }
    return stopping_replay_lookup{.found = true, .record = std::move(*stopping)};
}

auto find_failure_replay_locked(
    session_registry::implementation& state,
    const session_failure_commitment& failure_commitment,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<failure_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return failure_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_failed" || record.session_id != failure_commitment.session_id ||
        record.controller_plan_digest != failure_commitment.controller_plan_digest ||
        record.plan_content_digest != failure_commitment.plan_content_digest ||
        record.authorization_id != failure_commitment.authorization_id ||
        record.launch_profile_digest != failure_commitment.profile_digest ||
        record.failure_code != failure_code_name(failure_commitment.code) ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session failure idempotency payload changed"
        ));
    }
    auto failed = failed_record_from_wire(record);
    if (!failed) {
        return std::unexpected(failed.error());
    }
    return failure_replay_lookup{.found = true, .record = std::move(*failed)};
}

auto find_exited_replay_locked(
    session_registry::implementation& state,
    const container::authenticated_resource_enforcement_receipt& terminal,
    std::string_view request_digest,
    std::string_view idempotency_key
) -> session_registry_result<exited_replay_lookup> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state.requests.find(std::string{idempotency_key});
    if (existing == state.requests.end()) {
        return exited_replay_lookup{};
    }
    const auto& record = state.records[existing->second];
    if (record.operation != "mark_exited" || record.session_id != terminal.session_id ||
        record.controller_plan_digest != terminal.controller_plan_digest ||
        record.launch_profile_digest != terminal.receipt.profile_digest ||
        record.request_digest != request_digest) {
        return std::unexpected(failure(
            session_registry_error_code::idempotency_conflict,
            "session terminal idempotency payload changed"
        ));
    }
    auto exited = exited_record_from_wire(record);
    if (!exited) {
        return std::unexpected(exited.error());
    }
    return exited_replay_lookup{.found = true, .record = std::move(*exited)};
}

auto append_record_locked(session_registry::implementation& state, wire::persisted_session record)
    -> session_registry_result<session_record> {
    if (state.poisoned || !verify_identity(state)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    auto this_hash = hash_record(record);
    if (!this_hash) {
        return std::unexpected(storage_failure(this_hash.error()));
    }
    record.this_hash = std::move(*this_hash);
    auto encoded = encode_record(record);
    if (!encoded) {
        return std::unexpected(failure(session_registry_error_code::capacity, encoded.error()));
    }
    if (encoded->size() > state.max_bytes - state.durable_bytes) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry byte limit exhausted")
        );
    }
    const auto original_size = state.durable_bytes;
    if (auto written = write_at(state.opened.file.get(), *encoded, original_size); !written) {
        (void)rollback_append(state, original_size);
        return std::unexpected(storage_failure(written.error()));
    }
    if (auto synced = sync_descriptor(state.opened.file.get(), "sync session registry append");
        !synced) {
        (void)rollback_append(state, original_size);
        return std::unexpected(storage_failure(synced.error()));
    }
    auto identity = capture_identity(state.opened.file.get());
    if (!identity || identity->size != original_size + encoded->size()) {
        state.poisoned = true;
        return std::unexpected(storage_failure("session registry identity update failed"));
    }
    const auto index = state.records.size();
    state.durable_bytes += encoded->size();
    state.identity = *identity;
    state.sessions.insert_or_assign(record.session_id, index);
    state.requests.emplace(record.idempotency_key, index);
    state.records.push_back(std::move(record));
    return public_record(state.records.back());
}

} // namespace

session_registry::session_registry(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

session_registry::~session_registry() = default;

auto session_registry::open_or_create(
    const std::filesystem::path& path,
    std::shared_ptr<const supervisor::session_plan_validator> validator,
    std::shared_ptr<const supervisor::library_bundle_store> library_bundles,
    std::uint64_t max_bytes
) -> session_registry_result<std::unique_ptr<session_registry>> {
    if (!validator || path.empty() || max_bytes < min_registry_bytes ||
        max_bytes > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session registry configuration"
        ));
    }
    auto opened = open_registry(path);
    if (!opened) {
        return std::unexpected(storage_failure(opened.error()));
    }
    auto state = std::make_unique<implementation>();
    state->opened = std::move(*opened);
    state->validator = std::move(validator);
    state->library_bundles = std::move(library_bundles);
    state->max_bytes = max_bytes;
    if (state->opened.created) {
        if (auto initialized = initialize_empty(*state); !initialized) {
            std::string error = initialized.error();
            if (::unlinkat(state->opened.parent.get(), state->opened.name.c_str(), 0) != 0) {
                error += "; " + system_error("remove incomplete session registry");
            } else if (
                auto synced =
                    sync_descriptor(state->opened.parent.get(), "sync incomplete registry cleanup");
                !synced
            ) {
                error += "; " + synced.error();
            }
            return std::unexpected(storage_failure(std::move(error)));
        }
    }
    if (auto recovered = recover(*state); !recovered) {
        return std::unexpected(storage_failure(recovered.error()));
    }
    return std::make_unique<session_registry>(construction_token{}, std::move(state));
}

auto session_registry::create(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view plan_json,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_record> {
    if (!valid_identifier(session_id) || !valid_digest(controller_plan_digest) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session create request")
        );
    }
    auto request_digest = hash_plan(plan_json);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    {
        const std::scoped_lock lock{state_->mutex};
        auto replay = find_create_replay_locked(
            *state_, session_id, controller_plan_digest, *request_digest, idempotency_key
        );
        if (!replay) {
            return std::unexpected(replay.error());
        }
        if (replay->found) {
            return replay->record;
        }
    }
    auto canonical = state_->validator->canonicalize_json(plan_json, now_ms);
    if (!canonical) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_plan, "session plan was rejected")
        );
    }
    auto content_digest = hash_plan(canonical->canonical_json);
    if (!content_digest) {
        return std::unexpected(storage_failure(content_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_create_replay_locked(
        *state_, session_id, controller_plan_digest, *request_digest, idempotency_key
    );
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return replay->record;
    }
    if (state_->sessions.contains(std::string{session_id})) {
        return std::unexpected(failure(
            session_registry_error_code::session_conflict, "session identity already exists"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "create",
        .idempotency_key = std::string{idempotency_key},
        .session_id = std::string{session_id},
        .controller_plan_digest = std::string{controller_plan_digest},
        .request_digest = std::move(*request_digest),
        .plan_content_digest = std::move(*content_digest),
        .state = "created",
        .policy_revision = canonical->validation.policy_revision,
        .expires_at_ms = canonical->expires_at_ms,
        .created_at_ms = now_ms,
        .authorization_id = {},
        .authorized_at_ms = 0,
        .authorization_expires_at_ms = 0,
        .launch_profile_digest = {},
        .starting_at_ms = 0,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = std::move(canonical->canonical_json),
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    return append_record_locked(*state_, std::move(record));
}

auto session_registry::reserve_start(
    const session_start_authorization& authorization,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_start_reservation> {
    if (authorization.schema_version != 1 || !valid_identifier(authorization.authorization_id) ||
        !valid_identifier(authorization.session_id) ||
        !valid_digest(authorization.controller_plan_digest) ||
        !valid_digest(authorization.plan_content_digest) || !valid_identifier(idempotency_key) ||
        authorization.approved_at_ms == 0 ||
        authorization.expires_at_ms <= authorization.approved_at_ms ||
        authorization.expires_at_ms - authorization.approved_at_ms >
            max_start_authorization_ttl_ms ||
        now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "invalid session start authorization"
        ));
    }
    auto request_digest = hash_start_authorization(authorization);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    {
        const std::scoped_lock lock{state_->mutex};
        auto replay =
            find_start_replay_locked(*state_, authorization, *request_digest, idempotency_key);
        if (!replay) {
            return std::unexpected(replay.error());
        }
        if (replay->found) {
            return std::move(replay->reservation);
        }
    }
    if (authorization.approved_at_ms > now_ms || authorization.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "session start authorization is not currently valid"
        ));
    }

    std::string canonical_plan;
    {
        const std::scoped_lock lock{state_->mutex};
        if (state_->poisoned || !verify_identity(*state_)) {
            return std::unexpected(storage_failure("session registry is poisoned"));
        }
        const auto existing = state_->sessions.find(authorization.session_id);
        if (existing == state_->sessions.end()) {
            return std::unexpected(
                failure(session_registry_error_code::not_found, "session was not found")
            );
        }
        const auto& record = state_->records[existing->second];
        if (record.state != "created") {
            return std::unexpected(failure(
                session_registry_error_code::invalid_state,
                "session is not eligible for start reservation"
            ));
        }
        if (record.controller_plan_digest != authorization.controller_plan_digest ||
            record.plan_content_digest != authorization.plan_content_digest ||
            authorization.approved_at_ms < record.created_at_ms ||
            authorization.expires_at_ms > record.expires_at_ms) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_authorization,
                "start authorization does not bind the stored session plan"
            ));
        }
        canonical_plan = record.canonical_plan_json;
    }

    auto launch = state_->validator->resolve_runtime_launch_json(canonical_plan, now_ms);
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves to a runtime launch: " + launch.error()
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_start_replay_locked(*state_, authorization, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->reservation);
    }
    const auto existing = state_->sessions.find(authorization.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "created" ||
        prior.controller_plan_digest != authorization.controller_plan_digest ||
        prior.plan_content_digest != authorization.plan_content_digest ||
        prior.canonical_plan_json != canonical_plan) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state, "session changed before start reservation"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "reserve_start",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "preparing",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = authorization.authorization_id,
        .authorized_at_ms = authorization.approved_at_ms,
        .authorization_expires_at_ms = authorization.expires_at_ms,
        .launch_profile_digest = {},
        .starting_at_ms = 0,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto reserved = append_record_locked(*state_, std::move(record));
    if (!reserved) {
        return std::unexpected(reserved.error());
    }
    return session_start_reservation{
        .session = std::move(*reserved),
        .launch = std::move(*launch),
        .authorization_id = authorization.authorization_id,
        .authorization_expires_at_ms = authorization.expires_at_ms,
    };
}

auto session_registry::resolve_start_inputs(
    std::string_view session_id, std::string_view authorization_id, std::uint64_t now_ms
) -> session_registry_result<session_start_inputs> {
    if (!valid_identifier(session_id) || !valid_identifier(authorization_id) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session start-input request"
        ));
    }
    std::string canonical_plan;
    session_record prepared_session;
    std::uint64_t authorization_expires_at_ms = 0;
    {
        const std::scoped_lock lock{state_->mutex};
        if (state_->poisoned || !verify_identity(*state_)) {
            return std::unexpected(storage_failure("session registry is poisoned"));
        }
        const auto existing = state_->sessions.find(std::string{session_id});
        if (existing == state_->sessions.end()) {
            return std::unexpected(
                failure(session_registry_error_code::not_found, "session was not found")
            );
        }
        const auto& record = state_->records[existing->second];
        if (record.state != "preparing") {
            return std::unexpected(failure(
                session_registry_error_code::invalid_state,
                "session has no durable start reservation"
            ));
        }
        if (record.authorization_id != authorization_id ||
            record.authorization_expires_at_ms <= now_ms) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_authorization,
                "session start reservation is not currently authorized"
            ));
        }
        canonical_plan = record.canonical_plan_json;
        prepared_session = public_record(record);
        authorization_expires_at_ms = record.authorization_expires_at_ms;
    }

    auto launch = state_->validator->resolve_runtime_launch_json(canonical_plan, now_ms);
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves to a runtime launch: " + launch.error()
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }
    auto path_grants = state_->validator->resolve_path_grants_json(canonical_plan, now_ms);
    if (!path_grants) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session path grants no longer resolve"
        ));
    }
    auto library_projections =
        state_->validator->resolve_library_projection_targets_json(canonical_plan, now_ms);
    if (!library_projections) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session library projections no longer resolve"
        ));
    }
    std::vector<supervisor::resolved_library_projection> resolved_library_projections;
    if (!library_projections->empty()) {
        if (!state_->library_bundles) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_plan,
                "session library bundle store is unavailable"
            ));
        }
        auto resolved = state_->library_bundles->resolve_projections(*library_projections);
        if (!resolved) {
            return std::unexpected(failure(
                session_registry_error_code::invalid_plan,
                "stored session library bundles no longer resolve"
            ));
        }
        resolved_library_projections = std::move(*resolved);
    }

    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& current = state_->records[existing->second];
    if (current.state != "preparing" || current.authorization_id != authorization_id ||
        current.authorization_expires_at_ms != authorization_expires_at_ms ||
        current.authorization_expires_at_ms <= now_ms ||
        current.canonical_plan_json != canonical_plan ||
        public_record(current) != prepared_session) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session changed while resolving start inputs"
        ));
    }
    return session_start_inputs{
        .session = std::move(prepared_session),
        .launch = std::move(*launch),
        .path_grants = std::move(*path_grants),
        .library_projections = std::move(resolved_library_projections),
        .authorization_id = std::string{authorization_id},
        .authorization_expires_at_ms = authorization_expires_at_ms,
    };
}

auto session_registry::mark_starting(
    const session_execution_binding& binding,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_starting_record> {
    if (binding.schema_version != 1 || !valid_identifier(binding.session_id) ||
        !valid_digest(binding.controller_plan_digest) ||
        !valid_digest(binding.plan_content_digest) || !valid_identifier(binding.authorization_id) ||
        !valid_digest(binding.profile_digest) || !valid_cgroup_identity(binding.cgroup_identity) ||
        !valid_filesystem_identity(binding.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session execution commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            binding.session_id, binding.controller_plan_digest, binding.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "execution commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_execution_binding(binding);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_starting_replay_locked(*state_, binding, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(binding.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "preparing") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the starting transition"
        ));
    }
    if (prior.session_id != binding.session_id ||
        prior.controller_plan_digest != binding.controller_plan_digest ||
        prior.plan_content_digest != binding.plan_content_digest ||
        prior.authorization_id != binding.authorization_id ||
        prior.authorization_expires_at_ms <= now_ms || prior.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "execution commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_plan,
            "stored session plan no longer resolves before starting"
        ));
    }
    if (launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "direct-write start authorization is unavailable"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto authorization_expires_at_ms = prior.authorization_expires_at_ms;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_starting",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "starting",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = binding.cgroup_identity,
        .filesystem_identity = binding.filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_starting_record{
        .session = std::move(*appended),
        .authorization_id = binding.authorization_id,
        .authorization_expires_at_ms = authorization_expires_at_ms,
        .profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .cgroup_identity = binding.cgroup_identity,
        .filesystem_identity = binding.filesystem_identity,
    };
}

auto session_registry::status(std::string_view session_id) const
    -> session_registry_result<session_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return public_record(state_->records[existing->second]);
}

auto session_registry::starting_status(std::string_view session_id) const
    -> session_registry_result<session_starting_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return starting_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_running(
    const session_running_commitment& running_commitment,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_running_record> {
    if (running_commitment.schema_version != 1 ||
        !valid_identifier(running_commitment.session_id) ||
        !valid_digest(running_commitment.controller_plan_digest) ||
        !valid_digest(running_commitment.plan_content_digest) ||
        !valid_identifier(running_commitment.authorization_id) ||
        !valid_digest(running_commitment.profile_digest) ||
        !valid_process_identity(running_commitment.process_identity) ||
        !valid_filesystem_identity(running_commitment.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session running commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            running_commitment.session_id,
            running_commitment.controller_plan_digest,
            running_commitment.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "running commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_running_commitment(running_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_running_replay_locked(*state_, running_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(running_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the running transition"
        ));
    }
    if (prior.session_id != running_commitment.session_id ||
        prior.controller_plan_digest != running_commitment.controller_plan_digest ||
        prior.plan_content_digest != running_commitment.plan_content_digest ||
        prior.authorization_id != running_commitment.authorization_id ||
        prior.launch_profile_digest != running_commitment.profile_digest ||
        !prior.cgroup_identity ||
        prior.cgroup_identity->device != running_commitment.process_identity.cgroup_device ||
        prior.cgroup_identity->inode != running_commitment.process_identity.cgroup_inode ||
        prior.filesystem_identity != running_commitment.filesystem_identity ||
        now_ms < prior.starting_at_ms || now_ms >= prior.authorization_expires_at_ms ||
        now_ms >= prior.expires_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "running commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible before child release"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_running",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "running",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = now_ms,
        .stopping_at_ms = 0,
        .process_identity_schema_version = running_commitment.process_identity.schema_version,
        .process_pid = running_commitment.process_identity.pid,
        .process_boot_id = running_commitment.process_identity.boot_id,
        .process_start_time_ticks = running_commitment.process_identity.start_time_ticks,
        .process_cgroup_device = running_commitment.process_identity.cgroup_device,
        .process_cgroup_inode = running_commitment.process_identity.cgroup_inode,
        .process_cgroup_path_digest = running_commitment.process_identity.cgroup_path_digest,
        .cgroup_identity = prior.cgroup_identity,
        .filesystem_identity = prior.filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_running_record{
        .session = std::move(*appended),
        .profile_digest = running_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = now_ms,
        .process_identity = running_commitment.process_identity,
        .filesystem_identity = running_commitment.filesystem_identity,
    };
}

auto session_registry::running_status(std::string_view session_id) const
    -> session_registry_result<session_running_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return running_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_stopping(
    const session_running_commitment& running_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_stopping_record> {
    if (running_commitment.schema_version != 1 ||
        !valid_identifier(running_commitment.session_id) ||
        !valid_digest(running_commitment.controller_plan_digest) ||
        !valid_digest(running_commitment.plan_content_digest) ||
        !valid_identifier(running_commitment.authorization_id) ||
        !valid_digest(running_commitment.profile_digest) ||
        !valid_process_identity(running_commitment.process_identity) ||
        !valid_filesystem_identity(running_commitment.filesystem_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session stopping commitment"
        ));
    }
    auto request_digest = hash_stopping_commitment(running_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_stopping_replay_locked(*state_, running_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(running_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "running") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the stopping transition"
        ));
    }
    if (prior.session_id != running_commitment.session_id ||
        prior.controller_plan_digest != running_commitment.controller_plan_digest ||
        prior.plan_content_digest != running_commitment.plan_content_digest ||
        prior.authorization_id != running_commitment.authorization_id ||
        prior.launch_profile_digest != running_commitment.profile_digest ||
        !same_process_identity(prior, running_commitment.process_identity) ||
        prior.filesystem_identity != running_commitment.filesystem_identity ||
        now_ms < prior.running_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "stopping commitment does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto cgroup_identity = prior.cgroup_identity;
    const auto filesystem_identity = prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_stopping",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "stopping",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = now_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_stopping_record{
        .session = std::move(*appended),
        .profile_digest = running_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = now_ms,
        .process_identity = running_commitment.process_identity,
        .filesystem_identity = running_commitment.filesystem_identity,
    };
}

auto session_registry::stopping_status(std::string_view session_id) const
    -> session_registry_result<session_stopping_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return stopping_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_exited(
    const container::authenticated_resource_enforcement_receipt& terminal,
    const container::receipt_audit_producer& receipt_producer,
    std::string_view idempotency_key
) -> session_registry_result<session_exited_record> {
    const auto termination_name = termination_cause_name(terminal.receipt.termination_cause);
    auto receipt_digest = container::resource_enforcement_receipt_digest(terminal.receipt);
    if (terminal.schema_version != 1 || terminal.sequence == 0 || !valid_digest(terminal.key_id) ||
        !valid_identifier(terminal.session_id) || !valid_digest(terminal.controller_plan_digest) ||
        terminal.receipt.schema_version != 1 || !valid_digest(terminal.receipt.profile_digest) ||
        !valid_digest(terminal.receipt_digest) || !valid_digest(terminal.previous_hmac) ||
        !valid_digest(terminal.this_hmac) || termination_name.empty() ||
        terminal.receipt.started_at_ms == 0 ||
        terminal.receipt.finished_at_ms < terminal.receipt.started_at_ms ||
        !valid_identifier(idempotency_key) || !receipt_digest ||
        *receipt_digest != terminal.receipt_digest) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid authenticated session terminal envelope"
        ));
    }
    auto confirmed = receipt_producer.confirms_terminal(terminal);
    if (!confirmed) {
        return std::unexpected(storage_failure(confirmed.error()));
    }
    if (!*confirmed) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "terminal envelope is not durable in the receipt journal"
        ));
    }
    auto request_digest = hash_terminal_envelope(terminal);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay = find_exited_replay_locked(*state_, terminal, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(terminal.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "running" && prior.state != "stopping") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the exited transition"
        ));
    }
    if (prior.session_id != terminal.session_id ||
        prior.controller_plan_digest != terminal.controller_plan_digest ||
        prior.launch_profile_digest != terminal.receipt.profile_digest ||
        terminal.receipt.started_at_ms > prior.running_at_ms ||
        terminal.receipt.finished_at_ms <
            (prior.state == "stopping" ? prior.stopping_at_ms : prior.running_at_ms)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "terminal envelope does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto stopping_at_ms = prior.stopping_at_ms;
    auto process_identity = process_identity_from_wire(prior);
    if (!process_identity) {
        state_->poisoned = true;
        return std::unexpected(storage_failure("session registry process identity is invalid"));
    }
    const auto cgroup_identity = *prior.cgroup_identity;
    const auto filesystem_identity = *prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_exited",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "exited",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = prior.stopping_at_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = terminal.receipt.finished_at_ms,
        .receipt_started_at_ms = terminal.receipt.started_at_ms,
        .receipt_key_id = terminal.key_id,
        .receipt_sequence = terminal.sequence,
        .receipt_digest = terminal.receipt_digest,
        .receipt_previous_hmac = terminal.previous_hmac,
        .receipt_hmac = terminal.this_hmac,
        .termination_cause = std::string{termination_name},
        .exit_code = terminal.receipt.exit_code,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_exited_record{
        .session = std::move(*appended),
        .profile_digest = terminal.receipt.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = stopping_at_ms,
        .process_identity = std::move(*process_identity),
        .filesystem_identity = filesystem_identity,
        .finished_at_ms = terminal.receipt.finished_at_ms,
        .receipt_key_id = terminal.key_id,
        .receipt_sequence = terminal.sequence,
        .receipt_digest = terminal.receipt_digest,
        .receipt_hmac = terminal.this_hmac,
        .termination_cause = terminal.receipt.termination_cause,
        .exit_code = terminal.receipt.exit_code,
    };
}

auto session_registry::exited_status(std::string_view session_id) const
    -> session_registry_result<session_exited_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return exited_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_failed(
    const session_failure_commitment& failure_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<session_failed_record> {
    const auto failure_name = failure_code_name(failure_commitment.code);
    const auto parsed_failure = failure_code_from_wire(failure_name);
    if (failure_commitment.schema_version != 1 ||
        !valid_identifier(failure_commitment.session_id) ||
        !valid_digest(failure_commitment.controller_plan_digest) ||
        !valid_digest(failure_commitment.plan_content_digest) ||
        !valid_identifier(failure_commitment.authorization_id) ||
        !valid_digest(failure_commitment.profile_digest) || !valid_identifier(idempotency_key) ||
        now_ms == 0 || !parsed_failure || *parsed_failure != failure_commitment.code) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request, "invalid session failure commitment"
        ));
    }
    auto request_digest = hash_failure_commitment(failure_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }

    const std::scoped_lock lock{state_->mutex};
    auto replay =
        find_failure_replay_locked(*state_, failure_commitment, *request_digest, idempotency_key);
    if (!replay) {
        return std::unexpected(replay.error());
    }
    if (replay->found) {
        return std::move(replay->record);
    }
    const auto existing = state_->sessions.find(failure_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting" && prior.state != "running" && prior.state != "stopping") {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "session is not eligible for the failed transition"
        ));
    }
    if (prior.session_id != failure_commitment.session_id ||
        prior.controller_plan_digest != failure_commitment.controller_plan_digest ||
        prior.plan_content_digest != failure_commitment.plan_content_digest ||
        prior.authorization_id != failure_commitment.authorization_id ||
        prior.launch_profile_digest != failure_commitment.profile_digest ||
        now_ms < (prior.state == "stopping"
                      ? prior.stopping_at_ms
                      : (prior.state == "running" ? prior.running_at_ms : prior.starting_at_ms)) ||
        ((prior.state == "running" || prior.state == "stopping") &&
         failure_commitment.code != session_failure_code::supervisor_error &&
         failure_commitment.code != session_failure_code::recovered_without_process &&
         failure_commitment.code != session_failure_code::recovered_terminated)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "failure commitment does not match the durable starting session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    const auto starting_at_ms = prior.starting_at_ms;
    const auto running_at_ms = prior.running_at_ms;
    const auto stopping_at_ms = prior.stopping_at_ms;
    auto process_identity = process_identity_from_wire(prior);
    if ((prior.state == "running" || prior.state == "stopping") && !process_identity) {
        state_->poisoned = true;
        return std::unexpected(storage_failure("session registry process identity is invalid"));
    }
    const auto cgroup_identity = prior.cgroup_identity;
    const auto filesystem_identity = prior.filesystem_identity;

    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_failed",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "failed",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = prior.launch_profile_digest,
        .starting_at_ms = prior.starting_at_ms,
        .running_at_ms = prior.running_at_ms,
        .stopping_at_ms = prior.stopping_at_ms,
        .process_identity_schema_version = prior.process_identity_schema_version,
        .process_pid = prior.process_pid,
        .process_boot_id = prior.process_boot_id,
        .process_start_time_ticks = prior.process_start_time_ticks,
        .process_cgroup_device = prior.process_cgroup_device,
        .process_cgroup_inode = prior.process_cgroup_inode,
        .process_cgroup_path_digest = prior.process_cgroup_path_digest,
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .managed_runtime_identity = std::nullopt,
        .failure_code = std::string{failure_name},
        .finished_at_ms = now_ms,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return session_failed_record{
        .session = std::move(*appended),
        .profile_digest = failure_commitment.profile_digest,
        .starting_at_ms = starting_at_ms,
        .running_at_ms = running_at_ms,
        .stopping_at_ms = stopping_at_ms,
        .process_identity = std::move(process_identity),
        .cgroup_identity = cgroup_identity,
        .filesystem_identity = filesystem_identity,
        .failed_at_ms = now_ms,
        .code = failure_commitment.code,
    };
}

auto session_registry::failed_status(std::string_view session_id) const
    -> session_registry_result<session_failed_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return failed_record_from_wire(state_->records[existing->second]);
}

auto session_registry::mark_managed_starting(
    const managed_session_execution_binding& binding,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (binding.schema_version != 1 || !valid_identifier(binding.session_id) ||
        !valid_digest(binding.controller_plan_digest) ||
        !valid_digest(binding.plan_content_digest) || !valid_identifier(binding.authorization_id) ||
        !valid_digest(binding.profile_digest) ||
        !valid_managed_runtime_identity(binding.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session execution commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            binding.session_id, binding.controller_plan_digest, binding.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed execution commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest = hash_managed_execution_binding(binding);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_starting" ||
            record.session_id != binding.session_id ||
            record.controller_plan_digest != binding.controller_plan_digest ||
            record.plan_content_digest != binding.plan_content_digest ||
            record.authorization_id != binding.authorization_id ||
            record.launch_profile_digest != binding.profile_digest ||
            record.managed_runtime_identity != binding.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed starting idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(binding.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "preparing" || prior.session_id != binding.session_id ||
        prior.controller_plan_digest != binding.controller_plan_digest ||
        prior.plan_content_digest != binding.plan_content_digest ||
        prior.authorization_id != binding.authorization_id ||
        prior.authorization_expires_at_ms <= now_ms || prior.expires_at_ms <= now_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed execution commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible for managed start"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record{
        .schema_version = 1,
        .sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U,
        .operation = "mark_managed_starting",
        .idempotency_key = std::string{idempotency_key},
        .session_id = prior.session_id,
        .controller_plan_digest = prior.controller_plan_digest,
        .request_digest = std::move(*request_digest),
        .plan_content_digest = prior.plan_content_digest,
        .state = "starting",
        .policy_revision = prior.policy_revision,
        .expires_at_ms = prior.expires_at_ms,
        .created_at_ms = prior.created_at_ms,
        .authorization_id = prior.authorization_id,
        .authorized_at_ms = prior.authorized_at_ms,
        .authorization_expires_at_ms = prior.authorization_expires_at_ms,
        .launch_profile_digest = binding.profile_digest,
        .starting_at_ms = now_ms,
        .running_at_ms = 0,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = binding.runtime_identity,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = prior.canonical_plan_json,
        .previous_hash = state_->records.empty() ? std::string(digest_hex_bytes, '0')
                                                 : state_->records.back().this_hash,
        .this_hash = {},
    };
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_running(
    const managed_session_running_commitment& running,
    const container::receipt_audit_producer::terminal_reservation& receipt_reservation,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (running.schema_version != 1 || !valid_identifier(running.session_id) ||
        !valid_digest(running.controller_plan_digest) ||
        !valid_digest(running.plan_content_digest) ||
        !valid_identifier(running.authorization_id) || !valid_digest(running.profile_digest) ||
        !valid_managed_runtime_identity(running.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session running commitment"
        ));
    }
    if (!receipt_reservation.matches_execution(
            running.session_id, running.controller_plan_digest, running.profile_digest
        )) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed running commitment has no matching terminal receipt reservation"
        ));
    }
    auto request_digest =
        hash_managed_running_commitment(running, "glove.managed-session-running-commitment");
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_running" ||
            record.session_id != running.session_id ||
            record.controller_plan_digest != running.controller_plan_digest ||
            record.plan_content_digest != running.plan_content_digest ||
            record.authorization_id != running.authorization_id ||
            record.launch_profile_digest != running.profile_digest ||
            record.managed_runtime_identity != running.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed running idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(running.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "starting" || prior.session_id != running.session_id ||
        prior.controller_plan_digest != running.controller_plan_digest ||
        prior.plan_content_digest != running.plan_content_digest ||
        prior.authorization_id != running.authorization_id ||
        prior.launch_profile_digest != running.profile_digest ||
        prior.managed_runtime_identity != running.runtime_identity ||
        now_ms < prior.starting_at_ms || now_ms >= prior.authorization_expires_at_ms ||
        now_ms >= prior.expires_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed running commitment does not bind the current authorized session"
        ));
    }
    auto launch = state_->validator->resolve_runtime_launch_json(prior.canonical_plan_json, now_ms);
    if (!launch || launch->requires_direct_write_approval) {
        return std::unexpected(failure(
            launch ? session_registry_error_code::invalid_authorization
                   : session_registry_error_code::invalid_plan,
            "stored session plan is not eligible before managed child release"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_running";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "running";
    record.running_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_stopping(
    const managed_session_running_commitment& running,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_lifecycle_record> {
    if (running.schema_version != 1 || !valid_identifier(running.session_id) ||
        !valid_digest(running.controller_plan_digest) ||
        !valid_digest(running.plan_content_digest) ||
        !valid_identifier(running.authorization_id) || !valid_digest(running.profile_digest) ||
        !valid_managed_runtime_identity(running.runtime_identity) ||
        !valid_identifier(idempotency_key) || now_ms == 0) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session stopping commitment"
        ));
    }
    auto request_digest =
        hash_managed_running_commitment(running, "glove.managed-session-stopping-commitment");
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_stopping" ||
            record.session_id != running.session_id ||
            record.controller_plan_digest != running.controller_plan_digest ||
            record.plan_content_digest != running.plan_content_digest ||
            record.authorization_id != running.authorization_id ||
            record.launch_profile_digest != running.profile_digest ||
            record.managed_runtime_identity != running.runtime_identity ||
            record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed stopping idempotency payload changed"
            ));
        }
        return managed_lifecycle_from_wire(record);
    }
    const auto existing = state_->sessions.find(running.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if (prior.state != "running" || prior.session_id != running.session_id ||
        prior.controller_plan_digest != running.controller_plan_digest ||
        prior.plan_content_digest != running.plan_content_digest ||
        prior.authorization_id != running.authorization_id ||
        prior.launch_profile_digest != running.profile_digest ||
        prior.managed_runtime_identity != running.runtime_identity ||
        now_ms < prior.running_at_ms) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed stopping commitment does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_stopping";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "stopping";
    record.stopping_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_lifecycle_from_wire(state_->records.back());
}

auto session_registry::mark_managed_exited(
    const container::authenticated_resource_enforcement_receipt& terminal,
    const container::receipt_audit_producer& receipt_producer,
    std::string_view idempotency_key
) -> session_registry_result<managed_session_exited_record> {
    const auto termination_name = termination_cause_name(terminal.receipt.termination_cause);
    auto receipt_digest = container::resource_enforcement_receipt_digest(terminal.receipt);
    if (terminal.schema_version != 1 || terminal.sequence == 0 || !valid_digest(terminal.key_id) ||
        !valid_identifier(terminal.session_id) || !valid_digest(terminal.controller_plan_digest) ||
        terminal.receipt.schema_version != 1 || !valid_digest(terminal.receipt.profile_digest) ||
        !valid_digest(terminal.receipt_digest) || !valid_digest(terminal.previous_hmac) ||
        !valid_digest(terminal.this_hmac) || termination_name.empty() ||
        terminal.receipt.started_at_ms == 0 ||
        terminal.receipt.finished_at_ms < terminal.receipt.started_at_ms ||
        !valid_identifier(idempotency_key) || !receipt_digest ||
        *receipt_digest != terminal.receipt_digest) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid authenticated managed session terminal envelope"
        ));
    }
    auto confirmed = receipt_producer.confirms_terminal(terminal);
    if (!confirmed) {
        return std::unexpected(storage_failure(confirmed.error()));
    }
    if (!*confirmed) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_authorization,
            "managed terminal envelope is not durable in the receipt journal"
        ));
    }
    auto request_digest = hash_terminal_envelope(terminal);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_exited" ||
            record.session_id != terminal.session_id ||
            record.controller_plan_digest != terminal.controller_plan_digest ||
            record.launch_profile_digest != terminal.receipt.profile_digest ||
            record.receipt_sequence != terminal.sequence ||
            record.receipt_digest != terminal.receipt_digest ||
            record.receipt_hmac != terminal.this_hmac || record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed terminal idempotency payload changed"
            ));
        }
        return managed_exited_from_wire(record);
    }
    const auto existing = state_->sessions.find(terminal.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if ((prior.state != "running" && prior.state != "stopping") ||
        !prior.managed_runtime_identity || prior.session_id != terminal.session_id ||
        prior.controller_plan_digest != terminal.controller_plan_digest ||
        prior.launch_profile_digest != terminal.receipt.profile_digest ||
        terminal.receipt.started_at_ms > prior.running_at_ms ||
        terminal.receipt.finished_at_ms <
            (prior.state == "stopping" ? prior.stopping_at_ms : prior.running_at_ms)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed terminal envelope does not match the durable running session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_exited";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "exited";
    record.finished_at_ms = terminal.receipt.finished_at_ms;
    record.receipt_started_at_ms = terminal.receipt.started_at_ms;
    record.receipt_key_id = terminal.key_id;
    record.receipt_sequence = terminal.sequence;
    record.receipt_digest = terminal.receipt_digest;
    record.receipt_previous_hmac = terminal.previous_hmac;
    record.receipt_hmac = terminal.this_hmac;
    record.termination_cause = std::string{termination_name};
    record.exit_code = terminal.receipt.exit_code;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_exited_from_wire(state_->records.back());
}

auto session_registry::mark_managed_failed(
    const session_failure_commitment& failure_commitment,
    std::string_view idempotency_key,
    std::uint64_t now_ms
) -> session_registry_result<managed_session_failed_record> {
    const auto failure_name = failure_code_name(failure_commitment.code);
    if (failure_commitment.schema_version != 1 ||
        !valid_identifier(failure_commitment.session_id) ||
        !valid_digest(failure_commitment.controller_plan_digest) ||
        !valid_digest(failure_commitment.plan_content_digest) ||
        !valid_identifier(failure_commitment.authorization_id) ||
        !valid_digest(failure_commitment.profile_digest) || !valid_identifier(idempotency_key) ||
        now_ms == 0 || !failure_code_from_wire(failure_name)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_request,
            "invalid managed session failure commitment"
        ));
    }
    auto request_digest = hash_failure_commitment(failure_commitment);
    if (!request_digest) {
        return std::unexpected(storage_failure(request_digest.error()));
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    if (const auto replay = state_->requests.find(std::string{idempotency_key});
        replay != state_->requests.end()) {
        const auto& record = state_->records[replay->second];
        if (record.operation != "mark_managed_failed" ||
            record.session_id != failure_commitment.session_id ||
            record.controller_plan_digest != failure_commitment.controller_plan_digest ||
            record.plan_content_digest != failure_commitment.plan_content_digest ||
            record.authorization_id != failure_commitment.authorization_id ||
            record.launch_profile_digest != failure_commitment.profile_digest ||
            record.failure_code != failure_name || record.request_digest != *request_digest) {
            return std::unexpected(failure(
                session_registry_error_code::idempotency_conflict,
                "managed failure idempotency payload changed"
            ));
        }
        return managed_failed_from_wire(record);
    }
    const auto existing = state_->sessions.find(failure_commitment.session_id);
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    const auto& prior = state_->records[existing->second];
    if ((prior.state != "starting" && prior.state != "running" &&
         prior.state != "stopping") ||
        !prior.managed_runtime_identity ||
        prior.controller_plan_digest != failure_commitment.controller_plan_digest ||
        prior.plan_content_digest != failure_commitment.plan_content_digest ||
        prior.authorization_id != failure_commitment.authorization_id ||
        prior.launch_profile_digest != failure_commitment.profile_digest ||
        now_ms < (prior.state == "stopping"
                      ? prior.stopping_at_ms
                      : (prior.state == "running" ? prior.running_at_ms : prior.starting_at_ms)) ||
        ((prior.state == "running" || prior.state == "stopping") &&
         failure_commitment.code != session_failure_code::supervisor_error &&
         failure_commitment.code != session_failure_code::recovered_without_process &&
         failure_commitment.code != session_failure_code::recovered_terminated)) {
        return std::unexpected(failure(
            session_registry_error_code::invalid_state,
            "managed failure commitment does not match the durable session"
        ));
    }
    if (state_->records.size() >= max_records) {
        return std::unexpected(
            failure(session_registry_error_code::capacity, "session registry capacity exhausted")
        );
    }
    wire::persisted_session record = prior;
    record.sequence = static_cast<std::uint64_t>(state_->records.size()) + 1U;
    record.operation = "mark_managed_failed";
    record.idempotency_key = std::string{idempotency_key};
    record.request_digest = std::move(*request_digest);
    record.state = "failed";
    record.failure_code = std::string{failure_name};
    record.finished_at_ms = now_ms;
    record.previous_hash = state_->records.back().this_hash;
    record.this_hash.clear();
    auto appended = append_record_locked(*state_, std::move(record));
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return managed_failed_from_wire(state_->records.back());
}

auto session_registry::managed_lifecycle_status(std::string_view session_id) const
    -> session_registry_result<managed_session_lifecycle_record> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return managed_lifecycle_from_wire(state_->records[existing->second]);
}

auto session_registry::managed_recovery_candidates() const
    -> session_registry_result<std::vector<managed_session_lifecycle_record>> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    std::vector<managed_session_lifecycle_record> candidates;
    candidates.reserve(state_->sessions.size());
    for (const auto& [session_id, index] : state_->sessions) {
        const auto& record = state_->records[index];
        if ((record.state != "starting" && record.state != "running" &&
             record.state != "stopping") ||
            !record.managed_runtime_identity) {
            continue;
        }
        auto candidate = managed_lifecycle_from_wire(record);
        if (!candidate) {
            return std::unexpected(candidate.error());
        }
        candidates.push_back(std::move(*candidate));
    }
    std::ranges::sort(candidates, {}, [](const auto& candidate) -> std::string_view {
        return candidate.session.session_id;
    });
    return candidates;
}

auto session_registry::recovery_candidates() const
    -> session_registry_result<std::vector<session_recovery_record>> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    std::vector<session_recovery_record> candidates;
    candidates.reserve(state_->sessions.size());
    for (const auto& [session_id, index] : state_->sessions) {
        const auto& record = state_->records[index];
        if (record.state != "starting" && record.state != "running" && record.state != "stopping") {
            continue;
        }
        if (record.managed_runtime_identity) {
            continue;
        }
        candidates.push_back({
            .session = public_record(record),
            .authorization_id = record.authorization_id,
            .profile_digest = record.launch_profile_digest,
            .starting_at_ms = record.starting_at_ms,
            .running_at_ms = record.running_at_ms,
            .stopping_at_ms = record.stopping_at_ms,
            .process_identity = process_identity_from_wire(record),
            .cgroup_identity = record.cgroup_identity,
            .filesystem_identity = record.filesystem_identity,
        });
    }
    std::ranges::sort(candidates, {}, [](const auto& candidate) -> std::string_view {
        return candidate.session.session_id;
    });
    return candidates;
}

auto session_registry::canonical_plan(std::string_view session_id) const
    -> session_registry_result<std::string> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(
            failure(session_registry_error_code::invalid_request, "invalid session identity")
        );
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned || !verify_identity(*state_)) {
        return std::unexpected(storage_failure("session registry is poisoned"));
    }
    const auto existing = state_->sessions.find(std::string{session_id});
    if (existing == state_->sessions.end()) {
        return std::unexpected(
            failure(session_registry_error_code::not_found, "session was not found")
        );
    }
    return state_->records[existing->second].canonical_plan_json;
}

auto session_registry::record_count() const -> std::uint64_t {
    const std::scoped_lock lock{state_->mutex};
    return static_cast<std::uint64_t>(state_->records.size());
}

} // namespace glove::control
