#pragma once

#include "glove/control/session_registry.hpp"
#include "glove/control/session_registry_wire.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace glove::control {

// On-disk registry constants and internal state shared by the registry store
// and its recovery/replay state machine. Internal-only: include from
// session_registry.cpp / session_registry_recovery.cpp.

constexpr std::array<unsigned char, 8> registry_magic = {'G', 'L', 'V', 'S', 'E', 'S', '0', '5'};
constexpr std::size_t digest_hex_bytes = 64U;
constexpr std::uint64_t min_registry_bytes = 1'024U;
constexpr std::size_t max_records = 10'000U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::uint64_t max_start_authorization_ttl_ms = 120'000U;
constexpr glz::opts partial_read_options{.error_on_unknown_keys = false};

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

inline auto failure(session_registry_error_code code, std::string message)
    -> session_registry_error {
    return {.code = code, .message = std::move(message)};
}

inline auto storage_failure(std::string message) -> session_registry_error {
    return failure(session_registry_error_code::storage, std::move(message));
}

inline auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

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


using namespace wire;

inline auto valid_identifier(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

inline auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

inline auto refinement_plan(std::string_view canonical_plan_json) -> bool {
    wire::plan_runtime_header header;
    return !glz::read<partial_read_options>(header, canonical_plan_json) &&
           header.runtime_template_id == container::refinement_runtime_template_id;
}

inline auto valid_boot_id(std::string_view value) noexcept -> bool {
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

inline auto valid_process_identity(const linux_process_identity& identity) noexcept -> bool {
    const auto max_pid = static_cast<std::uint64_t>(std::numeric_limits<::pid_t>::max());
    return identity.schema_version == 1 && identity.pid != 0 && identity.pid <= max_pid &&
           valid_boot_id(identity.boot_id) && identity.start_time_ticks != 0 &&
           identity.cgroup_device != 0 && identity.cgroup_inode != 0 &&
           valid_digest(identity.cgroup_path_digest);
}

inline auto valid_filesystem_identity(const linux_filesystem_recovery_identity& identity) noexcept
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

inline auto valid_cgroup_identity(const linux_cgroup_recovery_identity& identity) noexcept -> bool {
    return identity.schema_version == 1 && identity.device != 0 && identity.inode != 0;
}

inline auto valid_managed_runtime_identity(const managed_runtime_recovery_identity& identity) noexcept
    -> bool {
    return identity.schema_version == 1 && identity.backend == "apple_container" &&
           valid_identifier(identity.instance_id) && valid_digest(identity.launch_identity_digest);
}

inline auto no_process_identity(const wire::persisted_session& record) noexcept -> bool {
    return record.process_identity_schema_version == 0 && record.process_pid == 0 &&
           record.process_boot_id.empty() && record.process_start_time_ticks == 0 &&
           record.process_cgroup_device == 0 && record.process_cgroup_inode == 0 &&
           record.process_cgroup_path_digest.empty();
}

inline auto no_resource_identity(const wire::persisted_session& record) noexcept -> bool {
    return no_process_identity(record) && !record.cgroup_identity && !record.filesystem_identity &&
           !record.managed_runtime_identity;
}

inline auto process_identity_from_wire(const wire::persisted_session& record)
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

inline auto same_process_identity(
    const wire::persisted_session& left, const wire::persisted_session& right
) noexcept -> bool {
    return left.process_identity_schema_version == right.process_identity_schema_version &&
           left.process_pid == right.process_pid && left.process_boot_id == right.process_boot_id &&
           left.process_start_time_ticks == right.process_start_time_ticks &&
           left.process_cgroup_device == right.process_cgroup_device &&
           left.process_cgroup_inode == right.process_cgroup_inode &&
           left.process_cgroup_path_digest == right.process_cgroup_path_digest;
}

inline auto same_process_identity(
    const wire::persisted_session& record, const linux_process_identity& identity
) noexcept -> bool {
    return record.process_identity_schema_version == identity.schema_version &&
           record.process_pid == identity.pid && record.process_boot_id == identity.boot_id &&
           record.process_start_time_ticks == identity.start_time_ticks &&
           record.process_cgroup_device == identity.cgroup_device &&
           record.process_cgroup_inode == identity.cgroup_inode &&
           record.process_cgroup_path_digest == identity.cgroup_path_digest;
}

template<typename Byte, std::size_t Extent>
    requires(sizeof(Byte) == 1)
inline auto read_at(int descriptor, std::span<Byte, Extent> bytes, std::uint64_t offset)
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

inline auto write_at(int descriptor, std::span<const unsigned char> bytes, std::uint64_t offset)
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

inline auto sync_descriptor(int descriptor, std::string_view operation)
    -> std::expected<void, std::string> {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error(operation));
    }
    return {};
}

inline auto inspect_file(int descriptor) -> std::expected<std::uint64_t, std::string> {
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

inline auto capture_identity(int descriptor) -> std::expected<registry_identity, std::string> {
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

inline auto open_registry(const std::filesystem::path& path)
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

inline auto public_record(const wire::persisted_session& record) -> session_record {
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

inline auto valid_record_shape(const wire::persisted_session& record, std::uint64_t sequence) -> bool {
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
    const bool managed_resources = no_process_identity(record) && !record.cgroup_identity &&
                                   !record.filesystem_identity && record.managed_runtime_identity &&
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
    const bool managed_running = record.running_at_ms >= record.starting_at_ms &&
                                 record.running_at_ms < record.authorization_expires_at_ms &&
                                 managed_resources;
    if (record.operation == "mark_managed_running" && record.state == "running") {
        return started && managed_running && no_stop_intent && record.failure_code.empty() &&
               record.finished_at_ms == 0 && no_terminal_receipt;
    }
    const bool stopping = running && record.stopping_at_ms >= record.running_at_ms;
    if (record.operation == "mark_stopping" && record.state == "stopping") {
        return started && stopping && record.failure_code.empty() && record.finished_at_ms == 0 &&
               no_terminal_receipt;
    }
    const bool managed_stopping = managed_running && record.stopping_at_ms >= record.running_at_ms;
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
    if ((record.operation == "mark_exited" || record.operation == "mark_refinement_exited") &&
        record.state == "exited") {
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
               record.finished_at_ms >= (record.stopping_at_ms != 0
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


} // namespace glove::control
