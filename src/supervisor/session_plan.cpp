#include "glove/supervisor/session_plan.hpp"

#include "glove/container/digest.hpp"
#include "glove/container/refinement_protocol.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "../container/receipt_json.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace wire {

struct path_grant {
    std::string alias;
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::uint64_t ttl_secs = 0;
    std::string cleanup_policy;
};

struct path_exposure_grant {
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::uint64_t ttl_secs = 0;
    std::string cleanup_policy;
};

struct library_projection {
    std::string projection_id;
    std::string content_digest;
    std::string destination_alias;
};

struct session_plan {
    std::uint8_t schema_version = 0;
    std::string runtime_id;
    std::string runtime_template_id;
    std::string adapter_command_digest;
    std::string sandbox_backend;
    std::string egress_policy_id;
    std::string tool_policy_id;
    std::vector<path_grant> path_grants;
    std::vector<library_projection> library_projections;
    std::vector<std::string> secret_handles;
    resource_limits limits;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::optional<container::refinement_plan_binding> refinement;
};

struct session_plan_v2 {
    std::uint8_t schema_version = 0;
    std::string runtime_id;
    std::string runtime_template_id;
    std::string adapter_command_digest;
    std::string sandbox_backend;
    std::string egress_policy_id;
    std::string tool_policy_id;
    std::vector<path_exposure_grant> path_grants;
    std::vector<library_projection> library_projections;
    std::vector<std::string> secret_handles;
    resource_limits limits;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::optional<container::refinement_plan_binding> refinement;
};

struct session_plan_header {
    std::uint8_t schema_version = 0;
};

struct path_access_policy {
    std::string access;
    std::string materialization;
    std::string create_policy;
    std::string cleanup_policy;
    std::uint64_t max_bytes = 0;
};

struct path_alias_policy {
    std::string alias;
    std::string host_path;
    std::string target_path;
    std::uint64_t max_ttl_secs = 0;
    std::vector<path_access_policy> access;
};

struct runtime_template_policy {
    std::string runtime_template_id;
    std::string runtime_id;
    std::string adapter_command_digest;
    std::string sandbox_backend;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
    // Owner-local only: a remote session plan cannot select or override it.
    std::optional<native_harness_adoption_policy> adoption;
    std::optional<runtime_launch_template> launch;
};

struct library_projection_destination_policy {
    std::string alias;
    std::string target_path;
};

struct resource_profile_policy {
    std::string profile_id;
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t memory_bytes = 0;
    std::uint32_t pids = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t terminal_output_bytes = 0;

    [[nodiscard]] auto limits() const -> resource_limits {
        return resource_limits{
            .cpu_time_ms = cpu_time_ms,
            .memory_bytes = memory_bytes,
            .pids = pids,
            .wall_time_ms = wall_time_ms,
            .disk_bytes = disk_bytes,
            .terminal_output_bytes = terminal_output_bytes,
        };
    }
};

struct egress_target_policy {
    std::string host;
    std::uint16_t port = 443;
    bool allow_private = false;
};

struct egress_policy {
    std::string policy_id;
    std::vector<egress_target_policy> targets;
};

struct secret_mount_policy {
    std::string handle;
    std::string runtime_id;
    std::string source_path;
    std::string target_path;
};

struct session_plan_policy {
    std::uint8_t schema_version = 0;
    std::uint64_t revision = 0;
    std::uint64_t max_plan_ttl_ms = 0;
    std::vector<runtime_template_policy> runtime_templates;
    std::vector<path_alias_policy> path_aliases;
    std::vector<library_projection_destination_policy> library_projection_destinations;
    std::vector<resource_profile_policy> resource_profiles;
    std::vector<std::string> egress_policy_ids;
    std::vector<std::string> tool_policy_ids;
    std::vector<std::string> secret_handles;
    std::vector<egress_policy> egress_policies;
    std::vector<secret_mount_policy> secret_mounts;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr glz::opts header_read_options{.error_on_unknown_keys = false};
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::size_t max_path_grants = 64U;
constexpr std::size_t max_library_projections = 128U;
constexpr std::size_t max_secret_handles = 32U;
constexpr std::size_t max_policy_file_bytes = std::size_t{1024} * 1024U;
constexpr std::size_t max_runtime_templates = 64U;
constexpr std::size_t max_resource_profiles = 64U;
constexpr std::size_t max_policy_identifiers = 128U;
constexpr std::size_t max_projection_destinations = 128U;
constexpr std::size_t max_egress_targets = 128U;
constexpr std::size_t max_launch_fields = 256U;
constexpr std::size_t max_launch_string_bytes = std::size_t{64} * 1024U;
constexpr std::size_t max_launch_path_bytes = 4'096U;

template<auto Options, typename Value>
auto read_untrusted_json(Value& value, std::string_view json) -> glz::error_ctx {
    // Public plan methods accept arbitrary byte spans. Glaze's padded parser
    // requires mutable, resizable storage, which this local copy provides.
    std::string parse_buffer{json};
    return glz::read<Options>(value, parse_buffer);
}

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;
    unique_fd(unique_fd&&) = delete;
    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_launch_string(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_launch_string_bytes &&
           value.find('\0') == std::string_view::npos;
}

auto valid_launch_path(std::string_view raw) -> bool {
    const std::filesystem::path path{raw};
    return !raw.empty() && raw.size() <= max_launch_path_bytes &&
           raw.find('\0') == std::string_view::npos && path.is_absolute() &&
           path != path.root_path() && path.lexically_normal() == path;
}

auto valid_environment_name(std::string_view name) -> bool {
    if (name.empty()) {
        return false;
    }
    const char first = name.front();
    const bool valid_first =
        (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_';
    if (!valid_first) {
        return false;
    }
    return std::ranges::all_of(name.substr(1), [](unsigned char byte) {
        return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
               (byte >= '0' && byte <= '9') || byte == '_';
    });
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root) -> bool;

auto validate_runtime_launch_template_impl(const runtime_launch_template& launch)
    -> std::expected<void, std::string> {
    const std::filesystem::path executable{launch.executable_path};
    const auto discovered_adapter = native_skill_runtime_adapter_for(launch.runtime_discovery);
    if (launch.runtime_discovery.empty()) {
        if (!valid_launch_path(launch.executable_path)) {
            return std::unexpected(
                std::string{"launch.executable_path must be a canonical absolute non-root path"}
            );
        }
        if (!launch.executable_search_paths.empty()) {
            return std::unexpected(
                std::string{"launch.executable_search_paths requires launch.runtime_discovery"}
            );
        }
    } else {
        if (!discovered_adapter) {
            return std::unexpected(
                "launch.runtime_discovery is unsupported: " + launch.runtime_discovery
            );
        }
        if (!launch.executable_path.empty()) {
            return std::unexpected(
                std::string{
                    "launch.executable_path must be empty when launch.runtime_discovery is set"
                }
            );
        }
        if (launch.executable_search_paths.empty()) {
            return std::unexpected(
                std::string{
                    "launch.executable_search_paths must contain at least one explicit directory"
                }
            );
        }
    }
    if (launch.arguments.size() > max_launch_fields) {
        return std::unexpected(std::string{"launch.arguments exceeds 256 entries"});
    }
    if (launch.environment.size() > max_launch_fields) {
        return std::unexpected(std::string{"launch.environment exceeds 256 entries"});
    }
    if (launch.read_only_paths.size() > max_launch_fields) {
        return std::unexpected(std::string{"launch.read_only_paths exceeds 256 entries"});
    }
    if (launch.executable_search_paths.size() > max_launch_fields) {
        return std::unexpected(std::string{"launch.executable_search_paths exceeds 256 entries"});
    }
    for (std::size_t index = 0; index < launch.arguments.size(); ++index) {
        if (!valid_launch_string(launch.arguments[index])) {
            return std::unexpected(
                "launch.arguments[" + std::to_string(index) + "] is empty or exceeds 64 KiB"
            );
        }
    }

    std::set<std::string> environment_names;
    std::string_view previous;
    for (std::size_t index = 0; index < launch.environment.size(); ++index) {
        const auto& entry = launch.environment[index];
        if (!valid_launch_string(entry)) {
            return std::unexpected(
                "launch.environment[" + std::to_string(index) + "] is empty or exceeds 64 KiB"
            );
        }
        const auto separator = entry.find('=');
        if (separator == std::string::npos) {
            return std::unexpected(
                "launch.environment[" + std::to_string(index) + "] must be NAME=VALUE"
            );
        }
        const std::string_view name{entry.data(), separator};
        if (!valid_environment_name(name)) {
            return std::unexpected(
                "launch.environment[" + std::to_string(index) + "] has an invalid name"
            );
        }
        if (!environment_names.emplace(name).second) {
            return std::unexpected(
                "launch.environment[" + std::to_string(index) + "] duplicates " + std::string{name}
            );
        }
        if (!previous.empty() && previous >= entry) {
            return std::unexpected(
                "launch.environment[" + std::to_string(index) +
                "] is not in strictly increasing byte order"
            );
        }
        previous = entry;
    }
    std::vector<std::filesystem::path> paths;
    paths.reserve(launch.read_only_paths.size());
    for (std::size_t index = 0; index < launch.read_only_paths.size(); ++index) {
        const auto& raw = launch.read_only_paths[index];
        const std::filesystem::path path{raw};
        if (!valid_launch_path(raw)) {
            return std::unexpected(
                "launch.read_only_paths[" + std::to_string(index) +
                "] must be a canonical absolute non-root path"
            );
        }
        // A package/interpreter closure may contain the pinned executable.
        // The Linux composer layers the executable descriptor after these
        // read-only roots, preserving its separately committed identity.
        if (std::ranges::any_of(paths, [&](const auto& existing) {
                return path_within(path, existing) || path_within(existing, path);
            })) {
            return std::unexpected(
                "launch.read_only_paths[" + std::to_string(index) +
                "] duplicates or overlaps an earlier entry"
            );
        }
        paths.push_back(path);
    }
    std::vector<std::filesystem::path> search_paths;
    search_paths.reserve(launch.executable_search_paths.size());
    for (std::size_t index = 0; index < launch.executable_search_paths.size(); ++index) {
        const auto& raw = launch.executable_search_paths[index];
        const std::filesystem::path path{raw};
        if (!valid_launch_path(raw)) {
            return std::unexpected(
                "launch.executable_search_paths[" + std::to_string(index) +
                "] must be a canonical absolute non-root path"
            );
        }
        if (std::ranges::any_of(search_paths, [&](const auto& existing) {
                return path_within(path, existing) || path_within(existing, path);
            })) {
            return std::unexpected(
                "launch.executable_search_paths[" + std::to_string(index) +
                "] duplicates or overlaps an earlier entry"
            );
        }
        search_paths.push_back(path);
    }
    return {};
}

class launch_template_encoder {
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

    void append_string(std::string_view value) {
        append_u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

private:
    std::vector<unsigned char> bytes_;
};

auto modification_time_matches(const struct stat& before, const struct stat& after) noexcept
    -> bool {
#if defined(__APPLE__)
    return before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
#else
    return before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
#endif
}

auto change_time_matches(const struct stat& before, const struct stat& after) noexcept -> bool {
#if defined(__APPLE__)
    return before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    return before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

auto same_file(const struct stat& before, const struct stat& after) noexcept -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           modification_time_matches(before, after) && change_time_matches(before, after);
}

auto load_policy_file(const std::filesystem::path& path)
    -> std::expected<std::string, std::string> {
    if (!path.is_absolute()) {
        return std::unexpected(std::string{"session policy path must be absolute"});
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open session policy"));
    }

    struct stat before{};

    if (::fstat(descriptor.get(), &before) != 0) {
        return std::unexpected(system_error("inspect session policy"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(before.st_mode) & permission_mask;
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        permissions != owner_permissions || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > max_policy_file_bytes ||
        static_cast<std::uint64_t>(before.st_size) >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::unexpected(
            std::string{"session policy must be a bounded owner-only single-link regular file"}
        );
    }
    std::string contents(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto read = ::pread(
            descriptor.get(),
            contents.data() + consumed,
            contents.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(
                read < 0 ? system_error("read session policy")
                         : std::string{"session policy ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(read);
    }

    struct stat after{};

    if (::fstat(descriptor.get(), &after) != 0 || !same_file(before, after)) {
        return std::unexpected(std::string{"session policy changed while loading"});
    }
    return contents;
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
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto complete_limits(const resource_limits& limits) noexcept -> bool {
    return limits.cpu_time_ms != 0 && limits.memory_bytes != 0 && limits.pids != 0 &&
           limits.wall_time_ms != 0 && limits.disk_bytes != 0 && limits.terminal_output_bytes != 0;
}

auto unique_identifiers(const std::vector<std::string>& values) -> bool {
    std::set<std::string> seen;
    return std::ranges::all_of(values, [&](const auto& value) {
        return valid_identifier(value) && seen.insert(value).second;
    });
}

template<typename Value, typename Projection>
auto canonical_unique(const std::vector<Value>& values, Projection projection) -> bool {
    for (std::size_t index = 0; index < values.size(); ++index) {
        const std::string_view current = projection(values[index]);
        if (!valid_identifier(current)) {
            return false;
        }
        if (index != 0 && projection(values[index - 1]) >= current) {
            return false;
        }
    }
    return true;
}

auto parse_backend(std::string_view value) -> std::expected<sandbox_backend, std::string> {
    if (value == "linux_production") {
        return sandbox_backend::linux_production;
    }
    if (value == "remote_linux_container") {
        return sandbox_backend::remote_linux_container;
    }
    if (value == "apple_container") {
        return sandbox_backend::apple_container;
    }
    if (value == "macos_experimental") {
        return sandbox_backend::macos_experimental;
    }
    return std::unexpected(std::string{"unknown sandbox backend"});
}

auto parse_access(std::string_view value) -> std::expected<path_access, std::string> {
    if (value == "read") {
        return path_access::read;
    }
    if (value == "ephemeral_write") {
        return path_access::ephemeral_write;
    }
    if (value == "retained_write") {
        return path_access::retained_write;
    }
    if (value == "direct_write") {
        return path_access::direct_write;
    }
    return std::unexpected(std::string{"unknown path access"});
}

template<typename Plan>
auto validate_remote_constraints(const Plan& plan, sandbox_backend backend)
    -> std::expected<void, std::string> {
    if (backend != sandbox_backend::remote_linux_container) {
        return {};
    }
    if (!plan.secret_handles.empty()) {
        return std::unexpected(std::string{"remote runtimes do not accept secret handles"});
    }
    if (std::ranges::any_of(plan.path_grants, [](const auto& grant) {
            return grant.access == "direct_write" || grant.access == "retained_write";
        })) {
        return std::unexpected(
            std::string{"remote runtimes do not accept direct or retained writes"}
        );
    }
    return {};
}

auto parse_materialization(std::string_view value)
    -> std::expected<path_materialization, std::string> {
    if (value == "bind") {
        return path_materialization::bind;
    }
    if (value == "snapshot") {
        return path_materialization::snapshot;
    }
    if (value == "git_worktree") {
        return path_materialization::git_worktree;
    }
    if (value == "copy") {
        return path_materialization::copy;
    }
    return std::unexpected(std::string{"unknown path materialization"});
}

auto parse_cleanup(std::string_view value) -> std::expected<path_cleanup_policy, std::string> {
    if (value == "remove") {
        return path_cleanup_policy::remove;
    }
    if (value == "retain") {
        return path_cleanup_policy::retain;
    }
    return std::unexpected(std::string{"unknown path cleanup policy"});
}

auto parse_create_policy(std::string_view value) -> std::expected<path_create_policy, std::string> {
    if (value == "never") {
        return path_create_policy::never;
    }
    if (value == "empty_directory") {
        return path_create_policy::empty_directory;
    }
    if (value == "git_worktree") {
        return path_create_policy::git_worktree;
    }
    return std::unexpected(std::string{"unknown path create policy"});
}

auto parse_host_cleanup(std::string_view value) -> std::expected<path_cleanup_policy, std::string> {
    if (value == "retain") {
        return path_cleanup_policy::retain;
    }
    if (value == "remove") {
        return path_cleanup_policy::remove;
    }
    return std::unexpected(std::string{"unknown host path cleanup policy"});
}

auto contains(const std::vector<std::string>& values, std::string_view value) -> bool {
    return std::ranges::find(values, value) != values.end();
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto valid_projection_destination_path(std::string_view raw) -> bool {
    const std::filesystem::path target{raw};
    if (!target.is_absolute() || target == target.root_path() ||
        target.lexically_normal() != target) {
        return false;
    }
    constexpr std::array<std::string_view, 6> reserved = {
        "/dev", "/proc", "/run", "/sys", "/tmp", "/var/tmp"
    };
    return std::ranges::none_of(reserved, [&](std::string_view candidate) {
        const std::filesystem::path reserved_path{candidate};
        return path_within(target, reserved_path) || path_within(reserved_path, target);
    });
}

auto remaining_whole_seconds(std::uint64_t expires_at_ms, std::uint64_t now_ms) -> std::uint64_t {
    return (expires_at_ms - now_ms) / 1'000U;
}

auto valid_projection_destinations(
    const std::vector<library_projection_destination_policy>& destinations
) -> bool {
    if (destinations.size() > max_projection_destinations) {
        return false;
    }
    std::set<std::string> aliases;
    std::vector<std::filesystem::path> targets;
    targets.reserve(destinations.size());
    for (const auto& destination : destinations) {
        if (!valid_identifier(destination.alias) ||
            !valid_projection_destination_path(destination.target_path) ||
            !aliases.insert(destination.alias).second) {
            return false;
        }
        const std::filesystem::path target{destination.target_path};
        if (std::ranges::any_of(targets, [&](const auto& existing) {
                return path_within(target, existing) || path_within(existing, target);
            })) {
            return false;
        }
        targets.push_back(target);
    }
    return true;
}

auto validate_runtime_policy(const runtime_template_policy& runtime)
    -> std::expected<void, std::string> {
    if (!valid_identifier(runtime.runtime_template_id)) {
        return std::unexpected(std::string{"runtime_template_id is invalid"});
    }
    if (!valid_identifier(runtime.runtime_id)) {
        return std::unexpected(std::string{"runtime_id is invalid"});
    }
    if (!valid_digest(runtime.adapter_command_digest)) {
        return std::unexpected(std::string{"adapter_command_digest must be lowercase SHA-256"});
    }
    if (!unique_identifiers(runtime.allowed_path_aliases)) {
        return std::unexpected(
            std::string{"allowed_path_aliases must be canonical unique identifiers"}
        );
    }
    if (!unique_identifiers(runtime.allowed_projection_destinations)) {
        return std::unexpected(
            std::string{"allowed_projection_destinations must be canonical unique identifiers"}
        );
    }
    if (runtime.adoption) {
        if (auto valid = validate_native_harness_adoption_policy(*runtime.adoption); !valid) {
            return std::unexpected(valid.error());
        }
    }
    if (!runtime.launch) {
        return {};
    }
    if (!runtime.launch->runtime_discovery.empty() &&
        runtime.launch->runtime_discovery != runtime.runtime_id) {
        return std::unexpected(std::string{"launch.runtime_discovery must match runtime_id"});
    }
    auto digest = runtime_launch_template_digest(*runtime.launch);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (*digest != runtime.adapter_command_digest) {
        return std::unexpected("adapter_command_digest mismatch: expected " + *digest);
    }
    return {};
}

auto validate_path_projection(
    const wire::session_plan& plan,
    const runtime_template_policy& runtime,
    const path_alias_registry& paths,
    std::uint64_t now_ms
) -> std::expected<void, std::string> {
    if (!canonical_unique(plan.path_grants, [](const auto& grant) -> std::string_view {
            return grant.alias;
        })) {
        return std::unexpected(std::string{"session path grants are not canonical"});
    }
    const auto remaining_ttl_ms = plan.expires_at_ms - now_ms;
    const auto remaining_ttl_secs =
        remaining_ttl_ms / 1'000U + static_cast<std::uint64_t>(remaining_ttl_ms % 1'000U != 0);
    for (const auto& grant : plan.path_grants) {
        if (!contains(runtime.allowed_path_aliases, grant.alias) ||
            grant.ttl_secs > remaining_ttl_secs) {
            return std::unexpected(std::string{"session path alias is not allowed for runtime"});
        }
        auto access = parse_access(grant.access);
        auto materialization = parse_materialization(grant.materialization);
        auto cleanup = parse_cleanup(grant.cleanup_policy);
        if (!access || !materialization || !cleanup) {
            return std::unexpected(std::string{"session path grant has unknown policy values"});
        }
        if (*access == path_access::retained_write) {
            return std::unexpected(
                std::string{"retained-write requires a versioned v2 exposure grant"}
            );
        }
        auto valid = paths.validate_plan(
            path_grant_plan_request{
                .grant =
                    path_grant_request{
                        .alias = grant.alias,
                        .access = *access,
                        .ttl_secs = grant.ttl_secs,
                        .max_bytes = grant.max_bytes,
                    },
                .materialization = *materialization,
                .cleanup_policy = *cleanup,
            }
        );
        if (!valid) {
            return std::unexpected(valid.error());
        }
    }
    return {};
}

auto validate_path_projection(
    const wire::session_plan_v2& plan,
    const runtime_template_policy& runtime,
    const path_exposure_registry* exposures,
    std::uint64_t now_ms
) -> std::expected<void, std::string> {
    if (exposures == nullptr) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    if (!canonical_unique(plan.path_grants, [](const auto& grant) -> std::string_view {
            return grant.exposure_id;
        })) {
        return std::unexpected(std::string{"session exposure grants are not canonical"});
    }
    const auto remaining_ttl_secs = remaining_whole_seconds(plan.expires_at_ms, now_ms);
    for (const auto& grant : plan.path_grants) {
        auto access = parse_access(grant.access);
        auto materialization = parse_materialization(grant.materialization);
        auto cleanup = parse_cleanup(grant.cleanup_policy);
        if (!access || !materialization || !cleanup || grant.ttl_secs > remaining_ttl_secs) {
            return std::unexpected(std::string{"session exposure grant is invalid"});
        }
        auto valid = exposures->validate_grant(
            path_exposure_grant{
                .exposure_id = grant.exposure_id,
                .generation = grant.generation,
                .scope_digest = grant.scope_digest,
                .access = *access,
                .materialization = *materialization,
                .max_bytes = grant.max_bytes,
                .ttl_secs = grant.ttl_secs,
                .cleanup_policy = *cleanup,
            },
            runtime.runtime_template_id,
            now_ms
        );
        if (!valid) {
            return std::unexpected(valid.error());
        }
    }
    return {};
}

auto plan_schema_version(std::string_view plan_json) -> result<std::uint8_t> {
    wire::session_plan_header header;
    if (const auto error = read_untrusted_json<header_read_options>(header, plan_json);
        error || header.schema_version == 0) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    return header.schema_version;
}

auto common_v1_plan(const wire::session_plan_v2& plan) -> wire::session_plan {
    return wire::session_plan{
        .schema_version = 1,
        .runtime_id = plan.runtime_id,
        .runtime_template_id = plan.runtime_template_id,
        .adapter_command_digest = plan.adapter_command_digest,
        .sandbox_backend = plan.sandbox_backend,
        .egress_policy_id = plan.egress_policy_id,
        .tool_policy_id = plan.tool_policy_id,
        .path_grants = {},
        .library_projections = plan.library_projections,
        .secret_handles = plan.secret_handles,
        .limits = plan.limits,
        .policy_revision = plan.policy_revision,
        .expires_at_ms = plan.expires_at_ms,
        .refinement = plan.refinement,
    };
}

auto valid_refinement_projection(const container::refinement_projection_binding& projection)
    -> bool {
    return valid_identifier(projection.projection_id) && valid_digest(projection.content_digest) &&
           valid_identifier(projection.destination_alias);
}

auto validate_refinement_plan(
    const wire::session_plan& plan, const runtime_template_policy& runtime
) -> std::expected<void, std::string> {
    const bool refinement_runtime =
        plan.runtime_template_id == container::refinement_runtime_template_id;
    if (!refinement_runtime) {
        if (plan.refinement) {
            return std::unexpected(std::string{"refinement binding requires refinement-eval-v1"});
        }
        return {};
    }
    if (runtime.backend != sandbox_backend::linux_production || !plan.refinement ||
        plan.refinement->schema_version != 1 || !plan.path_grants.empty() ||
        !valid_refinement_projection(plan.refinement->fixture) ||
        !valid_refinement_projection(plan.refinement->base) ||
        !valid_refinement_projection(plan.refinement->candidate) ||
        !valid_digest(plan.refinement->matched_context_digest) ||
        plan.refinement->fixture.projection_id == plan.refinement->base.projection_id ||
        plan.refinement->fixture.projection_id == plan.refinement->candidate.projection_id ||
        plan.refinement->base.projection_id == plan.refinement->candidate.projection_id) {
        return std::unexpected(std::string{"invalid refinement evaluation binding"});
    }
    const auto& selected = plan.refinement->variant == container::refinement_variant::base
                               ? plan.refinement->base
                               : plan.refinement->candidate;
    if (plan.library_projections.size() != 2U) {
        return std::unexpected(
            std::string{"refinement evaluation requires fixture and selected skill projections"}
        );
    }
    const auto matches = [&](const container::refinement_projection_binding& expected) {
        return std::ranges::any_of(plan.library_projections, [&](const auto& actual) {
            return actual.projection_id == expected.projection_id &&
                   actual.content_digest == expected.content_digest &&
                   actual.destination_alias == expected.destination_alias;
        });
    };
    if (!matches(plan.refinement->fixture) || !matches(selected)) {
        return std::unexpected(
            std::string{"refinement projections do not match the execution binding"}
        );
    }
    return {};
}

auto refinement_plan_context_digest(const wire::session_plan& plan)
    -> std::expected<std::string, std::string> {
    if (!plan.refinement) {
        return std::unexpected(std::string{"refinement plan binding is unavailable"});
    }
    launch_template_encoder encoder;
    encoder.append_string("glove.refinement-plan-context");
    encoder.append_u8(1);
    encoder.append_string(plan.runtime_id);
    encoder.append_string(plan.runtime_template_id);
    encoder.append_string(plan.adapter_command_digest);
    encoder.append_string(plan.sandbox_backend);
    encoder.append_string(plan.egress_policy_id);
    encoder.append_string(plan.tool_policy_id);
    encoder.append_u32(static_cast<std::uint32_t>(plan.secret_handles.size()));
    for (const auto& handle : plan.secret_handles) {
        encoder.append_string(handle);
    }
    encoder.append_u64(plan.limits.cpu_time_ms);
    encoder.append_u64(plan.limits.memory_bytes);
    encoder.append_u32(plan.limits.pids);
    encoder.append_u64(plan.limits.wall_time_ms);
    encoder.append_u64(plan.limits.disk_bytes);
    encoder.append_u64(plan.limits.terminal_output_bytes);
    encoder.append_u64(plan.policy_revision);
    for (const auto& projection : {plan.refinement->base, plan.refinement->candidate}) {
        encoder.append_string(projection.projection_id);
        encoder.append_string(projection.content_digest);
        encoder.append_string(projection.destination_alias);
    }
    return container::sha256_hex(encoder.bytes());
}

auto validate_library_projection(
    const wire::session_plan& plan, const runtime_template_policy& runtime
) -> std::expected<void, std::string> {
    if (!canonical_unique(plan.library_projections, [](const auto& projection) -> std::string_view {
            return projection.projection_id;
        })) {
        return std::unexpected(std::string{"session library projections are not canonical"});
    }
    for (const auto& projection : plan.library_projections) {
        if (!valid_digest(projection.content_digest) ||
            !valid_identifier(projection.destination_alias) ||
            !contains(runtime.allowed_projection_destinations, projection.destination_alias)) {
            return std::unexpected(std::string{"session library projection is not authorized"});
        }
    }
    return {};
}

auto validate_secret_projection(const wire::session_plan& plan, const session_plan_policy& policy)
    -> std::expected<void, std::string> {
    if (!canonical_unique(
            plan.secret_handles, [](const auto& handle) -> std::string_view { return handle; }
        ) ||
        std::ranges::any_of(plan.secret_handles, [&](const auto& handle) {
            return !contains(policy.secret_handles, handle);
        })) {
        return std::unexpected(std::string{"session secret handles are not authorized"});
    }
    return {};
}

auto valid_egress_policies(const session_plan_policy& policy) -> bool {
    if (policy.egress_policies.size() > max_policy_identifiers) {
        return false;
    }
    std::set<std::string> identifiers;
    for (const auto& egress : policy.egress_policies) {
        if (!valid_identifier(egress.policy_id) ||
            !contains(policy.egress_policy_ids, egress.policy_id) ||
            !identifiers.insert(egress.policy_id).second ||
            egress.targets.size() > max_egress_targets) {
            return false;
        }
        std::set<std::pair<std::string, std::uint16_t>> targets;
        for (const auto& target : egress.targets) {
            if (target.host.empty() || target.host.size() > 253U || target.port == 0 ||
                target.host.find('\0') != std::string::npos ||
                std::ranges::any_of(
                    target.host, [](unsigned char byte) { return byte <= 0x20U || byte == 0x7fU; }
                ) ||
                !targets.emplace(target.host, target.port).second) {
                return false;
            }
        }
    }
    return true;
}

auto valid_secret_mounts(const session_plan_policy& policy) -> bool {
    if (policy.secret_mounts.size() > max_policy_identifiers) {
        return false;
    }
    std::set<std::string> handles;
    std::set<std::pair<std::string, std::string>> targets;
    const std::filesystem::path managed_home{"/home/agent"};
    for (const auto& secret : policy.secret_mounts) {
        const std::filesystem::path source{secret.source_path};
        const std::filesystem::path target{secret.target_path};
        const bool runtime_exists =
            std::ranges::any_of(policy.runtime_templates, [&](const auto& runtime) {
                return runtime.runtime_id == secret.runtime_id;
            });
        if (!valid_identifier(secret.handle) || secret.handle.size() > 120U ||
            !valid_identifier(secret.runtime_id) ||
            !contains(policy.secret_handles, secret.handle) || !runtime_exists ||
            !source.is_absolute() || source == source.root_path() ||
            source.lexically_normal() != source || !target.is_absolute() ||
            target.lexically_normal() != target || target == managed_home ||
            !path_within(target, managed_home) || !handles.insert(secret.handle).second ||
            !targets.emplace(secret.runtime_id, secret.target_path).second) {
            return false;
        }
    }
    return true;
}

} // namespace

auto validate_runtime_launch_template(const runtime_launch_template& launch) -> result<void> {
    return validate_runtime_launch_template_impl(launch);
}

auto runtime_launch_template_digest(const runtime_launch_template& launch) -> result<std::string> {
    if (auto valid = validate_runtime_launch_template_impl(launch); !valid) {
        return std::unexpected(valid.error());
    }
    launch_template_encoder encoder;
    encoder.append_string("glove.runtime-launch-template");
    // Preserve v1 commitments for existing pinned policies. Discovery has a
    // separate version so its search surface is committed explicitly.
    encoder.append_u8(launch.runtime_discovery.empty() ? std::uint8_t{1} : std::uint8_t{2});
    if (!launch.runtime_discovery.empty()) {
        encoder.append_string(launch.runtime_discovery);
        encoder.append_u32(static_cast<std::uint32_t>(launch.executable_search_paths.size()));
        for (const auto& path : launch.executable_search_paths) {
            encoder.append_string(path);
        }
    }
    encoder.append_string(launch.executable_path);
    encoder.append_u32(static_cast<std::uint32_t>(launch.arguments.size()));
    for (const auto& argument : launch.arguments) {
        encoder.append_string(argument);
    }
    encoder.append_u32(static_cast<std::uint32_t>(launch.environment.size()));
    for (const auto& environment : launch.environment) {
        encoder.append_string(environment);
    }
    encoder.append_u32(static_cast<std::uint32_t>(launch.read_only_paths.size()));
    for (const auto& path : launch.read_only_paths) {
        encoder.append_string(path);
    }
    return container::sha256_hex(encoder.bytes());
}

auto resolve_runtime_executable(const runtime_launch_template& launch) -> result<std::string> {
    if (auto valid = validate_runtime_launch_template_impl(launch); !valid) {
        return std::unexpected(valid.error());
    }
    if (launch.runtime_discovery.empty()) {
        return launch.executable_path;
    }
    // This name is adapter-owned. It is not supplied by the Sage plan or
    // arbitrary policy data, and the final resolved file is identity-pinned by
    // managed launch binding before it is executed.
    const auto adapter = native_skill_runtime_adapter_for(launch.runtime_discovery);
    if (!adapter) {
        return std::unexpected(std::string{"runtime discovery adapter is unavailable"});
    }
    // Discovery is intentionally never delegated to the inherited PATH. Every
    // directory is an explicit, digest-bound operator policy value.
    std::vector<std::string> diagnostics;
    diagnostics.reserve(launch.executable_search_paths.size());
    for (const auto& configured_root : launch.executable_search_paths) {
        const auto failure = [&](std::string reason) {
            diagnostics.push_back(configured_root + ": " + std::move(reason));
        };
        std::error_code error;
        const auto root = std::filesystem::canonical(configured_root, error);
        if (error) {
            failure("cannot canonicalize directory (" + error.message() + ")");
            continue;
        }
        if (!std::filesystem::is_directory(root, error) || error) {
            failure(
                error ? "cannot inspect directory (" + error.message() + ")" : "is not a directory"
            );
            continue;
        }
        // All path components must be controlled by the service account (or
        // root) and may not be writable by another principal. A root-owned
        // sticky directory such as /tmp is safe as an ancestor: an unprivileged
        // user cannot rename this service-owned child from it.
        bool trusted = true;
        for (auto current = root;; current = current.parent_path()) {
            struct stat directory_status{};
            if (::stat(current.c_str(), &directory_status) != 0 ||
                !S_ISDIR(directory_status.st_mode)) {
                failure("cannot inspect trusted ancestor " + current.string());
                trusted = false;
                break;
            }
            if (directory_status.st_uid != 0 && directory_status.st_uid != ::geteuid()) {
                failure(
                    "ancestor " + current.string() + " is not owned by root or the service user"
                );
                trusted = false;
                break;
            }
            const bool writable_by_other = (directory_status.st_mode & (S_IWGRP | S_IWOTH)) != 0;
            const bool root_owned_sticky =
                directory_status.st_uid == 0 && (directory_status.st_mode & S_ISVTX) != 0;
            if (writable_by_other && !root_owned_sticky) {
                failure("ancestor " + current.string() + " is writable by another principal");
                trusted = false;
                break;
            }
            if (current == current.root_path()) {
                break;
            }
        }
        if (!trusted) {
            continue;
        }
        const std::filesystem::path candidate = root / adapter->executable_name;
        const auto status = std::filesystem::status(candidate, error);
        if (error) {
            failure(
                "cannot inspect expected executable " + candidate.string() + " (" +
                error.message() + ")"
            );
            continue;
        }
        if (!std::filesystem::is_regular_file(status)) {
            failure("expected executable is not a regular file: " + candidate.string());
            continue;
        }
        const auto permissions = status.permissions();
        if ((permissions &
             (std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec |
              std::filesystem::perms::others_exec)) == std::filesystem::perms::none) {
            failure("expected executable is not executable: " + candidate.string());
            continue;
        }
        const auto resolved = std::filesystem::canonical(candidate, error);
        if (!error && valid_launch_path(resolved.string())) {
            return resolved.string();
        }
        failure(
            error ? "cannot canonicalize executable (" + error.message() + ")"
                  : "resolved executable path is invalid"
        );
    }
    std::string message =
        std::string{"operator-installed "} + adapter->runtime_id + " executable is unavailable";
    if (!diagnostics.empty()) {
        message.append(": ");
        for (std::size_t index = 0; index < diagnostics.size(); ++index) {
            if (index != 0) {
                message.append("; ");
            }
            message.append(diagnostics[index]);
        }
    }
    return std::unexpected(std::move(message));
}

auto session_plan_validator::load(
    const std::filesystem::path& policy_path,
    std::shared_ptr<const path_exposure_registry> exposures
) -> result<session_plan_validator> {
    auto contents = load_policy_file(policy_path);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    wire::session_plan_policy encoded;
    if (const auto error = glz::read<strict_read_options>(encoded, *contents); error) {
        return std::unexpected(
            std::string{"invalid session policy JSON: "} + glz::format_error(error, *contents)
        );
    }
    if (encoded.schema_version != 1) {
        return std::unexpected(
            "schema_version must be 1, got " + std::to_string(encoded.schema_version)
        );
    }
    if (encoded.runtime_templates.empty() ||
        encoded.runtime_templates.size() > max_runtime_templates || encoded.path_aliases.empty() ||
        encoded.path_aliases.size() > max_path_grants || encoded.resource_profiles.empty() ||
        encoded.resource_profiles.size() > max_resource_profiles ||
        encoded.library_projection_destinations.size() > max_projection_destinations ||
        encoded.egress_policy_ids.size() > max_policy_identifiers ||
        encoded.tool_policy_ids.size() > max_policy_identifiers ||
        encoded.secret_handles.size() > max_policy_identifiers ||
        encoded.egress_policies.size() > max_policy_identifiers ||
        encoded.secret_mounts.size() > max_policy_identifiers) {
        return std::unexpected(std::string{"session policy collection exceeds its bound"});
    }

    std::vector<runtime_template_policy> runtimes;
    runtimes.reserve(encoded.runtime_templates.size());
    for (auto& runtime : encoded.runtime_templates) {
        auto backend = parse_backend(runtime.sandbox_backend);
        if (!backend) {
            return std::unexpected(backend.error());
        }
        runtimes.push_back(
            runtime_template_policy{
                .runtime_template_id = std::move(runtime.runtime_template_id),
                .runtime_id = std::move(runtime.runtime_id),
                .adapter_command_digest = std::move(runtime.adapter_command_digest),
                .backend = *backend,
                .allowed_path_aliases = std::move(runtime.allowed_path_aliases),
                .allowed_projection_destinations =
                    std::move(runtime.allowed_projection_destinations),
                .launch = std::exchange(runtime.launch, std::nullopt),
                .adoption = runtime.adoption,
            }
        );
    }

    std::vector<path_alias_policy> paths;
    paths.reserve(encoded.path_aliases.size());
    for (auto& path : encoded.path_aliases) {
        std::vector<path_access_policy> access;
        access.reserve(path.access.size());
        for (auto& mode : path.access) {
            auto access_mode = parse_access(mode.access);
            auto materialization = parse_materialization(mode.materialization);
            auto create_policy = parse_create_policy(mode.create_policy);
            auto cleanup_policy = parse_host_cleanup(mode.cleanup_policy);
            if (!access_mode || !materialization || !create_policy || !cleanup_policy) {
                return std::unexpected(std::string{"invalid host path access policy"});
            }
            access.push_back(
                path_access_policy{
                    .access = *access_mode,
                    .materialization = *materialization,
                    .create_policy = *create_policy,
                    .cleanup_policy = *cleanup_policy,
                    .max_bytes = mode.max_bytes,
                }
            );
        }
        paths.push_back(
            path_alias_policy{
                .alias = std::move(path.alias),
                .host_path = std::move(path.host_path),
                .target_path = std::move(path.target_path),
                .max_ttl_secs = path.max_ttl_secs,
                .access = std::move(access),
            }
        );
    }
    auto path_registry = path_alias_registry::build(std::move(paths));
    if (!path_registry) {
        return std::unexpected(path_registry.error());
    }
    std::vector<library_projection_destination_policy> projection_destinations;
    projection_destinations.reserve(encoded.library_projection_destinations.size());
    for (auto& destination : encoded.library_projection_destinations) {
        projection_destinations.push_back({
            .alias = std::move(destination.alias),
            .target_path = std::move(destination.target_path),
        });
    }
    std::set<std::string> resource_profile_ids;
    std::vector<resource_limits> resource_profiles;
    resource_profiles.reserve(encoded.resource_profiles.size());
    for (const auto& profile : encoded.resource_profiles) {
        auto limits = profile.limits();
        if (!valid_identifier(profile.profile_id) ||
            !resource_profile_ids.insert(profile.profile_id).second || !complete_limits(limits) ||
            std::ranges::find(resource_profiles, limits) != resource_profiles.end()) {
            return std::unexpected(std::string{"session plan resource policy is invalid"});
        }
        resource_profiles.push_back(limits);
    }
    std::vector<egress_policy> egress_policies;
    egress_policies.reserve(encoded.egress_policies.size());
    for (auto& egress : encoded.egress_policies) {
        std::vector<egress_target_policy> targets;
        targets.reserve(egress.targets.size());
        for (auto& target : egress.targets) {
            targets.push_back({
                .host = std::move(target.host),
                .port = target.port,
                .allow_private = target.allow_private,
            });
        }
        egress_policies.push_back({
            .policy_id = std::move(egress.policy_id),
            .targets = std::move(targets),
        });
    }
    std::vector<secret_mount_policy> secret_mounts;
    secret_mounts.reserve(encoded.secret_mounts.size());
    for (auto& secret : encoded.secret_mounts) {
        secret_mounts.push_back({
            .handle = std::move(secret.handle),
            .runtime_id = std::move(secret.runtime_id),
            .source_path = std::move(secret.source_path),
            .target_path = std::move(secret.target_path),
        });
    }
    return build(
        session_plan_policy{
            .revision = encoded.revision,
            .max_plan_ttl_ms = encoded.max_plan_ttl_ms,
            .runtime_templates = std::move(runtimes),
            .library_projection_destinations = std::move(projection_destinations),
            .resource_profiles = std::move(resource_profiles),
            .egress_policy_ids = std::move(encoded.egress_policy_ids),
            .tool_policy_ids = std::move(encoded.tool_policy_ids),
            .secret_handles = std::move(encoded.secret_handles),
            .egress_policies = std::move(egress_policies),
            .secret_mounts = std::move(secret_mounts),
        },
        std::move(*path_registry),
        std::move(exposures)
    );
}

auto session_plan_validator::build(
    session_plan_policy policy,
    path_alias_registry paths,
    std::shared_ptr<const path_exposure_registry> exposures
) -> result<session_plan_validator> {
    if (policy.revision == 0 || policy.max_plan_ttl_ms == 0 || policy.runtime_templates.empty() ||
        policy.runtime_templates.size() > max_runtime_templates || paths.size() == 0 ||
        paths.size() > max_path_grants || policy.resource_profiles.empty() ||
        policy.resource_profiles.size() > max_resource_profiles ||
        policy.egress_policy_ids.size() > max_policy_identifiers ||
        policy.tool_policy_ids.size() > max_policy_identifiers ||
        policy.secret_handles.size() > max_policy_identifiers ||
        !valid_projection_destinations(policy.library_projection_destinations) ||
        !unique_identifiers(policy.egress_policy_ids) ||
        !unique_identifiers(policy.tool_policy_ids) || !unique_identifiers(policy.secret_handles) ||
        !valid_egress_policies(policy) || !valid_secret_mounts(policy)) {
        return std::unexpected(std::string{"session plan policy is incomplete"});
    }

    std::set<std::string> runtime_templates;
    for (std::size_t index = 0; index < policy.runtime_templates.size(); ++index) {
        const auto& runtime = policy.runtime_templates[index];
        if (auto valid = validate_runtime_policy(runtime); !valid) {
            return std::unexpected(
                "runtime_templates[" + std::to_string(index) + "]: " + valid.error()
            );
        }
        if (std::ranges::any_of(runtime.allowed_projection_destinations, [&](const auto& alias) {
                return std::ranges::none_of(
                    policy.library_projection_destinations,
                    [&](const auto& destination) { return destination.alias == alias; }
                );
            })) {
            return std::unexpected(
                "runtime_templates[" + std::to_string(index) +
                "].allowed_projection_destinations contains an unknown alias"
            );
        }
        if (!runtime_templates.insert(runtime.runtime_template_id).second) {
            return std::unexpected(
                "runtime_templates[" + std::to_string(index) + "].runtime_template_id is duplicated"
            );
        }
    }

    for (std::size_t index = 0; index < policy.resource_profiles.size(); ++index) {
        const auto& profile = policy.resource_profiles[index];
        const bool plan_outlives_sandbox =
            profile.wall_time_ms <= std::numeric_limits<std::uint64_t>::max() - 1'000U &&
            policy.max_plan_ttl_ms >= profile.wall_time_ms + 1'000U;
        if (!complete_limits(profile) || !plan_outlives_sandbox ||
            std::ranges::find(
                policy.resource_profiles.begin(),
                policy.resource_profiles.begin() + static_cast<std::ptrdiff_t>(index),
                profile
            ) != policy.resource_profiles.begin() + static_cast<std::ptrdiff_t>(index)) {
            return std::unexpected(
                plan_outlives_sandbox
                    ? std::string{"session plan resource policy is invalid"}
                    : std::string{
                          "session plan policy TTL must outlive every sandbox wall limit by at "
                          "least one second"
                      }
            );
        }
    }

    session_plan_validator validator;
    validator.policy_ = std::move(policy);
    validator.paths_ = std::move(paths);
    validator.exposures_ = std::move(exposures);
    return validator;
}

auto session_plan_validator::validate_json(std::string_view plan_json, std::uint64_t now_ms) const
    -> result<session_plan_validation> {
    auto schema = plan_schema_version(plan_json);
    if (!schema) {
        return std::unexpected(schema.error());
    }
    if (*schema == 2) {
        wire::session_plan_v2 plan;
        if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json);
            error || plan.schema_version != 2 || plan.path_grants.size() > max_path_grants) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        auto common_json = glz::write_json(common_v1_plan(plan));
        if (!common_json) {
            return std::unexpected(std::string{"session plan validation encoding failed"});
        }
        if (auto common = validate_json(*common_json, now_ms); !common) {
            return std::unexpected(common.error());
        }
        const auto runtime =
            std::ranges::find_if(policy_.runtime_templates, [&](const auto& candidate) {
                return candidate.runtime_template_id == plan.runtime_template_id;
            });
        if (runtime == policy_.runtime_templates.end()) {
            return std::unexpected(std::string{"session plan runtime projection is unavailable"});
        }
        if (auto remote = validate_remote_constraints(plan, runtime->backend); !remote) {
            return std::unexpected(remote.error());
        }
        if (auto paths = validate_path_projection(plan, *runtime, exposures_.get(), now_ms);
            !paths) {
            return std::unexpected(paths.error());
        }
        return session_plan_validation{
            .schema_version = 2,
            .policy_revision = policy_.revision,
        };
    }
    if (*schema != 1) {
        return std::unexpected(std::string{"unsupported session plan schema"});
    }
    wire::session_plan plan;
    if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    if (plan.schema_version != 1 || plan.policy_revision != policy_.revision ||
        plan.expires_at_ms <= now_ms || plan.expires_at_ms - now_ms > policy_.max_plan_ttl_ms) {
        return std::unexpected(std::string{"session plan version, revision, or expiry is invalid"});
    }
    if (!valid_identifier(plan.runtime_id) || !valid_identifier(plan.runtime_template_id) ||
        !valid_digest(plan.adapter_command_digest) || !valid_identifier(plan.egress_policy_id) ||
        !valid_identifier(plan.tool_policy_id) || !complete_limits(plan.limits)) {
        return std::unexpected(std::string{"session plan contains invalid authority identifiers"});
    }
    if (plan.path_grants.size() > max_path_grants ||
        plan.library_projections.size() > max_library_projections ||
        plan.secret_handles.size() > max_secret_handles) {
        return std::unexpected(std::string{"session plan collection exceeds its bound"});
    }

    const auto runtime_entry =
        std::ranges::find_if(policy_.runtime_templates, [&](const auto& runtime) {
            return runtime.runtime_template_id == plan.runtime_template_id;
        });
    auto backend = parse_backend(plan.sandbox_backend);
    if (runtime_entry == policy_.runtime_templates.end() || !backend ||
        runtime_entry->runtime_id != plan.runtime_id ||
        runtime_entry->adapter_command_digest != plan.adapter_command_digest ||
        runtime_entry->backend != *backend) {
        return std::unexpected(std::string{"session plan runtime projection is not authorized"});
    }
    if (auto remote = validate_remote_constraints(plan, *backend); !remote) {
        return std::unexpected(remote.error());
    }
    if (!contains(policy_.egress_policy_ids, plan.egress_policy_id) ||
        !contains(policy_.tool_policy_ids, plan.tool_policy_id) ||
        std::ranges::find(policy_.resource_profiles, plan.limits) ==
            policy_.resource_profiles.end()) {
        return std::unexpected(std::string{"session plan policy projection is not authorized"});
    }

    if (auto paths = validate_path_projection(plan, *runtime_entry, paths_, now_ms); !paths) {
        return std::unexpected(paths.error());
    }
    if (auto libraries = validate_library_projection(plan, *runtime_entry); !libraries) {
        return std::unexpected(libraries.error());
    }
    if (auto refinement = validate_refinement_plan(plan, *runtime_entry); !refinement) {
        return std::unexpected(refinement.error());
    }
    if (auto secrets = validate_secret_projection(plan, policy_); !secrets) {
        return std::unexpected(secrets.error());
    }

    return session_plan_validation{
        .schema_version = 1,
        .policy_revision = policy_.revision,
    };
}

auto session_plan_validator::canonicalize_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<validated_session_plan_document> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    if (validation->schema_version == 2) {
        wire::session_plan_v2 plan;
        if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        auto canonical_json = glz::write_json(plan);
        if (!canonical_json) {
            return std::unexpected(std::string{"session plan canonical encoding failed"});
        }
        return validated_session_plan_document{
            .validation = *validation,
            .expires_at_ms = plan.expires_at_ms,
            .canonical_json = std::move(*canonical_json),
        };
    }
    wire::session_plan plan;
    if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    auto canonical_json = glz::write_json(plan);
    if (!canonical_json) {
        return std::unexpected(std::string{"session plan canonical encoding failed"});
    }
    return validated_session_plan_document{
        .validation = *validation,
        .expires_at_ms = plan.expires_at_ms,
        .canonical_json = std::move(*canonical_json),
    };
}

auto session_plan_validator::resolve_runtime_launch_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<runtime_launch_projection> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    wire::session_plan plan;
    if (validation->schema_version == 2) {
        wire::session_plan_v2 v2;
        if (const auto error = read_untrusted_json<strict_read_options>(v2, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        plan = common_v1_plan(v2);
    } else if (
        const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error
    ) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    const auto runtime =
        std::ranges::find_if(policy_.runtime_templates, [&](const auto& candidate) {
            return candidate.runtime_template_id == plan.runtime_template_id;
        });
    if (runtime == policy_.runtime_templates.end() || !runtime->launch) {
        return std::unexpected(std::string{"runtime launch template is unavailable"});
    }
    const runtime_launch_template launch = runtime->launch.value_or(runtime_launch_template{});
    auto executable = resolve_runtime_executable(launch);
    if (!executable) {
        return std::unexpected(executable.error());
    }
    std::vector<std::string> argv;
    const auto adapter = native_skill_runtime_adapter_for(runtime->runtime_id);
    if (adapter &&
        (adapter->managed_arguments.size() > max_launch_fields - launch.arguments.size() ||
         std::ranges::any_of(adapter->managed_arguments, [&](const auto& managed) {
             return std::ranges::find(launch.arguments, managed) != launch.arguments.end();
         }))) {
        return std::unexpected(
            std::string{"runtime launch conflicts with managed adapter arguments"}
        );
    }
    argv.reserve(launch.arguments.size() + 1U + (adapter ? adapter->managed_arguments.size() : 0U));
    argv.push_back(std::move(*executable));
    argv.insert(argv.end(), launch.arguments.begin(), launch.arguments.end());
    if (adapter) {
        argv.insert(
            argv.end(), adapter->managed_arguments.begin(), adapter->managed_arguments.end()
        );
    }
    std::vector<egress_target_policy> egress_targets;
    const auto egress = std::ranges::find_if(policy_.egress_policies, [&](const auto& candidate) {
        return candidate.policy_id == plan.egress_policy_id;
    });
    if (egress != policy_.egress_policies.end()) {
        egress_targets = egress->targets;
    } else if (plan.egress_policy_id != "no-network" && plan.egress_policy_id != "deny-all") {
        return std::unexpected(std::string{"runtime egress policy is unavailable"});
    }
    std::vector<secret_mount_policy> secret_mounts;
    secret_mounts.reserve(plan.secret_handles.size());
    for (const auto& handle : plan.secret_handles) {
        const auto secret = std::ranges::find_if(policy_.secret_mounts, [&](const auto& candidate) {
            return candidate.handle == handle && candidate.runtime_id == runtime->runtime_id;
        });
        if (secret == policy_.secret_mounts.end()) {
            return std::unexpected(std::string{"runtime secret broker is unavailable"});
        }
        secret_mounts.push_back(*secret);
    }
    std::optional<native_harness_adoption_identity> adoption;
    if (runtime->adoption) {
        auto resolved = resolve_native_harness_adoption(*runtime->adoption, runtime->runtime_id);
        if (!resolved) {
            return std::unexpected("resolve runtime adoption: " + resolved.error());
        }
        adoption = resolved->identity();
    }
    std::optional<container::refinement_execution_binding> refinement;
    if (plan.refinement) {
        auto plan_context = refinement_plan_context_digest(plan);
        if (!plan_context) {
            return std::unexpected(plan_context.error());
        }
        container::refinement_execution_binding execution;
        static_cast<container::refinement_plan_binding&>(execution) =
            container::refinement_plan_binding{
                .schema_version = plan.refinement->schema_version,
                .variant = plan.refinement->variant,
                .fixture = plan.refinement->fixture,
                .base = plan.refinement->base,
                .candidate = plan.refinement->candidate,
                .matched_context_digest = plan.refinement->matched_context_digest,
            };
        execution.plan_context_digest = std::move(*plan_context);
        refinement = std::move(execution);
    }
    return runtime_launch_projection{
        .validation = *validation,
        .runtime_id = runtime->runtime_id,
        .runtime_template_id = runtime->runtime_template_id,
        .adapter_command_digest = runtime->adapter_command_digest,
        .backend = runtime->backend,
        .argv = std::move(argv),
        .environment = launch.environment,
        .read_only_paths = launch.read_only_paths,
        .limits = plan.limits,
        .expires_at_ms = plan.expires_at_ms,
        .requires_direct_write_approval = std::ranges::any_of(
            plan.path_grants, [](const auto& grant) { return grant.access == "direct_write"; }
        ),
        .egress_policy_id = plan.egress_policy_id,
        .egress_targets = std::move(egress_targets),
        .secret_mounts = std::move(secret_mounts),
        .adoption = std::move(adoption),
        .refinement = std::move(refinement),
    };
}

auto session_plan_validator::resolve_native_harness_adoption_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<std::optional<resolved_native_harness_adoption>> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    wire::session_plan plan;
    if (validation->schema_version == 2) {
        wire::session_plan_v2 v2;
        if (const auto error = read_untrusted_json<strict_read_options>(v2, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        plan = common_v1_plan(v2);
    } else if (
        const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error
    ) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    const auto runtime =
        std::ranges::find_if(policy_.runtime_templates, [&](const auto& candidate) {
            return candidate.runtime_template_id == plan.runtime_template_id;
        });
    if (runtime == policy_.runtime_templates.end()) {
        return std::unexpected(std::string{"runtime template is unavailable"});
    }
    if (!runtime->adoption) {
        return std::optional<resolved_native_harness_adoption>{};
    }
    auto adoption = resolve_native_harness_adoption(*runtime->adoption, runtime->runtime_id);
    if (!adoption) {
        return std::unexpected("resolve runtime adoption: " + adoption.error());
    }
    return std::optional<resolved_native_harness_adoption>{std::move(*adoption)};
}

auto session_plan_validator::resolve_path_grants_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<std::vector<resolved_path_grant>> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    if (validation->schema_version == 2) {
        wire::session_plan_v2 plan;
        if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json);
            error || !exposures_) {
            return std::unexpected(std::string{"invalid session plan v2 path grants"});
        }
        std::vector<resolved_path_grant> resolved;
        resolved.reserve(plan.path_grants.size());
        for (const auto& grant : plan.path_grants) {
            auto access = parse_access(grant.access);
            auto materialization = parse_materialization(grant.materialization);
            auto cleanup = parse_cleanup(grant.cleanup_policy);
            if (!access || !materialization || !cleanup) {
                return std::unexpected(std::string{"session exposure grant is invalid"});
            }
            auto path = exposures_->resolve_grant(
                path_exposure_grant{
                    .exposure_id = grant.exposure_id,
                    .generation = grant.generation,
                    .scope_digest = grant.scope_digest,
                    .access = *access,
                    .materialization = *materialization,
                    .max_bytes = grant.max_bytes,
                    .ttl_secs = grant.ttl_secs,
                    .cleanup_policy = *cleanup,
                },
                plan.runtime_template_id,
                now_ms
            );
            if (!path) {
                return std::unexpected(path.error());
            }
            resolved.push_back(std::move(*path));
        }
        return resolved;
    }
    wire::session_plan plan;
    if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    std::vector<resolved_path_grant> resolved;
    resolved.reserve(plan.path_grants.size());
    for (const auto& grant : plan.path_grants) {
        auto access = parse_access(grant.access);
        if (!access) {
            return std::unexpected(access.error());
        }
        auto path = paths_.resolve(
            path_grant_request{
                .alias = grant.alias,
                .access = *access,
                .ttl_secs = grant.ttl_secs,
                .max_bytes = grant.max_bytes,
            }
        );
        if (!path) {
            return std::unexpected(path.error());
        }
        resolved.push_back(std::move(*path));
    }
    return resolved;
}

auto session_plan_validator::resolve_library_projections_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<std::vector<library_bundle_projection>> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    std::vector<library_bundle_projection> projections;
    std::vector<wire::library_projection> encoded;
    if (validation->schema_version == 2) {
        wire::session_plan_v2 plan;
        if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        encoded = std::move(plan.library_projections);
    } else {
        wire::session_plan plan;
        if (const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan schema"});
        }
        encoded = std::move(plan.library_projections);
    }
    projections.reserve(encoded.size());
    for (auto& projection : encoded) {
        projections.push_back({
            .projection_id = std::move(projection.projection_id),
            .content_digest = std::move(projection.content_digest),
            .destination_alias = std::move(projection.destination_alias),
        });
    }
    return projections;
}

auto session_plan_validator::resolve_library_projection_targets_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<std::vector<resolved_library_projection_target>> {
    auto projections = resolve_library_projections_json(plan_json, now_ms);
    if (!projections) {
        return std::unexpected(projections.error());
    }
    std::vector<resolved_library_projection_target> resolved;
    resolved.reserve(projections->size());
    for (auto& projection : *projections) {
        const auto destination = std::ranges::find_if(
            policy_.library_projection_destinations,
            [&](const auto& candidate) { return candidate.alias == projection.destination_alias; }
        );
        if (destination == policy_.library_projection_destinations.end()) {
            return std::unexpected(std::string{"library projection destination is unavailable"});
        }
        resolved.push_back({
            .projection = std::move(projection),
            .target_path = destination->target_path,
        });
    }
    return resolved;
}

auto session_plan_validator::refinement_plan_context_digest_json(
    std::string_view plan_json, std::uint64_t now_ms
) const -> result<std::string> {
    auto validation = validate_json(plan_json, now_ms);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    wire::session_plan plan;
    if (validation->schema_version == 2) {
        wire::session_plan_v2 v2;
        if (const auto error = read_untrusted_json<strict_read_options>(v2, plan_json); error) {
            return std::unexpected(std::string{"invalid session plan v2 schema"});
        }
        plan = common_v1_plan(v2);
    } else if (
        const auto error = read_untrusted_json<strict_read_options>(plan, plan_json); error
    ) {
        return std::unexpected(std::string{"invalid session plan schema"});
    }
    return refinement_plan_context_digest(plan);
}

} // namespace glove::supervisor
