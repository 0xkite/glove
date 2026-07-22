#include "glove/supervisor/session_plan.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
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

auto validate_launch_template(const runtime_launch_template& launch)
    -> std::expected<void, std::string> {
    const std::filesystem::path executable{launch.executable_path};
    if (launch.executable_path.empty() || launch.executable_path.size() > max_launch_path_bytes ||
        launch.executable_path.find('\0') != std::string::npos || !executable.is_absolute() ||
        executable == executable.root_path() || executable.lexically_normal() != executable ||
        launch.arguments.size() > max_launch_fields ||
        launch.environment.size() > max_launch_fields ||
        std::ranges::any_of(launch.arguments, [](const auto& value) {
            return !valid_launch_string(value);
        })) {
        return std::unexpected(std::string{"runtime launch template is invalid"});
    }

    std::set<std::string> environment_names;
    std::string_view previous;
    for (const auto& entry : launch.environment) {
        if (!valid_launch_string(entry)) {
            return std::unexpected(std::string{"runtime launch environment is not canonical"});
        }
        const auto separator = entry.find('=');
        if (separator == std::string::npos) {
            return std::unexpected(std::string{"runtime launch environment is not canonical"});
        }
        const std::string_view name{entry.data(), separator};
        if (!valid_environment_name(name) || !environment_names.emplace(name).second ||
            (!previous.empty() && previous >= entry)) {
            return std::unexpected(std::string{"runtime launch environment is not canonical"});
        }
        previous = entry;
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

auto validate_runtime_policy(const runtime_template_policy& runtime) -> bool {
    const bool identifiers = valid_identifier(runtime.runtime_template_id) &&
                             valid_identifier(runtime.runtime_id) &&
                             valid_digest(runtime.adapter_command_digest) &&
                             unique_identifiers(runtime.allowed_path_aliases) &&
                             unique_identifiers(runtime.allowed_projection_destinations);
    if (!identifiers || !runtime.launch) {
        return identifiers;
    }
    auto digest = runtime_launch_template_digest(*runtime.launch);
    return digest && *digest == runtime.adapter_command_digest;
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
    const auto remaining_ttl_ms = plan.expires_at_ms - now_ms;
    const auto remaining_ttl_secs =
        remaining_ttl_ms / 1'000U + static_cast<std::uint64_t>(remaining_ttl_ms % 1'000U != 0);
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
    };
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

} // namespace

auto runtime_launch_template_digest(const runtime_launch_template& launch) -> result<std::string> {
    if (auto valid = validate_launch_template(launch); !valid) {
        return std::unexpected(valid.error());
    }
    launch_template_encoder encoder;
    encoder.append_string("glove.runtime-launch-template");
    encoder.append_u8(std::uint8_t{1});
    encoder.append_string(launch.executable_path);
    encoder.append_u32(static_cast<std::uint32_t>(launch.arguments.size()));
    for (const auto& argument : launch.arguments) {
        encoder.append_string(argument);
    }
    encoder.append_u32(static_cast<std::uint32_t>(launch.environment.size()));
    for (const auto& environment : launch.environment) {
        encoder.append_string(environment);
    }
    return container::sha256_hex(encoder.bytes());
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
    if (const auto error = glz::read<strict_read_options>(encoded, *contents);
        error || encoded.schema_version != 1) {
        return std::unexpected(std::string{"invalid session policy schema"});
    }
    if (encoded.runtime_templates.empty() ||
        encoded.runtime_templates.size() > max_runtime_templates || encoded.path_aliases.empty() ||
        encoded.path_aliases.size() > max_path_grants || encoded.resource_profiles.empty() ||
        encoded.resource_profiles.size() > max_resource_profiles ||
        encoded.library_projection_destinations.size() > max_projection_destinations ||
        encoded.egress_policy_ids.size() > max_policy_identifiers ||
        encoded.tool_policy_ids.size() > max_policy_identifiers ||
        encoded.secret_handles.size() > max_policy_identifiers) {
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
                .launch = std::move(runtime.launch),
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
        !unique_identifiers(policy.tool_policy_ids) || !unique_identifiers(policy.secret_handles)) {
        return std::unexpected(std::string{"session plan policy is incomplete"});
    }

    std::set<std::string> runtime_templates;
    for (const auto& runtime : policy.runtime_templates) {
        if (!validate_runtime_policy(runtime) ||
            std::ranges::any_of(
                runtime.allowed_projection_destinations,
                [&](const auto& alias) {
                    return std::ranges::none_of(
                        policy.library_projection_destinations,
                        [&](const auto& destination) { return destination.alias == alias; }
                    );
                }
            ) ||
            !runtime_templates.insert(runtime.runtime_template_id).second) {
            return std::unexpected(std::string{"session plan runtime policy is invalid"});
        }
    }

    for (std::size_t index = 0; index < policy.resource_profiles.size(); ++index) {
        if (!complete_limits(policy.resource_profiles[index]) ||
            std::ranges::find(
                policy.resource_profiles.begin(),
                policy.resource_profiles.begin() + static_cast<std::ptrdiff_t>(index),
                policy.resource_profiles[index]
            ) != policy.resource_profiles.begin() + static_cast<std::ptrdiff_t>(index)) {
            return std::unexpected(std::string{"session plan resource policy is invalid"});
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
    std::vector<std::string> argv;
    argv.reserve(launch.arguments.size() + 1U);
    argv.push_back(launch.executable_path);
    argv.insert(argv.end(), launch.arguments.begin(), launch.arguments.end());
    return runtime_launch_projection{
        .validation = *validation,
        .runtime_id = runtime->runtime_id,
        .runtime_template_id = runtime->runtime_template_id,
        .adapter_command_digest = runtime->adapter_command_digest,
        .backend = runtime->backend,
        .argv = std::move(argv),
        .environment = launch.environment,
        .limits = plan.limits,
        .expires_at_ms = plan.expires_at_ms,
        .requires_direct_write_approval =
            validation->schema_version == 1 &&
            std::ranges::any_of(plan.path_grants, [](const auto& grant) {
                return grant.access == "direct_write";
            }),
    };
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

} // namespace glove::supervisor
