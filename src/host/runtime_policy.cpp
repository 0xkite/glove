#include "glove/host/runtime_policy.hpp"

#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <ranges>
#include <set>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::host {
namespace runtime_policy_wire {

struct runtime_template {
    std::string runtime_template_id;
    std::string runtime_id;
    std::string adapter_command_digest;
    std::string sandbox_backend;
    std::vector<std::string> allowed_path_aliases;
    std::vector<std::string> allowed_projection_destinations;
    supervisor::runtime_launch_template launch;
};

} // namespace runtime_policy_wire

namespace {

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && value.front() != '-' && value.front() != '.' &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto canonical_paths(const std::vector<std::filesystem::path>& paths, std::string_view field)
    -> result<std::vector<std::string>> {
    std::vector<std::string> canonical;
    canonical.reserve(paths.size());
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (!paths[index].is_absolute()) {
            return std::unexpected(
                std::string{field} + "[" + std::to_string(index) + "] must be absolute"
            );
        }
        std::error_code error;
        const auto resolved = std::filesystem::canonical(paths[index], error);
        if (error) {
            return std::unexpected(
                std::string{field} + "[" + std::to_string(index) +
                "] cannot be canonicalized: " + error.message()
            );
        }
        canonical.push_back(resolved.string());
    }
    return canonical;
}

auto canonical_identifiers(std::vector<std::string> values, std::string_view field)
    -> result<std::vector<std::string>> {
    if (!std::ranges::all_of(values, valid_identifier)) {
        return std::unexpected(std::string{field} + " contains an invalid identifier");
    }
    std::ranges::sort(values);
    if (std::ranges::adjacent_find(values) != values.end()) {
        return std::unexpected(std::string{field} + " contains a duplicate identifier");
    }
    return values;
}

auto backend_name(supervisor::sandbox_backend backend) -> std::string {
    return backend == supervisor::sandbox_backend::linux_production ? "linux_production"
                                                                    : "macos_experimental";
}

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto ensure_protected_directory(const std::filesystem::path& path) -> result<void> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(
            std::string{"protected harness directory must be a canonical absolute non-root path"}
        );
    }
    std::filesystem::path current = path.root_path();
    for (const auto& component : path.relative_path()) {
        current /= component;
        struct stat metadata{};
        if (::lstat(current.c_str(), &metadata) == 0) {
            if (!S_ISDIR(metadata.st_mode)) {
                return std::unexpected(
                    "protected harness ancestor is not a directory: " + current.string()
                );
            }
            const bool root_sticky = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
            if (metadata.st_uid != 0 && metadata.st_uid != ::geteuid()) {
                return std::unexpected(
                    "protected harness ancestor is not owned by root or the service user: " +
                    current.string()
                );
            }
            if ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !root_sticky) {
                return std::unexpected(
                    "protected harness ancestor is writable by another principal: " +
                    current.string()
                );
            }
            continue;
        }
        if (errno != ENOENT) {
            return std::unexpected(system_error("inspect protected harness directory"));
        }
        if (::mkdir(current.c_str(), 0700) != 0) {
            return std::unexpected(system_error("create protected harness directory"));
        }
    }
    return {};
}

} // namespace

auto detect_runtime_harnesses(const std::vector<std::filesystem::path>& executable_search_paths)
    -> std::vector<detected_runtime_harness> {
    std::vector<std::string> raw_paths;
    raw_paths.reserve(executable_search_paths.size());
    for (const auto& path : executable_search_paths) {
        raw_paths.push_back(path.string());
    }
    std::vector<detected_runtime_harness> detected;
    for (const auto& adapter : supervisor::native_skill_runtime_adapters()) {
        supervisor::runtime_launch_template launch{
            .runtime_discovery = adapter.runtime_id,
            .executable_path = {},
            .executable_search_paths = raw_paths,
            .arguments = {},
            .environment = {},
            .read_only_paths = {},
        };
        auto resolved = supervisor::resolve_runtime_executable(launch);
        detected.push_back({
            .runtime_id = adapter.runtime_id,
            .executable_name = adapter.executable_name,
            .available = resolved.has_value(),
            .resolved_executable =
                resolved ? std::filesystem::path{*resolved} : std::filesystem::path{},
            .diagnostic = resolved ? std::string{} : resolved.error(),
        });
    }
    return detected;
}

auto stage_runtime_harness(const runtime_harness_stage_options& options)
    -> result<staged_runtime_harness> {
    const auto adapter = supervisor::native_skill_runtime_adapter_for(options.runtime_id);
    if (!adapter) {
        return std::unexpected("unsupported runtime adapter: " + options.runtime_id);
    }
    if (!options.source_executable.is_absolute()) {
        return std::unexpected(std::string{"source executable path must be absolute"});
    }
    std::error_code error;
    const auto source = std::filesystem::canonical(options.source_executable, error);
    if (error) {
        return std::unexpected("canonicalize source executable: " + error.message());
    }
    const auto source_status = std::filesystem::status(source, error);
    if (error || !std::filesystem::is_regular_file(source_status)) {
        return std::unexpected(std::string{"source executable must be a regular file"});
    }
    const auto executable_bits = std::filesystem::perms::owner_exec |
                                 std::filesystem::perms::group_exec |
                                 std::filesystem::perms::others_exec;
    if ((source_status.permissions() & executable_bits) == std::filesystem::perms::none) {
        return std::unexpected(std::string{"source executable is not executable"});
    }
    if (options.protected_directory.empty() || !options.protected_directory.is_absolute()) {
        return std::unexpected(std::string{"protected harness directory must be absolute"});
    }
    auto directory = std::filesystem::weakly_canonical(options.protected_directory, error);
    if (error) {
        return std::unexpected("canonicalize protected harness directory: " + error.message());
    }
    const auto entry_point = directory / adapter->executable_name;
    bool changed = false;
    if (!options.dry_run) {
        if (auto prepared = ensure_protected_directory(directory); !prepared) {
            return std::unexpected(prepared.error());
        }
        struct stat existing{};
        if (::lstat(entry_point.c_str(), &existing) == 0) {
            const auto resolved = std::filesystem::canonical(entry_point, error);
            if (error || resolved != source) {
                return std::unexpected(
                    "refusing to overwrite existing harness entry point: " + entry_point.string()
                );
            }
        } else {
            if (errno != ENOENT) {
                return std::unexpected(system_error("inspect harness entry point"));
            }
            if (::symlink(source.c_str(), entry_point.c_str()) != 0) {
                return std::unexpected(system_error("create protected harness entry point"));
            }
            changed = true;
        }
        supervisor::runtime_launch_template launch{
            .runtime_discovery = options.runtime_id,
            .executable_path = {},
            .executable_search_paths = {directory.string()},
            .arguments = {},
            .environment = {},
            .read_only_paths = {},
        };
        auto resolved = supervisor::resolve_runtime_executable(launch);
        if (!resolved || std::filesystem::path{*resolved} != source) {
            if (changed) {
                (void)::unlink(entry_point.c_str());
            }
            return std::unexpected(
                resolved ? std::string{"staged entry point resolved to an unexpected executable"}
                         : resolved.error()
            );
        }
    }
    return staged_runtime_harness{
        .runtime_id = options.runtime_id,
        .executable_name = adapter->executable_name,
        .source_executable = source,
        .protected_entry_point = entry_point,
        .changed = changed,
    };
}

auto generate_runtime_policy(const runtime_policy_generation_options& options)
    -> result<generated_runtime_policy> {
    const auto adapter = supervisor::native_skill_runtime_adapter_for(options.runtime_id);
    if (!adapter) {
        return std::unexpected("unsupported runtime adapter: " + options.runtime_id);
    }
    const auto template_id = options.runtime_template_id.empty() ? options.runtime_id + "-safe"
                                                                 : options.runtime_template_id;
    if (!valid_identifier(template_id)) {
        return std::unexpected(std::string{"runtime_template_id is invalid"});
    }
    if (!options.executable_path.empty() && !options.executable_search_paths.empty()) {
        return std::unexpected(
            std::string{"executable_path and executable_search_paths are mutually exclusive"}
        );
    }
    if (options.executable_path.empty() && options.executable_search_paths.empty()) {
        return std::unexpected(
            std::string{"an explicit executable or at least one explicit search path is required; "
                        "inherited PATH is not trusted"}
        );
    }
    auto read_only_paths = canonical_paths(options.read_only_paths, "read_only_paths");
    if (!read_only_paths) {
        return std::unexpected(read_only_paths.error());
    }
    auto aliases = canonical_identifiers(options.allowed_path_aliases, "allowed_path_aliases");
    if (!aliases) {
        return std::unexpected(aliases.error());
    }
    auto destinations = canonical_identifiers(
        options.allowed_projection_destinations, "allowed_projection_destinations"
    );
    if (!destinations) {
        return std::unexpected(destinations.error());
    }
    auto environment = options.environment;
    std::ranges::sort(environment);
    supervisor::runtime_launch_template launch;
    if (options.executable_path.empty()) {
        auto search_paths =
            canonical_paths(options.executable_search_paths, "executable_search_paths");
        if (!search_paths) {
            return std::unexpected(search_paths.error());
        }
        launch.runtime_discovery = options.runtime_id;
        launch.executable_search_paths = std::move(*search_paths);
    } else {
        auto executable = canonical_paths({options.executable_path}, "executable_path");
        if (!executable) {
            return std::unexpected(executable.error());
        }
        std::error_code error;
        const auto status = std::filesystem::status(executable->front(), error);
        constexpr auto executable_bits = std::filesystem::perms::owner_exec |
                                         std::filesystem::perms::group_exec |
                                         std::filesystem::perms::others_exec;
        if (error || !std::filesystem::is_regular_file(status) ||
            (status.permissions() & executable_bits) == std::filesystem::perms::none) {
            return std::unexpected(
                std::string{"executable_path must resolve to an executable regular file"}
            );
        }
        launch.executable_path = std::move(executable->front());
    }
    launch.arguments = options.arguments;
    launch.environment = std::move(environment);
    launch.read_only_paths = std::move(*read_only_paths);
    if (auto valid = supervisor::validate_runtime_launch_template(launch); !valid) {
        return std::unexpected(valid.error());
    }
    auto executable = supervisor::resolve_runtime_executable(launch);
    if (!executable) {
        return std::unexpected(executable.error());
    }
    auto digest = supervisor::runtime_launch_template_digest(launch);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    runtime_policy_wire::runtime_template encoded{
        .runtime_template_id = template_id,
        .runtime_id = options.runtime_id,
        .adapter_command_digest = *digest,
        .sandbox_backend = backend_name(options.backend),
        .allowed_path_aliases = std::move(*aliases),
        .allowed_projection_destinations = std::move(*destinations),
        .launch = std::move(launch),
    };
    auto json = glz::write_json(encoded);
    if (!json) {
        return std::unexpected(
            std::string{"encode runtime policy template: "} +
            glz::format_error(json.error(), std::string{})
        );
    }
    json->push_back('\n');
    return generated_runtime_policy{
        .runtime_id = options.runtime_id,
        .runtime_template_id = template_id,
        .executable_name = adapter->executable_name,
        .resolved_executable = std::filesystem::path{*executable},
        .adapter_command_digest = std::move(*digest),
        .policy_template_json = std::move(*json),
    };
}

auto validate_session_policy_file(const std::filesystem::path& path) -> result<void> {
    if (!path.is_absolute()) {
        return std::unexpected(std::string{"session policy path must be absolute"});
    }
    auto validator = supervisor::session_plan_validator::load(path.lexically_normal());
    if (!validator) {
        return std::unexpected(validator.error());
    }
    return {};
}

} // namespace glove::host
