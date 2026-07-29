#include "glove/host/runtime_policy.hpp"

#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <fstream>
#include <limits>
#include <ranges>
#include <set>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>

extern char** environ;

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

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root) noexcept
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto capture_command(
    const std::filesystem::path& executable, const std::vector<std::string>& arguments
) -> result<std::string> {
    constexpr std::size_t max_output_bytes = 1024U * 1024U;
    std::array<int, 2> output_pipe{-1, -1};
    if (::pipe(output_pipe.data()) != 0) {
        return std::unexpected(system_error("create dependency command pipe"));
    }
    if (::fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC) < 0 ||
        ::fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        const auto error = system_error("protect dependency command pipe");
        (void)::close(output_pipe[0]);
        (void)::close(output_pipe[1]);
        return std::unexpected(error);
    }

    ::posix_spawn_file_actions_t actions{};
    if (::posix_spawn_file_actions_init(&actions) != 0) {
        (void)::close(output_pipe[0]);
        (void)::close(output_pipe[1]);
        return std::unexpected(std::string{"initialize dependency command"});
    }
    const std::array action_results = {
        ::posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO),
        ::posix_spawn_file_actions_addclose(&actions, output_pipe[0]),
        ::posix_spawn_file_actions_addclose(&actions, output_pipe[1]),
        ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0),
    };
    if (const auto failed =
            std::ranges::find_if(action_results, [](int result) { return result != 0; });
        failed != action_results.end()) {
        (void)::posix_spawn_file_actions_destroy(&actions);
        (void)::close(output_pipe[0]);
        (void)::close(output_pipe[1]);
        return std::unexpected(
            std::string{"configure dependency command: "} +
            std::error_code{*failed, std::generic_category()}.message()
        );
    }

    std::vector<std::string> owned_argv;
    owned_argv.reserve(arguments.size() + 1U);
    owned_argv.push_back(executable.string());
    owned_argv.insert(owned_argv.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(owned_argv.size() + 1U);
    for (auto& argument : owned_argv) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    ::pid_t child = -1;
    const int spawned =
        ::posix_spawn(&child, executable.c_str(), &actions, nullptr, argv.data(), environ);
    (void)::posix_spawn_file_actions_destroy(&actions);
    (void)::close(output_pipe[1]);
    if (spawned != 0) {
        (void)::close(output_pipe[0]);
        return std::unexpected(
            std::string{"launch dependency command: "} +
            std::error_code{spawned, std::generic_category()}.message()
        );
    }

    std::string output;
    std::array<char, 4096> buffer{};
    while (output.size() <= max_output_bytes) {
        const auto count = ::read(output_pipe[0], buffer.data(), buffer.size());
        if (count > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    (void)::close(output_pipe[0]);
    int child_status = 0;
    ::pid_t waited = -1;
    do {
        waited = ::waitpid(child, &child_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        return std::unexpected(std::string{"wait for dependency command: "} + std::strerror(errno));
    }
    if (output.size() > max_output_bytes || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        return std::unexpected(std::string{"dependency command failed"});
    }
    return output;
}

auto valid_formula_name(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= 128U &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return std::isalnum(byte) != 0 || byte == '@' || byte == '+' || byte == '-' ||
                      byte == '_' || byte == '.';
           });
}

struct homebrew_keg {
    std::filesystem::path prefix;
    std::string formula;
    std::filesystem::path root;
};

auto homebrew_keg_for(const std::filesystem::path& path) -> std::optional<homebrew_keg> {
    std::filesystem::path prefix;
    auto component = path.begin();
    for (; component != path.end() && *component != "Cellar"; ++component) {
        prefix /= *component;
    }
    if (component == path.end()) {
        return std::nullopt;
    }
    ++component;
    if (component == path.end()) {
        return std::nullopt;
    }
    const std::string formula = component->string();
    ++component;
    if (!valid_formula_name(formula) || component == path.end()) {
        return std::nullopt;
    }
    return homebrew_keg{
        .prefix = prefix,
        .formula = formula,
        .root = prefix / "Cellar" / formula / *component,
    };
}

auto append_homebrew_runtime_closure(
    const homebrew_keg& interpreter, std::vector<std::filesystem::path>& paths
) -> result<void> {
    const auto brew = interpreter.prefix / "bin" / "brew";
    std::error_code error;
    const auto canonical_brew = std::filesystem::canonical(brew, error);
    if (error) {
        return std::unexpected("resolve Homebrew dependency tool: " + error.message());
    }
    auto dependencies =
        capture_command(canonical_brew, {"deps", "--installed", "--formula", interpreter.formula});
    if (!dependencies) {
        return std::unexpected(dependencies.error());
    }
    paths.push_back(interpreter.root);
    std::istringstream lines{*dependencies};
    for (std::string formula; std::getline(lines, formula);) {
        if (!valid_formula_name(formula)) {
            return std::unexpected(std::string{"Homebrew returned an invalid dependency name"});
        }
        const auto dependency_link = interpreter.prefix / "opt" / formula;
        const auto dependency = std::filesystem::canonical(dependency_link, error);
        if (error) {
            return std::unexpected(
                "resolve Homebrew dependency " + formula + ": " + error.message()
            );
        }
        const auto keg = homebrew_keg_for(dependency);
        if (!keg) {
            return std::unexpected(
                "Homebrew dependency does not resolve to one immutable keg: " + formula
            );
        }
        paths.push_back(keg->root);
    }
    return {};
}

auto minimise_roots(std::vector<std::filesystem::path> paths)
    -> std::vector<std::filesystem::path> {
    std::ranges::sort(paths);
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    std::vector<std::filesystem::path> roots;
    for (const auto& candidate : paths) {
        if (std::ranges::any_of(roots, [&](const auto& root) {
                return path_within(candidate, root);
            })) {
            continue;
        }
        std::erase_if(roots, [&](const auto& root) { return path_within(root, candidate); });
        roots.push_back(candidate);
    }
    std::ranges::sort(roots);
    return roots;
}

struct runtime_dependency_closure {
    std::filesystem::path executable;
    std::vector<std::string> arguments;
    std::vector<std::filesystem::path> read_only_paths;
};

auto package_root_for(const std::filesystem::path& source) -> std::filesystem::path {
    std::error_code error;
    for (auto current = source.parent_path(); current != current.root_path();
         current = current.parent_path()) {
        const auto manifest = current / "package.json";
        if (std::filesystem::is_regular_file(manifest, error) && !error) {
            return current;
        }
        error.clear();
    }
    return source;
}

auto derive_runtime_dependency_closure(
    const std::filesystem::path& source_entry, const std::filesystem::path& source
) -> result<runtime_dependency_closure> {
    std::ifstream input{source, std::ios::binary};
    std::string first_line;
    std::getline(input, first_line);
    if (!first_line.starts_with("#!")) {
        return runtime_dependency_closure{
            .executable = source,
            .arguments = {},
            .read_only_paths = {source},
        };
    }
    first_line.erase(0, 2);
    std::istringstream shebang{first_line};
    std::vector<std::string> fields;
    for (std::string field; shebang >> field;) {
        fields.push_back(std::move(field));
    }
    if (fields.empty() || fields.size() > 2U) {
        return std::unexpected(std::string{"unsupported harness interpreter directive"});
    }

    std::filesystem::path interpreter;
    std::error_code error;
    if (fields.front() == "/usr/bin/env") {
        if (fields.size() != 2U || fields[1].find('/') != std::string::npos) {
            return std::unexpected(std::string{"unsupported env-based harness interpreter"});
        }
        interpreter = std::filesystem::canonical(source_entry.parent_path() / fields[1], error);
        if (error) {
            return std::unexpected(
                "resolve adjacent harness interpreter " + fields[1] + ": " + error.message()
            );
        }
    } else {
        if (fields.size() != 1U || !std::filesystem::path{fields.front()}.is_absolute()) {
            return std::unexpected(std::string{"harness interpreter must be absolute"});
        }
        interpreter = std::filesystem::canonical(fields.front(), error);
        if (error) {
            return std::unexpected("resolve harness interpreter: " + error.message());
        }
    }
    const auto status = std::filesystem::status(interpreter, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return std::unexpected(std::string{"harness interpreter is not a regular file"});
    }

    std::vector<std::filesystem::path> roots{package_root_for(source)};
    if (const auto keg = homebrew_keg_for(interpreter)) {
        if (auto appended = append_homebrew_runtime_closure(*keg, roots); !appended) {
            return std::unexpected(appended.error());
        }
    } else if (fields.front() == "/usr/bin/env") {
        const auto installation_root = interpreter.parent_path().parent_path();
        if (installation_root == installation_root.root_path()) {
            return std::unexpected(
                std::string{"refusing root-wide interpreter dependency closure"}
            );
        }
        roots.push_back(installation_root);
    }
    return runtime_dependency_closure{
        .executable = std::move(interpreter),
        .arguments = {source.string()},
        .read_only_paths = minimise_roots(std::move(roots)),
    };
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
    auto dependency_closure = derive_runtime_dependency_closure(options.source_executable, source);
    if (!dependency_closure) {
        return std::unexpected(dependency_closure.error());
    }
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
        .launch_executable = std::move(dependency_closure->executable),
        .launch_arguments = std::move(dependency_closure->arguments),
        .read_only_paths = std::move(dependency_closure->read_only_paths),
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
