#include "runtime_snapshot.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

extern char** environ;

namespace glove::host::snapshot {

namespace {

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

} // namespace

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
    const homebrew_keg& interpreter,
    std::vector<std::filesystem::path>& paths,
    bool allow_dependency_commands
) -> result<void> {
    if (!allow_dependency_commands) {
        return std::unexpected(
            std::string{"Homebrew dependency closure requires executing brew; dry-run planning "
                        "does not execute dependency commands"}
        );
    }
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


constexpr std::uint64_t max_snapshot_bytes = std::uint64_t{2} * 1024U * 1024U * 1024U;
constexpr std::size_t max_snapshot_entries = 200'000U;

auto append_snapshot_file_digest(
    const std::filesystem::path& path,
    std::string_view relative,
    std::string& manifest,
    std::uint64_t& total_bytes
) -> result<void> {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return std::unexpected(system_error("open harness snapshot file"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
        const auto error = system_error("inspect harness snapshot file");
        (void)::close(descriptor);
        return std::unexpected(error);
    }
    const auto size = static_cast<std::uint64_t>(metadata.st_size);
    if (size > max_snapshot_bytes || total_bytes > max_snapshot_bytes - size) {
        (void)::close(descriptor);
        return std::unexpected(std::string{"harness snapshot exceeds the 2 GiB safety limit"});
    }
    auto digest = container::sha256_fd_hex(descriptor, std::max<std::uint64_t>(size, 1U));
    const int close_result = ::close(descriptor);
    if (!digest || close_result != 0) {
        return std::unexpected(
            digest ? system_error("close harness snapshot file")
                   : "hash harness snapshot file: " + digest.error()
        );
    }
    total_bytes += size;
    manifest.append("f\0", 2);
    manifest.append(relative);
    manifest.push_back('\0');
    manifest.append((metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 ? "x" : "-");
    manifest.push_back('\0');
    manifest.append(std::to_string(size));
    manifest.push_back('\0');
    manifest.append(*digest);
    manifest.push_back('\0');
    return {};
}

auto snapshot_tree_digest(
    const std::filesystem::path& root,
    std::uint64_t* logical_bytes,
    std::uint64_t* entry_count
) -> result<std::string> {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (error) {
        return std::unexpected("inspect harness snapshot root: " + error.message());
    }
    std::string manifest;
    std::uint64_t total_bytes = 0;
    std::uint64_t total_entries = 0;
    if (std::filesystem::is_regular_file(status)) {
        if (auto appended =
                append_snapshot_file_digest(root, root.filename().string(), manifest, total_bytes);
            !appended) {
            return std::unexpected(appended.error());
        }
        total_entries = 1;
    } else if (std::filesystem::is_directory(status)) {
        std::vector<std::filesystem::path> entries;
        for (std::filesystem::recursive_directory_iterator
                 iterator{root, std::filesystem::directory_options::none, error},
             end;
             iterator != end;
             iterator.increment(error)) {
            if (error) {
                return std::unexpected("enumerate harness snapshot: " + error.message());
            }
            if (entries.size() >= max_snapshot_entries) {
                return std::unexpected(
                    std::string{"harness snapshot exceeds the 200000 entry safety limit"}
                );
            }
            entries.push_back(iterator->path());
        }
        total_entries = static_cast<std::uint64_t>(entries.size());
        std::ranges::sort(entries, [&](const auto& left, const auto& right) {
            return left.lexically_relative(root).generic_string() <
                   right.lexically_relative(root).generic_string();
        });
        const auto canonical_root = std::filesystem::canonical(root, error);
        if (error) {
            return std::unexpected("canonicalize harness snapshot root: " + error.message());
        }
        for (const auto& entry : entries) {
            const auto relative = entry.lexically_relative(root).generic_string();
            const auto entry_status = std::filesystem::symlink_status(entry, error);
            if (error) {
                return std::unexpected("inspect harness snapshot entry: " + error.message());
            }
            if (std::filesystem::is_directory(entry_status)) {
                manifest.append("d\0", 2);
                manifest.append(relative);
                manifest.push_back('\0');
            } else if (std::filesystem::is_regular_file(entry_status)) {
                if (auto appended =
                        append_snapshot_file_digest(entry, relative, manifest, total_bytes);
                    !appended) {
                    return std::unexpected(appended.error());
                }
            } else if (std::filesystem::is_symlink(entry_status)) {
                const auto target = std::filesystem::read_symlink(entry, error);
                if (error || target.is_absolute()) {
                    return std::unexpected(
                        std::string{"harness snapshot contains an unsafe symbolic link"}
                    );
                }
                const auto resolved = std::filesystem::canonical(entry, error);
                if (error || !path_within(resolved, canonical_root)) {
                    return std::unexpected(
                        std::string{"harness snapshot symbolic link escapes its closure"}
                    );
                }
                manifest.append("l\0", 2);
                manifest.append(relative);
                manifest.push_back('\0');
                manifest.append(target.generic_string());
                manifest.push_back('\0');
            } else {
                return std::unexpected(
                    std::string{"harness snapshot contains an unsupported special file"}
                );
            }
        }
    } else {
        return std::unexpected(std::string{"harness snapshot root must be a file or directory"});
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(manifest.data()),
        manifest.size(),
    };
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash harness snapshot manifest"});
    }
    if (logical_bytes != nullptr) {
        *logical_bytes = total_bytes;
    }
    if (entry_count != nullptr) {
        *entry_count = total_entries;
    }
    return *digest;
}

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
    const std::filesystem::path& source_entry,
    const std::filesystem::path& source,
    bool allow_dependency_commands
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
        if (auto appended = append_homebrew_runtime_closure(*keg, roots, allow_dependency_commands);
            !appended) {
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
    } else {
        roots.push_back(interpreter);
    }
    return runtime_dependency_closure{
        .executable = std::move(interpreter),
        .arguments = {source.string()},
        .read_only_paths = minimise_roots(std::move(roots)),
    };
}

auto path_ancestors_are_launch_trusted(const std::filesystem::path& path) -> bool {
    std::error_code error;
    auto current = std::filesystem::is_directory(path, error)
                       ? std::filesystem::canonical(path, error)
                       : std::filesystem::canonical(path, error).parent_path();
    if (error || current.empty()) {
        return false;
    }
    for (;;) {
        struct stat metadata{};
        if (::stat(current.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            (metadata.st_uid != 0 && metadata.st_uid != ::geteuid())) {
            return false;
        }
        const bool writable_by_other = (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        const bool root_owned_sticky = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
        if (writable_by_other && !root_owned_sticky) {
            return false;
        }
        if (current == current.root_path()) {
            return true;
        }
        current = current.parent_path();
    }
}

auto closure_launch_is_trusted(const runtime_dependency_closure& closure) -> bool {
    return path_ancestors_are_launch_trusted(closure.executable) &&
           std::ranges::all_of(closure.read_only_paths, path_ancestors_are_launch_trusted);
}


auto snapshot_payload_root(const std::filesystem::path& payload_root, std::size_t index)
    -> std::filesystem::path {
    return payload_root / ("root-" + std::to_string(index));
}

auto map_snapshot_path(
    const std::filesystem::path& source,
    std::span<const std::filesystem::path> closure_roots,
    const std::filesystem::path& payload_root
) -> result<std::filesystem::path> {
    for (std::size_t index = 0; index < closure_roots.size(); ++index) {
        const auto& closure_root = closure_roots[index];
        const auto mapped_root = snapshot_payload_root(payload_root, index);
        if (std::filesystem::is_regular_file(closure_root)) {
            if (source == closure_root) {
                return mapped_root / closure_root.filename();
            }
            continue;
        }
        if (path_within(source, closure_root)) {
            return mapped_root / source.lexically_relative(closure_root);
        }
    }
    return std::unexpected(std::string{"runtime path is outside its snapshot closure"});
}

auto snapshot_closure_digest(
    std::span<const std::filesystem::path> roots,
    std::uint64_t* logical_bytes,
    std::uint64_t* entry_count
) -> result<std::string> {
    if (roots.empty() || roots.size() > 64U) {
        return std::unexpected(std::string{"runtime snapshot has an invalid closure root count"});
    }
    std::string manifest{"glove.runtime-snapshot.v2", 25U};
    std::uint64_t total_bytes = 0;
    std::uint64_t total_entries = 0;
    for (const auto& root : roots) {
        std::uint64_t root_bytes = 0;
        std::uint64_t root_entries = 0;
        auto digest = snapshot_tree_digest(root, &root_bytes, &root_entries);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        if (root_bytes > max_snapshot_bytes - total_bytes ||
            root_entries > max_snapshot_entries - total_entries) {
            return std::unexpected(
                std::string{"combined harness snapshot exceeds its safety limit"}
            );
        }
        total_bytes += root_bytes;
        total_entries += root_entries;
        manifest.push_back('\0');
        manifest.append(*digest);
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(manifest.data()),
        manifest.size(),
    };
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash combined harness snapshot manifest"});
    }
    if (logical_bytes != nullptr) {
        *logical_bytes = total_bytes;
    }
    if (entry_count != nullptr) {
        *entry_count = total_entries;
    }
    return *digest;
}

auto materialized_snapshot_digest(const std::filesystem::path& payload_root, std::size_t root_count)
    -> result<std::string> {
    std::vector<std::filesystem::path> roots;
    roots.reserve(root_count);
    for (std::size_t index = 0; index < root_count; ++index) {
        roots.push_back(snapshot_payload_root(payload_root, index));
    }
    return snapshot_closure_digest(roots);
}

auto plan_runtime_snapshot(
    const std::filesystem::path& protected_directory,
    const std::filesystem::path& source,
    const runtime_dependency_closure& closure
) -> result<planned_runtime_snapshot> {
    std::uint64_t logical_bytes = 0;
    std::uint64_t entries = 0;
    auto digest = snapshot_closure_digest(closure.read_only_paths, &logical_bytes, &entries);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    const auto snapshot_root = protected_directory / "snapshots" / *digest;
    const auto payload_root = snapshot_root / "payload";
    auto mapped_source = map_snapshot_path(source, closure.read_only_paths, payload_root);
    auto mapped_executable =
        map_snapshot_path(closure.executable, closure.read_only_paths, payload_root);
    if (!mapped_source || !mapped_executable) {
        return std::unexpected(!mapped_source ? mapped_source.error() : mapped_executable.error());
    }
    std::vector<std::string> mapped_arguments;
    mapped_arguments.reserve(closure.arguments.size());
    for (const auto& argument : closure.arguments) {
        const std::filesystem::path candidate{argument};
        if (!candidate.is_absolute()) {
            mapped_arguments.push_back(argument);
            continue;
        }
        auto mapped = map_snapshot_path(candidate, closure.read_only_paths, payload_root);
        if (!mapped) {
            return std::unexpected(mapped.error());
        }
        mapped_arguments.push_back(mapped->string());
    }
    return planned_runtime_snapshot{
        .digest = std::move(*digest),
        .logical_bytes = logical_bytes,
        .entries = entries,
        .snapshot_root = snapshot_root,
        .payload_root = payload_root,
        .mapped_source = std::move(*mapped_source),
        .source_roots = closure.read_only_paths,
        .closure = {
            .executable = std::move(*mapped_executable),
            .arguments = std::move(mapped_arguments),
            .read_only_paths = {payload_root},
        },
    };
}

auto protect_snapshot_tree(const std::filesystem::path& payload_root) -> result<void> {
    std::error_code error;
    std::vector<std::filesystem::path> entries;
    if (std::filesystem::is_directory(payload_root, error)) {
        for (std::filesystem::recursive_directory_iterator
                 iterator{payload_root, std::filesystem::directory_options::none, error},
             end;
             iterator != end;
             iterator.increment(error)) {
            if (error) {
                return std::unexpected("enumerate staged harness snapshot: " + error.message());
            }
            entries.push_back(iterator->path());
        }
    }
    std::ranges::reverse(entries);
    for (const auto& entry : entries) {
        const auto status = std::filesystem::symlink_status(entry, error);
        if (error) {
            return std::unexpected("inspect staged harness snapshot: " + error.message());
        }
        if (std::filesystem::is_symlink(status)) {
            continue;
        }
        const mode_t mode =
            std::filesystem::is_directory(status)
                ? 0500
                : ((status.permissions() &
                    (std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec |
                     std::filesystem::perms::others_exec)) != std::filesystem::perms::none
                       ? 0500
                       : 0400);
        if (::chmod(entry.c_str(), mode) != 0) {
            return std::unexpected(system_error("protect staged harness snapshot"));
        }
    }
    if (::chmod(payload_root.c_str(), 0500) != 0) {
        return std::unexpected(system_error("protect staged harness snapshot root"));
    }
    return {};
}

auto materialize_runtime_snapshot(const planned_runtime_snapshot& plan) -> result<bool> {
    std::error_code error;
    if (std::filesystem::exists(plan.snapshot_root, error)) {
        auto existing_digest =
            materialized_snapshot_digest(plan.payload_root, plan.source_roots.size());
        if (!existing_digest || *existing_digest != plan.digest) {
            return std::unexpected(
                std::string{"existing runtime snapshot does not match its content address"}
            );
        }
        return false;
    }
    if (error) {
        return std::unexpected("inspect runtime snapshot: " + error.message());
    }
    const auto snapshots = plan.snapshot_root.parent_path();
    if (auto prepared = ensure_protected_directory(snapshots); !prepared) {
        return std::unexpected(prepared.error());
    }
    const auto temporary =
        snapshots / (".staging-" + plan.digest + "-" + std::to_string(::getpid()));
    if (std::filesystem::exists(temporary, error) || error) {
        return std::unexpected(std::string{"runtime snapshot staging path already exists"});
    }
    if (!std::filesystem::create_directory(temporary, error) || error) {
        return std::unexpected("create runtime snapshot staging directory: " + error.message());
    }
    const auto temporary_payload = temporary / "payload";
    const auto remove_temporary = [&] {
        std::error_code ignored;
        std::filesystem::permissions(
            temporary,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::add,
            ignored
        );
        std::filesystem::remove_all(temporary, ignored);
    };
    if (!std::filesystem::create_directory(temporary_payload, error) || error) {
        remove_temporary();
        return std::unexpected("create runtime snapshot payload: " + error.message());
    }
    for (std::size_t index = 0; index < plan.source_roots.size() && !error; ++index) {
        const auto& closure_root = plan.source_roots[index];
        const auto destination = snapshot_payload_root(temporary_payload, index);
        if (std::filesystem::is_directory(closure_root, error)) {
            std::filesystem::copy(
                closure_root,
                destination,
                std::filesystem::copy_options::recursive |
                    std::filesystem::copy_options::copy_symlinks,
                error
            );
        } else {
            std::filesystem::create_directory(destination, error);
            if (!error) {
                std::filesystem::copy_file(
                    closure_root,
                    destination / closure_root.filename(),
                    std::filesystem::copy_options::none,
                    error
                );
            }
        }
    }
    if (error) {
        remove_temporary();
        return std::unexpected("copy runtime snapshot: " + error.message());
    }
    auto copied_digest = materialized_snapshot_digest(temporary_payload, plan.source_roots.size());
    if (!copied_digest || *copied_digest != plan.digest) {
        remove_temporary();
        return std::unexpected(
            copied_digest ? std::string{"runtime source changed while it was being snapshotted"}
                          : copied_digest.error()
        );
    }
    if (auto protected_tree = protect_snapshot_tree(temporary_payload); !protected_tree) {
        remove_temporary();
        return std::unexpected(protected_tree.error());
    }
    // The published snapshot root is also an adoption trust boundary. Do not
    // leave its creation mode subject to the operator's umask.
    if (::chmod(temporary.c_str(), 0500) != 0) {
        remove_temporary();
        return std::unexpected(system_error("protect runtime snapshot root"));
    }
    if (::rename(temporary.c_str(), plan.snapshot_root.c_str()) != 0) {
        const int rename_error = errno;
        remove_temporary();
        if (rename_error == EEXIST || rename_error == ENOTEMPTY) {
            auto existing_digest =
                materialized_snapshot_digest(plan.payload_root, plan.source_roots.size());
            if (existing_digest && *existing_digest == plan.digest) {
                return false;
            }
        }
        return std::unexpected(system_error("publish runtime snapshot", rename_error));
    }
    return true;
}

} // namespace glove::host::snapshot
