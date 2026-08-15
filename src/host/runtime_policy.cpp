#include "glove/host/runtime_policy.hpp"

#include "glove/container/digest.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "runtime_policy_wire.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <spawn.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <sstream>
#include <string_view>
#include <system_error>
#include <utility>

extern char** environ;

namespace glove::host {

namespace {

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && value.front() != '-' && value.front() != '.' &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto canonical_paths(
    const std::vector<std::filesystem::path>& paths,
    std::string_view field,
    bool allow_planned_paths = false
) -> result<std::vector<std::string>> {
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
            if (allow_planned_paths && paths[index].lexically_normal() == paths[index]) {
                canonical.push_back(paths[index].string());
                continue;
            }
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
    switch (backend) {
    case supervisor::sandbox_backend::linux_production:
        return "linux_production";
    case supervisor::sandbox_backend::remote_linux_container:
        return "remote_linux_container";
    case supervisor::sandbox_backend::apple_container:
        return "apple_container";
    case supervisor::sandbox_backend::macos_experimental:
        return "macos_experimental";
    }
    return "unsupported";
}

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto read_policy_contents(const std::filesystem::path& path) -> result<std::optional<std::string>> {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            return std::nullopt;
        }
        return std::unexpected(system_error("open session policy"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > 1024U * 1024U) {
        (void)::close(descriptor);
        return std::unexpected(
            std::string{"existing session policy ownership, mode, link count, or size is unsafe"}
        );
    }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto count =
            ::read(descriptor, contents.data() + consumed, contents.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const auto error = system_error("read existing session policy");
            (void)::close(descriptor);
            return std::unexpected(error);
        }
        consumed += static_cast<std::size_t>(count);
    }
    if (::close(descriptor) != 0) {
        return std::unexpected(system_error("close existing session policy"));
    }
    return contents;
}

auto write_owner_file_exclusive(const std::filesystem::path& path, std::string_view contents)
    -> result<void> {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return std::unexpected(system_error("create session policy"));
    }
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto count =
            ::write(descriptor, contents.data() + consumed, contents.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const auto error = system_error("write session policy");
            (void)::close(descriptor);
            (void)::unlink(path.c_str());
            return std::unexpected(error);
        }
        consumed += static_cast<std::size_t>(count);
    }
    const int sync_result = ::fsync(descriptor);
    const int sync_error = errno;
    const int close_result = ::close(descriptor);
    if (sync_result != 0 || close_result != 0) {
        errno = sync_result != 0 ? sync_error : errno;
        const auto error = system_error("sync session policy");
        (void)::unlink(path.c_str());
        return std::unexpected(error);
    }
    return {};
}

class policy_update_lock {
public:
    policy_update_lock() = default;
    policy_update_lock(const policy_update_lock&) = delete;
    auto operator=(const policy_update_lock&) -> policy_update_lock& = delete;

    policy_update_lock(policy_update_lock&& other) noexcept
        : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(policy_update_lock&& other) noexcept -> policy_update_lock& {
        if (this != &other) {
            close();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~policy_update_lock() { close(); }

    [[nodiscard]] static auto acquire(const std::filesystem::path& policy_path)
        -> result<policy_update_lock> {
        const auto lock_path = policy_path.string() + ".lock";
        const int descriptor =
            ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0) {
            return std::unexpected(system_error("open session policy update lock"));
        }
        struct stat metadata{};
        if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
            (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U) {
            (void)::close(descriptor);
            return std::unexpected(
                std::string{"session policy update lock ownership or mode is unsafe"}
            );
        }
        if (::flock(descriptor, LOCK_EX) != 0) {
            const auto error = system_error("lock session policy update");
            (void)::close(descriptor);
            return std::unexpected(error);
        }
        policy_update_lock lock;
        lock.descriptor_ = descriptor;
        return lock;
    }

private:
    void close() noexcept {
        if (descriptor_ >= 0) {
            (void)::flock(descriptor_, LOCK_UN);
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

auto encode_session_policy(const runtime_policy_wire::session_policy& policy)
    -> result<std::string> {
    auto encoded = glz::write_json(policy);
    if (!encoded) {
        return std::unexpected(
            std::string{"encode complete session policy: "} +
            glz::format_error(encoded.error(), std::string{})
        );
    }
    encoded->push_back('\n');
    return *encoded;
}

struct prepared_policy_update {
    std::string contents;
    std::optional<std::string> previous_contents;
    bool changed = false;
};

auto derive_policy_update(
    runtime_policy_wire::session_policy policy, const std::filesystem::path& policy_path
) -> result<prepared_policy_update> {
    auto previous = read_policy_contents(policy_path);
    if (!previous) {
        return std::unexpected(previous.error());
    }
    if (!*previous) {
        auto contents = encode_session_policy(policy);
        if (!contents) {
            return std::unexpected(contents.error());
        }
        return prepared_policy_update{
            .contents = std::move(*contents),
            .previous_contents = std::nullopt,
            .changed = true,
        };
    }
    if (auto valid = validate_session_policy_file(policy_path); !valid) {
        return std::unexpected(std::string{"existing session policy is invalid: "} + valid.error());
    }

    runtime_policy_wire::session_policy existing_policy;
    if (const auto decoded = glz::read_json(existing_policy, **previous)) {
        return std::unexpected(
            std::string{"decode existing session policy: "} + glz::format_error(decoded, **previous)
        );
    }
    if (existing_policy.revision == 0) {
        return std::unexpected(std::string{"existing session policy revision is invalid"});
    }
    policy.revision = existing_policy.revision;
    auto candidate_at_existing_revision = encode_session_policy(policy);
    if (!candidate_at_existing_revision) {
        return std::unexpected(candidate_at_existing_revision.error());
    }
    auto canonical_existing = encode_session_policy(existing_policy);
    if (!canonical_existing) {
        return std::unexpected(canonical_existing.error());
    }
    if (*candidate_at_existing_revision == *canonical_existing) {
        return prepared_policy_update{
            .contents = std::move(*candidate_at_existing_revision),
            .previous_contents = std::move(**previous),
            .changed = false,
        };
    }
    if (existing_policy.revision == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(std::string{"session policy revision is exhausted"});
    }
    policy.revision = existing_policy.revision + 1U;
    auto incremented = encode_session_policy(policy);
    if (!incremented) {
        return std::unexpected(incremented.error());
    }
    return prepared_policy_update{
        .contents = std::move(*incremented),
        .previous_contents = std::move(**previous),
        .changed = true,
    };
}

auto activate_policy_update(
    const std::filesystem::path& policy_path, const prepared_policy_update& update
) -> result<void> {
    if (!update.changed) {
        return {};
    }
    const auto candidate_path = std::filesystem::path{
        policy_path.string() + ".candidate-" + std::to_string(::getpid()) + "-" +
            std::to_string(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()
                )
                    .count()
            ),
    };
    if (auto written = write_owner_file_exclusive(candidate_path, update.contents); !written) {
        return std::unexpected(written.error());
    }
    if (auto valid = validate_session_policy_file(candidate_path); !valid) {
        (void)::unlink(candidate_path.c_str());
        return std::unexpected(
            std::string{"generated session policy failed validation: "} + valid.error()
        );
    }
    auto current = read_policy_contents(policy_path);
    if (!current) {
        (void)::unlink(candidate_path.c_str());
        return std::unexpected(current.error());
    }
    if (*current != update.previous_contents) {
        (void)::unlink(candidate_path.c_str());
        return std::unexpected(
            std::string{"session policy changed while its update was being prepared"}
        );
    }
    if (::rename(candidate_path.c_str(), policy_path.c_str()) != 0) {
        const auto error = system_error("activate session policy update");
        (void)::unlink(candidate_path.c_str());
        return std::unexpected(error);
    }
    const int parent =
        ::open(policy_path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0) {
        return std::unexpected(system_error("open session policy directory after activation"));
    }
    const int sync_result = ::fsync(parent);
    const int sync_error = errno;
    (void)::close(parent);
    if (sync_result != 0) {
        return std::unexpected(
            system_error("sync session policy directory after activation", sync_error)
        );
    }
    return {};
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

auto canonical_owner_secret(const std::filesystem::path& path) -> result<std::filesystem::path> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"secret source must be a normalized absolute file"});
    }
    struct stat link_status{};
    if (::lstat(path.c_str(), &link_status) != 0 || S_ISLNK(link_status.st_mode)) {
        return std::unexpected(std::string{"secret source must not be a symbolic link"});
    }
    std::error_code error;
    const auto canonical = std::filesystem::canonical(path, error);
    struct stat metadata{};
    if (error || ::stat(canonical.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U || metadata.st_size <= 0 ||
        metadata.st_size > 1024 * 1024 || metadata.st_dev != link_status.st_dev ||
        metadata.st_ino != link_status.st_ino) {
        return std::unexpected(
            std::string{"secret source must be one owner-only, single-link regular file"}
        );
    }
    return canonical;
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

struct runtime_dependency_closure {
    std::filesystem::path executable;
    std::vector<std::string> arguments;
    std::vector<std::filesystem::path> read_only_paths;
};

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
    std::uint64_t* logical_bytes = nullptr,
    std::uint64_t* entry_count = nullptr
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

struct planned_runtime_snapshot {
    std::string digest;
    std::uint64_t logical_bytes = 0;
    std::uint64_t entries = 0;
    std::filesystem::path snapshot_root;
    std::filesystem::path payload_root;
    std::filesystem::path mapped_source;
    std::vector<std::filesystem::path> source_roots;
    runtime_dependency_closure closure;
};

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
    std::uint64_t* logical_bytes = nullptr,
    std::uint64_t* entry_count = nullptr
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
        struct stat metadata{};
        if (::lstat(plan.snapshot_root.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            metadata.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0500U) {
            return std::unexpected(
                std::string{"existing runtime snapshot root is not owner-protected"}
            );
        }
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
    // Publish under an owner-only parent before sealing the final root. Some
    // platforms reject renaming a non-writable directory; the verified 0700
    // parent prevents another principal from observing this transition.
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
    if (::chmod(plan.snapshot_root.c_str(), 0500) != 0) {
        const int protection_error = errno;
        std::error_code ignored;
        std::filesystem::permissions(
            plan.snapshot_root,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::add,
            ignored
        );
        std::filesystem::remove_all(plan.snapshot_root, ignored);
        return std::unexpected(system_error("protect runtime snapshot root", protection_error));
    }
    return true;
}

} // namespace

auto detect_runtime_harnesses(const std::vector<std::filesystem::path>& executable_search_paths)
    -> std::vector<detected_runtime_harness> {
    std::vector<detected_runtime_harness> detected;
    for (const auto& adapter : supervisor::native_skill_runtime_adapters()) {
        std::filesystem::path source_entry;
        std::string diagnostic =
            "expected executable '" + adapter.executable_name + "' was not found";
        for (const auto& root : executable_search_paths) {
            if (!root.is_absolute()) {
                diagnostic = "harness search path must be absolute";
                continue;
            }
            const auto candidate = (root / adapter.executable_name).lexically_normal();
            std::error_code error;
            const auto resolved = std::filesystem::canonical(candidate, error);
            const auto status =
                error ? std::filesystem::file_status{} : std::filesystem::status(resolved, error);
            const auto executable_bits = std::filesystem::perms::owner_exec |
                                         std::filesystem::perms::group_exec |
                                         std::filesystem::perms::others_exec;
            if (!error && std::filesystem::is_regular_file(status) &&
                (status.permissions() & executable_bits) != std::filesystem::perms::none) {
                // Setup discovery is not launch authorization. Preserve the
                // explicit adapter-named entry so staging can derive and copy
                // its package/interpreter topology before launch trust runs.
                source_entry = candidate;
                diagnostic.clear();
                break;
            }
        }
        detected.push_back({
            .runtime_id = adapter.runtime_id,
            .executable_name = adapter.executable_name,
            .available = !source_entry.empty(),
            .resolved_executable = std::move(source_entry),
            .diagnostic = std::move(diagnostic),
        });
    }
    return detected;
}

namespace {

auto stage_runtime_harness_impl(
    const runtime_harness_stage_options& options, bool allow_dependency_commands
) -> result<staged_runtime_harness> {
    const auto adapter = supervisor::native_skill_runtime_adapter_for(options.runtime_id);
    if (!adapter) {
        return std::unexpected("unsupported runtime adapter: " + options.runtime_id);
    }
    std::string adoption_manifest_digest;
    if (adapter->adoption_manifest) {
        auto manifest = supervisor::native_harness_adoption_manifest_digest(*adapter);
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        adoption_manifest_digest = std::move(*manifest);
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
    auto dependency_closure = derive_runtime_dependency_closure(
        options.source_executable, source, allow_dependency_commands
    );
    if (!dependency_closure) {
        return std::unexpected(dependency_closure.error());
    }
    std::optional<planned_runtime_snapshot> snapshot;
    if ((adapter->adoption_manifest && adapter->adoption_manifest->require_snapshot) ||
        !closure_launch_is_trusted(*dependency_closure)) {
        auto planned = plan_runtime_snapshot(directory, source, *dependency_closure);
        if (!planned) {
            return std::unexpected("derive protected runtime snapshot: " + planned.error());
        }
        snapshot = std::move(*planned);
    }
    const auto expected_entry_target = snapshot ? snapshot->mapped_source : source;
    const auto& launch_closure = snapshot ? snapshot->closure : *dependency_closure;
    struct stat existing{};
    bool entry_exists = false;
    bool entry_requires_update = false;
    if (::lstat(entry_point.c_str(), &existing) == 0) {
        const auto resolved = std::filesystem::canonical(entry_point, error);
        if (!error && resolved == expected_entry_target) {
            entry_exists = true;
        } else if (
            !error && S_ISLNK(existing.st_mode) && existing.st_uid == ::geteuid() &&
            path_within(resolved, directory / "snapshots")
        ) {
            // A prior setup revision may point at an older immutable snapshot.
            // Only that exact managed topology is replaceable; arbitrary files,
            // directories, and links outside this adapter's snapshot store
            // remain protected from overwrite.
            entry_exists = true;
            entry_requires_update = true;
        } else {
            return std::unexpected(
                "refusing to overwrite existing harness entry point: " + entry_point.string()
            );
        }
    } else if (errno != ENOENT) {
        return std::unexpected(system_error("inspect harness entry point"));
    }
    bool changed = false;
    if (!options.dry_run) {
        if (auto prepared = ensure_protected_directory(directory); !prepared) {
            return std::unexpected(prepared.error());
        }
        if (snapshot) {
            auto materialized = materialize_runtime_snapshot(*snapshot);
            if (!materialized) {
                return std::unexpected(materialized.error());
            }
            changed = *materialized;
        }
        if (!entry_exists || entry_requires_update) {
            const auto staged_entry = directory / ("." + adapter->executable_name + ".next-" +
                                                   std::to_string(::getpid()));
            if (::symlink(expected_entry_target.c_str(), staged_entry.c_str()) != 0) {
                return std::unexpected(system_error("stage protected harness entry point"));
            }
            if (::rename(staged_entry.c_str(), entry_point.c_str()) != 0) {
                const auto message = system_error("activate protected harness entry point");
                (void)::unlink(staged_entry.c_str());
                return std::unexpected(message);
            }
            const int directory_fd =
                ::open(directory.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
            if (directory_fd < 0 || ::fsync(directory_fd) != 0) {
                const auto message = system_error("sync protected harness entry point");
                if (directory_fd >= 0) {
                    (void)::close(directory_fd);
                }
                return std::unexpected(message);
            }
            (void)::close(directory_fd);
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
        if (!resolved || std::filesystem::path{*resolved} != expected_entry_target) {
            if (!entry_exists) {
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
        .source_executable = options.source_executable.lexically_normal(),
        .protected_entry_point = entry_point,
        .launch_executable = launch_closure.executable,
        .launch_arguments = launch_closure.arguments,
        .read_only_paths = launch_closure.read_only_paths,
        .snapshot_digest = snapshot ? snapshot->digest : std::string{},
        .adoption_manifest_digest = std::move(adoption_manifest_digest),
        .snapshot_logical_bytes = snapshot ? snapshot->logical_bytes : 0,
        .snapshot_entries = snapshot ? snapshot->entries : 0,
        .changed = changed,
    };
}

} // namespace

auto stage_runtime_harness(const runtime_harness_stage_options& options)
    -> result<staged_runtime_harness> {
    return stage_runtime_harness_impl(options, !options.dry_run);
}

namespace {

auto valid_pi_package_id(std::string_view value) -> bool {
    if (value.empty() || value.size() > 214U || value.starts_with('.') || value.contains("..") ||
        std::ranges::any_of(value, [](unsigned char byte) {
            return !(
                std::isalnum(byte) || byte == '@' || byte == '/' || byte == '-' || byte == '_' ||
                byte == '.'
            );
        })) {
        return false;
    }
    const auto slash = value.find('/');
    if (value.starts_with('@')) {
        return slash != std::string_view::npos && slash > 1U && slash + 1U < value.size() &&
               value.find('/', slash + 1U) == std::string_view::npos;
    }
    return slash == std::string_view::npos;
}

auto read_pi_settings_discovery(const std::filesystem::path& path)
    -> result<runtime_policy_wire::pi_settings_discovery> {
    std::error_code error;
    const auto canonical = std::filesystem::canonical(path, error);
    if (error || !std::filesystem::is_regular_file(canonical, error)) {
        return std::unexpected(std::string{"Pi settings discovery file must be a regular file"});
    }
    const auto size = std::filesystem::file_size(canonical, error);
    if (error || size > 1024U * 1024U) {
        return std::unexpected(std::string{"Pi settings discovery file exceeds 1 MiB"});
    }
    std::ifstream input{canonical, std::ios::binary};
    std::string contents{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    runtime_policy_wire::pi_settings_discovery settings;
    if (const auto decoded =
            glz::read<glz::opts{.error_on_unknown_keys = false}>(settings, contents)) {
        return std::unexpected(
            "decode Pi settings discovery: " + glz::format_error(decoded, contents)
        );
    }
    return settings;
}

auto read_pi_package_metadata(const std::filesystem::path& package)
    -> result<runtime_policy_wire::pi_package_metadata> {
    const auto metadata_path = package / "package.json";
    std::error_code error;
    const auto size = std::filesystem::file_size(metadata_path, error);
    if (error || size == 0U || size > 1024U * 1024U) {
        return std::unexpected(std::string{"Pi package metadata is missing or exceeds 1 MiB"});
    }
    std::ifstream input{metadata_path, std::ios::binary};
    std::string contents{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    runtime_policy_wire::pi_package_metadata metadata;
    if (const auto decoded =
            glz::read<glz::opts{.error_on_unknown_keys = false}>(metadata, contents)) {
        return std::unexpected(
            "decode Pi package metadata: " + glz::format_error(decoded, contents)
        );
    }
    return metadata;
}

} // namespace

auto generate_pi_adoption_manifest(const pi_adoption_manifest_options& options)
    -> result<generated_pi_adoption_manifest> {
    if (!options.settings_path.is_absolute() || !options.package_store_root.is_absolute() ||
        !options.protected_directory.is_absolute()) {
        return std::unexpected(std::string{"Pi adoption paths must be absolute"});
    }
    auto settings = read_pi_settings_discovery(options.settings_path);
    if (!settings) {
        return std::unexpected(settings.error());
    }
    std::error_code error;
    const auto store = std::filesystem::canonical(options.package_store_root, error);
    if (error || !std::filesystem::is_directory(store, error)) {
        return std::unexpected(std::string{"Pi package store must be an existing directory"});
    }
    const auto protected_directory =
        std::filesystem::weakly_canonical(options.protected_directory, error);
    if (error || protected_directory == protected_directory.root_path()) {
        return std::unexpected(std::string{"Pi protected manifest directory is invalid"});
    }
    std::set<std::string> selected;
    for (const auto& source : settings->packages) {
        if (!source.starts_with("npm:")) {
            return std::unexpected(std::string{"Pi package source must use npm: discovery syntax"});
        }
        const std::string id = source.substr(4U);
        if (!valid_pi_package_id(id) || !selected.insert(id).second) {
            return std::unexpected(std::string{"Pi package source is invalid or duplicated"});
        }
    }
    if (selected.empty()) {
        return std::unexpected(std::string{"Pi settings selected no package sources"});
    }
    // Resolve a flattened npm-style dependency closure from the explicitly
    // selected extensions. Versions remain package-manager discovery data;
    // the snapshot digest commits the actual package bytes.
    std::set<std::string> closure_ids = selected;
    std::vector<std::string> pending{selected.begin(), selected.end()};
    std::vector<std::filesystem::path> roots;
    for (std::size_t index = 0; index < pending.size(); ++index) {
        const auto& id = pending[index];
        const auto package = std::filesystem::canonical(store / id, error);
        if (error || !std::filesystem::is_directory(package, error) ||
            !path_within(package, store) ||
            !std::filesystem::is_regular_file(package / "package.json", error)) {
            return std::unexpected("Pi package discovery path is unavailable: " + id);
        }
        auto metadata = read_pi_package_metadata(package);
        if (!metadata) {
            return std::unexpected("read Pi package metadata for " + id + ": " + metadata.error());
        }
        roots.push_back(package);
        for (const auto& [dependency, version] : metadata->dependencies) {
            if (!valid_pi_package_id(dependency) || version.empty()) {
                return std::unexpected("Pi package dependency is invalid: " + dependency);
            }
            if (closure_ids.insert(dependency).second) {
                pending.push_back(dependency);
            }
        }
    }
    const std::vector<std::string> package_ids{closure_ids.begin(), closure_ids.end()};
    std::ranges::sort(roots);
    runtime_dependency_closure closure{
        .executable = roots.front() / "package.json",
        .arguments = {},
        .read_only_paths = roots,
    };
    auto planned = plan_runtime_snapshot(protected_directory, closure.executable, closure);
    if (!planned) {
        return std::unexpected("plan Pi package snapshot: " + planned.error());
    }
    std::string generated_settings{"{\"packages\":["};
    for (std::size_t index = 0; index < package_ids.size(); ++index) {
        if (index != 0U) {
            generated_settings.push_back(',');
        }
        generated_settings += "\"./extensions/" + std::to_string(index) + "\"";
    }
    generated_settings += "],\"enableSkillCommands\":true}\n";
    std::string material{"glove.pi-adoption-manifest-v1"};
    material.push_back('\0');
    material += planned->digest;
    material.push_back('\0');
    for (const auto& id : package_ids) {
        material += id;
        material.push_back('\0');
    }
    material += generated_settings;
    const auto bytes =
        std::span{reinterpret_cast<const unsigned char*>(material.data()), material.size()};
    auto manifest_digest = container::sha256_hex(bytes);
    if (!manifest_digest) {
        return std::unexpected(manifest_digest.error());
    }
    const auto manifest_path =
        protected_directory / "manifests" / (*manifest_digest + std::string{".json"});
    std::string persisted_manifest{
        "{\"schema_version\":1,\"runtime_id\":\"pi\",\"manifest_digest\":\"" + *manifest_digest +
        "\",\"snapshot_digest\":\"" + planned->digest + "\",\"packages\":["
    };
    for (std::size_t index = 0; index < package_ids.size(); ++index) {
        if (index != 0U) {
            persisted_manifest.push_back(',');
        }
        persisted_manifest += "\"" + package_ids[index] + "\"";
    }
    // The generated settings are a standalone JSON file and deliberately end
    // with a newline. Embed its JSON value without that transport newline so
    // the protected manifest remains canonical JSON.
    const auto settings_value = generated_settings.ends_with('\n')
                                    ? generated_settings.substr(0, generated_settings.size() - 1U)
                                    : generated_settings;
    persisted_manifest += "],\"generated_settings\":" + settings_value + "}";
    bool changed = false;
    if (!options.dry_run) {
        auto materialized = materialize_runtime_snapshot(*planned);
        if (!materialized) {
            return std::unexpected("materialize Pi package snapshot: " + materialized.error());
        }
        changed = *materialized;
        if (auto prepared = ensure_protected_directory(manifest_path.parent_path()); !prepared) {
            return std::unexpected(prepared.error());
        }
        auto existing = read_policy_contents(manifest_path);
        if (!existing) {
            return std::unexpected("read existing Pi adoption manifest: " + existing.error());
        }
        if (!*existing) {
            if (auto written = write_owner_file_exclusive(manifest_path, persisted_manifest);
                !written) {
                return std::unexpected("write Pi adoption manifest: " + written.error());
            }
            changed = true;
        } else if (**existing != persisted_manifest) {
            return std::unexpected(
                std::string{"existing Pi adoption manifest does not match its digest"}
            );
        }
    }
    return generated_pi_adoption_manifest{
        .manifest_digest = std::move(*manifest_digest),
        .snapshot_digest = planned->digest,
        .package_ids = std::move(package_ids),
        .generated_settings_json = std::move(generated_settings),
        .snapshot_root = planned->snapshot_root,
        .manifest_path = manifest_path,
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
    auto read_only_paths = canonical_paths(
        options.read_only_paths, "read_only_paths", options.allow_planned_snapshot_paths
    );
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
        auto executable = canonical_paths(
            {options.executable_path}, "executable_path", options.allow_planned_snapshot_paths
        );
        if (!executable) {
            return std::unexpected(executable.error());
        }
        std::error_code error;
        const auto status = std::filesystem::status(executable->front(), error);
        constexpr auto executable_bits = std::filesystem::perms::owner_exec |
                                         std::filesystem::perms::group_exec |
                                         std::filesystem::perms::others_exec;
        const bool planned_executable =
            options.allow_planned_snapshot_paths && error &&
            std::ranges::any_of(*read_only_paths, [&](const auto& root) {
                return path_within(
                    std::filesystem::path{executable->front()}, std::filesystem::path{root}
                );
            });
        if (!planned_executable &&
            (error || !std::filesystem::is_regular_file(status) ||
             (status.permissions() & executable_bits) == std::filesystem::perms::none)) {
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
        .adoption = std::nullopt,
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

auto prepare_session_policy(const session_policy_prepare_options& options)
    -> result<prepared_session_policy> {
    if (options.executable_search_paths.empty()) {
        return std::unexpected(
            std::string{"at least one explicit harness search path is required"}
        );
    }
    if (options.hostile_content_analysis &&
        options.backend != supervisor::sandbox_backend::linux_production) {
        return std::unexpected(
            std::string{"hostile-content analysis requires the Linux managed-session backend"}
        );
    }
    if (options.hostile_content_analysis &&
        (!options.egress_policies.empty() || !options.secret_mounts.empty())) {
        return std::unexpected(
            std::string{"hostile-content analysis forbids egress policies and secret mounts"}
        );
    }
    if (!options.protected_harness_root.is_absolute() || !options.workspace_root.is_absolute() ||
        !options.policy_path.is_absolute()) {
        return std::unexpected(
            std::string{"harness root, workspace root, and policy path must be absolute"}
        );
    }
    std::error_code error;
    const auto harness_root =
        std::filesystem::weakly_canonical(options.protected_harness_root, error);
    if (error || harness_root == harness_root.root_path()) {
        return std::unexpected(std::string{"protected harness root is invalid"});
    }
    const auto workspace = std::filesystem::canonical(options.workspace_root, error);
    if (error || !std::filesystem::is_directory(workspace)) {
        return std::unexpected(std::string{"workspace root must be an existing directory"});
    }
    const auto policy_parent = std::filesystem::weakly_canonical(
        options.policy_path.lexically_normal().parent_path(), error
    );
    if (error) {
        return std::unexpected("canonicalize session policy directory: " + error.message());
    }
    const auto policy_path = policy_parent / options.policy_path.filename();
    if (policy_path == policy_path.root_path() || policy_path.filename().empty()) {
        return std::unexpected(std::string{"session policy path is invalid"});
    }

    auto detections = detect_runtime_harnesses(options.executable_search_paths);
    auto selected_runtimes =
        canonical_identifiers(options.selected_runtime_ids, "selected_runtime_ids");
    if (!selected_runtimes) {
        return std::unexpected(selected_runtimes.error());
    }
    std::vector<staged_runtime_harness> planned_runtimes;
    std::vector<runtime_policy_wire::runtime_template> templates;
    for (const auto& detected : detections) {
        if (!detected.available ||
            (!selected_runtimes->empty() &&
             !std::ranges::binary_search(*selected_runtimes, detected.runtime_id))) {
            continue;
        }
        auto staged = stage_runtime_harness_impl(
            {
                .runtime_id = detected.runtime_id,
                .source_executable = detected.resolved_executable,
                .protected_directory = harness_root / detected.runtime_id,
                .dry_run = true,
            },
            !options.dry_run
        );
        if (!staged) {
            return std::unexpected(
                "derive " + detected.runtime_id + " launch closure: " + staged.error()
            );
        }
        auto generated = generate_runtime_policy({
            .runtime_id = detected.runtime_id,
            .runtime_template_id =
                detected.runtime_id +
                (options.hostile_content_analysis ? "-hostile-analysis" : "-safe"),
            .backend = options.backend,
            .executable_path = staged->launch_executable,
            .executable_search_paths = {},
            .arguments = staged->launch_arguments,
            .environment = {},
            .read_only_paths = staged->read_only_paths,
            .allowed_path_aliases = {"workspace"},
            .allowed_projection_destinations = {"libraries"},
            .allow_planned_snapshot_paths = !staged->snapshot_digest.empty(),
        });
        if (!generated) {
            return std::unexpected(
                "generate " + detected.runtime_id + " template: " + generated.error()
            );
        }
        runtime_policy_wire::runtime_template policy_template;
        if (const auto decoded = glz::read_json(policy_template, generated->policy_template_json)) {
            return std::unexpected(
                "decode generated " + detected.runtime_id +
                " template: " + glz::format_error(decoded, generated->policy_template_json)
            );
        }
        planned_runtimes.push_back(std::move(*staged));
        templates.push_back(std::move(policy_template));
    }
    if (planned_runtimes.empty()) {
        return std::unexpected(
            selected_runtimes->empty()
                ? std::string{"none of the supported harnesses were found in the explicit search "
                              "paths"}
                : std::string{"none of the selected harnesses were found in the explicit search "
                              "paths"}
        );
    }
    for (const auto& selected : *selected_runtimes) {
        if (!std::ranges::any_of(planned_runtimes, [&](const auto& runtime) {
                return runtime.runtime_id == selected;
            })) {
            return std::unexpected(
                "selected runtime is not available in the explicit search paths: " + selected
            );
        }
    }

    const bool pi_selected = std::ranges::any_of(planned_runtimes, [](const auto& runtime) {
        return runtime.runtime_id == "pi";
    });
    if (pi_selected != options.pi_adoption.has_value()) {
        return std::unexpected(
            pi_selected ? std::string{"Pi enrollment requires --pi-settings, --pi-package-store, "
                                      "and --pi-adoption-root"}
                        : std::string{"Pi adoption inputs require the Pi runtime to be selected"}
        );
    }
    if (options.pi_adoption) {
        auto adoption_options = *options.pi_adoption;
        adoption_options.dry_run = options.dry_run;
        auto adoption = generate_pi_adoption_manifest(adoption_options);
        if (!adoption) {
            return std::unexpected("generate Pi adoption manifest: " + adoption.error());
        }
        const auto pi_template = std::ranges::find(templates, "pi", [](const auto& template_) {
            return template_.runtime_id;
        });
        if (pi_template == templates.end()) {
            return std::unexpected(std::string{"Pi runtime template is missing"});
        }
        pi_template->adoption = supervisor::native_harness_adoption_policy{
            .manifest_root = adoption->snapshot_root.parent_path().parent_path().string(),
            .manifest_digest = adoption->manifest_digest,
            .snapshot_digest = adoption->snapshot_digest,
        };
    }

    constexpr std::uint64_t mebibyte = std::uint64_t{1024} * 1024U;
    std::vector<std::string> egress_policy_ids = {"no-network"};
    std::vector<runtime_policy_wire::egress_policy> egress_policies;
    egress_policies.reserve(options.egress_policies.size());
    std::set<std::string> egress_ids;
    for (const auto& egress : options.egress_policies) {
        if (!valid_identifier(egress.policy_id) || egress.policy_id == "no-network" ||
            egress.targets.empty() || egress.targets.size() > 128U ||
            !egress_ids.insert(egress.policy_id).second) {
            return std::unexpected(std::string{"online egress policy is invalid or duplicated"});
        }
        egress_policy_ids.push_back(egress.policy_id);
        runtime_policy_wire::egress_policy encoded_egress{
            .policy_id = egress.policy_id,
            .targets = {},
        };
        std::set<std::pair<std::string, std::uint16_t>> targets;
        encoded_egress.targets.reserve(egress.targets.size());
        for (const auto& target : egress.targets) {
            if (target.host.empty() || target.host.size() > 253U || target.port == 0 ||
                target.host.find('\0') != std::string::npos ||
                std::ranges::any_of(
                    target.host, [](unsigned char byte) { return byte <= 0x20U || byte == 0x7fU; }
                ) ||
                !targets.emplace(target.host, target.port).second) {
                return std::unexpected(
                    std::string{"online egress target is invalid or duplicated"}
                );
            }
            encoded_egress.targets.push_back({
                .host = target.host,
                .port = target.port,
                .allow_private = target.allow_private,
            });
        }
        egress_policies.push_back(std::move(encoded_egress));
    }
    std::vector<std::string> secret_handles;
    std::vector<runtime_policy_wire::secret_mount_policy> secret_mounts;
    secret_handles.reserve(options.secret_mounts.size());
    secret_mounts.reserve(options.secret_mounts.size());
    std::set<std::string> handles;
    std::set<std::pair<std::string, std::string>> secret_targets;
    for (const auto& secret : options.secret_mounts) {
        const bool runtime_exists = std::ranges::any_of(planned_runtimes, [&](const auto& runtime) {
            return runtime.runtime_id == secret.runtime_id;
        });
        const std::filesystem::path target{secret.target_path};
        const std::filesystem::path managed_home{"/home/agent"};
        auto source = canonical_owner_secret(secret.source_path);
        const auto home_mismatch =
            std::mismatch(managed_home.begin(), managed_home.end(), target.begin(), target.end());
        if (!source || !valid_identifier(secret.handle) || secret.handle.size() > 120U ||
            !valid_identifier(secret.runtime_id) || !runtime_exists || !target.is_absolute() ||
            target.lexically_normal() != target || target == managed_home ||
            home_mismatch.first != managed_home.end() || !handles.insert(secret.handle).second ||
            !secret_targets.emplace(secret.runtime_id, secret.target_path).second) {
            return std::unexpected(
                source ? std::string{"secret mount is invalid or duplicated"} : source.error()
            );
        }
        secret_handles.push_back(secret.handle);
        secret_mounts.push_back({
            .handle = secret.handle,
            .runtime_id = secret.runtime_id,
            .source_path = source->string(),
            .target_path = secret.target_path,
        });
    }
    const std::uint64_t workspace_limit =
        options.hostile_content_analysis ? 64U * mebibyte : 1024U * mebibyte;
    std::vector<runtime_policy_wire::path_access> workspace_access;
    if (!options.hostile_content_analysis) {
        workspace_access.push_back({
            .access = "read",
            .materialization = "bind",
            .create_policy = "never",
            .cleanup_policy = "retain",
            .max_bytes = 0,
        });
    }
    workspace_access.push_back({
        .access = "ephemeral_write",
        .materialization = "copy",
        .create_policy = "empty_directory",
        .cleanup_policy = "remove",
        .max_bytes = workspace_limit,
    });
    if (!options.hostile_content_analysis) {
        workspace_access.push_back({
            .access = "retained_write",
            .materialization = "copy",
            .create_policy = "empty_directory",
            .cleanup_policy = "retain",
            .max_bytes = workspace_limit,
        });
    }
    std::vector<runtime_policy_wire::resource_profile> resource_profiles;
    if (options.hostile_content_analysis) {
        resource_profiles.push_back({
            .profile_id = "hostile-analysis",
            .cpu_time_ms = 30'000,
            .memory_bytes = 512U * mebibyte,
            .pids = 64,
            .wall_time_ms = 60'000,
            .disk_bytes = 128U * mebibyte,
            .terminal_output_bytes = mebibyte,
        });
    } else {
        resource_profiles = {
            {
                .profile_id = "small",
                .cpu_time_ms = 60'000,
                .memory_bytes = 1024U * mebibyte,
                .pids = 256,
                .wall_time_ms = 120'000,
                .disk_bytes = 2048U * mebibyte,
                .terminal_output_bytes = 16U * mebibyte,
            },
            {
                .profile_id = "interactive",
                .cpu_time_ms = 120'000,
                .memory_bytes = 1024U * mebibyte,
                .pids = 256,
                .wall_time_ms = 300'000,
                .disk_bytes = 2048U * mebibyte,
                .terminal_output_bytes = 16U * mebibyte,
            },
        };
    }
    runtime_policy_wire::session_policy policy{
        .runtime_templates = std::move(templates),
        .path_aliases = {{
            .alias = "workspace",
            .host_path = workspace.string(),
            .target_path = "/workspace",
            .max_ttl_secs = 86'400,
            .access = std::move(workspace_access),
        }},
        .library_projection_destinations = {{
            .alias = "libraries",
            .target_path = "/opt/sage/library-bundles",
        }},
        .resource_profiles = std::move(resource_profiles),
        .egress_policy_ids = std::move(egress_policy_ids),
        .tool_policy_ids = {"sage-readonly"},
        .secret_handles = std::move(secret_handles),
        .egress_policies = std::move(egress_policies),
        .secret_mounts = std::move(secret_mounts),
    };
    std::optional<policy_update_lock> update_lock;
    if (!options.dry_run) {
        if (auto prepared = ensure_protected_directory(policy_path.parent_path()); !prepared) {
            return std::unexpected(prepared.error());
        }
        auto acquired = policy_update_lock::acquire(policy_path);
        if (!acquired) {
            return std::unexpected(acquired.error());
        }
        update_lock.emplace(std::move(*acquired));
    }
    auto update = derive_policy_update(std::move(policy), policy_path);
    if (!update) {
        return std::unexpected(update.error());
    }
    if (options.dry_run) {
        return prepared_session_policy{
            .policy_path = policy_path,
            .detections = std::move(detections),
            .runtimes = std::move(planned_runtimes),
            .policy_json = std::move(update->contents),
            .changed = update->changed,
            .dry_run = true,
        };
    }

    bool changed = false;
    std::vector<staged_runtime_harness> applied_runtimes;
    applied_runtimes.reserve(planned_runtimes.size());
    for (const auto& runtime : planned_runtimes) {
        auto staged = stage_runtime_harness({
            .runtime_id = runtime.runtime_id,
            .source_executable = runtime.source_executable,
            .protected_directory = harness_root / runtime.runtime_id,
            .dry_run = false,
        });
        if (!staged) {
            return std::unexpected("stage " + runtime.runtime_id + ": " + staged.error());
        }
        changed = changed || staged->changed;
        applied_runtimes.push_back(std::move(*staged));
    }
    if (auto activated = activate_policy_update(policy_path, *update); !activated) {
        return std::unexpected(activated.error());
    }
    changed = changed || update->changed;
    return prepared_session_policy{
        .policy_path = policy_path,
        .detections = std::move(detections),
        .runtimes = std::move(applied_runtimes),
        .policy_json = std::move(update->contents),
        .changed = changed,
        .dry_run = false,
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
