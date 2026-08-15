#include "glove/host/runtime_policy.hpp"

#include "glove/container/digest.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "runtime_policy_wire.hpp"
#include "runtime_snapshot.hpp"

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

namespace glove::host {

using snapshot::closure_launch_is_trusted;
using snapshot::derive_runtime_dependency_closure;
using snapshot::ensure_protected_directory;
using snapshot::materialize_runtime_snapshot;
using snapshot::path_within;
using snapshot::plan_runtime_snapshot;
using snapshot::planned_runtime_snapshot;
using snapshot::runtime_dependency_closure;
using snapshot::system_error;

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
