#include "glove/host/setup.hpp"

#include "glove/container/digest.hpp"
#include "glove/host/runtime_policy.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string_view>
#include <system_error>

#if defined(__linux__)
#    include <pwd.h>
#    include <sys/random.h>
#endif
#if defined(__APPLE__)
#    include <mach-o/dyld.h>
#endif

extern char** environ;

namespace glove::host {
namespace setup_wire {

struct mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct root {
    std::string root_id;
    std::string host_root;
    std::vector<mode> allowed_modes;
    std::uint64_t max_ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

struct policy {
    std::uint8_t schema_version = 1;
    std::vector<root> roots;
};

struct ledger_resource {
    std::string kind;
    std::string path;
    bool owned = false;
    std::optional<std::string> content_sha256;
};

struct ledger {
    std::uint8_t schema_version = 1;
    std::string config_path;
    std::vector<ledger_resource> resources;
};

struct apple_container_runtime {
    std::string image_reference;
    std::string image_digest;
    std::string harness_closure_digest;
    std::uint8_t agent_runtime_adapter_schema_version = 0;
};

struct runtime_pair {
    std::optional<apple_container_runtime> apple_container_runtime;
};

} // namespace setup_wire

namespace {

constexpr std::uint64_t mebibyte = std::uint64_t{1024} * 1024U;
constexpr std::uint64_t max_setup_ledger_bytes = mebibyte;

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && value.front() != '-' && value.front() != '.' &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

#if defined(__APPLE__)
auto installed_apple_container_runtime() -> result<std::optional<apple_container_config>> {
    std::uint32_t size = 0;
    if (::_NSGetExecutablePath(nullptr, &size) != -1 || size == 0 || size > 64U * 1024U) {
        return std::unexpected(std::string{"resolve installed Glove executable size"});
    }
    std::vector<char> executable_bytes(size);
    if (::_NSGetExecutablePath(executable_bytes.data(), &size) != 0) {
        return std::unexpected(std::string{"resolve installed Glove executable"});
    }
    std::error_code filesystem_error;
    const auto executable =
        std::filesystem::canonical(executable_bytes.data(), filesystem_error);
    if (filesystem_error) {
        return std::unexpected(
            std::string{"canonicalize installed Glove executable: "} + filesystem_error.message()
        );
    }
    const auto release_root =
        executable.parent_path().parent_path().parent_path();
    const auto manifest_path = release_root / "runtime-pair.json";
    if (!std::filesystem::exists(manifest_path, filesystem_error)) {
        return std::optional<apple_container_config>{};
    }
    struct stat metadata {};
    if (::lstat(manifest_path.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_nlink != 1 ||
        (metadata.st_uid != ::geteuid() && metadata.st_uid != 0) ||
        (static_cast<unsigned int>(metadata.st_mode) & 0022U) != 0U ||
        metadata.st_size <= 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_setup_ledger_bytes) {
        return std::unexpected(std::string{"installed runtime pair manifest is unsafe"});
    }
    std::ifstream input{manifest_path, std::ios::binary};
    std::string contents(
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}
    );
    setup_wire::runtime_pair pair;
    constexpr glz::opts strict{.error_on_unknown_keys = false};
    if (const auto error = glz::read<strict>(pair, contents); error) {
        return std::unexpected(
            std::string{"installed runtime pair manifest is invalid: "} +
            glz::format_error(error, contents)
        );
    }
    if (!pair.apple_container_runtime) {
        return std::optional<apple_container_config>{};
    }
    if (pair.apple_container_runtime->agent_runtime_adapter_schema_version != 1) {
        return std::unexpected(
            std::string{"installed Apple runtime adapter schema is unsupported"}
        );
    }
    return std::optional<apple_container_config>{apple_container_config{
        .cli = "/usr/local/bin/container",
        .image = pair.apple_container_runtime->image_reference,
        .image_digest = pair.apple_container_runtime->image_digest,
        .harness_closure_digest = pair.apple_container_runtime->harness_closure_digest,
    }};
}

auto run_apple_container_command(
    const std::filesystem::path& cli, std::initializer_list<std::string> arguments
) -> result<void> {
    struct stat metadata {};
    if (::lstat(cli.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || (static_cast<unsigned int>(metadata.st_mode) & 0022U) != 0U ||
        (static_cast<unsigned int>(metadata.st_mode) & 0111U) == 0U) {
        return std::unexpected(
            std::string{"Apple Container CLI must be an immutable root-owned executable"}
        );
    }
    std::vector<std::string> owned;
    owned.reserve(arguments.size() + 1U);
    owned.push_back(cli.string());
    owned.insert(owned.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(owned.size() + 1U);
    for (auto& value : owned) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    ::pid_t child = -1;
    const int spawned =
        ::posix_spawn(&child, cli.c_str(), nullptr, nullptr, argv.data(), environ);
    if (spawned != 0) {
        return std::unexpected(system_error("start Apple Container command", spawned));
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return std::unexpected(system_error("wait for Apple Container command"));
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(std::string{"Apple Container command failed"});
    }
    return {};
}
#endif

auto create_owner_directory(const std::filesystem::path& path) -> result<void> {
    struct stat existing{};
    if (::lstat(path.c_str(), &existing) == 0) {
        if (!S_ISDIR(existing.st_mode) || existing.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(existing.st_mode) & 0777U) != 0700U) {
            return std::unexpected(
                "existing directory is not a current-user mode-0700 directory: " + path.string()
            );
        }
        return {};
    }
    if (errno != ENOENT) {
        return std::unexpected(system_error("inspect directory"));
    }
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        return std::unexpected("create directory " + path.string() + ": " + error.message());
    }
    if (::chmod(path.c_str(), 0700) != 0) {
        return std::unexpected(system_error("protect directory"));
    }
    struct stat metadata{};
    if (::lstat(path.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"directory ownership or mode is unsafe"});
    }
    return {};
}

auto owner_directory_exists(const std::filesystem::path& path) -> result<bool> {
    struct stat metadata{};
    if (::lstat(path.c_str(), &metadata) != 0) {
        if (errno == ENOENT) {
            return false;
        }
        return std::unexpected(system_error("inspect setup directory"));
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            "existing directory is not a current-user mode-0700 directory: " + path.string()
        );
    }
    return true;
}

auto write_exact(int descriptor, std::string_view contents) -> result<void> {
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto written =
            ::write(descriptor, contents.data() + consumed, contents.size() - consumed);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return std::unexpected(system_error("write protected file"));
        }
        consumed += static_cast<std::size_t>(written);
    }
    if (::fsync(descriptor) != 0) {
        return std::unexpected(system_error("sync protected file"));
    }
    return {};
}

auto create_owner_file(const std::filesystem::path& path, std::string_view contents)
    -> result<void> {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        if (errno == EEXIST) {
            return std::unexpected("refusing to overwrite existing file: " + path.string());
        }
        return std::unexpected(system_error("create protected file"));
    }
    auto written = write_exact(descriptor, contents);
    const int close_result = ::close(descriptor);
    if (!written) {
        (void)::unlink(path.c_str());
        return written;
    }
    if (close_result != 0) {
        (void)::unlink(path.c_str());
        return std::unexpected(system_error("close protected file"));
    }
    return {};
}

#if defined(__linux__)
auto enable_user_lingering() -> result<void> {
    constexpr std::string_view loginctl = "/usr/bin/loginctl";
    struct stat executable{};
    if (::stat(loginctl.data(), &executable) != 0 || !S_ISREG(executable.st_mode) ||
        executable.st_uid != 0 || (executable.st_mode & 0111U) == 0 ||
        (executable.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return std::unexpected(
            std::string{"persistent service requires immutable root-owned /usr/bin/loginctl"}
        );
    }
    const auto* account = ::getpwuid(::geteuid());
    if (account == nullptr || account->pw_name == nullptr || *account->pw_name == '\0') {
        return std::unexpected(std::string{"resolve current account for user lingering"});
    }
    std::array<char*, 4> arguments{
        const_cast<char*>(loginctl.data()),
        const_cast<char*>("enable-linger"),
        account->pw_name,
        nullptr,
    };
    ::pid_t child = -1;
    const int spawned =
        ::posix_spawn(&child, loginctl.data(), nullptr, nullptr, arguments.data(), environ);
    if (spawned != 0) {
        return std::unexpected(system_error("start loginctl enable-linger", spawned));
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return std::unexpected(system_error("wait for loginctl enable-linger"));
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(
            std::string{"loginctl could not enable lingering; review local policy and rerun setup"}
        );
    }
    return {};
}
#endif

auto read_owner_file(const std::filesystem::path& path, std::uint64_t max_bytes)
    -> result<std::string> {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return std::unexpected(system_error("open protected file"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U || metadata.st_size <= 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_bytes) {
        (void)::close(descriptor);
        return std::unexpected(std::string{"protected file ownership, mode, or size is unsafe"});
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
            (void)::close(descriptor);
            return std::unexpected(system_error("read protected file"));
        }
        consumed += static_cast<std::size_t>(count);
    }
    if (::close(descriptor) != 0) {
        return std::unexpected(system_error("close protected file"));
    }
    return contents;
}

auto content_sha256(std::string_view contents) -> result<std::string> {
    const auto* first = reinterpret_cast<const unsigned char*>(contents.data());
    return container::sha256_hex(std::span<const unsigned char>{first, contents.size()});
}

auto file_sha256(const std::filesystem::path& path, std::uint64_t max_bytes)
    -> result<std::string> {
    auto contents = read_owner_file(path, max_bytes);
    return contents ? content_sha256(*contents) : std::unexpected(contents.error());
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_resource_kind(std::string_view kind) -> bool {
    return kind == "config" || kind == "audit_key" || kind == "path_exposure_policy" ||
           kind == "runtime_directory" || kind == "state_directory" || kind == "config_directory" ||
           kind == "materialization_root" || kind == "library_bundle_root" ||
           kind == "receipt_journal" || kind == "session_policy" || kind == "session_store" ||
           kind == "path_exposure_journal";
}

auto encode_setup_ledger(const setup_ledger& value) -> result<std::string> {
    setup_wire::ledger wire{
        .schema_version = value.schema_version,
        .config_path = value.config_path.string(),
        .resources = {},
    };
    wire.resources.reserve(value.resources.size());
    for (const auto& resource : value.resources) {
        wire.resources.push_back({
            .kind = resource.kind,
            .path = resource.path.string(),
            .owned = resource.owned,
            .content_sha256 = resource.content_sha256,
        });
    }
    auto encoded = glz::write_json(wire);
    if (!encoded) {
        return std::unexpected(std::string{"encode setup ledger"});
    }
    encoded->push_back('\n');
    return std::move(*encoded);
}

auto validate_setup_ledger(const setup_ledger& value) -> result<void> {
    if (value.schema_version != 1 || !value.ledger_path.is_absolute() ||
        value.ledger_path == value.ledger_path.root_path() || !value.config_path.is_absolute() ||
        value.config_path == value.config_path.root_path() || value.resources.empty() ||
        value.resources.size() > 64U) {
        return std::unexpected(std::string{"setup ledger identity is invalid"});
    }
    std::vector<std::filesystem::path> seen;
    seen.reserve(value.resources.size());
    for (const auto& resource : value.resources) {
        if (!valid_resource_kind(resource.kind) || !resource.path.is_absolute() ||
            resource.path == resource.path.root_path() ||
            resource.path.lexically_normal() != resource.path ||
            std::ranges::find(seen, resource.path) != seen.end() ||
            (resource.content_sha256 && !valid_digest(*resource.content_sha256))) {
            return std::unexpected(std::string{"setup ledger resource is invalid"});
        }
        seen.push_back(resource.path);
    }
    return {};
}

auto make_setup_ledger(
    const setup_plan& plan,
    const std::vector<std::filesystem::path>& created_directories,
    bool config_created,
    bool audit_key_created,
    bool exposure_policy_created
) -> result<setup_ledger> {
    setup_ledger ledger{
        .schema_version = 1,
        .ledger_path = setup_ledger_path(plan.service),
        .config_path = plan.config_path,
        .resources = {},
    };
    const auto directory_owned = [&](const std::filesystem::path& path) {
        return std::ranges::find(created_directories, path) != created_directories.end();
    };
    const auto add_directory = [&](std::string kind, const std::filesystem::path& path) {
        if (std::ranges::none_of(ledger.resources, [&](const auto& existing) {
                return existing.path == path;
            })) {
            ledger.resources.push_back({
                .kind = std::move(kind),
                .path = path,
                .owned = directory_owned(path),
                .content_sha256 = std::nullopt,
            });
        }
    };
    add_directory("config_directory", plan.config_path.parent_path());
    add_directory("state_directory", plan.service.audit_key.parent_path());
    add_directory("runtime_directory", plan.service.runtime_directory);
    if (plan.service.materialization_root) {
        add_directory("materialization_root", *plan.service.materialization_root);
    }
    if (plan.service.library_bundle_root) {
        add_directory("library_bundle_root", *plan.service.library_bundle_root);
    }
    auto config_digest = file_sha256(plan.config_path, max_setup_ledger_bytes);
    auto key_digest = file_sha256(plan.service.audit_key, 65U);
    if (!config_digest || !key_digest) {
        return std::unexpected(!config_digest ? config_digest.error() : key_digest.error());
    }
    ledger.resources.push_back({
        .kind = "audit_key",
        .path = plan.service.audit_key,
        .owned = audit_key_created,
        .content_sha256 = std::move(*key_digest),
    });
    if (plan.service.path_exposure_policy) {
        auto policy_digest = file_sha256(*plan.service.path_exposure_policy, mebibyte);
        if (!policy_digest) {
            return std::unexpected(policy_digest.error());
        }
        ledger.resources.push_back({
            .kind = "path_exposure_policy",
            .path = *plan.service.path_exposure_policy,
            .owned = exposure_policy_created,
            .content_sha256 = std::move(*policy_digest),
        });
    }
    ledger.resources.push_back({
        .kind = "config",
        .path = plan.config_path,
        .owned = config_created,
        .content_sha256 = std::move(*config_digest),
    });
    if (auto valid = validate_setup_ledger(ledger); !valid) {
        return std::unexpected(valid.error());
    }
    return ledger;
}

auto write_or_validate_setup_ledger(const setup_ledger& ledger) -> result<void> {
    auto encoded = encode_setup_ledger(ledger);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (std::filesystem::exists(ledger.ledger_path)) {
        auto existing = read_owner_file(ledger.ledger_path, max_setup_ledger_bytes);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        auto loaded = load_setup_ledger(ledger.ledger_path);
        if (!loaded || loaded->config_path != ledger.config_path) {
            return std::unexpected(
                std::string{"existing setup ledger does not describe this configuration"}
            );
        }
        return {};
    }
    return create_owner_file(ledger.ledger_path, *encoded);
}

auto valid_audit_key(std::string_view key) -> bool {
    return key.size() == 65U && key.back() == '\n' &&
           std::ranges::all_of(key.substr(0, 64U), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto fill_random(std::array<unsigned char, 32>& bytes) -> result<void> {
#if defined(__APPLE__)
    ::arc4random_buf(bytes.data(), bytes.size());
    return {};
#elif defined(__linux__)
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto count = ::getrandom(bytes.data() + consumed, bytes.size() - consumed, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(system_error("generate audit key"));
        }
        consumed += static_cast<std::size_t>(count);
    }
    return {};
#else
    return std::unexpected(std::string{"secure key generation is unsupported on this platform"});
#endif
}

auto key_hex() -> result<std::string> {
    constexpr std::string_view digits = "0123456789abcdef";
    std::array<unsigned char, 32> bytes{};
    auto filled = fill_random(bytes);
    if (!filled) {
        return std::unexpected(filled.error());
    }
    std::string encoded;
    encoded.reserve((bytes.size() * 2U) + 1U);
    for (const auto byte : bytes) {
        encoded.push_back(digits.at(byte >> 4U));
        encoded.push_back(digits.at(byte & 0x0fU));
    }
    std::ranges::fill(bytes, 0U);
    encoded.push_back('\n');
    return encoded;
}

auto exposure_policy_json(const setup_plan& plan) -> result<std::string> {
    if (!plan.canonical_protected_root) {
        return std::string{};
    }
    setup_wire::policy policy{
        .schema_version = 1,
        .roots = {
            {.root_id = plan.root_id,
             .host_root = plan.canonical_protected_root->string(),
             .allowed_modes =
                 {{.access = "read",
                   .materialization = "bind",
                   .max_bytes = 0,
                   .cleanup_policy = "retain"},
                  {.access = "ephemeral_write",
                   .materialization = "copy",
                   .max_bytes = 1'073'741'824,
                   .cleanup_policy = "remove"},
                  {.access = "retained_write",
                   .materialization = "copy",
                   .max_bytes = 1'073'741'824,
                   .cleanup_policy = "retain"}},
             .max_ttl_secs = 86'400,
             .allowed_runtime_template_ids = plan.runtime_template_ids}
        },
    };
    std::string encoded;
    if (const auto error = glz::write_json(policy, encoded)) {
        return std::unexpected("encode path exposure policy: " + glz::format_error(error));
    }
    encoded.push_back('\n');
    return encoded;
}

} // namespace

auto plan_setup(const setup_options& options, const environment& values) -> result<setup_plan> {
    auto roots = resolve_directories(values);
    if (!roots) {
        return std::unexpected(roots.error());
    }
    if (!valid_identifier(options.root_id) || options.runtime_template_ids.empty() ||
        !std::ranges::all_of(options.runtime_template_ids, valid_identifier)) {
        return std::unexpected(std::string{"setup identifiers are invalid"});
    }
    std::optional<std::filesystem::path> canonical_root;
    if (options.protected_root) {
        std::error_code error;
        canonical_root = std::filesystem::canonical(*options.protected_root, error);
        if (error || !std::filesystem::is_directory(*canonical_root)) {
            return std::unexpected(std::string{"protected root must be an existing directory"});
        }
    }
    std::optional<std::filesystem::path> session_policy;
    if (options.session_policy) {
        if (!options.session_policy->is_absolute()) {
            return std::unexpected(std::string{"session policy path must be absolute"});
        }
        session_policy = options.session_policy->lexically_normal();
    }
    config service{
        .persistent_service = options.persistent_service.value_or(false),
        .runtime_directory = roots->runtime,
        .audit_key = roots->state / "audit.key",
        .receipt_journal = roots->state / "receipts.journal",
        .session_policy = session_policy,
        .session_store =
            session_policy ? std::optional{roots->state / "sessions.journal"} : std::nullopt,
        .materialization_root =
            session_policy ? std::optional{roots->state / "materializations"} : std::nullopt,
        .library_bundle_root =
            session_policy ? std::optional{roots->data / "library-bundles"} : std::nullopt,
        .path_exposure_policy = canonical_root
                                    ? std::optional{roots->config / "path-exposure-policy.json"}
                                    : std::nullopt,
        .path_exposure_journal =
            canonical_root ? std::optional{roots->state / "path-exposures.journal"} : std::nullopt,
        .apple_container = std::nullopt,
    };
#if defined(__APPLE__)
    if (session_policy) {
        auto apple_runtime = installed_apple_container_runtime();
        if (!apple_runtime) {
            return std::unexpected(apple_runtime.error());
        }
        service.apple_container = std::move(*apple_runtime);
    }
#endif
    if (auto valid = validate(service); !valid) {
        return std::unexpected(valid.error());
    }
    const auto config_path = options.config_path.value_or(default_config_path(*roots));
    if (!config_path.is_absolute()) {
        return std::unexpected(std::string{"setup configuration path must be absolute"});
    }
    std::optional<std::filesystem::path> migrate_runtime_from;
    bool add_paired_apple_runtime = false;
    if (std::filesystem::exists(config_path)) {
        auto existing = load_config(config_path);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        if (!options.persistent_service) {
            service.persistent_service = existing->persistent_service;
        }
        const bool runtime_differs =
            existing->runtime_directory != service.runtime_directory;
        const bool paired_apple_addition =
            !existing->apple_container && service.apple_container.has_value();
        auto known_existing = service;
        if (runtime_differs) {
            known_existing.runtime_directory = existing->runtime_directory;
        }
        if (paired_apple_addition) {
            known_existing.apple_container.reset();
        }
        if (*existing != service && *existing == known_existing) {
            std::optional<std::filesystem::path> legacy_runtime;
            if (runtime_differs && values.xdg_runtime_dir) {
                const std::filesystem::path root{*values.xdg_runtime_dir};
                if (root.is_absolute() && root != root.root_path()) {
                    legacy_runtime = root.lexically_normal() / "glove";
                }
            }
#if defined(__linux__)
            // Non-login SSH and service-manager environments commonly omit
            // XDG_RUNTIME_DIR even though the old generated configuration used
            // its canonical systemd location. Recognize only this exact
            // per-UID path; never infer an arbitrary volatile directory.
            if (runtime_differs && !legacy_runtime) {
                legacy_runtime =
                    std::filesystem::path{"/run/user"} / std::to_string(::geteuid()) / "glove";
            }
#endif
#if defined(__APPLE__)
            if (runtime_differs && !legacy_runtime && values.temporary_directory) {
                const std::filesystem::path root{*values.temporary_directory};
                if (root.is_absolute() && root != root.root_path()) {
                    legacy_runtime =
                        root.lexically_normal() / ("glove-" + std::to_string(::geteuid()));
                }
            }
#endif
            if (runtime_differs &&
                (!legacy_runtime || existing->runtime_directory != *legacy_runtime)) {
                return std::unexpected(
                    std::string{
                        "existing configuration differs beyond the known volatile runtime path"
                    }
                );
            }
            if (runtime_differs) {
                migrate_runtime_from = existing->runtime_directory;
            }
            add_paired_apple_runtime = paired_apple_addition;
        } else if (*existing != service) {
            return std::unexpected(
                std::string{"existing configuration differs from the requested setup"}
            );
        }
    }
    return setup_plan{
        .service = std::move(service),
        .config_path = config_path.lexically_normal(),
        .migrate_runtime_from = std::move(migrate_runtime_from),
        .add_paired_apple_runtime = add_paired_apple_runtime,
        .canonical_protected_root = std::move(canonical_root),
        .root_id = options.root_id,
        .runtime_template_ids = options.runtime_template_ids,
        .dry_run = options.dry_run,
    };
}

auto execute_setup(const setup_plan& plan) -> result<void> {
    auto encoded = encode_config(plan.service);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (plan.dry_run) {
        return {};
    }
#if defined(__APPLE__)
    if (plan.service.apple_container) {
        if (auto status = run_apple_container_command(
                plan.service.apple_container->cli, {"system", "status"}
            );
            !status) {
            return std::unexpected(
                status.error() +
                "; start Apple Container with `/usr/local/bin/container system start`"
            );
        }
        if (auto pulled = run_apple_container_command(
                plan.service.apple_container->cli,
                {"image", "pull", plan.service.apple_container->image}
            );
            !pulled) {
            return std::unexpected(
                pulled.error() + "; pull the digest-addressed managed guest before retrying setup"
            );
        }
    }
#endif
    std::vector<std::filesystem::path> created_directories;
    const auto ensure_directory = [&](const std::filesystem::path& path) -> result<void> {
        auto existed = owner_directory_exists(path);
        if (!existed) {
            return std::unexpected(existed.error());
        }
        if (auto created = create_owner_directory(path); !created) {
            return created;
        }
        if (!*existed) {
            created_directories.push_back(path);
        }
        return {};
    };
#if defined(__linux__)
    if (plan.service.persistent_service) {
        if (auto lingering = enable_user_lingering(); !lingering) {
            return std::unexpected(lingering.error());
        }
    }
#endif
    if (std::filesystem::exists(plan.config_path)) {
        auto existing = load_config(plan.config_path);
        auto expected_existing = plan.service;
        if (plan.migrate_runtime_from) {
            expected_existing.runtime_directory = *plan.migrate_runtime_from;
        }
        if (plan.add_paired_apple_runtime) {
            expected_existing.apple_container.reset();
        }
        if (!existing || *existing != expected_existing) {
            return std::unexpected(
                "existing configuration differs from the requested setup; refusing to overwrite"
            );
        }
        if (plan.migrate_runtime_from || plan.add_paired_apple_runtime) {
            if (plan.migrate_runtime_from) {
                if (std::filesystem::exists(*plan.migrate_runtime_from / "gloved.sock")) {
                    return std::unexpected(
                        std::string{"stop gloved before migrating its volatile runtime directory"}
                    );
                }
                if (auto created = ensure_directory(plan.service.runtime_directory); !created) {
                    return created;
                }
            }
            const auto candidate =
                plan.config_path.parent_path() /
                (plan.config_path.filename().string() + ".migrate-" + std::to_string(::getpid()));
            if (auto written = create_owner_file(candidate, *encoded); !written) {
                return written;
            }
            if (::rename(candidate.c_str(), plan.config_path.c_str()) != 0) {
                const auto error = system_error("activate migrated configuration");
                (void)::unlink(candidate.c_str());
                return std::unexpected(error);
            }
            existing = plan.service;
        }
        auto existing_key = read_owner_file(plan.service.audit_key, 65U);
        if (!existing_key || !valid_audit_key(*existing_key)) {
            return std::unexpected(
                existing_key ? "existing audit key is invalid" : existing_key.error()
            );
        }
        if (plan.service.path_exposure_policy) {
            auto expected_policy = exposure_policy_json(plan);
            auto existing_policy = read_owner_file(*plan.service.path_exposure_policy, mebibyte);
            if (!expected_policy || !existing_policy || *existing_policy != *expected_policy) {
                return std::unexpected(
                    "existing path exposure policy differs from the requested setup; refusing to "
                    "overwrite"
                );
            }
        }
        if (plan.service.session_policy) {
            if (auto valid = validate_session_policy_file(*plan.service.session_policy); !valid) {
                return std::unexpected("session policy is invalid: " + valid.error());
            }
        }
        for (const auto& directory : {
                 std::optional{plan.service.runtime_directory},
                 plan.service.materialization_root,
                 plan.service.library_bundle_root,
             }) {
            if (directory) {
                if (auto created = ensure_directory(*directory); !created) {
                    return created;
                }
            }
        }
        auto ledger = make_setup_ledger(plan, created_directories, false, false, false);
        return ledger ? write_or_validate_setup_ledger(*ledger) : std::unexpected(ledger.error());
    }
    for (const auto& directory : {
             plan.config_path.parent_path(),
             plan.service.audit_key.parent_path(),
             plan.service.runtime_directory,
         }) {
        if (auto created = ensure_directory(directory); !created) {
            return created;
        }
    }
    for (const auto& directory : {
             plan.service.materialization_root,
             plan.service.library_bundle_root,
         }) {
        if (directory) {
            if (auto created = ensure_directory(*directory); !created) {
                return created;
            }
        }
    }
    if (plan.service.session_policy) {
        if (auto valid = validate_session_policy_file(*plan.service.session_policy); !valid) {
            return std::unexpected("session policy is invalid: " + valid.error());
        }
    }
    bool audit_key_created = false;
    if (std::filesystem::exists(plan.service.audit_key)) {
        auto existing_key = read_owner_file(plan.service.audit_key, 65U);
        if (!existing_key || !valid_audit_key(*existing_key)) {
            return std::unexpected(
                existing_key ? "existing audit key is invalid" : existing_key.error()
            );
        }
    } else {
        auto key = key_hex();
        if (!key) {
            return std::unexpected(key.error());
        }
        auto created = create_owner_file(plan.service.audit_key, *key);
        std::ranges::fill(*key, '\0');
        if (!created) {
            return created;
        }
        audit_key_created = true;
    }
    bool exposure_policy_created = false;
    if (plan.service.path_exposure_policy) {
        auto policy = exposure_policy_json(plan);
        if (!policy) {
            if (audit_key_created) {
                (void)::unlink(plan.service.audit_key.c_str());
            }
            return std::unexpected(policy.error());
        }
        if (std::filesystem::exists(*plan.service.path_exposure_policy)) {
            auto existing_policy = read_owner_file(*plan.service.path_exposure_policy, mebibyte);
            if (!existing_policy || *existing_policy != *policy) {
                if (audit_key_created) {
                    (void)::unlink(plan.service.audit_key.c_str());
                }
                return std::unexpected(
                    "existing path exposure policy differs from the requested setup; refusing to "
                    "overwrite"
                );
            }
        } else {
            if (auto created = create_owner_file(*plan.service.path_exposure_policy, *policy);
                !created) {
                if (audit_key_created) {
                    (void)::unlink(plan.service.audit_key.c_str());
                }
                return created;
            }
            exposure_policy_created = true;
        }
    }
    if (auto created = create_owner_file(plan.config_path, *encoded); !created) {
        if (exposure_policy_created) {
            (void)::unlink(plan.service.path_exposure_policy->c_str());
        }
        if (audit_key_created) {
            (void)::unlink(plan.service.audit_key.c_str());
        }
        return created;
    }
    auto ledger = make_setup_ledger(
        plan, created_directories, true, audit_key_created, exposure_policy_created
    );
    std::string ledger_error;
    if (ledger) {
        if (auto written = write_or_validate_setup_ledger(*ledger); written) {
            return {};
        } else {
            ledger_error = written.error();
        }
    } else {
        ledger_error = ledger.error();
    }
    (void)::unlink(plan.config_path.c_str());
    if (exposure_policy_created) {
        (void)::unlink(plan.service.path_exposure_policy->c_str());
    }
    if (audit_key_created) {
        (void)::unlink(plan.service.audit_key.c_str());
    }
    for (auto path = created_directories.rbegin(); path != created_directories.rend(); ++path) {
        (void)::rmdir(path->c_str());
    }
    return std::unexpected(std::move(ledger_error));
}

auto setup_ledger_path(const config& service) -> std::filesystem::path {
    return service.audit_key.parent_path() / "setup-ledger.json";
}

auto load_setup_ledger(const std::filesystem::path& path) -> result<setup_ledger> {
    auto contents = read_owner_file(path, max_setup_ledger_bytes);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    setup_wire::ledger wire;
    constexpr glz::opts strict{.error_on_unknown_keys = true};
    if (const auto error = glz::read<strict>(wire, *contents); error) {
        return std::unexpected(
            std::string{"setup ledger JSON is invalid: "} + glz::format_error(error, *contents)
        );
    }
    setup_ledger decoded{
        .schema_version = wire.schema_version,
        .ledger_path = path.lexically_normal(),
        .config_path = wire.config_path,
        .resources = {},
    };
    decoded.resources.reserve(wire.resources.size());
    for (auto& resource : wire.resources) {
        decoded.resources.push_back({
            .kind = std::move(resource.kind),
            .path = std::move(resource.path),
            .owned = resource.owned,
            .content_sha256 = std::move(resource.content_sha256),
        });
    }
    if (auto valid = validate_setup_ledger(decoded); !valid) {
        return std::unexpected(valid.error());
    }
    return decoded;
}

auto plan_setup_adoption(const std::filesystem::path& config_path) -> result<setup_ledger> {
    auto service = load_config(config_path);
    if (!service) {
        return std::unexpected("load configuration for adoption: " + service.error());
    }
    for (const auto& directory : {
             std::optional{service->runtime_directory},
             service->materialization_root,
             service->library_bundle_root,
         }) {
        if (!directory) {
            continue;
        }
        auto exists = owner_directory_exists(*directory);
        if (!exists || !*exists) {
            return std::unexpected(
                exists ? "configured setup directory is missing: " + directory->string()
                       : exists.error()
            );
        }
    }
    if (service->session_policy) {
        if (auto valid = validate_session_policy_file(*service->session_policy); !valid) {
            return std::unexpected("session policy is invalid: " + valid.error());
        }
    }
    setup_plan plan{
        .service = *service,
        .config_path = config_path.lexically_normal(),
        .migrate_runtime_from = std::nullopt,
        .add_paired_apple_runtime = false,
        .canonical_protected_root = std::nullopt,
        .root_id = "adopted",
        .runtime_template_ids = {},
        .dry_run = false,
    };
    auto ledger = make_setup_ledger(plan, {}, false, false, false);
    if (!ledger) {
        return std::unexpected(ledger.error());
    }
    const auto add_retained = [&](std::string kind, const std::filesystem::path& path) {
        if (std::filesystem::exists(path) &&
            std::ranges::none_of(ledger->resources, [&](const auto& resource) {
                return resource.path == path;
            })) {
            ledger->resources.push_back({
                .kind = std::move(kind),
                .path = path,
                .owned = false,
                .content_sha256 = std::nullopt,
            });
        }
    };
    add_retained("receipt_journal", service->receipt_journal);
    if (service->session_policy) {
        add_retained("session_policy", *service->session_policy);
    }
    if (service->session_store) {
        add_retained("session_store", *service->session_store);
    }
    if (service->path_exposure_journal) {
        add_retained("path_exposure_journal", *service->path_exposure_journal);
    }
    if (auto valid = validate_setup_ledger(*ledger); !valid) {
        return std::unexpected(valid.error());
    }
    return ledger;
}

auto execute_setup_adoption(const setup_ledger& ledger) -> result<void> {
    if (std::ranges::any_of(ledger.resources, [](const auto& resource) {
            return resource.owned;
        })) {
        return std::unexpected(std::string{"adoption ledger may not claim resource ownership"});
    }
    auto refreshed = plan_setup_adoption(ledger.config_path);
    if (!refreshed || *refreshed != ledger) {
        return std::unexpected(std::string{"setup resources changed after adoption preview"});
    }
    return write_or_validate_setup_ledger(ledger);
}

auto setup_ledger_sha256(const setup_ledger& ledger) -> result<std::string> {
    auto encoded = encode_setup_ledger(ledger);
    return encoded ? content_sha256(*encoded) : std::unexpected(encoded.error());
}

auto plan_setup_cleanup(const std::filesystem::path& config_path) -> result<setup_cleanup_plan> {
    auto service = load_config(config_path);
    if (!service) {
        return std::unexpected("load configuration before cleanup preview: " + service.error());
    }
    const auto ledger_path = setup_ledger_path(*service);
    auto ledger = load_setup_ledger(ledger_path);
    if (!ledger) {
        return std::unexpected("load setup ledger: " + ledger.error());
    }
    if (ledger->config_path != config_path.lexically_normal()) {
        return std::unexpected(std::string{"setup ledger configuration identity changed"});
    }
    setup_cleanup_plan plan{
        .ledger = std::move(*ledger),
        .items = {},
        .ledger_removable = false,
    };
    plan.items.reserve(plan.ledger.resources.size());
    std::vector<std::filesystem::path> scheduled_removals{plan.ledger.ledger_path};
    for (auto resource = plan.ledger.resources.rbegin(); resource != plan.ledger.resources.rend();
         ++resource) {
        setup_cleanup_item item{
            .resource = *resource,
            .removable = false,
            .absent = false,
            .reason = {},
        };
        struct stat metadata{};
        if (::lstat(resource->path.c_str(), &metadata) != 0) {
            if (errno == ENOENT) {
                item.absent = true;
                item.reason = "already absent";
            } else {
                item.reason = system_error("inspect setup resource");
            }
        } else if (!resource->owned) {
            item.reason = "retained because setup did not create it";
        } else if (resource->content_sha256) {
            if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
                metadata.st_nlink != 1 ||
                (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U) {
                item.reason = "file identity or ownership changed";
            } else {
                auto digest = file_sha256(resource->path, max_setup_ledger_bytes);
                if (!digest) {
                    item.reason = digest.error();
                } else if (*digest != *resource->content_sha256) {
                    item.reason = "file content changed after setup";
                } else {
                    item.removable = true;
                    item.reason = "owned file matches setup ledger";
                    scheduled_removals.push_back(resource->path);
                }
            }
        } else if (
            !S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U
        ) {
            item.reason = "directory identity or ownership changed";
        } else {
            std::error_code error;
            bool empty = true;
            for (std::filesystem::directory_iterator entries{resource->path, error}, end;
                 !error && entries != end;
                 entries.increment(error)) {
                if (std::ranges::find(scheduled_removals, entries->path()) ==
                    scheduled_removals.end()) {
                    empty = false;
                }
            }
            if (error) {
                item.reason = "could not inspect directory contents: " + error.message();
            } else if (!empty) {
                item.reason = "owned directory contains retained or unmanaged state";
            } else {
                item.removable = true;
                item.reason = "owned directory is empty after planned removals";
                scheduled_removals.push_back(resource->path);
            }
        }
        plan.items.push_back(std::move(item));
    }
    plan.ledger_removable = true;
    return plan;
}

auto execute_setup_cleanup(const setup_cleanup_plan& plan, std::string_view confirmed_ledger_sha256)
    -> result<void> {
    auto current = load_setup_ledger(plan.ledger.ledger_path);
    if (!current || *current != plan.ledger) {
        return std::unexpected(std::string{"setup ledger changed after cleanup preview"});
    }
    auto digest = setup_ledger_sha256(*current);
    if (!digest || *digest != confirmed_ledger_sha256) {
        return std::unexpected(std::string{"cleanup confirmation does not match setup ledger"});
    }
    auto refreshed = plan_setup_cleanup(plan.ledger.config_path);
    if (!refreshed || refreshed->items != plan.items || refreshed->blocked()) {
        return std::unexpected(
            std::string{"setup resources changed after cleanup preview; preview again"}
        );
    }
    for (const auto& item : refreshed->items) {
        if (!item.resource.owned || item.absent) {
            continue;
        }
        if (!item.removable) {
            return std::unexpected(
                "setup resource is not removable: " + item.resource.path.string()
            );
        }
        if (item.resource.content_sha256 && ::unlink(item.resource.path.c_str()) != 0) {
            return std::unexpected(system_error("remove setup resource"));
        }
    }
    if (::unlink(plan.ledger.ledger_path.c_str()) != 0) {
        return std::unexpected(system_error("remove setup ledger"));
    }
    for (const auto& item : refreshed->items) {
        if (!item.resource.owned || item.absent || item.resource.content_sha256) {
            continue;
        }
        if (::rmdir(item.resource.path.c_str()) != 0) {
            return std::unexpected(system_error("remove setup directory"));
        }
    }
    return {};
}

} // namespace glove::host
