#include "glove/host/setup.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <system_error>

#if defined(__linux__)
#    include <sys/random.h>
#endif

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

} // namespace setup_wire

namespace {

constexpr std::uint64_t mebibyte = std::uint64_t{1024} * 1024U;

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
    };
    if (auto valid = validate(service); !valid) {
        return std::unexpected(valid.error());
    }
    const auto config_path = options.config_path.value_or(default_config_path(*roots));
    if (!config_path.is_absolute()) {
        return std::unexpected(std::string{"setup configuration path must be absolute"});
    }
    return setup_plan{
        .service = std::move(service),
        .config_path = config_path.lexically_normal(),
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
    if (std::filesystem::exists(plan.config_path)) {
        auto existing = load_config(plan.config_path);
        if (!existing || *existing != plan.service) {
            return std::unexpected(
                "existing configuration differs from the requested setup; refusing to overwrite"
            );
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
            if (auto policy = read_owner_file(*plan.service.session_policy, mebibyte); !policy) {
                return std::unexpected(
                    "session policy is not a protected owner-only file: " + policy.error()
                );
            }
        }
        for (const auto& directory : {
                 std::optional{plan.service.runtime_directory},
                 plan.service.materialization_root,
                 plan.service.library_bundle_root,
             }) {
            if (directory) {
                if (auto created = create_owner_directory(*directory); !created) {
                    return created;
                }
            }
        }
        return {};
    }
    for (const auto& directory : {
             plan.config_path.parent_path(),
             plan.service.audit_key.parent_path(),
             plan.service.runtime_directory,
         }) {
        if (auto created = create_owner_directory(directory); !created) {
            return created;
        }
    }
    for (const auto& directory : {
             plan.service.materialization_root,
             plan.service.library_bundle_root,
         }) {
        if (directory) {
            if (auto created = create_owner_directory(*directory); !created) {
                return created;
            }
        }
    }
    if (plan.service.session_policy) {
        if (auto policy = read_owner_file(*plan.service.session_policy, mebibyte); !policy) {
            return std::unexpected(
                "session policy is not a protected owner-only file: " + policy.error()
            );
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
    return {};
}

} // namespace glove::host
