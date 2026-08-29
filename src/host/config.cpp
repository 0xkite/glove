#include "glove/host/config.hpp"

#include "glove/container/image_identity.hpp"
#include "glove/host/remote_backend.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace glove::host {
namespace config_wire_types {
struct sage_guest_wire {
    std::string binary_digest;
    std::string source_revision;
    std::uint8_t policy_schema_version = 0;
    std::string library_projection_schema;
};

struct apple_container_wire {
    std::string cli;
    std::string image;
    std::string image_digest;
    std::optional<std::string> harness_closure_digest;
    std::optional<sage_guest_wire> sage_guest;
};

struct remote_backend_wire {
    std::string host;
    std::string user;
    std::uint16_t port = 0;
    std::string host_public_key;
    std::string host_key_fingerprint;
    std::string identity_file;
    std::string executor_digest;
    std::string container_image;
    std::string container_image_digest;
    std::uint64_t channel_timeout_ms = 0;
    std::uint64_t max_clock_skew_ms = 0;
    std::uint32_t max_sessions = 0;
    std::string staging_root;
};

struct config_wire {
    std::uint8_t schema_version = 0;
    bool persistent_service = false;
    std::string runtime_directory;
    std::string audit_key;
    std::string receipt_journal;
    std::optional<std::string> session_policy;
    std::optional<std::string> session_store;
    std::optional<std::string> materialization_root;
    std::optional<std::string> library_bundle_root;
    std::optional<std::string> path_exposure_policy;
    std::optional<std::string> path_exposure_journal;
    std::optional<apple_container_wire> apple_container;
    std::optional<remote_backend_wire> remote_backend;
};
} // namespace config_wire_types

namespace {

using config_wire_types::apple_container_wire;
using config_wire_types::config_wire;
using config_wire_types::remote_backend_wire;
using config_wire_types::sage_guest_wire;

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::uint64_t max_config_bytes = std::uint64_t{1024} * 1024U;

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

auto absolute_directory(
    const std::optional<std::string>& configured,
    const std::filesystem::path& fallback,
    std::string_view name
) -> result<std::filesystem::path> {
    const std::filesystem::path selected =
        configured ? std::filesystem::path{*configured} : fallback;
    if (!selected.is_absolute() || selected == selected.root_path()) {
        return std::unexpected(std::string{name} + " must resolve to a dedicated absolute path");
    }
    return selected.lexically_normal();
}

auto environment_value(const char* name) -> std::optional<std::string> {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return std::string{value};
    }
    return std::nullopt;
}

auto optional_path(const std::optional<std::string>& value)
    -> std::optional<std::filesystem::path> {
    return value ? std::optional<std::filesystem::path>{*value} : std::nullopt;
}

auto optional_string(const std::optional<std::filesystem::path>& value)
    -> std::optional<std::string> {
    return value ? std::optional<std::string>{value->string()} : std::nullopt;
}

auto read_owner_only_file(const std::filesystem::path& path) -> result<std::string> {
    if (!path.is_absolute()) {
        return std::unexpected(std::string{"configuration path must be absolute"});
    }
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open configuration"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect configuration"));
    }
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & 0777U;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        permissions != 0600U || metadata.st_size <= 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_config_bytes ||
        static_cast<std::uint64_t>(metadata.st_size) > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(
            std::string{"configuration must be a bounded owner-only single-link file"}
        );
    }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto read =
            ::read(descriptor.get(), contents.data() + consumed, contents.size() - consumed);
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(
                read < 0 ? system_error("read configuration")
                         : std::string{"configuration ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(read);
    }
    return contents;
}

auto valid_sha256_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_host_token(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 253U && value.front() != '-' &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '.' || byte == '-' || byte == ':';
           });
}

auto valid_user_token(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 32U &&
           ((value.front() >= 'a' && value.front() <= 'z') || value.front() == '_') &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '_' ||
                      byte == '-';
           });
}

auto all_configured_paths(const config& value) -> std::vector<std::filesystem::path> {
    std::vector<std::filesystem::path> paths{
        value.runtime_directory,
        value.audit_key,
        value.receipt_journal,
    };
    for (const auto* optional : {
             &value.session_policy,
             &value.session_store,
             &value.materialization_root,
             &value.library_bundle_root,
             &value.path_exposure_policy,
             &value.path_exposure_journal,
         }) {
        if (*optional) {
            paths.push_back(**optional);
        }
    }
    if (value.apple_container) {
        paths.push_back(value.apple_container->cli);
    }
    if (value.remote_backend) {
        paths.push_back(value.remote_backend->identity_file);
    }
    return paths;
}

} // namespace

auto current_environment() -> environment {
    return {
        .home = environment_value("HOME"),
        .xdg_config_home = environment_value("XDG_CONFIG_HOME"),
        .xdg_state_home = environment_value("XDG_STATE_HOME"),
        .xdg_data_home = environment_value("XDG_DATA_HOME"),
        .xdg_cache_home = environment_value("XDG_CACHE_HOME"),
        .xdg_runtime_dir = environment_value("XDG_RUNTIME_DIR"),
        .temporary_directory = environment_value("TMPDIR"),
    };
}

auto resolve_directories(const environment& values) -> result<directories> {
    if (!values.home) {
        return std::unexpected(std::string{"HOME is required when an XDG directory is unset"});
    }
    const std::filesystem::path home{*values.home};
    if (!home.is_absolute() || home == home.root_path()) {
        return std::unexpected(std::string{"HOME must be a dedicated absolute path"});
    }
    auto config_root = absolute_directory(values.xdg_config_home, home / ".config", "config root");
    auto state_root =
        absolute_directory(values.xdg_state_home, home / ".local/state", "state root");
    auto data_root = absolute_directory(values.xdg_data_home, home / ".local/share", "data root");
    auto cache_root = absolute_directory(values.xdg_cache_home, home / ".cache", "cache root");
    if (!config_root || !state_root || !data_root || !cache_root) {
        return std::unexpected(
            !config_root  ? config_root.error()
            : !state_root ? state_root.error()
            : !data_root  ? data_root.error()
                          : cache_root.error()
        );
    }

    const auto runtime_fallback = *state_root / "glove/runtime";
    auto runtime_root = absolute_directory(std::nullopt, runtime_fallback, "runtime root");
    if (!runtime_root) {
        return std::unexpected(runtime_root.error());
    }
    return directories{
        .config = *config_root / "glove",
        .state = *state_root / "glove",
        .data = *data_root / "glove",
        .cache = *cache_root / "glove",
        .runtime = *runtime_root,
    };
}

auto default_config_path(const directories& values) -> std::filesystem::path {
    return values.config / "config.json";
}

auto validate(const remote_backend_config& value) -> result<void> {
    const auto staging = value.staging_root.lexically_normal();
    const bool valid_staging = value.staging_root.is_absolute() &&
                               value.staging_root != value.staging_root.root_path() &&
                               staging == value.staging_root;
    const bool valid_identity = value.identity_file.is_absolute() &&
                                value.identity_file != value.identity_file.root_path() &&
                                value.identity_file.lexically_normal() == value.identity_file;
    if (!valid_host_token(value.host) || !valid_user_token(value.user) || value.port == 0 ||
        !valid_identity || !valid_staging || !valid_sha256_digest(value.executor_digest) ||
        !container::valid_immutable_container_image(
            value.container_image, value.container_image_digest
        ) ||
        value.channel_timeout_ms < 100U || value.channel_timeout_ms > 60'000U ||
        value.max_clock_skew_ms > 5'000U || value.max_sessions == 0 || value.max_sessions > 64U) {
        return std::unexpected(std::string{"remote backend configuration is invalid"});
    }
    auto fingerprint = openssh_host_key_fingerprint(value.host_public_key);
    if (!fingerprint || *fingerprint != value.host_key_fingerprint) {
        return std::unexpected(std::string{"remote backend host key fingerprint mismatch"});
    }
    return {};
}

auto validate(const config& value) -> result<void> {
    if (value.schema_version != 1) {
        return std::unexpected(std::string{"unsupported configuration schema"});
    }
    const auto paths = all_configured_paths(value);
    for (const auto& path : paths) {
        if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
            return std::unexpected(
                std::string{"configuration paths must be dedicated normalized absolute paths"}
            );
        }
    }
    for (std::size_t left = 0; left < paths.size(); ++left) {
        for (std::size_t right = left + 1; right < paths.size(); ++right) {
            if (paths[left] == paths[right]) {
                return std::unexpected(std::string{"configuration paths must be distinct"});
            }
        }
    }
    if (value.session_store && !value.session_policy) {
        return std::unexpected(std::string{"session store requires a session policy"});
    }
    if ((value.materialization_root || value.library_bundle_root) && !value.session_store) {
        return std::unexpected(std::string{"managed-session roots require a session store"});
    }
    if (value.apple_container) {
        const auto& apple = *value.apple_container;
        const bool valid_closure_digest =
            !apple.harness_closure_digest || valid_sha256_digest(*apple.harness_closure_digest);
        const bool valid_guest =
            !apple.sage_guest ||
            (apple.harness_closure_digest && valid_sha256_digest(apple.sage_guest->binary_digest) &&
             (apple.sage_guest->source_revision == "unknown" ||
              (apple.sage_guest->source_revision.size() == 40U &&
               std::ranges::all_of(
                   apple.sage_guest->source_revision,
                   [](char byte) {
                       return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
                   }
               ))) &&
             apple.sage_guest->policy_schema_version == 1U &&
             apple.sage_guest->library_projection_schema == "sage_bundle_v1");
        if (!value.session_store || !value.materialization_root ||
            !container::valid_immutable_container_image(apple.image, apple.image_digest) ||
            !valid_closure_digest || !valid_guest) {
            return std::unexpected(
                std::string{"Apple Container runtime requires managed-session roots and an exact "
                            "image digest"}
            );
        }
    }
    if (value.remote_backend) {
        if (!value.session_policy || !value.session_store || value.materialization_root ||
            value.apple_container) {
            return std::unexpected(
                std::string{"remote backend requires session storage and excludes local runtimes"}
            );
        }
        if (auto valid = validate(*value.remote_backend); !valid) {
            return std::unexpected(valid.error());
        }
    }
    if (value.path_exposure_policy.has_value() != value.path_exposure_journal.has_value()) {
        return std::unexpected(
            std::string{"path exposure policy and journal must be configured together"}
        );
    }
    return {};
}

auto load_config(const std::filesystem::path& path) -> result<config> {
    auto contents = read_owner_only_file(path);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    config_wire encoded;
    if (const auto error = glz::read<strict_read_options>(encoded, *contents); error) {
        return std::unexpected(
            std::string{"configuration JSON is invalid: "} + glz::format_error(error, *contents)
        );
    }
    config decoded{
        .schema_version = encoded.schema_version,
        .persistent_service = encoded.persistent_service,
        .runtime_directory = encoded.runtime_directory,
        .audit_key = encoded.audit_key,
        .receipt_journal = encoded.receipt_journal,
        .session_policy = optional_path(encoded.session_policy),
        .session_store = optional_path(encoded.session_store),
        .materialization_root = optional_path(encoded.materialization_root),
        .library_bundle_root = optional_path(encoded.library_bundle_root),
        .path_exposure_policy = optional_path(encoded.path_exposure_policy),
        .path_exposure_journal = optional_path(encoded.path_exposure_journal),
        .apple_container =
            encoded.apple_container
                ? std::optional<apple_container_config>{apple_container_config{
                      .cli = encoded.apple_container->cli,
                      .image = encoded.apple_container->image,
                      .image_digest = encoded.apple_container->image_digest,
                      .harness_closure_digest = encoded.apple_container->harness_closure_digest,
                      .sage_guest =
                          encoded.apple_container->sage_guest
                              ? std::optional<sage_guest_config>{sage_guest_config{
                                    .binary_digest =
                                        encoded.apple_container->sage_guest->binary_digest,
                                    .source_revision =
                                        encoded.apple_container->sage_guest->source_revision,
                                    .policy_schema_version =
                                        encoded.apple_container->sage_guest->policy_schema_version,
                                    .library_projection_schema = encoded.apple_container->sage_guest
                                                                     ->library_projection_schema,
                                }}
                              : std::nullopt,
                  }}
                : std::nullopt,
        .remote_backend =
            encoded.remote_backend
                ? std::optional<remote_backend_config>{remote_backend_config{
                      .host = encoded.remote_backend->host,
                      .user = encoded.remote_backend->user,
                      .port = encoded.remote_backend->port,
                      .host_public_key = encoded.remote_backend->host_public_key,
                      .host_key_fingerprint = encoded.remote_backend->host_key_fingerprint,
                      .identity_file = encoded.remote_backend->identity_file,
                      .executor_digest = encoded.remote_backend->executor_digest,
                      .container_image = encoded.remote_backend->container_image,
                      .container_image_digest = encoded.remote_backend->container_image_digest,
                      .channel_timeout_ms = encoded.remote_backend->channel_timeout_ms,
                      .max_clock_skew_ms = encoded.remote_backend->max_clock_skew_ms,
                      .max_sessions = encoded.remote_backend->max_sessions,
                      .staging_root = encoded.remote_backend->staging_root,
                  }}
                : std::nullopt,
    };
    if (auto valid = validate(decoded); !valid) {
        return std::unexpected(valid.error());
    }
    return decoded;
}

auto encode_config(const config& value) -> result<std::string> {
    if (auto valid = validate(value); !valid) {
        return std::unexpected(valid.error());
    }
    auto encoded = glz::write_json(
        config_wire{
            .schema_version = value.schema_version,
            .persistent_service = value.persistent_service,
            .runtime_directory = value.runtime_directory.string(),
            .audit_key = value.audit_key.string(),
            .receipt_journal = value.receipt_journal.string(),
            .session_policy = optional_string(value.session_policy),
            .session_store = optional_string(value.session_store),
            .materialization_root = optional_string(value.materialization_root),
            .library_bundle_root = optional_string(value.library_bundle_root),
            .path_exposure_policy = optional_string(value.path_exposure_policy),
            .path_exposure_journal = optional_string(value.path_exposure_journal),
            .apple_container =
                value.apple_container
                    ? std::optional<apple_container_wire>{apple_container_wire{
                          .cli = value.apple_container->cli.string(),
                          .image = value.apple_container->image,
                          .image_digest = value.apple_container->image_digest,
                          .harness_closure_digest = value.apple_container->harness_closure_digest,
                          .sage_guest =
                              value.apple_container->sage_guest
                                  ? std::optional<sage_guest_wire>{sage_guest_wire{
                                        .binary_digest =
                                            value.apple_container->sage_guest->binary_digest,
                                        .source_revision =
                                            value.apple_container->sage_guest->source_revision,
                                        .policy_schema_version = value.apple_container->sage_guest
                                                                     ->policy_schema_version,
                                        .library_projection_schema =
                                            value.apple_container->sage_guest
                                                ->library_projection_schema,
                                    }}
                                  : std::nullopt,
                      }}
                    : std::nullopt,
            .remote_backend =
                value.remote_backend
                    ? std::optional<remote_backend_wire>{remote_backend_wire{
                          .host = value.remote_backend->host,
                          .user = value.remote_backend->user,
                          .port = value.remote_backend->port,
                          .host_public_key = value.remote_backend->host_public_key,
                          .host_key_fingerprint = value.remote_backend->host_key_fingerprint,
                          .identity_file = value.remote_backend->identity_file.string(),
                          .executor_digest = value.remote_backend->executor_digest,
                          .container_image = value.remote_backend->container_image,
                          .container_image_digest = value.remote_backend->container_image_digest,
                          .channel_timeout_ms = value.remote_backend->channel_timeout_ms,
                          .max_clock_skew_ms = value.remote_backend->max_clock_skew_ms,
                          .max_sessions = value.remote_backend->max_sessions,
                          .staging_root = value.remote_backend->staging_root.string(),
                      }}
                    : std::nullopt,
        }
    );
    if (!encoded) {
        return std::unexpected(std::string{"encode configuration JSON"});
    }
    encoded->push_back('\n');
    return std::move(*encoded);
}

auto write_config_exclusive(const std::filesystem::path& path, const config& value)
    -> result<void> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path ||
        path.filename().empty()) {
        return std::unexpected(
            std::string{"configuration output path must be normalized absolute"}
        );
    }
    std::error_code error;
    const auto parent = std::filesystem::canonical(path.parent_path(), error);
    struct stat parent_metadata{};
    if (error || ::lstat(parent.c_str(), &parent_metadata) != 0 ||
        !S_ISDIR(parent_metadata.st_mode) || parent_metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(parent_metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"configuration output directory must exist with current-user mode 0700"}
        );
    }
    auto encoded = encode_config(value);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    const unique_fd descriptor{
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)
    };
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("create configuration"));
    }
    std::size_t consumed = 0;
    while (consumed < encoded->size()) {
        const auto written =
            ::write(descriptor.get(), encoded->data() + consumed, encoded->size() - consumed);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            (void)::unlink(path.c_str());
            return std::unexpected(system_error("write configuration"));
        }
        consumed += static_cast<std::size_t>(written);
    }
    if (::fsync(descriptor.get()) != 0) {
        (void)::unlink(path.c_str());
        return std::unexpected(system_error("sync configuration"));
    }
    return {};
}

} // namespace glove::host
