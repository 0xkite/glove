#include "glove/host/config.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string_view>
#include <system_error>
#include <vector>

namespace glove::host {
namespace config_wire_types {
struct config_wire {
    std::uint8_t schema_version = 0;
    std::string runtime_directory;
    std::string audit_key;
    std::string receipt_journal;
    std::optional<std::string> session_policy;
    std::optional<std::string> session_store;
    std::optional<std::string> materialization_root;
    std::optional<std::string> library_bundle_root;
    std::optional<std::string> path_exposure_policy;
    std::optional<std::string> path_exposure_journal;
};
} // namespace config_wire_types

namespace {

using config_wire_types::config_wire;

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
        static_cast<std::uint64_t>(metadata.st_size) >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
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

    std::filesystem::path runtime_fallback = *state_root / "glove/runtime";
#if defined(__APPLE__)
    if (values.temporary_directory) {
        const std::filesystem::path temporary{*values.temporary_directory};
        if (temporary.is_absolute() && temporary != temporary.root_path()) {
            runtime_fallback = temporary / ("glove-" + std::to_string(::geteuid()));
        }
    }
#endif
    auto runtime_root =
        absolute_directory(values.xdg_runtime_dir, runtime_fallback, "runtime root");
    if (!runtime_root) {
        return std::unexpected(runtime_root.error());
    }
    return directories{
        .config = *config_root / "glove",
        .state = *state_root / "glove",
        .data = *data_root / "glove",
        .cache = *cache_root / "glove",
        .runtime = values.xdg_runtime_dir ? *runtime_root / "glove" : *runtime_root,
    };
}

auto default_config_path(const directories& values) -> std::filesystem::path {
    return values.config / "config.json";
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
        .runtime_directory = encoded.runtime_directory,
        .audit_key = encoded.audit_key,
        .receipt_journal = encoded.receipt_journal,
        .session_policy = optional_path(encoded.session_policy),
        .session_store = optional_path(encoded.session_store),
        .materialization_root = optional_path(encoded.materialization_root),
        .library_bundle_root = optional_path(encoded.library_bundle_root),
        .path_exposure_policy = optional_path(encoded.path_exposure_policy),
        .path_exposure_journal = optional_path(encoded.path_exposure_journal),
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
            .runtime_directory = value.runtime_directory.string(),
            .audit_key = value.audit_key.string(),
            .receipt_journal = value.receipt_journal.string(),
            .session_policy = optional_string(value.session_policy),
            .session_store = optional_string(value.session_store),
            .materialization_root = optional_string(value.materialization_root),
            .library_bundle_root = optional_string(value.library_bundle_root),
            .path_exposure_policy = optional_string(value.path_exposure_policy),
            .path_exposure_journal = optional_string(value.path_exposure_journal),
        }
    );
    if (!encoded) {
        return std::unexpected(std::string{"encode configuration JSON"});
    }
    encoded->push_back('\n');
    return std::move(*encoded);
}

} // namespace glove::host
