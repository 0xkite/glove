#include "glove/control/receipt_audit_unix_server.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/host/config.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_exposure_journal.hpp"
#include "glove/supervisor/session_plan.hpp"

#if defined(__linux__)
#    include "linux_session_executor.hpp"
#    include "linux_session_preparation.hpp"
#endif

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <csignal>

#if defined(__APPLE__)
#    include <stdlib.h>
#elif defined(__linux__)
#    include <sys/random.h>
#endif

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

constexpr std::string_view socket_name = "gloved.sock";
constexpr std::string_view secret_name = "bootstrap-secret";
constexpr std::string_view lock_name = "gloved.lock";
constexpr std::uint64_t accept_poll_ms = 250U;
constexpr std::uint64_t connection_timeout_ms = 5'000U;

// POSIX signal handlers require process-lifetime state with signal-safe access.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
volatile ::sig_atomic_t shutdown_requested = 0;

extern "C" void request_shutdown(int /*signal*/) noexcept {
    shutdown_requested = 1;
}

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

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

template<typename Value, std::size_t Size> void wipe(std::array<Value, Size>& values) noexcept {
    volatile Value* bytes = values.data();
    for (std::size_t index = 0; index < values.size(); ++index) {
        bytes[index] = Value{};
    }
}

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

struct options {
    std::filesystem::path runtime_directory;
    std::filesystem::path audit_key;
    std::filesystem::path journal;
    std::optional<std::filesystem::path> session_policy;
    std::optional<std::filesystem::path> session_store;
    std::optional<std::filesystem::path> materialization_root;
    std::optional<std::filesystem::path> library_bundle_root;
    std::optional<std::filesystem::path> path_exposure_policy;
    std::optional<std::filesystem::path> path_exposure_journal;
};

auto parse_options(int argc, char** argv) -> std::expected<options, std::string> {
    if (argc == 3 && std::string_view{argv[1]} == "--config") {
        auto configured = glove::host::load_config(std::filesystem::path{argv[2]});
        if (!configured) {
            return std::unexpected(configured.error());
        }
        return options{
            .runtime_directory = configured->runtime_directory,
            .audit_key = configured->audit_key,
            .journal = configured->receipt_journal,
            .session_policy = configured->session_policy,
            .session_store = configured->session_store,
            .materialization_root = configured->materialization_root,
            .library_bundle_root = configured->library_bundle_root,
            .path_exposure_policy = configured->path_exposure_policy,
            .path_exposure_journal = configured->path_exposure_journal,
        };
    }
    if (argc < 7 || argc > 19 || argc % 2 == 0) {
        return std::unexpected(std::string{"expected three required and up to six optional paths"});
    }

    options parsed;
    std::optional<std::filesystem::path> runtime_directory;
    std::optional<std::filesystem::path> audit_key;
    std::optional<std::filesystem::path> journal;
    std::optional<std::filesystem::path> session_policy;
    std::optional<std::filesystem::path> session_store;
    std::optional<std::filesystem::path> materialization_root;
    std::optional<std::filesystem::path> library_bundle_root;
    std::optional<std::filesystem::path> path_exposure_policy;
    std::optional<std::filesystem::path> path_exposure_journal;
    for (int index = 1; index < argc; index += 2) {
        const std::string_view option{argv[index]};
        const std::filesystem::path value{argv[index + 1]};
        if (option == "--runtime-dir" && !runtime_directory) {
            runtime_directory = value;
        } else if (option == "--audit-key" && !audit_key) {
            audit_key = value;
        } else if (option == "--journal" && !journal) {
            journal = value;
        } else if (option == "--session-policy" && !session_policy) {
            session_policy = value;
        } else if (option == "--session-store" && !session_store) {
            session_store = value;
        } else if (option == "--materialization-root" && !materialization_root) {
            materialization_root = value;
        } else if (option == "--library-bundle-root" && !library_bundle_root) {
            library_bundle_root = value;
        } else if (option == "--path-exposure-policy" && !path_exposure_policy) {
            path_exposure_policy = value;
        } else if (option == "--path-exposure-journal" && !path_exposure_journal) {
            path_exposure_journal = value;
        } else {
            return std::unexpected(std::string{"unknown or duplicate gloved option"});
        }
    }
    if (!runtime_directory || !audit_key || !journal || !runtime_directory->is_absolute() ||
        !audit_key->is_absolute() || !journal->is_absolute() ||
        (session_policy && !session_policy->is_absolute()) ||
        (session_store && !session_store->is_absolute()) ||
        (materialization_root && !materialization_root->is_absolute()) ||
        (library_bundle_root && !library_bundle_root->is_absolute()) ||
        (path_exposure_policy && !path_exposure_policy->is_absolute()) ||
        (path_exposure_journal && !path_exposure_journal->is_absolute())) {
        return std::unexpected(std::string{"gloved paths must be absolute"});
    }
    if (path_exposure_policy.has_value() != path_exposure_journal.has_value()) {
        return std::unexpected(
            std::string{"path exposure policy and journal must be configured together"}
        );
    }
    if (session_store) {
        if (!session_policy) {
            return std::unexpected(std::string{"session store requires a session policy"});
        }
        if (*session_store == *audit_key || *session_store == *journal ||
            *session_store == session_policy.value()) {
            return std::unexpected(std::string{"session store path must be dedicated"});
        }
    }
    if (materialization_root) {
        if (!session_policy || !session_store) {
            return std::unexpected(
                std::string{"materialization root requires session policy and store"}
            );
        }
        if (*materialization_root == *runtime_directory || *materialization_root == *audit_key ||
            *materialization_root == *journal || *materialization_root == *session_policy ||
            *materialization_root == *session_store) {
            return std::unexpected(std::string{"materialization root path must be dedicated"});
        }
    }
    if (library_bundle_root) {
        if (!session_policy || !session_store) {
            return std::unexpected(
                std::string{"library bundle root requires session policy and store"}
            );
        }
        if (*library_bundle_root == *runtime_directory || *library_bundle_root == *audit_key ||
            *library_bundle_root == *journal || *library_bundle_root == *session_policy ||
            *library_bundle_root == *session_store ||
            (materialization_root && *library_bundle_root == *materialization_root)) {
            return std::unexpected(std::string{"library bundle root path must be dedicated"});
        }
    }
    if (path_exposure_policy &&
        (*path_exposure_policy == *runtime_directory || *path_exposure_policy == *audit_key ||
         *path_exposure_policy == *journal || *path_exposure_policy == *path_exposure_journal ||
         (session_policy && *path_exposure_policy == *session_policy) ||
         (session_store && *path_exposure_policy == *session_store) ||
         (materialization_root && *path_exposure_policy == *materialization_root) ||
         (library_bundle_root && *path_exposure_policy == *library_bundle_root))) {
        return std::unexpected(std::string{"path exposure policy path must be dedicated"});
    }
    if (path_exposure_journal &&
        (*path_exposure_journal == *runtime_directory || *path_exposure_journal == *audit_key ||
         *path_exposure_journal == *journal ||
         (session_policy && *path_exposure_journal == *session_policy) ||
         (session_store && *path_exposure_journal == *session_store) ||
         (materialization_root && *path_exposure_journal == *materialization_root) ||
         (library_bundle_root && *path_exposure_journal == *library_bundle_root))) {
        return std::unexpected(std::string{"path exposure journal path must be dedicated"});
    }
    parsed.runtime_directory = std::move(*runtime_directory);
    parsed.audit_key = std::move(*audit_key);
    parsed.journal = std::move(*journal);
    parsed.session_policy = std::move(session_policy);
    parsed.session_store = std::move(session_store);
    parsed.materialization_root = std::move(materialization_root);
    parsed.library_bundle_root = std::move(library_bundle_root);
    parsed.path_exposure_policy = std::move(path_exposure_policy);
    parsed.path_exposure_journal = std::move(path_exposure_journal);
    return parsed;
}

auto open_runtime_directory(const std::filesystem::path& path)
    -> std::expected<unique_fd, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open gloved runtime directory"));
    }

    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect gloved runtime directory"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0700U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        permissions != owner_permissions) {
        return std::unexpected(std::string{"gloved runtime directory must be owner-only"});
    }
    return descriptor;
}

#if defined(__linux__)
auto validate_materialization_root(const std::filesystem::path& path)
    -> std::expected<void, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const unique_fd descriptor{
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
    };
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open session materialization root"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect session materialization root"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0700U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        permissions != owner_permissions) {
        return std::unexpected(
            std::string{"session materialization root must be an owner-only directory"}
        );
    }
    return {};
}
#endif

auto acquire_instance_lock(int directory_descriptor) -> std::expected<unique_fd, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd descriptor{::openat(
        directory_descriptor, lock_name.data(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600
    )};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open gloved instance lock"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect gloved instance lock"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        permissions != owner_permissions) {
        return std::unexpected(std::string{"gloved instance lock is unsafe"});
    }
    if (::flock(descriptor.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return std::unexpected(std::string{"another gloved instance owns the runtime"});
        }
        return std::unexpected(system_error("acquire gloved instance lock"));
    }
    return descriptor;
}

auto remove_stale_socket(int directory_descriptor) -> std::expected<void, std::string> {
    struct stat metadata{};
    if (::fstatat(directory_descriptor, socket_name.data(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(system_error("inspect stale gloved socket"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISSOCK(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        permissions != owner_permissions) {
        return std::unexpected(std::string{"existing gloved socket is unsafe"});
    }
    if (::unlinkat(directory_descriptor, socket_name.data(), 0) != 0) {
        return std::unexpected(system_error("remove stale gloved socket"));
    }
    if (::fsync(directory_descriptor) != 0) {
        return std::unexpected(system_error("sync stale gloved socket removal"));
    }
    return {};
}

auto write_exact(int descriptor, const char* bytes, std::size_t size)
    -> std::expected<void, std::string> {
    std::size_t written = 0;
    while (written < size) {
        const auto result = ::write(descriptor, bytes + written, size - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(
                result < 0 ? system_error("write bootstrap secret")
                           : std::string{"bootstrap secret write made no progress"}
            );
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

auto lowercase_hex(const std::byte* bytes, std::size_t size, char* output) noexcept -> void {
    constexpr std::string_view digits = "0123456789abcdef";
    for (std::size_t index = 0; index < size; ++index) {
        const auto value = std::to_integer<unsigned int>(bytes[index]);
        output[index * 2U] = digits[value >> 4U];
        output[(index * 2U) + 1U] = digits[value & 0x0fU];
    }
}

auto fill_random(std::byte* output, std::size_t size) -> std::expected<void, std::string> {
#if defined(__APPLE__)
    ::arc4random_buf(output, size);
    return {};
#elif defined(__linux__)
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto result = ::getrandom(output + consumed, size - consumed, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(
                result < 0 ? system_error("generate bootstrap secret")
                           : std::string{"bootstrap secret entropy source made no progress"}
            );
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
#else
    (void)output;
    (void)size;
    return std::unexpected(std::string{"secure bootstrap entropy is unsupported"});
#endif
}

auto rotate_bootstrap_secret(int directory_descriptor) -> std::expected<void, std::string> {
    std::array<std::byte, 40> randomness{};
    std::array<char, 65> encoded_secret{};
    std::array<char, 16> encoded_suffix{};
    const auto clear_sensitive_state = [&]() noexcept {
        wipe(randomness);
        wipe(encoded_secret);
        wipe(encoded_suffix);
    };
    if (auto generated = fill_random(randomness.data(), randomness.size()); !generated) {
        const auto error = generated.error();
        clear_sensitive_state();
        return std::unexpected(error);
    }
    lowercase_hex(randomness.data(), 32U, encoded_secret.data());
    encoded_secret.back() = '\n';
    lowercase_hex(randomness.data() + 32U, 8U, encoded_suffix.data());
    const std::string temporary_name =
        ".bootstrap-secret.tmp." + std::string{encoded_suffix.data(), encoded_suffix.size()};

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const unique_fd temporary{::openat(
        directory_descriptor,
        temporary_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    )};
    if (temporary.get() < 0) {
        const auto error = system_error("create bootstrap secret");
        clear_sensitive_state();
        return std::unexpected(error);
    }
    bool temporary_exists = true;
    const auto remove_temporary = [&]() noexcept {
        if (temporary_exists) {
            (void)::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
        }
    };
    if (auto written = write_exact(temporary.get(), encoded_secret.data(), encoded_secret.size());
        !written) {
        const auto error = written.error();
        remove_temporary();
        clear_sensitive_state();
        return std::unexpected(error);
    }
    if (::fsync(temporary.get()) != 0) {
        const auto error = system_error("sync bootstrap secret");
        remove_temporary();
        clear_sensitive_state();
        return std::unexpected(error);
    }
    if (::renameat(
            directory_descriptor, temporary_name.c_str(), directory_descriptor, secret_name.data()
        ) != 0) {
        const auto error = system_error("rotate bootstrap secret");
        remove_temporary();
        clear_sensitive_state();
        return std::unexpected(error);
    }
    temporary_exists = false;
    if (::fsync(directory_descriptor) != 0) {
        const auto error = system_error("sync bootstrap secret directory");
        clear_sensitive_state();
        return std::unexpected(error);
    }
    clear_sensitive_state();
    return {};
}

auto install_shutdown_handlers() -> std::expected<void, std::string> {
    struct sigaction action{};
    action.sa_handler = request_shutdown;
    if (sigemptyset(&action.sa_mask) != 0 || ::sigaction(SIGINT, &action, nullptr) != 0 ||
        ::sigaction(SIGTERM, &action, nullptr) != 0) {
        return std::unexpected(system_error("install gloved shutdown handler"));
    }
    return {};
}

auto run(const options& configured) -> std::expected<void, std::string> {
    std::shared_ptr<glove::supervisor::path_exposure_registry> path_exposures;
    if (configured.path_exposure_policy) {
        auto loaded = glove::supervisor::path_exposure_registry::load(
            *configured.path_exposure_policy,
            *configured.path_exposure_journal,
            glove::supervisor::default_path_exposure_journal_bytes
        );
        if (!loaded) {
            return std::unexpected(std::string{"load path exposure policy: "} + loaded.error());
        }
        path_exposures =
            std::make_shared<glove::supervisor::path_exposure_registry>(std::move(*loaded));
    }
    std::shared_ptr<const glove::supervisor::session_plan_validator> plan_validator;
    if (configured.session_policy) {
        auto loaded = glove::supervisor::session_plan_validator::load(
            *configured.session_policy, path_exposures
        );
        if (!loaded) {
            return std::unexpected(std::string{"load session policy: "} + loaded.error());
        }
        plan_validator =
            std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*loaded));
    }
    auto runtime_directory = open_runtime_directory(configured.runtime_directory);
    if (!runtime_directory) {
        return std::unexpected(runtime_directory.error());
    }
    auto instance_lock = acquire_instance_lock(runtime_directory->get());
    if (!instance_lock) {
        return std::unexpected(instance_lock.error());
    }
    std::shared_ptr<glove::control::session_registry> sessions;
    if (configured.session_store) {
        std::shared_ptr<const glove::supervisor::library_bundle_store> library_bundles;
        if (configured.library_bundle_root) {
            auto opened =
                glove::supervisor::library_bundle_store::open(*configured.library_bundle_root);
            if (!opened) {
                return std::unexpected(std::string{"open library bundle root: "} + opened.error());
            }
            library_bundles =
                std::make_shared<const glove::supervisor::library_bundle_store>(std::move(*opened));
        }
        auto opened = glove::control::session_registry::open_or_create(
            *configured.session_store, plan_validator, std::move(library_bundles)
        );
        if (!opened) {
            return std::unexpected(std::string{"open session store: "} + opened.error().message);
        }
        sessions = std::shared_ptr<glove::control::session_registry>{std::move(*opened)};
    }
    std::shared_ptr<glove::control::linux_detail::linux_session_runtime> session_runtime;
#if defined(__linux__)
    std::optional<glove::control::linux_detail::linux_session_preparer> session_preparer;
    if (configured.materialization_root) {
        if (auto valid = validate_materialization_root(*configured.materialization_root); !valid) {
            return std::unexpected(valid.error());
        }
        auto prepared = glove::control::linux_detail::linux_session_preparer::create(
            configured.materialization_root->string()
        );
        if (!prepared) {
            return std::unexpected(
                std::string{"prepare Linux session runtime: "} + prepared.error()
            );
        }
        session_preparer.emplace(std::move(*prepared));
        auto runtime = glove::control::linux_detail::linux_session_runtime::create(
            *sessions, *session_preparer, {}
        );
        if (!runtime) {
            return std::unexpected(std::string{"create Linux session runtime: "} + runtime.error());
        }
        session_runtime = std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
            std::move(*runtime)
        };
    }
#else
    if (configured.materialization_root) {
        return std::unexpected(std::string{"managed session launch requires Linux"});
    }
#endif
    if (auto recovered = remove_stale_socket(runtime_directory->get()); !recovered) {
        return std::unexpected(recovered.error());
    }
    if (auto rotated = rotate_bootstrap_secret(runtime_directory->get()); !rotated) {
        return std::unexpected(rotated.error());
    }
    if (auto handlers = install_shutdown_handlers(); !handlers) {
        return std::unexpected(handlers.error());
    }

    glove::control::receipt_audit_unix_server_config server_config{
        .socket_path = configured.runtime_directory / socket_name,
        .bootstrap_secret_path = configured.runtime_directory / secret_name,
        .producer =
            {
                .key_path = configured.audit_key,
                .journal_path = configured.journal,
            },
        .plan_validator = std::move(plan_validator),
        .sessions = std::move(sessions),
        .session_runtime = std::move(session_runtime),
        .path_exposures = std::move(path_exposures),
        .materialization_root = configured.materialization_root
                                    ? configured.materialization_root->string()
                                    : std::string{},
        .io_timeout_ms = connection_timeout_ms,
    };
    auto server = glove::control::receipt_audit_unix_server::create(std::move(server_config));
    if (!server) {
        return std::unexpected(server.error());
    }
    while (shutdown_requested == 0) {
        auto served = (*server)->serve_one_for(accept_poll_ms);
        if (!served) {
            return std::unexpected(served.error());
        }
    }
    return {};
}

void print_usage() {
    std::cerr << "usage: gloved --config <owner-only-json>\n"
                 "   or: gloved --runtime-dir <absolute-dir> --audit-key <absolute-file> "
                 "--journal <absolute-file> [--session-policy <owner-only-json> "
                 "[--session-store <owner-only-journal> "
                 "[--materialization-root <owner-only-directory>] "
                 "[--library-bundle-root <owner-only-directory>]]]\n"
                 "[--path-exposure-policy <owner-only-json> "
                 "--path-exposure-journal <owner-only-journal>]\n"
                 "managed sessions require Linux; legacy direct-write launch remains disabled\n";
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        auto configured = parse_options(argc, argv);
        if (!configured) {
            print_usage();
            std::cerr << "gloved: " << configured.error() << '\n';
            return 2;
        }
        if (auto result = run(*configured); !result) {
            std::cerr << "gloved: " << result.error() << '\n';
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "gloved: unhandled failure: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "gloved: unhandled non-standard failure\n";
        return 1;
    }
}
