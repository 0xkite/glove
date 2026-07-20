#include "glove/host/daemon.hpp"

#include "glove/host/control_client.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <mach-o/dyld.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

// POSIX exposes the inherited process environment only through this global.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern char** environ;

namespace glove::host {
namespace {

#if defined(__linux__)
constexpr std::string_view systemd_service_name = "sage-gloved.service";
#elif defined(__APPLE__)
constexpr std::string_view launchd_service_name = "org.sage-protocol.gloved";
#endif
constexpr std::uint64_t max_service_bytes = std::uint64_t{64} * 1024U;
constexpr auto manager_timeout = std::chrono::seconds{15};
constexpr auto health_timeout = std::chrono::seconds{5};
constexpr auto poll_interval = std::chrono::milliseconds{25};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto current_executable() -> result<std::filesystem::path> {
#if defined(__linux__)
    std::array<char, 4096> path{};
    const auto length = ::readlink("/proc/self/exe", path.data(), path.size());
    if (length <= 0 || static_cast<std::size_t>(length) == path.size()) {
        return std::unexpected(system_error("resolve glove executable"));
    }
    return std::filesystem::path{std::string_view{path.data(), static_cast<std::size_t>(length)}};
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    (void)::_NSGetExecutablePath(nullptr, &size);
    if (size == 0 || size > 4096U) {
        return std::unexpected(std::string{"resolve glove executable: path is too long"});
    }
    std::vector<char> path(size);
    if (::_NSGetExecutablePath(path.data(), &size) != 0) {
        return std::unexpected(std::string{"resolve glove executable"});
    }
    return std::filesystem::path{path.data()};
#else
    return std::unexpected(std::string{"daemon management is unsupported on this platform"});
#endif
}

auto canonical_executable(const std::optional<std::filesystem::path>& configured)
    -> result<std::filesystem::path> {
    auto executable =
        configured ? result<std::filesystem::path>{*configured} : current_executable();
    if (!executable) {
        return std::unexpected(executable.error());
    }
    std::filesystem::path candidate =
        configured ? *executable : executable->parent_path() / "gloved";
    std::error_code error;
    candidate = std::filesystem::canonical(candidate, error);
    if (error || !candidate.is_absolute() || candidate == candidate.root_path()) {
        return std::unexpected(std::string{"gloved must resolve to an existing absolute path"});
    }
    struct stat metadata{};
    if (::lstat(candidate.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        (metadata.st_uid != ::geteuid() && metadata.st_uid != 0) ||
        (static_cast<unsigned int>(metadata.st_mode) & 0022U) != 0U ||
        ::access(candidate.c_str(), X_OK) != 0) {
        return std::unexpected(
            std::string{"gloved must be a protected current-user or root executable"}
        );
    }
    return candidate;
}

#if defined(__linux__)
auto safe_systemd_path(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 4096U &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return byte >= 0x20U && byte < 0x7fU && byte != '"' && byte != '\\' && byte != '$' &&
                      byte != '%';
           });
}
#endif

#if defined(__APPLE__)
auto xml_escape(std::string_view value) -> std::string {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char byte : value) {
        switch (byte) {
        case '&':
            escaped.append("&amp;");
            break;
        case '<':
            escaped.append("&lt;");
            break;
        case '>':
            escaped.append("&gt;");
            break;
        case '"':
            escaped.append("&quot;");
            break;
        case '\'':
            escaped.append("&apos;");
            break;
        default:
            escaped.push_back(byte);
        }
    }
    return escaped;
}
#endif

#if defined(__linux__)
auto systemd_definition(
    const std::filesystem::path& gloved, const std::filesystem::path& config_path
) -> result<std::string> {
    const auto executable = gloved.string();
    const auto config = config_path.string();
    if (!safe_systemd_path(executable) || !safe_systemd_path(config)) {
        return std::unexpected(
            std::string{"systemd service paths contain unsupported control or expansion bytes"}
        );
    }
    return "[Unit]\n"
           "Description=Sage Glove agent-session supervisor\n\n"
           "[Service]\n"
           "Type=simple\n"
           "ExecStart=\"" +
           executable + "\" --config \"" + config +
           "\"\nRestart=on-failure\nRestartSec=2s\nTimeoutStopSec=15s\nUMask=0077\n\n"
           "[Install]\nWantedBy=default.target\n";
}
#endif

#if defined(__APPLE__)
auto launchd_definition(
    const std::filesystem::path& gloved, const std::filesystem::path& config_path
) -> result<std::string> {
    const auto executable = gloved.string();
    const auto config = config_path.string();
    if (executable.empty() || config.empty() || executable.size() > 4096U ||
        config.size() > 4096U) {
        return std::unexpected(std::string{"launchd service paths are invalid"});
    }
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n<dict>\n"
           "    <key>Label</key>\n    <string>" +
           std::string{launchd_service_name} +
           "</string>\n"
           "    <key>ProgramArguments</key>\n    <array>\n"
           "        <string>" +
           xml_escape(executable) +
           "</string>\n        <string>--config</string>\n        <string>" + xml_escape(config) +
           "</string>\n    </array>\n"
           "    <key>RunAtLoad</key>\n    <false/>\n"
           "    <key>KeepAlive</key>\n    <dict>\n"
           "        <key>SuccessfulExit</key>\n        <false/>\n    </dict>\n"
           "    <key>ProcessType</key>\n    <string>Interactive</string>\n"
           "    <key>ThrottleInterval</key>\n    <integer>2</integer>\n"
           "</dict>\n</plist>\n";
}
#endif

auto create_owner_directory(const std::filesystem::path& path) -> result<void> {
    struct stat metadata{};
    if (::lstat(path.c_str(), &metadata) == 0) {
        if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(metadata.st_mode) & 0022U) != 0U) {
            return std::unexpected(
                std::string{"service directory is not a protected current-user directory: "} +
                path.string()
            );
        }
        return {};
    }
    if (errno != ENOENT) {
        return std::unexpected(system_error("inspect service directory"));
    }
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error || ::chmod(path.c_str(), 0700) != 0) {
        return std::unexpected(
            error ? "create service directory: " + error.message()
                  : system_error("protect service directory")
        );
    }
    return {};
}

auto write_exact(int descriptor, std::string_view contents) -> result<void> {
    std::size_t written = 0;
    while (written < contents.size()) {
        const auto count =
            ::write(descriptor, contents.data() + written, contents.size() - written);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(system_error("write service definition"));
        }
        written += static_cast<std::size_t>(count);
    }
    return {};
}

auto read_definition(const std::filesystem::path& path) -> result<std::optional<std::string>> {
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        if (errno == ENOENT) {
            return std::nullopt;
        }
        return std::unexpected(system_error("open existing service definition"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect existing service definition"));
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0022U) != 0U || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_service_bytes) {
        return std::unexpected(std::string{"existing service definition is unsafe"});
    }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto count =
            ::read(descriptor.get(), contents.data() + consumed, contents.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(system_error("read existing service definition"));
        }
        consumed += static_cast<std::size_t>(count);
    }
    return contents;
}

auto install_definition(const daemon_service_plan& plan) -> result<bool> {
    if (plan.service_definition.empty() || plan.service_definition.size() > max_service_bytes) {
        return std::unexpected(std::string{"service definition is empty or exceeds its bound"});
    }
    if (auto directory = create_owner_directory(plan.service_path.parent_path()); !directory) {
        return std::unexpected(directory.error());
    }
    auto existing_definition = read_definition(plan.service_path);
    if (!existing_definition) {
        return std::unexpected(existing_definition.error());
    }
    if (*existing_definition && **existing_definition == plan.service_definition) {
        return false;
    }
    std::string temporary = plan.service_path.string() + ".tmp-XXXXXX";
    const unique_fd descriptor{::mkstemp(temporary.data())};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("create temporary service definition"));
    }
    if (::fchmod(descriptor.get(), 0600) != 0 ||
        ::fcntl(descriptor.get(), F_SETFD, FD_CLOEXEC) != 0) {
        const auto error = system_error("protect temporary service definition");
        (void)::unlink(temporary.c_str());
        return std::unexpected(error);
    }
    if (auto written = write_exact(descriptor.get(), plan.service_definition);
        !written || ::fsync(descriptor.get()) != 0) {
        const auto error = written ? system_error("sync service definition") : written.error();
        (void)::unlink(temporary.c_str());
        return std::unexpected(error);
    }
    struct stat existing{};
    if (::lstat(plan.service_path.c_str(), &existing) == 0) {
        if (!S_ISREG(existing.st_mode) || existing.st_uid != ::geteuid() ||
            existing.st_nlink != 1 || (static_cast<unsigned int>(existing.st_mode) & 0022U) != 0U) {
            (void)::unlink(temporary.c_str());
            return std::unexpected(std::string{"existing service definition is unsafe"});
        }
    } else if (errno != ENOENT) {
        const auto error = system_error("inspect existing service definition");
        (void)::unlink(temporary.c_str());
        return std::unexpected(error);
    }
    if (::rename(temporary.c_str(), plan.service_path.c_str()) != 0) {
        const auto error = system_error("install service definition");
        (void)::unlink(temporary.c_str());
        return std::unexpected(error);
    }
    const unique_fd directory{::open(
        plan.service_path.parent_path().c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW
    )};
    if (directory.get() < 0 || ::fsync(directory.get()) != 0) {
        return std::unexpected(system_error("sync service directory"));
    }
    return true;
}

auto run_command(
    const std::filesystem::path& executable,
    const std::vector<std::string>& arguments,
    bool quiet = false
) -> result<int> {
    std::vector<char*> argv;
    auto executable_text = executable.string();
    argv.reserve(arguments.size() + 2U);
    argv.push_back(executable_text.data());
    for (const auto& argument : arguments) {
        argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions{};
    if (::posix_spawn_file_actions_init(&actions) != 0) {
        return std::unexpected(std::string{"initialize service-manager process actions"});
    }
    if (quiet) {
        if (::posix_spawn_file_actions_addopen(
                &actions, STDOUT_FILENO, "/dev/null", O_WRONLY | O_CLOEXEC, 0
            ) != 0 ||
            ::posix_spawn_file_actions_addopen(
                &actions, STDERR_FILENO, "/dev/null", O_WRONLY | O_CLOEXEC, 0
            ) != 0) {
            (void)::posix_spawn_file_actions_destroy(&actions);
            return std::unexpected(std::string{"configure service-manager process output"});
        }
    }
    ::pid_t process = -1;
    const int spawned =
        ::posix_spawn(&process, executable.c_str(), &actions, nullptr, argv.data(), environ);
    (void)::posix_spawn_file_actions_destroy(&actions);
    if (spawned != 0) {
        return std::unexpected(system_error("start service manager", spawned));
    }
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + manager_timeout;
    for (;;) {
        const auto waited = ::waitpid(process, &status, WNOHANG);
        if (waited == process) {
            break;
        }
        if (waited < 0 && errno != EINTR) {
            return std::unexpected(system_error("wait for service manager"));
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            (void)::kill(process, SIGKILL);
            while (::waitpid(process, &status, 0) < 0 && errno == EINTR) {}
            return std::unexpected(std::string{"service manager timed out"});
        }
        std::this_thread::sleep_for(poll_interval);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return std::unexpected(std::string{"service manager terminated abnormally"});
}

auto manager_command(
    const daemon_service_plan& plan, std::vector<std::string> arguments, bool quiet = false
) -> result<int> {
    const std::filesystem::path executable = plan.manager == daemon_service_manager::systemd_user
                                                 ? "/usr/bin/systemctl"
                                                 : "/bin/launchctl";
    return run_command(executable, arguments, quiet);
}

auto require_success(result<int> status, std::string_view operation) -> result<void> {
    if (!status) {
        return std::unexpected(status.error());
    }
    if (*status != 0) {
        return std::unexpected(
            std::string{operation} + " failed with exit status " + std::to_string(*status)
        );
    }
    return {};
}

auto launchd_target(const daemon_service_plan& plan) -> std::string {
    return "gui/" + std::to_string(plan.user_id) + "/" + plan.service_name;
}

auto wait_for_health(const daemon_service_plan& plan) -> result<void> {
    auto configured = load_config(plan.config_path);
    if (!configured) {
        return std::unexpected(configured.error());
    }
    std::string last_error = "control service did not become ready";
    const auto deadline = std::chrono::steady_clock::now() + health_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto health = supervisor_health(*configured);
        if (health) {
            return {};
        }
        last_error = health.error();
        std::this_thread::sleep_for(poll_interval);
    }
    return std::unexpected("Glove daemon started without becoming healthy: " + last_error);
}

} // namespace

auto plan_daemon_service(const daemon_options& options, const environment& values)
    -> result<daemon_service_plan> {
    auto directories = resolve_directories(values);
    if (!directories) {
        return std::unexpected(directories.error());
    }
    const auto config_path = options.config_path.value_or(default_config_path(*directories));
    if (!config_path.is_absolute() || config_path == config_path.root_path() ||
        config_path.lexically_normal() != config_path) {
        return std::unexpected(
            std::string{"daemon configuration path must be a normalized absolute path"}
        );
    }
    auto configured = load_config(config_path);
    if (!configured) {
        return std::unexpected("load daemon configuration: " + configured.error());
    }
    auto gloved = canonical_executable(options.gloved_path);
    if (!gloved) {
        return std::unexpected(gloved.error());
    }
#if defined(__linux__)
    auto definition = systemd_definition(*gloved, config_path);
    if (!definition) {
        return std::unexpected(definition.error());
    }
    return daemon_service_plan{
        .manager = daemon_service_manager::systemd_user,
        .config_path = config_path,
        .gloved_path = *gloved,
        .service_path =
            directories->config.parent_path() / "systemd/user" / std::string{systemd_service_name},
        .service_name = std::string{systemd_service_name},
        .service_definition = std::move(*definition),
        .user_id = static_cast<unsigned long>(::geteuid()),
    };
#elif defined(__APPLE__)
    if (!values.home) {
        return std::unexpected(std::string{"HOME is required for launchd service installation"});
    }
    auto definition = launchd_definition(*gloved, config_path);
    if (!definition) {
        return std::unexpected(definition.error());
    }
    return daemon_service_plan{
        .manager = daemon_service_manager::launchd_user,
        .config_path = config_path,
        .gloved_path = *gloved,
        .service_path = std::filesystem::path{*values.home} / "Library/LaunchAgents" /
                        (std::string{launchd_service_name} + ".plist"),
        .service_name = std::string{launchd_service_name},
        .service_definition = std::move(*definition),
        .user_id = static_cast<unsigned long>(::geteuid()),
    };
#else
    return std::unexpected(std::string{"daemon management is unsupported on this platform"});
#endif
}

auto install_daemon_service(const daemon_service_plan& plan) -> result<void> {
    auto installed = install_definition(plan);
    if (!installed) {
        return std::unexpected(installed.error());
    }
    if (plan.manager == daemon_service_manager::systemd_user) {
        return require_success(
            manager_command(plan, {"--user", "daemon-reload"}), "systemd user daemon reload"
        );
    }
    const auto registered = manager_command(plan, {"print", launchd_target(plan)}, true);
    if (!registered) {
        return std::unexpected(registered.error());
    }
    if (*registered == 0) {
        if (!*installed) {
            return {};
        }
        if (auto unloaded = require_success(
                manager_command(plan, {"bootout", launchd_target(plan)}),
                "reload launchd user service"
            );
            !unloaded) {
            return unloaded;
        }
    }
    return require_success(
        manager_command(
            plan, {"bootstrap", "gui/" + std::to_string(plan.user_id), plan.service_path.string()}
        ),
        "launchd user service registration"
    );
}

auto daemon_service_is_active(const daemon_service_plan& plan) -> result<bool> {
    auto configured = load_config(plan.config_path);
    if (!configured) {
        return std::unexpected(configured.error());
    }
    return supervisor_health(*configured).has_value();
}

auto start_daemon_service(const daemon_service_plan& plan) -> result<void> {
    if (auto installed = install_daemon_service(plan); !installed) {
        return installed;
    }
    const auto arguments = plan.manager == daemon_service_manager::systemd_user
                               ? std::vector<std::string>{"--user", "start", plan.service_name}
                               : std::vector<std::string>{"kickstart", launchd_target(plan)};
    if (auto started = require_success(manager_command(plan, arguments), "start Glove daemon");
        !started) {
        return started;
    }
    return wait_for_health(plan);
}

auto stop_daemon_service(const daemon_service_plan& plan) -> result<void> {
    if (plan.manager == daemon_service_manager::systemd_user) {
        return require_success(
            manager_command(plan, {"--user", "stop", plan.service_name}), "stop Glove daemon"
        );
    }
    auto registered = manager_command(plan, {"print", launchd_target(plan)}, true);
    if (!registered) {
        return std::unexpected(registered.error());
    }
    if (*registered != 0) {
        return {};
    }
    return require_success(
        manager_command(plan, {"bootout", launchd_target(plan)}), "stop Glove daemon"
    );
}

auto restart_daemon_service(const daemon_service_plan& plan) -> result<void> {
    if (plan.manager == daemon_service_manager::systemd_user) {
        if (auto installed = install_daemon_service(plan); !installed) {
            return installed;
        }
        return require_success(
            manager_command(plan, {"--user", "restart", plan.service_name}), "restart Glove daemon"
        );
    }
    if (auto stopped = stop_daemon_service(plan); !stopped) {
        return stopped;
    }
    return start_daemon_service(plan);
}

} // namespace glove::host
