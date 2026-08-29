#include "glove/host/doctor.hpp"

#include "glove/host/control_client.hpp"
#include "glove/host/setup.hpp"

#if defined(__linux__)
#    include <pwd.h>
#    include <sched.h>
#endif
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>
#include <utility>

extern char** environ;

namespace glove::host {
namespace {

auto owner_only_directory(const std::filesystem::path& path) -> bool {
    struct stat metadata{};
    return ::lstat(path.c_str(), &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
           metadata.st_uid == ::geteuid() &&
           (static_cast<unsigned int>(metadata.st_mode) & 0777U) == 0700U;
}

auto owner_only_file(const std::filesystem::path& path) -> bool {
    struct stat metadata{};
    return ::lstat(path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode) &&
           metadata.st_uid == ::geteuid() && metadata.st_nlink == 1 &&
           (static_cast<unsigned int>(metadata.st_mode) & 0777U) == 0600U;
}

auto root_owned_executable(const std::filesystem::path& path) -> bool {
    struct stat metadata{};
    return ::lstat(path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode) &&
           metadata.st_uid == 0 && (static_cast<unsigned int>(metadata.st_mode) & 0022U) == 0 &&
           ::access(path.c_str(), X_OK) == 0;
}

#if defined(__linux__)
auto read_text(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path};
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

auto has_controller(std::string_view controllers, std::string_view required) -> bool {
    std::istringstream fields{std::string{controllers}};
    for (std::string field; fields >> field;) {
        if (field == required) {
            return true;
        }
    }
    return false;
}

auto namespaces_available() -> bool {
    const auto child = ::fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        ::_exit(::unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET) == 0 ? 0 : 1);
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

auto linux_host_checks(bool required, bool persistent_service) -> std::vector<doctor_check> {
    const auto status = [required](bool passed) {
        return passed     ? doctor_status::passed
               : required ? doctor_status::failed
                          : doctor_status::warning;
    };
    std::vector<doctor_check> checks;
    const auto controllers = read_text("/sys/fs/cgroup/cgroup.controllers");
    const bool cgroup = has_controller(controllers, "cpu") &&
                        has_controller(controllers, "memory") &&
                        has_controller(controllers, "pids");
    checks.push_back({
        .code = "linux_cgroup_v2",
        .status = status(cgroup),
        .message = cgroup ? "cgroup v2 exposes cpu, memory, and pids; session receipts must prove "
                            "service delegation."
                          : "cgroup v2 cpu, memory, and pids controllers are not all available.",
        .recovery = "Enable unified cgroup v2 and install the generated service with `Delegate=cpu "
                    "memory pids`.",
    });
    const bool namespaces = namespaces_available();
    checks.push_back({
        .code = "linux_namespaces",
        .status = status(namespaces),
        .message = namespaces
                       ? "Unprivileged user, mount, and network namespace creation succeeded."
                       : "Unprivileged user, mount, and network namespace creation failed.",
        .recovery =
            "Enable unprivileged user namespaces and permit mount and network namespace creation.",
    });
    const bool seccomp = std::filesystem::exists("/proc/sys/kernel/seccomp/actions_avail");
    checks.push_back({
        .code = "linux_seccomp",
        .status = status(seccomp),
        .message = seccomp ? "Kernel seccomp actions are available."
                           : "Kernel seccomp support was not detected.",
        .recovery = "Use a kernel with seccomp filtering enabled.",
    });
    const auto user_runtime = std::filesystem::path{"/run/user"} / std::to_string(::geteuid());
    const bool systemd_user = std::filesystem::exists(user_runtime / "systemd/private");
    checks.push_back({
        .code = "linux_systemd_user",
        .status = systemd_user ? doctor_status::passed : doctor_status::warning,
        .message = systemd_user ? "The systemd user manager is available."
                                : "The systemd user manager is not currently available.",
        .recovery = "Start the systemd user manager before installing the Glove service.",
    });
    const auto* account = ::getpwuid(::geteuid());
    const bool lingering = account != nullptr &&
                           std::filesystem::exists(
                               std::filesystem::path{"/var/lib/systemd/linger"} / account->pw_name
                           );
    checks.push_back({
        .code = "linux_user_lingering",
        .status = persistent_service && !lingering ? doctor_status::failed : doctor_status::passed,
        .message =
            persistent_service
                ? (lingering ? "User lingering satisfies the configured persistent service."
                             : "Persistent service is configured, but user lingering is disabled.")
                : "The service is intentionally scoped to the current login session.",
        .recovery = persistent_service && !lingering
                        ? "Preview `glove setup --persistent --dry-run`, then apply with `--yes`."
                        : "",
    });
    const bool loop = ::access("/dev/loop-control", R_OK | W_OK) == 0;
    const bool mkfs =
        root_owned_executable("/usr/sbin/mkfs.ext4") || root_owned_executable("/sbin/mkfs.ext4");
    checks.push_back({
        .code = "linux_retained_storage",
        .status = loop && mkfs ? doctor_status::passed : doctor_status::warning,
        .message = loop && mkfs
                       ? "Loop-control and immutable root-owned mkfs.ext4 support retained images."
                       : "Retained-image prerequisites are incomplete; ephemeral sessions remain "
                         "available.",
        .recovery =
            "Provide controlled loop access and root-owned mkfs.ext4 only for retained writes.",
    });
    return checks;
}
#endif

#if defined(__APPLE__)
auto apple_command_ok(
    const std::filesystem::path& cli, std::initializer_list<std::string> arguments
) -> bool {
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
    if (::posix_spawn(&child, cli.c_str(), nullptr, nullptr, argv.data(), environ) != 0) {
        return false;
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

auto apple_host_checks(const std::optional<apple_container_config>& runtime)
    -> std::vector<doctor_check> {
    if (!runtime) {
        return {{
            .code = "apple_container_runtime",
            .status = doctor_status::warning,
            .message = "No paired Apple Container managed guest is configured.",
            .recovery = "Install a provenance-verified Sage/Glove release pair, then rerun setup.",
        }};
    }
    const bool cli_safe = root_owned_executable(runtime->cli);
    const bool system_ready = cli_safe && apple_command_ok(runtime->cli, {"system", "status"});
    const bool image_ready =
        system_ready && apple_command_ok(runtime->cli, {"image", "inspect", runtime->image});
    return {
        {
            .code = "apple_container_cli",
            .status = cli_safe ? doctor_status::passed : doctor_status::failed,
            .message = cli_safe ? "Apple Container CLI is an immutable root-owned executable."
                                : "Apple Container CLI is missing or mutable.",
            .recovery = "Install the signed Apple Container package at /usr/local/bin/container.",
        },
        {
            .code = "apple_container_system",
            .status = system_ready ? doctor_status::passed : doctor_status::failed,
            .message = system_ready ? "Apple Container system services are ready."
                                    : "Apple Container system services are unavailable.",
            .recovery = "Run `/usr/local/bin/container system start` and retry.",
        },
        {
            .code = "apple_container_guest",
            .status = image_ready ? doctor_status::passed : doctor_status::failed,
            .message = image_ready
                           ? "The configured managed guest image is available for validation."
                           : "The configured digest-addressed managed guest is unavailable.",
            .recovery = "Rerun `glove setup --yes` to pull the paired managed guest.",
        },
    };
}
#endif

} // namespace

auto doctor_report::healthy() const -> bool {
    return std::ranges::none_of(checks, [](const auto& check) {
        return check.status == doctor_status::failed;
    });
}

auto diagnose(const std::filesystem::path& config_path) -> doctor_report {
    doctor_report report{.config_path = config_path, .checks = {}};
    auto configured = load_config(config_path);
    if (!configured) {
        report.checks.push_back({
            .code = "config_invalid",
            .status = doctor_status::failed,
            .message = configured.error(),
            .recovery =
                "Run `glove setup --dry-run`, inspect the plan, then run `glove setup --yes`.",
        });
        return report;
    }
    report.checks.push_back({
        .code = "config_valid",
        .status = doctor_status::passed,
        .message = "Trusted Glove configuration is valid.",
        .recovery = {},
    });
    report.checks.push_back({
        .code = "runtime_directory",
        .status = owner_only_directory(configured->runtime_directory) ? doctor_status::passed
                                                                      : doctor_status::failed,
        .message = owner_only_directory(configured->runtime_directory)
                       ? "Runtime directory is owner-only."
                       : "Runtime directory is missing or not owner-only mode 0700.",
        .recovery =
            "Repair the configured runtime directory ownership and mode before starting gloved.",
    });
    report.checks.push_back({
        .code = "audit_key",
        .status =
            owner_only_file(configured->audit_key) ? doctor_status::passed : doctor_status::failed,
        .message = owner_only_file(configured->audit_key)
                       ? "Audit key is an owner-only single-link file."
                       : "Audit key is missing or fails owner-only file checks.",
        .recovery =
            "Restore the configured audit key as a current-user mode-0600 single-link file.",
    });
    const auto ledger_path = setup_ledger_path(*configured);
    auto ledger = load_setup_ledger(ledger_path);
    const bool ledger_matches = ledger && ledger->config_path == config_path.lexically_normal();
    report.checks.push_back({
        .code = "setup_ledger",
        .status = ledger_matches ? doctor_status::passed : doctor_status::warning,
        .message = ledger_matches
                       ? "The owner-only setup resource ledger matches this configuration."
                       : "The setup resource ledger is absent, invalid, or belongs to another "
                         "configuration; runtime operation is unaffected, but managed cleanup is "
                         "disabled.",
        .recovery = ledger_matches
                        ? ""
                        : "Run `glove setup adopt --config <file> --dry-run`, inspect the retained "
                          "set, then apply it with `--yes`.",
    });
    const auto recovery_manifest =
        configured->audit_key.parent_path() / "audit-recovery.active.json";
    const bool recovery_incomplete = std::filesystem::exists(recovery_manifest);
    report.checks.push_back({
        .code = "audit_recovery",
        .status = recovery_incomplete ? doctor_status::failed : doctor_status::passed,
        .message = recovery_incomplete ? "A coordinated Sage/Glove audit recovery is incomplete."
                                       : "No interrupted coordinated audit recovery is active.",
        .recovery = recovery_incomplete
                        ? "Keep Sage and gloved stopped, then resume `sage fleet host "
                          "recover-audit --glove-config <file> --yes`."
                        : "",
    });
    report.checks.push_back({
        .code = "session_policy",
        .status = configured->session_policy
                      ? (owner_only_file(*configured->session_policy) ? doctor_status::passed
                                                                      : doctor_status::failed)
                      : doctor_status::warning,
        .message = configured->session_policy && owner_only_file(*configured->session_policy)
                       ? "Session policy is configured."
                   : configured->session_policy
                       ? "Session policy is missing or fails owner-only file checks."
                       : "Session planning is disabled because no session policy is configured.",
        .recovery =
            "Configure an owner-reviewed session policy before enabling Sage execution hosting.",
    });
    report.checks.push_back({
        .code = "path_exposure_policy",
        .status = configured->path_exposure_policy
                      ? (owner_only_file(*configured->path_exposure_policy) ? doctor_status::passed
                                                                            : doctor_status::failed)
                      : doctor_status::warning,
        .message =
            configured->path_exposure_policy && owner_only_file(*configured->path_exposure_policy)
                ? "Project exposure policy is configured."
            : configured->path_exposure_policy
                ? "Project exposure policy is missing or fails owner-only file checks."
                : "Project enrollment is disabled because no protected root is configured.",
        .recovery = "Re-run setup with `--path-root <absolute-directory>`.",
    });
    for (const auto& [code, path] : {
             std::pair<std::string_view, std::optional<std::filesystem::path>>{
                 "materialization_root", configured->materialization_root
             },
             {"library_bundle_root", configured->library_bundle_root},
         }) {
        if (path) {
            const bool safe = owner_only_directory(*path);
            report.checks.push_back({
                .code = std::string{code},
                .status = safe ? doctor_status::passed : doctor_status::failed,
                .message = safe ? std::string{code} + " is owner-only."
                                : std::string{code} + " is missing or not mode 0700.",
                .recovery =
                    "Repair the configured directory ownership and mode before starting gloved.",
            });
        }
    }
#if defined(__linux__)
    auto host_checks =
        linux_host_checks(configured->session_policy.has_value(), configured->persistent_service);
    report.checks.insert(
        report.checks.end(),
        std::make_move_iterator(host_checks.begin()),
        std::make_move_iterator(host_checks.end())
    );
#endif
#if defined(__APPLE__)
    auto host_checks = apple_host_checks(configured->apple_container);
    report.checks.insert(
        report.checks.end(),
        std::make_move_iterator(host_checks.begin()),
        std::make_move_iterator(host_checks.end())
    );
#endif
    auto health = supervisor_health(*configured);
    report.checks.push_back({
        .code = "control_service",
        .status = health ? doctor_status::passed : doctor_status::warning,
        .message = health ? "Glove control service is authenticated and responsive."
                          : "Glove control service is unavailable: " + health.error(),
        .recovery = "Run `glove daemon start`, then rerun `glove doctor`.",
    });
    return report;
}

} // namespace glove::host
