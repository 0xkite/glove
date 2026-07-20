#include "glove/host/doctor.hpp"

#include "glove/host/control_client.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <string_view>
#include <utility>

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

} // namespace

auto doctor_report::healthy() const -> bool {
    return std::ranges::none_of(checks, [](const auto& check) {
        return check.status == doctor_status::failed;
    });
}

auto diagnose(const std::filesystem::path& config_path) -> doctor_report {
    doctor_report report{.config_path = config_path};
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
    auto health = supervisor_health(*configured);
    report.checks.push_back({
        .code = "control_service",
        .status = health ? doctor_status::passed : doctor_status::warning,
        .message = health ? "Glove control service is authenticated and responsive."
                          : "Glove control service is unavailable: " + health.error(),
        .recovery = "Start the registered gloved user service, then rerun `glove doctor`.",
    });
    return report;
}

} // namespace glove::host
