#include "cli.hpp"

#include "glove/host/config.hpp"
#include "glove/host/control_client.hpp"
#include "glove/host/daemon.hpp"
#include "glove/host/doctor.hpp"
#include "glove/host/setup.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {
namespace doctor_wire {
struct doctor_check_wire {
    std::string code;
    std::string status;
    std::string message;
    std::string recovery;
};

struct doctor_report_wire {
    std::uint8_t schema_version = 1;
    std::string config_path;
    bool healthy = false;
    std::vector<doctor_check_wire> checks;
};
} // namespace doctor_wire

namespace {

using doctor_wire::doctor_report_wire;

auto print_error(std::string_view code, std::string_view message, std::string_view recovery)
    -> int {
    std::fprintf(
        stderr,
        "error[%.*s]: %.*s\nTry:\n  %.*s\n",
        static_cast<int>(code.size()),
        code.data(),
        static_cast<int>(message.size()),
        message.data(),
        static_cast<int>(recovery.size()),
        recovery.data()
    );
    return 1;
}

auto default_path() -> result<std::filesystem::path> {
    auto directories = resolve_directories(current_environment());
    if (!directories) {
        return std::unexpected(directories.error());
    }
    return default_config_path(*directories);
}

auto status_name(doctor_status value) -> std::string_view {
    switch (value) {
    case doctor_status::passed:
        return "passed";
    case doctor_status::warning:
        return "warning";
    case doctor_status::failed:
        return "failed";
    }
    return "failed";
}

auto default_project_identifier(std::string_view name) -> std::string {
    std::string identifier;
    identifier.reserve(std::min<std::size_t>(name.size(), 128U));
    for (const char byte : name) {
        const bool allowed = (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                             (byte >= 'a' && byte <= 'z') || byte == '_' || byte == '.';
        const char normalized = allowed ? byte : '-';
        if (identifier.size() == 128U) {
            break;
        }
        if (normalized != '-' || identifier.empty() || identifier.back() != '-') {
            identifier.push_back(normalized);
        }
    }
    while (!identifier.empty() && (identifier.front() == '-' || identifier.front() == '.')) {
        identifier.erase(identifier.begin());
    }
    while (!identifier.empty() && identifier.back() == '-') {
        identifier.pop_back();
    }
    return identifier.empty() ? "project" : identifier;
}

void print_setup_usage() {
    std::fprintf(
        stderr,
        "usage: glove setup [--config <absolute-file>] [--path-root <absolute-directory>] "
        "[--session-policy <absolute-file>] "
        "[--root-id <id>] [--runtime <template-id>]... [--dry-run | --yes]\n"
    );
}

void print_daemon_usage() {
    std::fprintf(
        stderr,
        "usage: glove daemon <install|start|stop|restart|status> "
        "[--config <absolute-file>] [--gloved <absolute-file>]\n"
    );
}

} // namespace

auto setup_command(std::span<char* const> arguments) -> int {
    setup_options options;
    bool yes = false;
    bool runtime_overridden = false;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--dry-run") {
            options.dry_run = true;
            ++index;
        } else if (argument == "--yes") {
            yes = true;
            ++index;
        } else if (
            argument == "--config" || argument == "--path-root" || argument == "--session-policy" ||
            argument == "--root-id" || argument == "--runtime"
        ) {
            if (index + 1 >= arguments.size()) {
                print_setup_usage();
                return 2;
            }
            const std::string value{arguments[index + 1]};
            if (argument == "--config") {
                options.config_path = value;
            } else if (argument == "--path-root") {
                options.protected_root = value;
            } else if (argument == "--session-policy") {
                options.session_policy = value;
            } else if (argument == "--root-id") {
                options.root_id = value;
            } else {
                if (!runtime_overridden) {
                    options.runtime_template_ids.clear();
                    runtime_overridden = true;
                }
                options.runtime_template_ids.push_back(value);
            }
            index += 2;
        } else if (argument == "-h" || argument == "--help") {
            print_setup_usage();
            return 0;
        } else {
            print_setup_usage();
            return 2;
        }
    }
    if (options.dry_run && yes) {
        return print_error(
            "setup_conflicting_flags",
            "--dry-run and --yes cannot be combined.",
            "glove setup --help"
        );
    }
    auto plan = plan_setup(options, current_environment());
    if (!plan) {
        return print_error("setup_invalid", plan.error(), "glove setup --help");
    }
    std::printf("Configuration: %s\n", plan->config_path.c_str());
    std::printf("Runtime:       %s\n", plan->service.runtime_directory.c_str());
    std::printf("State:         %s\n", plan->service.audit_key.parent_path().c_str());
    if (plan->canonical_protected_root) {
        std::printf(
            "Protected root: %s (%s)\n",
            plan->canonical_protected_root->c_str(),
            plan->root_id.c_str()
        );
    } else {
        std::printf("Protected root: none (project enrollment disabled)\n");
    }
    if (options.dry_run) {
        std::printf("Dry run: no files were changed.\n");
        return 0;
    }
    if (!yes) {
        return print_error(
            "setup_confirmation_required",
            "Machine setup creates protected configuration, state, and key material.",
            "glove setup --dry-run\n  glove setup --yes"
        );
    }
    if (auto executed = execute_setup(*plan); !executed) {
        return print_error("setup_failed", executed.error(), "glove doctor");
    }
    std::printf("Glove machine setup completed.\nNext:\n  glove daemon start\n  glove doctor\n");
    if (plan->canonical_protected_root) {
        std::printf("  glove init <project-path> --root %s\n", plan->root_id.c_str());
    }
    return 0;
}

auto daemon_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "-h" ||
        std::string_view{arguments.front()} == "--help") {
        print_daemon_usage();
        return arguments.empty() ? 2 : 0;
    }
    const std::string_view action{arguments.front()};
    daemon_options options;
    for (std::size_t index = 1; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (index + 1 >= arguments.size() || (argument != "--config" && argument != "--gloved")) {
            print_daemon_usage();
            return 2;
        }
        if (argument == "--config") {
            options.config_path = arguments[index + 1];
        } else {
            options.gloved_path = arguments[index + 1];
        }
        index += 2;
    }
    if (action != "install" && action != "start" && action != "stop" && action != "restart" &&
        action != "status") {
        print_daemon_usage();
        return 2;
    }
    auto plan = plan_daemon_service(options, current_environment());
    if (!plan) {
        return print_error("daemon_invalid", plan.error(), "glove setup --yes");
    }
    if (action == "status") {
        auto active = daemon_service_is_active(*plan);
        if (!active) {
            return print_error("daemon_status_failed", active.error(), "glove daemon start");
        }
        std::printf(
            "Glove daemon: %s (%s)\n", *active ? "running" : "stopped", plan->service_name.c_str()
        );
        return *active ? 0 : 3;
    }
    result<void> changed;
    if (action == "install") {
        changed = install_daemon_service(*plan);
    } else if (action == "start") {
        changed = start_daemon_service(*plan);
    } else if (action == "stop") {
        changed = stop_daemon_service(*plan);
    } else {
        changed = restart_daemon_service(*plan);
    }
    if (!changed) {
        return print_error(
            "daemon_" + std::string{action} + "_failed",
            changed.error(),
            action == "stop" ? "glove daemon status" : "glove doctor"
        );
    }
    const std::string completed_action = action == "install"   ? "installed"
                                         : action == "start"   ? "started"
                                         : action == "stop"    ? "stopped"
                                         : action == "restart" ? "restarted"
                                                               : std::string{action};
    std::printf("Glove daemon %s: %s\n", completed_action.c_str(), plan->service_name.c_str());
    return 0;
}

auto doctor_command(std::span<char* const> arguments) -> int {
    std::optional<std::filesystem::path> config_path;
    bool json = false;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--json") {
            json = true;
            ++index;
        } else if (argument == "--config" && index + 1 < arguments.size()) {
            config_path = arguments[index + 1];
            index += 2;
        } else if (argument == "-h" || argument == "--help") {
            std::fprintf(stderr, "usage: glove doctor [--config <absolute-file>] [--json]\n");
            return 0;
        } else {
            std::fprintf(stderr, "usage: glove doctor [--config <absolute-file>] [--json]\n");
            return 2;
        }
    }
    if (!config_path) {
        auto resolved = default_path();
        if (!resolved) {
            return print_error(
                "doctor_environment_invalid", resolved.error(), "glove setup --dry-run"
            );
        }
        config_path = std::move(*resolved);
    }
    const auto report = diagnose(*config_path);
    if (json) {
        doctor_report_wire encoded{
            .config_path = report.config_path.string(),
            .healthy = report.healthy(),
            .checks = {},
        };
        for (const auto& check : report.checks) {
            encoded.checks.push_back({
                .code = check.code,
                .status = std::string{status_name(check.status)},
                .message = check.message,
                .recovery = check.recovery,
            });
        }
        auto output = glz::write_json(encoded);
        if (!output) {
            return print_error(
                "doctor_encode_failed", "Could not encode diagnostic output.", "glove doctor"
            );
        }
        std::printf("%s\n", output->c_str());
    } else {
        std::printf("Glove doctor: %s\n", report.healthy() ? "ready" : "not ready");
        for (const auto& check : report.checks) {
            const char marker = check.status == doctor_status::passed    ? '+'
                                : check.status == doctor_status::warning ? '!'
                                                                         : 'x';
            std::printf("%c [%s] %s\n", marker, check.code.c_str(), check.message.c_str());
            if (check.status != doctor_status::passed && !check.recovery.empty()) {
                std::printf("    %s\n", check.recovery.c_str());
            }
        }
    }
    return report.healthy() ? 0 : 1;
}

auto config_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "--help") {
        std::fprintf(
            stderr, "usage: glove config <path|show|validate> [--config <absolute-file>]\n"
        );
        return arguments.empty() ? 2 : 0;
    }
    const std::string_view action{arguments.front()};
    std::optional<std::filesystem::path> config_path;
    if (arguments.size() == 3 && std::string_view{arguments[1]} == "--config") {
        config_path = arguments[2];
    } else if (arguments.size() != 1) {
        std::fprintf(
            stderr, "usage: glove config <path|show|validate> [--config <absolute-file>]\n"
        );
        return 2;
    }
    if (!config_path) {
        auto resolved = default_path();
        if (!resolved) {
            return print_error(
                "config_environment_invalid", resolved.error(), "glove setup --dry-run"
            );
        }
        config_path = std::move(*resolved);
    }
    if (action == "path") {
        std::printf("%s\n", config_path->c_str());
        return 0;
    }
    auto loaded = load_config(*config_path);
    if (!loaded) {
        return print_error("config_invalid", loaded.error(), "glove doctor");
    }
    if (action == "validate") {
        std::printf("Configuration is valid: %s\n", config_path->c_str());
        return 0;
    }
    if (action == "show") {
        auto encoded = encode_config(*loaded);
        if (!encoded) {
            return print_error("config_encode_failed", encoded.error(), "glove doctor");
        }
        std::printf("%s", encoded->c_str());
        return 0;
    }
    return print_error("config_action_invalid", "Unknown config action.", "glove config --help");
}

auto init_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "-h" ||
        std::string_view{arguments.front()} == "--help") {
        std::fprintf(
            stderr,
            "usage: glove init <project> [--config <absolute-file>] [--id <id>] [--root <id>] "
            "[--label <text>] [--access <read|ephemeral-write|retained-write>] "
            "[--max-bytes <bytes>] [--ttl-secs <seconds>] [--runtime <template-id>]... "
            "[--request-id <id>]\n"
        );
        return arguments.empty() ? 2 : 0;
    }
    project_enrollment enrollment{
        .project = arguments.front(),
        .exposure_id = {},
        .root_id = "projects",
        .display_label = {},
        .access = project_access::read,
        .max_bytes = 0,
        .ttl_secs = 3'600,
        .runtime_template_ids = {"codex-safe", "pi-safe"},
        .idempotency_key = {},
    };
    std::optional<std::filesystem::path> config_path;
    bool runtime_overridden = false;
    for (std::size_t index = 1; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (index + 1 >= arguments.size() ||
            (argument != "--config" && argument != "--id" && argument != "--root" &&
             argument != "--label" && argument != "--access" && argument != "--max-bytes" &&
             argument != "--ttl-secs" && argument != "--runtime" && argument != "--request-id")) {
            return print_error(
                "init_usage", "Project enrollment arguments are invalid.", "glove init --help"
            );
        }
        const std::string value{arguments[index + 1]};
        if (argument == "--config") {
            config_path = value;
        } else if (argument == "--id") {
            enrollment.exposure_id = value;
        } else if (argument == "--root") {
            enrollment.root_id = value;
        } else if (argument == "--label") {
            enrollment.display_label = value;
        } else if (argument == "--access") {
            if (value == "read") {
                enrollment.access = project_access::read;
            } else if (value == "ephemeral-write") {
                enrollment.access = project_access::ephemeral_write;
            } else if (value == "retained-write") {
                enrollment.access = project_access::retained_write;
            } else {
                return print_error(
                    "init_access_invalid", "Unknown project access mode.", "glove init --help"
                );
            }
        } else if (argument == "--max-bytes") {
            try {
                enrollment.max_bytes = std::stoull(value);
            } catch (const std::exception&) {
                return print_error(
                    "init_max_bytes_invalid", "--max-bytes must be an integer.", "glove init --help"
                );
            }
        } else if (argument == "--ttl-secs") {
            try {
                enrollment.ttl_secs = std::stoull(value);
            } catch (const std::exception&) {
                return print_error(
                    "init_ttl_invalid", "--ttl-secs must be an integer.", "glove init --help"
                );
            }
        } else if (argument == "--runtime") {
            if (!runtime_overridden) {
                enrollment.runtime_template_ids.clear();
                runtime_overridden = true;
            }
            enrollment.runtime_template_ids.push_back(value);
        } else {
            enrollment.idempotency_key = value;
        }
        index += 2;
    }
    std::error_code canonical_error;
    enrollment.project = std::filesystem::canonical(enrollment.project, canonical_error);
    if (canonical_error) {
        return print_error(
            "init_project_invalid",
            "Project path does not resolve to an existing directory.",
            "glove init <existing-project>"
        );
    }
    const auto basename = enrollment.project.filename().string();
    if (enrollment.exposure_id.empty()) {
        enrollment.exposure_id = default_project_identifier(basename);
    }
    if (enrollment.display_label.empty()) {
        enrollment.display_label = basename;
    }
    if (enrollment.idempotency_key.empty()) {
        enrollment.idempotency_key = "init-" + enrollment.exposure_id;
    }
    if (enrollment.access != project_access::read && enrollment.max_bytes == 0) {
        enrollment.max_bytes = std::uint64_t{1024} * 1024U * 1024U;
    }
    if (!config_path) {
        auto resolved = default_path();
        if (!resolved) {
            return print_error(
                "init_environment_invalid", resolved.error(), "glove setup --dry-run"
            );
        }
        config_path = std::move(*resolved);
    }
    auto configured = load_config(*config_path);
    if (!configured) {
        return print_error("init_config_invalid", configured.error(), "glove doctor");
    }
    if (!configured->path_exposure_policy) {
        return print_error(
            "init_policy_unavailable",
            "Project enrollment requires a setup-approved protected root.",
            "glove setup --path-root <absolute-directory> --dry-run"
        );
    }
    auto exposure = enroll_project(*configured, enrollment);
    if (!exposure) {
        return print_error("init_failed", exposure.error(), "glove doctor");
    }
    std::printf("Project enrolled: %s\n", exposure->exposure_id.c_str());
    std::printf("Generation:       %llu\n", static_cast<unsigned long long>(exposure->generation));
    std::printf("Scope digest:     %s\n", exposure->scope_digest.c_str());
    std::printf("Next:\n  sage fleet paths list\n");
    return 0;
}

} // namespace glove::host
