#include "cli.hpp"

#include "glove/host/config.hpp"
#include "glove/host/control_client.hpp"
#include "glove/host/daemon.hpp"
#include "glove/host/doctor.hpp"
#include "glove/host/operator_experience.hpp"
#include "glove/host/runtime_policy.hpp"
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

namespace policy_wire {
struct harness {
    std::string runtime_id;
    std::string executable_name;
    bool available = false;
    std::string resolved_executable;
    std::string diagnostic;
};

struct detection_report {
    std::uint8_t schema_version = 1;
    std::vector<std::string> search_paths;
    std::vector<harness> harnesses;
};

struct stage_report {
    std::uint8_t schema_version = 1;
    std::string runtime_id;
    std::string protected_entry_point;
    std::string source_executable;
    std::string launch_executable;
    std::vector<std::string> launch_arguments;
    std::vector<std::string> read_only_paths;
    bool changed = false;
    bool dry_run = false;
};

struct validation_report {
    std::uint8_t schema_version = 1;
    bool valid = false;
    std::string policy_path;
    std::string code;
    std::string message;
    std::string recovery;
};
} // namespace policy_wire

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
        "usage:\n"
        "  glove setup guide [--json]\n"
        "  glove setup [--config <absolute-file>] [--path-root <absolute-directory>] "
        "[--session-policy <absolute-file>] "
        "[--root-id <id>] [--runtime <template-id>]... [--dry-run | --yes]\n"
    );
}

auto print_setup_guidance(bool json) -> int {
    const auto guidance = operator_setup_guidance();
    if (json) {
        auto encoded = glz::write_json(guidance);
        if (!encoded) {
            return print_error(
                "setup_guide_encode_failed", "Could not encode setup guidance.", "glove setup guide"
            );
        }
        std::printf("%s\n", encoded->c_str());
        return 0;
    }
    std::printf(
        "Detected platform: %s\nRecommended path: %s\n",
        guidance.platform.c_str(),
        guidance.recommended_path.empty() ? "none" : guidance.recommended_path.c_str()
    );
    for (const auto& path : guidance.paths) {
        std::printf(
            "\n%s%s%s\n"
            "  Goal:       %s\n"
            "  Isolation:  %s\n"
            "  Cost:       %s\n"
            "  Receipts:   %s\n"
            "  Limitation: %s\n"
            "  Next:       %s\n",
            path.id.c_str(),
            path.recommended ? " (recommended)" : "",
            path.eligible ? "" : " (not eligible on this host)",
            path.goal.c_str(),
            path.isolation.c_str(),
            path.cost.c_str(),
            path.receipts.c_str(),
            path.limitation.c_str(),
            path.next_command.c_str()
        );
    }
    return 0;
}

void print_daemon_usage() {
    std::fprintf(
        stderr,
        "usage: glove daemon <install|start|stop|restart|status> "
        "[--config <absolute-file>] [--gloved <absolute-file>]\n"
    );
}

void print_policy_usage() {
    std::fprintf(
        stderr,
        "usage:\n"
        "  glove policy detect --search-path <absolute-directory>... [--json]\n"
        "  glove policy stage --runtime <id> --source <absolute-file>\n"
        "      --directory <absolute-directory> [--dry-run | --yes] [--json]\n"
        "  glove policy generate --runtime <id>\n"
        "      (--executable <absolute-file> | --search-path <absolute-directory>...)\n"
        "      [--template-id <id>] [--backend <linux_production|macos_experimental>]\n"
        "      [--argument <value>]... [--environment <NAME=VALUE>]...\n"
        "      [--read-only-path <absolute-path>]... [--path-alias <id>]...\n"
        "      [--projection-destination <id>]...\n"
        "  glove policy validate --file <absolute-file>\n"
        "  glove policy explain --file <absolute-file> [--json]\n"
    );
}

} // namespace

auto setup_command(std::span<char* const> arguments) -> int {
    if (!arguments.empty() && std::string_view{arguments.front()} == "guide") {
        if (arguments.size() == 1U) {
            return print_setup_guidance(false);
        }
        if (arguments.size() == 2U && std::string_view{arguments[1]} == "--json") {
            return print_setup_guidance(true);
        }
        print_setup_usage();
        return 2;
    }
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
    if (options.session_policy) {
        auto valid = validate_session_policy_file(*options.session_policy);
        if (!valid) {
            return print_error(
                "setup_session_policy_invalid",
                valid.error(),
                "glove policy explain --file <absolute-file>\n"
                "  glove policy validate --file <absolute-file>"
            );
        }
    }
    auto plan = plan_setup(options, current_environment());
    if (!plan) {
        return print_error("setup_invalid", plan.error(), "glove setup --help");
    }
    std::printf("Configuration: %s\n", plan->config_path.c_str());
    const auto guidance = operator_setup_guidance();
    std::printf(
        "Platform shipping lane: %s (run `glove setup guide` for tradeoffs)\n",
        guidance.recommended_path.empty() ? "unsupported" : guidance.recommended_path.c_str()
    );
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
    if (plan->service.session_policy) {
        std::printf("  glove policy validate --file %s\n", plan->service.session_policy->c_str());
    }
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

auto policy_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "-h" ||
        std::string_view{arguments.front()} == "--help") {
        print_policy_usage();
        return arguments.empty() ? 2 : 0;
    }
    const std::string_view action{arguments.front()};
    if (arguments.size() == 2U &&
        (std::string_view{arguments[1]} == "-h" || std::string_view{arguments[1]} == "--help")) {
        print_policy_usage();
        return 0;
    }
    if (action == "detect") {
        std::vector<std::filesystem::path> search_paths;
        bool json = false;
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (argument == "--json") {
                json = true;
                ++index;
            } else if (argument == "--search-path" && index + 1 < arguments.size()) {
                search_paths.emplace_back(arguments[index + 1]);
                index += 2;
            } else {
                print_policy_usage();
                return 2;
            }
        }
        if (search_paths.empty()) {
            return print_error(
                "policy_search_path_required",
                "Harness detection requires an explicit search directory; inherited PATH is not "
                "trusted.",
                "glove policy detect --search-path <absolute-directory> --json"
            );
        }
        const auto detected = detect_runtime_harnesses(search_paths);
        if (json) {
            policy_wire::detection_report report;
            for (const auto& path : search_paths) {
                report.search_paths.push_back(path.string());
            }
            for (const auto& harness : detected) {
                report.harnesses.push_back({
                    .runtime_id = harness.runtime_id,
                    .executable_name = harness.executable_name,
                    .available = harness.available,
                    .resolved_executable = harness.resolved_executable.string(),
                    .diagnostic = harness.diagnostic,
                });
            }
            auto encoded = glz::write_json(report);
            if (!encoded) {
                return print_error(
                    "policy_encode_failed",
                    "Could not encode harness detection output.",
                    "glove policy detect --help"
                );
            }
            std::printf("%s\n", encoded->c_str());
        } else {
            for (const auto& harness : detected) {
                if (harness.available) {
                    std::printf(
                        "+ %-12s %s\n",
                        harness.runtime_id.c_str(),
                        harness.resolved_executable.c_str()
                    );
                } else {
                    std::printf(
                        "- %-12s %s\n", harness.runtime_id.c_str(), harness.diagnostic.c_str()
                    );
                }
            }
        }
        return 0;
    }
    if (action == "stage") {
        runtime_harness_stage_options options;
        bool yes = false;
        bool json = false;
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (argument == "--yes") {
                yes = true;
                ++index;
            } else if (argument == "--dry-run") {
                options.dry_run = true;
                ++index;
            } else if (argument == "--json") {
                json = true;
                ++index;
            } else if (
                index + 1 < arguments.size() &&
                (argument == "--runtime" || argument == "--source" || argument == "--directory")
            ) {
                const std::string value{arguments[index + 1]};
                if (argument == "--runtime") {
                    options.runtime_id = value;
                } else if (argument == "--source") {
                    options.source_executable = value;
                } else {
                    options.protected_directory = value;
                }
                index += 2;
            } else {
                print_policy_usage();
                return 2;
            }
        }
        if (yes && options.dry_run) {
            return print_error(
                "policy_conflicting_flags",
                "--dry-run and --yes cannot be combined.",
                "glove policy stage --help"
            );
        }
        if (options.runtime_id.empty() || options.source_executable.empty() ||
            options.protected_directory.empty()) {
            print_policy_usage();
            return 2;
        }
        if (!yes && !options.dry_run) {
            return print_error(
                "policy_confirmation_required",
                "Staging creates a protected adapter-named entry point on this machine.",
                "glove policy stage --runtime <id> --source <absolute-file> --directory "
                "<absolute-directory> --dry-run\n"
                "  glove policy stage --runtime <id> --source <absolute-file> --directory "
                "<absolute-directory> --yes"
            );
        }
        auto staged = stage_runtime_harness(options);
        if (!staged) {
            return print_error("policy_stage_failed", staged.error(), "glove policy stage --help");
        }
        policy_wire::stage_report report{
            .runtime_id = staged->runtime_id,
            .protected_entry_point = staged->protected_entry_point.string(),
            .source_executable = staged->source_executable.string(),
            .launch_executable = staged->launch_executable.string(),
            .launch_arguments = staged->launch_arguments,
            .read_only_paths = {},
            .changed = staged->changed,
            .dry_run = options.dry_run,
        };
        report.read_only_paths.reserve(staged->read_only_paths.size());
        for (const auto& path : staged->read_only_paths) {
            report.read_only_paths.push_back(path.string());
        }
        if (json) {
            auto encoded = glz::write_json(report);
            if (!encoded) {
                return print_error(
                    "policy_encode_failed",
                    "Could not encode harness staging output.",
                    "glove policy stage --help"
                );
            }
            std::printf("%s\n", encoded->c_str());
            return 0;
        }
        std::printf(
            "%s harness entry point: %s\n",
            options.dry_run ? "Planned" : (staged->changed ? "Created" : "Verified"),
            staged->protected_entry_point.c_str()
        );
        std::printf(
            "Source executable:          %s\n"
            "Launch executable:          %s\n",
            staged->source_executable.c_str(),
            staged->launch_executable.c_str()
        );
        for (const auto& argument : staged->launch_arguments) {
            std::printf("Launch argument:            %s\n", argument.c_str());
        }
        for (const auto& path : staged->read_only_paths) {
            std::printf("Read-only dependency root:  %s\n", path.c_str());
        }
        std::printf(
            "Next:\n"
            "  Use --json to pass this exact launch closure to policy generation.\n"
            "  glove policy detect --search-path %s --json\n",
            staged->protected_entry_point.parent_path().c_str()
        );
        return 0;
    }
    if (action == "generate") {
        runtime_policy_generation_options options;
#if defined(__linux__)
        options.backend = supervisor::sandbox_backend::linux_production;
#else
        options.backend = supervisor::sandbox_backend::macos_experimental;
#endif
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (index + 1 >= arguments.size()) {
                print_policy_usage();
                return 2;
            }
            const std::string value{arguments[index + 1]};
            if (argument == "--runtime") {
                options.runtime_id = value;
            } else if (argument == "--template-id") {
                options.runtime_template_id = value;
            } else if (argument == "--backend") {
                if (value == "linux_production") {
                    options.backend = supervisor::sandbox_backend::linux_production;
                } else if (value == "macos_experimental") {
                    options.backend = supervisor::sandbox_backend::macos_experimental;
                } else {
                    return print_error(
                        "policy_backend_invalid",
                        "Unknown sandbox backend.",
                        "glove policy generate --help"
                    );
                }
            } else if (argument == "--executable") {
                options.executable_path = value;
            } else if (argument == "--search-path") {
                options.executable_search_paths.emplace_back(value);
            } else if (argument == "--argument") {
                options.arguments.push_back(value);
            } else if (argument == "--environment") {
                options.environment.push_back(value);
            } else if (argument == "--read-only-path") {
                options.read_only_paths.emplace_back(value);
            } else if (argument == "--path-alias") {
                options.allowed_path_aliases.push_back(value);
            } else if (argument == "--projection-destination") {
                options.allowed_projection_destinations.push_back(value);
            } else {
                print_policy_usage();
                return 2;
            }
            index += 2;
        }
        if (options.runtime_id.empty()) {
            return print_error(
                "policy_runtime_required",
                "Runtime adapter ID is required.",
                "glove policy generate --runtime <id> --executable <absolute-file>\n"
                "  glove policy generate --runtime <id> --search-path <absolute-directory>"
            );
        }
        auto generated = generate_runtime_policy(options);
        if (!generated) {
            return print_error(
                "policy_generate_failed", generated.error(), "glove policy detect --help"
            );
        }
        std::fprintf(
            stderr,
            "Resolved executable: %s\nAdapter digest:     %s\n",
            generated->resolved_executable.c_str(),
            generated->adapter_command_digest.c_str()
        );
        std::printf("%s", generated->policy_template_json.c_str());
        return 0;
    }
    if (action == "validate" || action == "explain") {
        std::optional<std::filesystem::path> policy_path;
        bool json = false;
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (argument == "--json" && action == "explain") {
                json = true;
                ++index;
            } else if (argument == "--file" && index + 1 < arguments.size()) {
                policy_path = arguments[index + 1];
                index += 2;
            } else {
                print_policy_usage();
                return 2;
            }
        }
        if (!policy_path) {
            print_policy_usage();
            return 2;
        }
        auto valid = validate_session_policy_file(*policy_path);
        if (action == "validate") {
            if (!valid) {
                return print_error(
                    "policy_invalid",
                    valid.error(),
                    "fix the reported field, chmod 600 <policy>, then rerun glove policy validate"
                );
            }
            std::printf("Session policy is valid: %s\n", policy_path->c_str());
            return 0;
        }
        policy_wire::validation_report report{
            .valid = valid.has_value(),
            .policy_path = policy_path->string(),
            .code = valid ? "policy_valid" : "policy_invalid",
            .message =
                valid ? "Session policy schema and local invariants are valid." : valid.error(),
            .recovery =
                valid ? std::string{}
                      : "Fix the reported field, protect the file with mode 0600, and validate "
                        "again.",
        };
        if (json) {
            auto encoded = glz::write_json(report);
            if (!encoded) {
                return print_error(
                    "policy_encode_failed",
                    "Could not encode policy diagnostic output.",
                    "glove policy explain --help"
                );
            }
            std::printf("%s\n", encoded->c_str());
        } else {
            std::printf(
                "%c [%s] %s\n",
                report.valid ? '+' : 'x',
                report.code.c_str(),
                report.message.c_str()
            );
            if (!report.recovery.empty()) {
                std::printf("    %s\n", report.recovery.c_str());
            }
        }
        return valid ? 0 : 1;
    }
    print_policy_usage();
    return 2;
}

auto init_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "-h" ||
        std::string_view{arguments.front()} == "--help") {
        std::fprintf(
            stderr,
            "usage: glove init <project> [--config <absolute-file>] [--id <id>] [--root <id>] "
            "[--label <text>] [--purpose <inspect|experiment|retain>] "
            "[--access <read|ephemeral-write|retained-write>] "
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
    project_purpose purpose = project_purpose::inspect;
    std::optional<project_access> access_override;
    std::optional<std::uint64_t> max_bytes_override;
    std::optional<std::uint64_t> ttl_secs_override;
    std::optional<std::filesystem::path> config_path;
    bool runtime_overridden = false;
    for (std::size_t index = 1; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (index + 1 >= arguments.size() ||
            (argument != "--config" && argument != "--id" && argument != "--root" &&
             argument != "--label" && argument != "--purpose" && argument != "--access" &&
             argument != "--max-bytes" && argument != "--ttl-secs" && argument != "--runtime" &&
             argument != "--request-id")) {
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
        } else if (argument == "--purpose") {
            if (value != "inspect" && value != "experiment" && value != "retain") {
                return print_error(
                    "init_purpose_invalid", "Unknown project purpose.", "glove init --help"
                );
            }
            purpose = parse_project_purpose(value);
        } else if (argument == "--access") {
            if (value == "read") {
                access_override = project_access::read;
            } else if (value == "ephemeral-write") {
                access_override = project_access::ephemeral_write;
            } else if (value == "retained-write") {
                access_override = project_access::retained_write;
            } else {
                return print_error(
                    "init_access_invalid", "Unknown project access mode.", "glove init --help"
                );
            }
        } else if (argument == "--max-bytes") {
            try {
                max_bytes_override = std::stoull(value);
            } catch (const std::exception&) {
                return print_error(
                    "init_max_bytes_invalid", "--max-bytes must be an integer.", "glove init --help"
                );
            }
        } else if (argument == "--ttl-secs") {
            try {
                ttl_secs_override = std::stoull(value);
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
    const auto purpose_defaults = defaults_for(purpose);
    enrollment.access = access_override.value_or(purpose_defaults.access);
    const auto default_write_bytes = std::uint64_t{1024} * 1024U * 1024U;
    enrollment.max_bytes = max_bytes_override.value_or(
        enrollment.access == project_access::read
            ? 0
            : std::max(purpose_defaults.max_bytes, default_write_bytes)
    );
    enrollment.ttl_secs = ttl_secs_override.value_or(purpose_defaults.ttl_secs);
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
    const auto access_name = enrollment.access == project_access::read ? "read-only"
                             : enrollment.access == project_access::ephemeral_write
                                 ? "ephemeral write"
                                 : "retained write";
    const auto writable_scope =
        enrollment.access == project_access::read
            ? std::string{"none"}
            : "isolated copy, up to " + std::to_string(enrollment.max_bytes) + " bytes";
    const auto cleanup =
        enrollment.access == project_access::read
            ? std::string{"No writable project copy is created."}
        : enrollment.access == project_access::ephemeral_write
            ? std::string{"The writable copy is removed after the session."}
            : std::string{"The writable copy is retained for explicit review and apply."};
    std::printf(
        "Purpose:          %s\n"
        "Access:           %s\n"
        "Writable scope:   %s\n"
        "Cleanup:          %s\n"
        "Enrollment TTL:   %llu seconds\n",
        project_purpose_name(purpose).data(),
        access_name,
        writable_scope.c_str(),
        cleanup.c_str(),
        static_cast<unsigned long long>(enrollment.ttl_secs)
    );
    if (access_override || max_bytes_override || ttl_secs_override) {
        std::printf("Advanced overrides: active (review access, quota, and TTL above)\n");
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
