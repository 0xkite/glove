#include "cli.hpp"

#include "glove/host/config.hpp"
#include "glove/host/control_client.hpp"
#include "glove/host/daemon.hpp"
#include "glove/host/doctor.hpp"
#include "glove/host/onboarding_plan.hpp"
#include "glove/host/operator_experience.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/host/setup.hpp"

#include "doctor_wire.hpp"
#include "policy_wire.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {
namespace {

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
        "  glove setup adopt [--config <absolute-file>] [--dry-run | --yes]\n"
        "  glove setup cleanup [--config <absolute-file>]\n"
        "      [--dry-run | --yes --confirm-ledger <sha256>]\n"
        "  glove setup plan --path-root <absolute-directory>\n"
        "      --search-path <absolute-directory>... [--config <absolute-file>]\n"
        "      [--runtime <adapter-id>]... [--backend <linux_production|apple_container>]\n"
        "      [--hostile-content] [--pi-settings <absolute-file>\n"
        "       --pi-package-store <absolute-directory> --pi-adoption-root <absolute-directory>]\n"
        "      [--show-policy] [--json]\n"
        "  glove setup policy --search-path <absolute-directory>...\n"
        "      --harness-root <absolute-directory> --path-root <absolute-directory>\n"
        "      --output <absolute-file> [--backend <linux_production|apple_container>]\n"
        "      [--runtime <adapter-id>]... [--hostile-content]\n"
        "      [--pi-settings <absolute-file> --pi-package-store <absolute-directory>\n"
        "       --pi-adoption-root <absolute-directory>]\n"
        "      [--egress <policy-id> <host> <port>]...\n"
        "      [--secret <runtime-id> <handle> <absolute-source> <sandbox-target>]...\n"
        "      [--dry-run | --yes] [--json]\n"
        "  glove setup [--config <absolute-file>] [--path-root <absolute-directory>] "
        "[--session-policy <absolute-file>] "
        "[--root-id <id>] [--runtime <template-id>]... [--persistent] "
        "[--dry-run | --yes]\n"
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
        "  glove policy adopt-pi --settings <absolute-file> --package-store <absolute-directory>\n"
        "      --directory <absolute-directory> [--dry-run | --yes] [--json]\n"
        "  glove policy generate --runtime <id>\n"
        "      (--executable <absolute-file> | --search-path <absolute-directory>...)\n"
        "      [--template-id <id>] [--backend <linux_production|apple_container>]\n"
        "      [--argument <value>]... [--environment <NAME=VALUE>]...\n"
        "      [--read-only-path <absolute-path>]... [--path-alias <id>]...\n"
        "      [--projection-destination <id>]...\n"
        "  glove policy validate --file <absolute-file>\n"
        "  glove policy explain --file <absolute-file> [--json]\n"
    );
}

auto setup_policy_command(std::span<char* const> arguments) -> int {
    if (arguments.size() == 1U && (std::string_view{arguments.front()} == "-h" ||
                                   std::string_view{arguments.front()} == "--help")) {
        print_setup_usage();
        return 0;
    }
    session_policy_prepare_options options;
#if defined(__linux__)
    options.backend = supervisor::sandbox_backend::linux_production;
#endif
    bool yes = false;
    bool json = false;
    std::optional<std::filesystem::path> pi_settings;
    std::optional<std::filesystem::path> pi_package_store;
    std::optional<std::filesystem::path> pi_adoption_root;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--dry-run") {
            options.dry_run = true;
            ++index;
        } else if (argument == "--yes") {
            yes = true;
            ++index;
        } else if (argument == "--json") {
            json = true;
            ++index;
        } else if (argument == "--hostile-content") {
            options.hostile_content_analysis = true;
            ++index;
        } else if (argument == "--egress" && index + 3U < arguments.size()) {
            const std::string policy_id{arguments[index + 1U]};
            const std::string host{arguments[index + 2U]};
            const std::string_view raw_port{arguments[index + 3U]};
            std::uint16_t port = 0;
            const auto parsed =
                std::from_chars(raw_port.data(), raw_port.data() + raw_port.size(), port);
            if (parsed.ec != std::errc{} || parsed.ptr != raw_port.data() + raw_port.size() ||
                port == 0) {
                return print_error(
                    "setup_policy_egress_invalid",
                    "Egress port must be an integer from 1 through 65535.",
                    "glove setup policy --help"
                );
            }
            const auto existing = std::ranges::find(
                options.egress_policies, policy_id, &supervisor::egress_policy::policy_id
            );
            if (existing == options.egress_policies.end()) {
                options.egress_policies.push_back({
                    .policy_id = policy_id,
                    .targets = {{.host = host, .port = port, .allow_private = false}},
                });
            } else {
                existing->targets.push_back({
                    .host = host,
                    .port = port,
                    .allow_private = false,
                });
            }
            index += 4U;
        } else if (argument == "--secret" && index + 4U < arguments.size()) {
            options.secret_mounts.push_back({
                .handle = arguments[index + 2U],
                .runtime_id = arguments[index + 1U],
                .source_path = arguments[index + 3U],
                .target_path = arguments[index + 4U],
            });
            index += 5U;
        } else if (index + 1 < arguments.size()) {
            const std::string value{arguments[index + 1]};
            if (argument == "--search-path") {
                options.executable_search_paths.emplace_back(value);
            } else if (argument == "--runtime") {
                options.selected_runtime_ids.push_back(value);
            } else if (argument == "--harness-root") {
                options.protected_harness_root = value;
            } else if (argument == "--pi-settings") {
                pi_settings = value;
            } else if (argument == "--pi-package-store") {
                pi_package_store = value;
            } else if (argument == "--pi-adoption-root") {
                pi_adoption_root = value;
            } else if (argument == "--path-root") {
                options.workspace_root = value;
            } else if (argument == "--output") {
                options.policy_path = value;
            } else if (argument == "--backend") {
                if (value == "linux_production") {
                    options.backend = supervisor::sandbox_backend::linux_production;
                } else if (value == "apple_container") {
                    options.backend = supervisor::sandbox_backend::apple_container;
                } else {
                    return print_error(
                        "setup_policy_backend_invalid",
                        "Unknown sandbox backend.",
                        "glove setup policy --help"
                    );
                }
            } else {
                print_setup_usage();
                return 2;
            }
            index += 2;
        } else {
            print_setup_usage();
            return 2;
        }
    }
    if (const auto pi_adoption_argument_count =
            static_cast<unsigned>(pi_settings.has_value()) +
            static_cast<unsigned>(pi_package_store.has_value()) +
            static_cast<unsigned>(pi_adoption_root.has_value());
        pi_adoption_argument_count != 0U) {
        if (pi_adoption_argument_count != 3U) {
            return print_error(
                "setup_policy_pi_adoption_incomplete",
                "Pi adoption requires --pi-settings, --pi-package-store, and --pi-adoption-root "
                "together.",
                "glove setup policy --help"
            );
        }
        options.pi_adoption = pi_adoption_manifest_options{
            .settings_path = *pi_settings,
            .package_store_root = *pi_package_store,
            .protected_directory = *pi_adoption_root,
        };
    }
    if (options.dry_run && yes) {
        return print_error(
            "setup_policy_conflicting_flags",
            "--dry-run and --yes cannot be combined.",
            "glove setup policy --help"
        );
    }
    if (!options.dry_run && !yes) {
        return print_error(
            "setup_policy_confirmation_required",
            "Harness staging and policy creation require explicit confirmation.",
            "glove setup policy ... --dry-run\n  glove setup policy ... --yes"
        );
    }
    auto prepared = prepare_session_policy(options);
    if (!prepared) {
        return print_error("setup_policy_failed", prepared.error(), "glove setup policy --help");
    }
    policy_wire::prepared_policy_report report{
        .policy_path = prepared->policy_path.string(),
        .detections = {},
        .runtimes = {},
        .session_policy_json = prepared->policy_json,
        .changed = prepared->changed,
        .dry_run = prepared->dry_run,
    };
    for (const auto& detection : prepared->detections) {
        report.detections.push_back({
            .runtime_id = detection.runtime_id,
            .executable_name = detection.executable_name,
            .available = detection.available,
            .resolved_executable = detection.resolved_executable.string(),
            .diagnostic = detection.diagnostic,
        });
    }
    for (const auto& runtime : prepared->runtimes) {
        policy_wire::stage_report staged{
            .runtime_id = runtime.runtime_id,
            .protected_entry_point = runtime.protected_entry_point.string(),
            .source_executable = runtime.source_executable.string(),
            .launch_executable = runtime.launch_executable.string(),
            .launch_arguments = runtime.launch_arguments,
            .read_only_paths = {},
            .snapshot_digest = runtime.snapshot_digest,
            .adoption_manifest_digest = runtime.adoption_manifest_digest,
            .snapshot_logical_bytes = runtime.snapshot_logical_bytes,
            .snapshot_entries = runtime.snapshot_entries,
            .changed = runtime.changed,
            .dry_run = prepared->dry_run,
        };
        for (const auto& path : runtime.read_only_paths) {
            staged.read_only_paths.push_back(path.string());
        }
        report.runtimes.push_back(std::move(staged));
    }
    if (json) {
        auto encoded = policy_wire::encode(report);
        if (!encoded) {
            return print_error(
                "setup_policy_encode_failed",
                "Could not encode prepared policy report.",
                "glove setup policy --help"
            );
        }
        std::printf("%s\n", encoded->c_str());
        return 0;
    }
    for (const auto& detection : prepared->detections) {
        std::printf(
            "%c %-12s %s\n",
            detection.available ? '+' : '-',
            detection.runtime_id.c_str(),
            detection.available ? detection.resolved_executable.c_str()
                                : detection.diagnostic.c_str()
        );
    }
    std::printf(
        "%s session policy: %s\n",
        prepared->dry_run   ? "Would create"
        : prepared->changed ? "Prepared"
                            : "Verified",
        prepared->policy_path.c_str()
    );
    if (prepared->dry_run) {
        std::printf("%s", prepared->policy_json.c_str());
    } else {
        std::printf(
            "Next:\n  glove policy validate --file %s\n"
            "  glove setup --session-policy %s --dry-run\n",
            prepared->policy_path.c_str(),
            prepared->policy_path.c_str()
        );
    }
    return 0;
}

auto setup_plan_command(std::span<char* const> arguments) -> int {
    if (arguments.size() == 1U && (std::string_view{arguments.front()} == "-h" ||
                                   std::string_view{arguments.front()} == "--help")) {
        print_setup_usage();
        return 0;
    }
    onboarding_plan_options options;
#if defined(__linux__)
    options.backend = supervisor::sandbox_backend::linux_production;
#endif
    bool json = false;
    bool show_policy = false;
    std::optional<std::filesystem::path> pi_settings;
    std::optional<std::filesystem::path> pi_package_store;
    std::optional<std::filesystem::path> pi_adoption_root;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--json") {
            json = true;
            ++index;
        } else if (argument == "--show-policy") {
            show_policy = true;
            ++index;
        } else if (argument == "--hostile-content") {
            options.hostile_content_analysis = true;
            ++index;
        } else if (index + 1U < arguments.size()) {
            const std::filesystem::path value{arguments[index + 1U]};
            if (argument == "--config") {
                options.config_path = value;
            } else if (argument == "--path-root") {
                options.protected_root = value;
            } else if (argument == "--search-path") {
                options.executable_search_paths.push_back(value);
            } else if (argument == "--runtime") {
                options.selected_runtime_ids.push_back(value.string());
            } else if (argument == "--pi-settings") {
                pi_settings = value;
            } else if (argument == "--pi-package-store") {
                pi_package_store = value;
            } else if (argument == "--pi-adoption-root") {
                pi_adoption_root = value;
            } else if (argument == "--backend") {
                if (value == "linux_production") {
                    options.backend = supervisor::sandbox_backend::linux_production;
                } else if (value == "apple_container") {
                    options.backend = supervisor::sandbox_backend::apple_container;
                } else {
                    return print_error(
                        "setup_plan_backend_invalid",
                        "Unknown sandbox backend.",
                        "glove setup plan --help"
                    );
                }
            } else {
                print_setup_usage();
                return 2;
            }
            index += 2U;
        } else {
            print_setup_usage();
            return 2;
        }
    }
    if (const auto pi_adoption_argument_count =
            static_cast<unsigned>(pi_settings.has_value()) +
            static_cast<unsigned>(pi_package_store.has_value()) +
            static_cast<unsigned>(pi_adoption_root.has_value());
        pi_adoption_argument_count != 0U) {
        if (pi_adoption_argument_count != 3U) {
            return print_error(
                "setup_plan_pi_adoption_incomplete",
                "Pi adoption requires --pi-settings, --pi-package-store, and --pi-adoption-root "
                "together.",
                "glove setup plan --help"
            );
        }
        options.pi_adoption = pi_adoption_manifest_options{
            .settings_path = *pi_settings,
            .package_store_root = *pi_package_store,
            .protected_directory = *pi_adoption_root,
            .dry_run = true,
        };
    }
    auto planned = plan_onboarding(options, current_environment());
    if (!planned) {
        return print_error("setup_plan_failed", planned.error(), "glove setup plan --help");
    }

    const auto guidance = operator_setup_guidance();
    policy_wire::onboarding_plan_report report{
        .platform = guidance.platform,
        .recommended_path = guidance.recommended_path,
        .config_path = planned->setup.config_path.string(),
        .policy_path = planned->session_policy.policy_path.string(),
        .protected_harness_root = planned->protected_harness_root.string(),
        .protected_project_root = planned->setup.canonical_protected_root->string(),
        .runtime_template_ids = planned->setup.runtime_template_ids,
        .detections = {},
        .sandbox_backend = options.backend == supervisor::sandbox_backend::linux_production
                               ? "linux_production"
                               : "apple_container",
        .network_denied = true,
        .credentials_configured = false,
        .hostile_content = options.hostile_content_analysis,
        .session_policy_json =
            show_policy ? std::optional{planned->session_policy.policy_json} : std::nullopt,
        .next_actions = {
            "Review the policy preview and detected closures before any write.",
            "Use the explicit `glove setup policy ... --yes` workflow to stage the reviewed "
            "closures and create the policy.",
            "Use the explicit `glove setup ... --yes` workflow to create machine-local "
            "configuration and enable the reviewed policy.",
        },
    };
    for (const auto& detection : planned->session_policy.detections) {
        report.detections.push_back({
            .runtime_id = detection.runtime_id,
            .executable_name = detection.executable_name,
            .available = detection.available,
            .resolved_executable = detection.resolved_executable.string(),
            .diagnostic = detection.diagnostic,
        });
    }
    if (json) {
        auto encoded = policy_wire::encode(report);
        if (!encoded) {
            return print_error(
                "setup_plan_encode_failed",
                "Could not encode read-only setup plan.",
                "glove setup plan --help"
            );
        }
        std::printf("%s\n", encoded->c_str());
        return 0;
    }

    std::printf(
        "Read-only managed-session plan (no files were changed)\n"
        "Platform shipping lane: %s\n"
        "Configuration:          %s\n"
        "Session policy:         %s\n"
        "Protected harness root: %s\n"
        "Protected project root: %s\n",
        report.recommended_path.empty() ? "unsupported" : report.recommended_path.c_str(),
        report.config_path.c_str(),
        report.policy_path.c_str(),
        report.protected_harness_root.c_str(),
        report.protected_project_root.c_str()
    );
    for (const auto& template_id : report.runtime_template_ids) {
        std::printf("Runtime template:      %s\n", template_id.c_str());
    }
    for (const auto& detection : report.detections) {
        std::printf(
            "%c %-12s %s\n",
            detection.available ? '+' : '-',
            detection.runtime_id.c_str(),
            detection.available ? detection.resolved_executable.c_str()
                                : detection.diagnostic.c_str()
        );
    }
    std::printf("\nNext:\n");
    for (const auto& next : report.next_actions) {
        std::printf("  %s\n", next.c_str());
    }
    return 0;
}

auto setup_cleanup_command(std::span<char* const> arguments) -> int {
    std::optional<std::filesystem::path> config_path;
    std::string confirmation;
    bool dry_run = false;
    bool yes = false;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--dry-run") {
            dry_run = true;
            ++index;
        } else if (argument == "--yes") {
            yes = true;
            ++index;
        } else if (argument == "--config" || argument == "--confirm-ledger") {
            if (index + 1U >= arguments.size()) {
                print_setup_usage();
                return 2;
            }
            if (argument == "--config") {
                config_path = arguments[index + 1U];
            } else {
                confirmation = arguments[index + 1U];
            }
            index += 2U;
        } else if (argument == "-h" || argument == "--help") {
            print_setup_usage();
            return 0;
        } else {
            print_setup_usage();
            return 2;
        }
    }
    if (dry_run && yes) {
        return print_error(
            "setup_cleanup_conflicting_flags",
            "--dry-run and --yes cannot be combined.",
            "glove setup cleanup --dry-run"
        );
    }
    if (!config_path) {
        auto directories = resolve_directories(current_environment());
        if (!directories) {
            return print_error(
                "setup_cleanup_invalid", directories.error(), "glove setup cleanup --help"
            );
        }
        config_path = default_config_path(*directories);
    }
    if (!config_path->is_absolute()) {
        return print_error(
            "setup_cleanup_invalid",
            "Cleanup configuration path must be absolute.",
            "glove setup cleanup --help"
        );
    }
    auto plan = plan_setup_cleanup(config_path->lexically_normal());
    if (!plan) {
        return print_error(
            "setup_cleanup_preview_failed", plan.error(), "glove setup cleanup --help"
        );
    }
    auto digest = setup_ledger_sha256(plan->ledger);
    if (!digest) {
        return print_error(
            "setup_cleanup_preview_failed", digest.error(), "glove setup cleanup --help"
        );
    }
    std::printf(
        "Setup cleanup preview\nLedger: %s\nLedger SHA-256: %s\n",
        plan->ledger.ledger_path.c_str(),
        digest->c_str()
    );
    for (const auto& item : plan->items) {
        const char* action = !item.resource.owned ? "retain"
                             : item.absent        ? "absent"
                             : item.removable     ? "remove"
                                                  : "blocked";
        std::printf(
            "  %-7s %-22s %s (%s)\n",
            action,
            item.resource.kind.c_str(),
            item.resource.path.c_str(),
            item.reason.c_str()
        );
    }
    std::printf("  remove  setup_ledger           %s\n", plan->ledger.ledger_path.c_str());
    if (plan->blocked()) {
        return print_error(
            "setup_cleanup_blocked",
            "Owned resources contain changed or unmanaged state; nothing was removed.",
            "Stop services, preserve durable data, and run the preview again."
        );
    }
    if (dry_run) {
        std::printf("Dry run: no files were changed.\n");
        return 0;
    }
    if (!yes || confirmation.empty()) {
        return print_error(
            "setup_cleanup_confirmation_required",
            "Cleanup requires the exact ledger digest from this preview.",
            "glove setup cleanup --yes --confirm-ledger " + *digest
        );
    }
    if (auto removed = execute_setup_cleanup(*plan, confirmation); !removed) {
        return print_error(
            "setup_cleanup_failed", removed.error(), "glove setup cleanup --dry-run"
        );
    }
    std::printf("Glove setup-owned resources removed; retained resources were unchanged.\n");
    return 0;
}

auto setup_adopt_command(std::span<char* const> arguments) -> int {
    std::optional<std::filesystem::path> config_path;
    bool dry_run = false;
    bool yes = false;
    for (std::size_t index = 0; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--dry-run") {
            dry_run = true;
            ++index;
        } else if (argument == "--yes") {
            yes = true;
            ++index;
        } else if (argument == "--config" && index + 1U < arguments.size()) {
            config_path = arguments[index + 1U];
            index += 2U;
        } else if (argument == "-h" || argument == "--help") {
            print_setup_usage();
            return 0;
        } else {
            print_setup_usage();
            return 2;
        }
    }
    if (dry_run && yes) {
        return print_error(
            "setup_adopt_conflicting_flags",
            "--dry-run and --yes cannot be combined.",
            "glove setup adopt --dry-run"
        );
    }
    if (!config_path) {
        auto directories = resolve_directories(current_environment());
        if (!directories) {
            return print_error(
                "setup_adopt_invalid", directories.error(), "glove setup adopt --help"
            );
        }
        config_path = default_config_path(*directories);
    }
    if (!config_path->is_absolute()) {
        return print_error(
            "setup_adopt_invalid",
            "Adoption configuration path must be absolute.",
            "glove setup adopt --help"
        );
    }
    auto ledger = plan_setup_adoption(config_path->lexically_normal());
    if (!ledger) {
        return print_error("setup_adopt_invalid", ledger.error(), "glove doctor");
    }
    auto digest = setup_ledger_sha256(*ledger);
    if (!digest) {
        return print_error("setup_adopt_invalid", digest.error(), "glove doctor");
    }
    std::printf(
        "Setup adoption preview\nConfiguration: %s\nLedger: %s\nLedger SHA-256: %s\n",
        ledger->config_path.c_str(),
        ledger->ledger_path.c_str(),
        digest->c_str()
    );
    for (const auto& resource : ledger->resources) {
        std::printf("  retain  %-22s %s\n", resource.kind.c_str(), resource.path.c_str());
    }
    if (dry_run) {
        std::printf("Dry run: no files were changed.\n");
        return 0;
    }
    if (!yes) {
        return print_error(
            "setup_adopt_confirmation_required",
            "Adoption records existing resources as retained and creates no cleanup ownership.",
            "glove setup adopt --config " + ledger->config_path.string() + " --yes"
        );
    }
    if (auto adopted = execute_setup_adoption(*ledger); !adopted) {
        return print_error("setup_adopt_failed", adopted.error(), "glove doctor");
    }
    std::printf("Existing Glove resources adopted as retained; cleanup ownership remains empty.\n");
    return 0;
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
    if (!arguments.empty() && std::string_view{arguments.front()} == "plan") {
        return setup_plan_command(arguments.subspan(1));
    }
    if (!arguments.empty() && std::string_view{arguments.front()} == "policy") {
        return setup_policy_command(arguments.subspan(1));
    }
    if (!arguments.empty() && std::string_view{arguments.front()} == "cleanup") {
        return setup_cleanup_command(arguments.subspan(1));
    }
    if (!arguments.empty() && std::string_view{arguments.front()} == "adopt") {
        return setup_adopt_command(arguments.subspan(1));
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
        } else if (argument == "--persistent") {
            options.persistent_service = true;
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
    if (plan->migrate_runtime_from) {
        std::printf(
            "Runtime migration: %s -> %s (old directory is retained)\n",
            plan->migrate_runtime_from->c_str(),
            plan->service.runtime_directory.c_str()
        );
    }
    std::printf("State:         %s\n", plan->service.audit_key.parent_path().c_str());
    if (plan->service.apple_container) {
        std::printf(
            "Managed guest: %s\n  image=%s\n  closure=%s\n",
            plan->service.apple_container->cli.c_str(),
            plan->service.apple_container->image_digest.c_str(),
            plan->service.apple_container->harness_closure_digest
                ? plan->service.apple_container->harness_closure_digest->c_str()
                : "probe-only"
        );
    }
    std::printf(
        "Service scope: %s\n",
        plan->service.persistent_service
            ? "persistent across logout/reboot (enables Linux user lingering)"
            : "current login session"
    );
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
    std::printf(
        "Glove machine setup completed.\nNext:\n"
        "  glove daemon start --config %s\n"
        "  glove doctor --config %s\n",
        plan->config_path.c_str(),
        plan->config_path.c_str()
    );
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
        auto output = doctor_wire::encode_report(report);
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
            stderr,
            "usage:\n"
            "  glove config <path|show|validate> [--config <absolute-file>]\n"
            "  glove config derive --config <absolute-source> --session-policy <absolute-file>\n"
            "      --output <absolute-file> [--dry-run | --yes]\n"
        );
        return arguments.empty() ? 2 : 0;
    }
    const std::string_view action{arguments.front()};
    if (action == "derive") {
        std::filesystem::path source;
        std::filesystem::path session_policy;
        std::filesystem::path output;
        bool dry_run = false;
        bool yes = false;
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (argument == "--dry-run") {
                dry_run = true;
                ++index;
            } else if (argument == "--yes") {
                yes = true;
                ++index;
            } else if (index + 1U < arguments.size()) {
                if (argument == "--config") {
                    source = arguments[index + 1U];
                } else if (argument == "--session-policy") {
                    session_policy = arguments[index + 1U];
                } else if (argument == "--output") {
                    output = arguments[index + 1U];
                } else {
                    return print_error(
                        "config_derive_argument_invalid",
                        "Unknown config derivation argument.",
                        "glove config --help"
                    );
                }
                index += 2U;
            } else {
                return print_error(
                    "config_derive_argument_invalid",
                    "Config derivation argument is missing a value.",
                    "glove config --help"
                );
            }
        }
        if (source.empty() || session_policy.empty() || output.empty() || !source.is_absolute() ||
            !session_policy.is_absolute() || !output.is_absolute() ||
            source.lexically_normal() != source ||
            session_policy.lexically_normal() != session_policy ||
            output.lexically_normal() != output || source == output || dry_run == yes) {
            return print_error(
                "config_derive_invalid",
                "Derivation requires distinct normalized absolute paths and exactly one of "
                "--dry-run or --yes.",
                "glove config --help"
            );
        }
        auto derived = load_config(source);
        if (!derived) {
            return print_error("config_derive_source_invalid", derived.error(), "glove doctor");
        }
        if (auto valid_policy = validate_session_policy_file(session_policy); !valid_policy) {
            return print_error(
                "config_derive_policy_invalid", valid_policy.error(), "glove policy validate"
            );
        }
        derived->session_policy = session_policy;
        if (auto valid_config = validate(*derived); !valid_config) {
            return print_error(
                "config_derive_result_invalid", valid_config.error(), "glove config --help"
            );
        }
        auto encoded = encode_config(*derived);
        if (!encoded) {
            return print_error(
                "config_derive_encode_failed", encoded.error(), "glove config --help"
            );
        }
        bool changed = false;
        if (!dry_run) {
            if (std::filesystem::exists(output)) {
                auto existing = load_config(output);
                if (!existing || *existing != *derived) {
                    return print_error(
                        "config_derive_output_conflict",
                        "Existing derived config differs; refusing to overwrite.",
                        "Choose a new --output path or restore the reviewed source."
                    );
                }
            } else if (auto written = write_config_exclusive(output, *derived); !written) {
                return print_error(
                    "config_derive_write_failed", written.error(), "glove config --help"
                );
            } else {
                changed = true;
            }
        }
        std::printf(
            "%s configuration: %s\n%s",
            dry_run ? "Would create" : (changed ? "Created" : "Verified"),
            output.c_str(),
            encoded->c_str()
        );
        return 0;
    }
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
            auto encoded = policy_wire::encode(report);
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
            .snapshot_digest = staged->snapshot_digest,
            .adoption_manifest_digest = staged->adoption_manifest_digest,
            .snapshot_logical_bytes = staged->snapshot_logical_bytes,
            .snapshot_entries = staged->snapshot_entries,
            .changed = staged->changed,
            .dry_run = options.dry_run,
        };
        report.read_only_paths.reserve(staged->read_only_paths.size());
        for (const auto& path : staged->read_only_paths) {
            report.read_only_paths.push_back(path.string());
        }
        if (json) {
            auto encoded = policy_wire::encode(report);
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
        if (!staged->adoption_manifest_digest.empty()) {
            std::printf(
                "Harness adoption manifest: %s\n", staged->adoption_manifest_digest.c_str()
            );
        }
        if (!staged->snapshot_digest.empty()) {
            std::printf(
                "Protected snapshot digest:  %s\n"
                "Snapshot logical size:      %llu bytes across %llu entries\n",
                staged->snapshot_digest.c_str(),
                static_cast<unsigned long long>(staged->snapshot_logical_bytes),
                static_cast<unsigned long long>(staged->snapshot_entries)
            );
        }
        std::printf(
            "Next:\n"
            "  Use --json to pass this exact launch closure to policy generation.\n"
            "  glove policy detect --search-path %s --json\n",
            staged->protected_entry_point.parent_path().c_str()
        );
        return 0;
    }
    if (action == "adopt-pi") {
        pi_adoption_manifest_options options;
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
            } else if (index + 1U < arguments.size()) {
                const std::filesystem::path value{arguments[index + 1U]};
                if (argument == "--settings") {
                    options.settings_path = value;
                } else if (argument == "--package-store") {
                    options.package_store_root = value;
                } else if (argument == "--directory") {
                    options.protected_directory = value;
                } else {
                    print_policy_usage();
                    return 2;
                }
                index += 2U;
            } else {
                print_policy_usage();
                return 2;
            }
        }
        if (yes && options.dry_run) {
            return print_error(
                "policy_conflicting_flags",
                "--dry-run and --yes cannot be combined.",
                "glove policy adopt-pi --help"
            );
        }
        if (options.settings_path.empty() || options.package_store_root.empty() ||
            options.protected_directory.empty()) {
            print_policy_usage();
            return 2;
        }
        if (!yes && !options.dry_run) {
            return print_error(
                "policy_confirmation_required",
                "Pi adoption snapshots selected package closures on this machine.",
                "glove policy adopt-pi --settings <absolute-file> --package-store "
                "<absolute-directory> --directory <absolute-directory> --dry-run\n"
                "  glove policy adopt-pi --settings <absolute-file> --package-store "
                "<absolute-directory> --directory <absolute-directory> --yes"
            );
        }
        auto adopted = generate_pi_adoption_manifest(options);
        if (!adopted) {
            return print_error(
                "policy_pi_adoption_failed", adopted.error(), "glove policy adopt-pi --help"
            );
        }
        policy_wire::pi_adoption_report report{
            .runtime_id = "pi",
            .manifest_digest = adopted->manifest_digest,
            .snapshot_digest = adopted->snapshot_digest,
            .package_ids = adopted->package_ids,
            .changed = adopted->changed,
            .dry_run = options.dry_run,
        };
        if (json) {
            auto encoded = policy_wire::encode(report);
            if (!encoded) {
                return print_error(
                    "policy_encode_failed",
                    "Could not encode Pi adoption report.",
                    "glove policy adopt-pi --help"
                );
            }
            std::printf("%s\n", encoded->c_str());
            return 0;
        }
        std::printf(
            "%s Pi adoption manifest: %s\nSnapshot digest: %s\n",
            options.dry_run ? "Planned" : (adopted->changed ? "Created" : "Verified"),
            adopted->manifest_digest.c_str(),
            adopted->snapshot_digest.c_str()
        );
        for (const auto& package_id : adopted->package_ids) {
            std::printf("Package closure member: %s\n", package_id.c_str());
        }
        return 0;
    }
    if (action == "generate") {
        runtime_policy_generation_options options;
#if defined(__linux__)
        options.backend = supervisor::sandbox_backend::linux_production;
#else
        options.backend = supervisor::sandbox_backend::apple_container;
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
                } else if (value == "apple_container") {
                    options.backend = supervisor::sandbox_backend::apple_container;
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
            auto encoded = policy_wire::encode(report);
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

auto workspace_command(std::span<char* const> arguments) -> int {
    if (arguments.empty() || std::string_view{arguments.front()} == "--help" ||
        std::string_view{arguments.front()} == "-h") {
        std::fprintf(
            stderr,
            "usage:\n"
            "  glove workspace discover <path> --root <id> [--config <absolute-file>]\n"
            "  glove workspace register <path> [glove init options]\n"
            "  glove workspace list [--config <absolute-file>] [--json]\n"
            "  glove workspace start --session <id> --controller-digest <sha256>\n"
            "      --plan-json <canonical-json> --request-id <id> [--config <absolute-file>]\n"
            "  glove workspace resume --session <id> [--config <absolute-file>]\n"
        );
        return arguments.empty() ? 2 : 0;
    }
    const std::string_view action{arguments.front()};
    if (action == "register") {
        return init_command(arguments.subspan(1));
    }
    if (action == "discover") {
        if (arguments.size() < 4U || std::string_view{arguments[2]} != "--root") {
            return print_error(
                "workspace_discover_usage",
                "Discovery requires one explicit path and a protected-root identifier.",
                "glove workspace discover <path> --root <id>"
            );
        }
        std::error_code error;
        const auto path = std::filesystem::canonical(arguments[1], error);
        if (error || !std::filesystem::is_directory(path, error)) {
            return print_error(
                "workspace_discover_path_invalid",
                "Workspace path must resolve to an existing directory.",
                "glove workspace discover <existing-directory> --root <id>"
            );
        }
        const std::string root_id{arguments[3]};
        if (root_id.empty() || root_id.size() > 128U || root_id.front() == '-' ||
            root_id.front() == '.') {
            return print_error(
                "workspace_discover_root_invalid",
                "Protected-root identifier is invalid.",
                "glove workspace discover <path> --root <configured-root-id>"
            );
        }
        // Discovery deliberately scans only the caller's one explicit path.
        // Containment and durable registration remain enforced by `register`.
        std::printf(
            "Workspace candidate: %s\nProtected root:      %s\nNext:\n"
            "  glove workspace register %s --root %s\n",
            path.c_str(),
            root_id.c_str(),
            path.c_str(),
            root_id.c_str()
        );
        return 0;
    }
    if (action == "start") {
        workspace_session_create_request request;
        std::optional<std::filesystem::path> config_path;
        for (std::size_t index = 1; index < arguments.size();) {
            const std::string_view argument{arguments[index]};
            if (index + 1U >= arguments.size()) {
                return print_error(
                    "workspace_start_usage",
                    "Workspace start arguments are invalid.",
                    "glove workspace start --help"
                );
            }
            const std::string value{arguments[index + 1U]};
            if (argument == "--session") {
                request.session_id = value;
            } else if (argument == "--controller-digest") {
                request.controller_plan_digest = value;
            } else if (argument == "--plan-json") {
                request.canonical_plan_json = value;
            } else if (argument == "--request-id") {
                request.idempotency_key = value;
            } else if (argument == "--config") {
                config_path = value;
            } else {
                return print_error(
                    "workspace_start_usage",
                    "Workspace start arguments are invalid.",
                    "glove workspace start --help"
                );
            }
            index += 2U;
        }
        if (!config_path) {
            auto resolved = default_path();
            if (!resolved) {
                return print_error(
                    "workspace_environment_invalid", resolved.error(), "glove setup --dry-run"
                );
            }
            config_path = *resolved;
        }
        auto configured = load_config(*config_path);
        if (!configured) {
            return print_error("workspace_config_invalid", configured.error(), "glove doctor");
        }
        auto created = create_workspace_session(*configured, request);
        if (!created) {
            return print_error("workspace_start_failed", created.error(), "glove daemon status");
        }
        std::printf(
            "Session recorded: %s\nState:            %s\nPlan digest:      %s\n"
            "Launch remains controller-authorized; this command cannot start a process.\n",
            created->session_id.c_str(),
            created->state.c_str(),
            created->plan_content_digest.c_str()
        );
        return 0;
    }
    if (action == "resume") {
        if ((arguments.size() != 3U && arguments.size() != 5U) ||
            std::string_view{arguments[1]} != "--session" ||
            (arguments.size() == 5U && std::string_view{arguments[3]} != "--config")) {
            return print_error(
                "workspace_resume_usage",
                "Resume requires an exact session identifier.",
                "glove workspace resume --session <id> [--config <absolute-file>]"
            );
        }
        std::optional<std::filesystem::path> config_path;
        if (arguments.size() == 5U) {
            config_path = arguments[4];
        } else {
            auto resolved = default_path();
            if (!resolved) {
                return print_error(
                    "workspace_environment_invalid", resolved.error(), "glove setup --dry-run"
                );
            }
            config_path = *resolved;
        }
        auto configured = load_config(*config_path);
        if (!configured) {
            return print_error("workspace_config_invalid", configured.error(), "glove doctor");
        }
        auto status = workspace_session_status_for(*configured, arguments[2]);
        if (!status) {
            return print_error("workspace_resume_failed", status.error(), "glove daemon status");
        }
        if (status->state != "starting" && status->state != "running" &&
            status->state != "stopping") {
            return print_error(
                "workspace_resume_ineligible",
                "Only an existing starting, running, or stopping managed session is resumable.",
                "glove workspace start --help"
            );
        }
        std::printf(
            "Session recovery candidate: %s\nState:                      %s\n"
            "The daemon owns reconciliation; no new launch authorization was minted.\n",
            status->session_id.c_str(),
            status->state.c_str()
        );
        return 0;
    }
    if (action != "list") {
        return print_error(
            "workspace_action_invalid", "Unknown workspace action.", "glove workspace --help"
        );
    }
    std::optional<std::filesystem::path> config_path;
    bool json = false;
    for (std::size_t index = 1; index < arguments.size();) {
        const std::string_view argument{arguments[index]};
        if (argument == "--json") {
            json = true;
            ++index;
        } else if (argument == "--config" && index + 1U < arguments.size()) {
            config_path = arguments[index + 1U];
            index += 2U;
        } else {
            return print_error(
                "workspace_list_usage",
                "Workspace list arguments are invalid.",
                "glove workspace list [--config <absolute-file>] [--json]"
            );
        }
    }
    if (!config_path) {
        auto resolved = default_path();
        if (!resolved) {
            return print_error(
                "workspace_environment_invalid", resolved.error(), "glove setup --dry-run"
            );
        }
        config_path = *resolved;
    }
    auto configured = load_config(*config_path);
    if (!configured) {
        return print_error("workspace_config_invalid", configured.error(), "glove doctor");
    }
    auto workspaces = list_workspace_exposures(*configured);
    if (!workspaces) {
        return print_error("workspace_list_failed", workspaces.error(), "glove daemon status");
    }
    if (json) {
        auto encoded = glz::write_json(*workspaces);
        if (!encoded) {
            return print_error(
                "workspace_list_encode_failed",
                "Could not encode workspace inventory.",
                "glove workspace list"
            );
        }
        std::printf("%s\n", encoded->c_str());
        return 0;
    }
    for (const auto& workspace : *workspaces) {
        std::printf(
            "%s generation=%llu state=%s label=%s expires_at_ms=%llu scope_digest=%s\n",
            workspace.exposure_id.c_str(),
            static_cast<unsigned long long>(workspace.generation),
            workspace.state.c_str(),
            workspace.display_label.c_str(),
            static_cast<unsigned long long>(workspace.expires_at_ms),
            workspace.scope_digest.c_str()
        );
    }
    return 0;
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
