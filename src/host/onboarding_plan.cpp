#include "glove/host/onboarding_plan.hpp"

#include <system_error>

namespace glove::host {

namespace {

auto derived_policy_path(const std::filesystem::path& config_path) -> std::filesystem::path {
    return config_path.parent_path() / "session-policy.json";
}

auto derived_harness_root(const std::filesystem::path& config_path) -> std::filesystem::path {
    return config_path.parent_path() / "harnesses";
}

} // namespace

auto plan_onboarding(const onboarding_plan_options& options, const environment& values)
    -> result<onboarding_plan> {
    if (options.protected_root.empty()) {
        return std::unexpected(std::string{"guided setup requires a protected project root"});
    }
    if (options.executable_search_paths.empty()) {
        return std::unexpected(
            std::string{"guided setup requires at least one explicit harness search directory"}
        );
    }

    auto directories = resolve_directories(values);
    if (!directories) {
        return std::unexpected(directories.error());
    }
    std::error_code error;
    const auto protected_root = std::filesystem::canonical(options.protected_root, error);
    if (error || !std::filesystem::is_directory(protected_root)) {
        return std::unexpected(std::string{"protected root must be an existing directory"});
    }
    const auto config_path = std::filesystem::weakly_canonical(
        options.config_path.value_or(default_config_path(*directories)), error
    );
    if (error || !config_path.is_absolute() || config_path.filename().empty()) {
        return std::unexpected(std::string{"guided setup configuration path is invalid"});
    }
    const auto policy_path = derived_policy_path(config_path);
    const auto harness_root = derived_harness_root(config_path);

    session_policy_prepare_options policy_options{
        .executable_search_paths = options.executable_search_paths,
        .protected_harness_root = harness_root,
        .workspace_root = protected_root,
        .policy_path = policy_path,
        .backend = options.backend,
        .egress_policies = {},
        .secret_mounts = {},
        .selected_runtime_ids = options.selected_runtime_ids,
        .pi_adoption = options.pi_adoption,
        .hostile_content_analysis = options.hostile_content_analysis,
        .dry_run = true,
    };
    auto policy = prepare_session_policy(policy_options);
    if (!policy) {
        return std::unexpected(policy.error());
    }

    std::vector<std::string> runtime_template_ids;
    runtime_template_ids.reserve(policy->runtimes.size());
    for (const auto& runtime : policy->runtimes) {
        runtime_template_ids.push_back(
            runtime.runtime_id + (options.hostile_content_analysis ? "-hostile-analysis" : "-safe")
        );
    }
    setup_options setup_options{
        .config_path = config_path,
        .protected_root = protected_root,
        .session_policy = policy_path,
        .root_id = "projects",
        .runtime_template_ids = std::move(runtime_template_ids),
        .persistent_service = std::nullopt,
        .dry_run = true,
    };
    auto setup = plan_setup(setup_options, values);
    if (!setup) {
        return std::unexpected(setup.error());
    }

    return onboarding_plan{
        .setup = std::move(*setup),
        .protected_harness_root = std::move(harness_root),
        .session_policy = std::move(*policy),
    };
}

} // namespace glove::host
