#include "glove/host/config.hpp"
#include "glove/host/doctor.hpp"
#include "glove/host/setup.hpp"
#include "glove/supervisor/path_exposure.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-host-config-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto run() -> int {
    using namespace glove::host;
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    environment values{};
    values.home = temporary.root().string();
    values.xdg_runtime_dir = (temporary.root() / "run/user/501").string();
    auto directories = resolve_directories(values);
    REQUIRE(directories.has_value());
    REQUIRE(directories->config == temporary.root() / ".config/glove");
    REQUIRE(directories->state == temporary.root() / ".local/state/glove");
    REQUIRE(directories->runtime == temporary.root() / ".local/state/glove/runtime");

    const auto session_policy = temporary.root() / "session-policy.json";
    setup_options managed_options{};
    managed_options.session_policy = session_policy;
    managed_options.dry_run = true;
    auto managed_plan = plan_setup(managed_options, values);
    REQUIRE(managed_plan.has_value());
    REQUIRE(managed_plan->service.session_policy == session_policy);
    REQUIRE(managed_plan->service.session_store == directories->state / "sessions.journal");
    REQUIRE(managed_plan->service.materialization_root == directories->state / "materializations");
    REQUIRE(managed_plan->service.library_bundle_root == directories->data / "library-bundles");

    const auto project_root = temporary.root() / "projects\"quoted";
    const auto project = project_root / "sage-protocol";
    REQUIRE(std::filesystem::create_directories(project));
    setup_options options{};
    options.protected_root = project_root;
    options.dry_run = true;
    auto dry_run = plan_setup(options, values);
    REQUIRE(dry_run.has_value());
    REQUIRE(execute_setup(*dry_run).has_value());
    REQUIRE(!std::filesystem::exists(dry_run->config_path));

    options.dry_run = false;
    auto plan = plan_setup(options, values);
    REQUIRE(plan.has_value());
    REQUIRE(execute_setup(*plan).has_value());
    auto loaded = load_config(plan->config_path);
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->runtime_directory == directories->runtime);
    REQUIRE(loaded->path_exposure_policy.has_value());
    auto registry = glove::supervisor::path_exposure_registry::load(
        *loaded->path_exposure_policy, *loaded->path_exposure_journal, 1024U * 1024U
    );
    REQUIRE(registry.has_value());
    REQUIRE(execute_setup(*plan).has_value());
    const auto legacy_runtime = temporary.root() / "run/user/501/glove";
    REQUIRE(std::filesystem::create_directories(legacy_runtime));
    REQUIRE(::chmod(legacy_runtime.c_str(), 0700) == 0);
    REQUIRE(std::filesystem::remove(plan->config_path));
    auto legacy_config = *loaded;
    legacy_config.runtime_directory = legacy_runtime;
    REQUIRE(write_config_exclusive(plan->config_path, legacy_config).has_value());
    auto migration = plan_setup(options, values);
    REQUIRE(migration.has_value());
    REQUIRE(migration->migrate_runtime_from == legacy_runtime);
    REQUIRE(execute_setup(*migration).has_value());
    auto migrated = load_config(plan->config_path);
    REQUIRE(migrated.has_value());
    REQUIRE(migrated->runtime_directory == directories->runtime);
    REQUIRE(std::filesystem::exists(legacy_runtime));
#if defined(__linux__)
    REQUIRE(std::filesystem::remove(plan->config_path));
    auto ssh_legacy_config = *loaded;
    ssh_legacy_config.runtime_directory =
        std::filesystem::path{"/run/user"} / std::to_string(::geteuid()) / "glove";
    REQUIRE(write_config_exclusive(plan->config_path, ssh_legacy_config).has_value());
    auto ssh_values = values;
    ssh_values.xdg_runtime_dir.reset();
    auto ssh_migration = plan_setup(options, ssh_values);
    REQUIRE(ssh_migration.has_value());
    REQUIRE(ssh_migration->migrate_runtime_from == ssh_legacy_config.runtime_directory);
#endif
    REQUIRE(std::filesystem::remove(plan->config_path));
    REQUIRE(execute_setup(*plan).has_value());
    REQUIRE(load_config(plan->config_path).has_value());
    const auto ledger_path = setup_ledger_path(plan->service);
    auto ledger = load_setup_ledger(ledger_path);
    REQUIRE(ledger.has_value());
    REQUIRE(ledger->config_path == plan->config_path);
    REQUIRE(!ledger->resources.empty());
    REQUIRE(execute_setup(*plan).has_value());
    REQUIRE(load_setup_ledger(ledger_path) == ledger);

    const auto report = diagnose(plan->config_path);
    REQUIRE(report.healthy());
    REQUIRE(report.checks.size() >= 5U);

    const auto derived_path = temporary.root() / ".config/glove/derived.json";
    auto derived = *loaded;
    derived.session_policy = session_policy;
    REQUIRE(write_config_exclusive(derived_path, derived).has_value());
    auto loaded_derived = load_config(derived_path);
    REQUIRE(loaded_derived.has_value());
    REQUIRE(*loaded_derived == derived);
    REQUIRE(!write_config_exclusive(derived_path, derived).has_value());

    const auto apple_path = temporary.root() / ".config/glove/apple.json";
    auto apple = managed_plan->service;
    apple.apple_container = apple_container_config{
        .cli = "/usr/local/bin/container",
        .image = "ghcr.io/sage-protocol/glove-agent-runtime:0.0.1",
        .image_digest = "sha256:" + std::string(64U, 'a'),
        .harness_closure_digest = "sha256:" + std::string(64U, 'b'),
    };
    REQUIRE(write_config_exclusive(apple_path, apple).has_value());
    REQUIRE(load_config(apple_path) == apple);
    auto invalid_apple = apple;
    invalid_apple.apple_container->image_digest = "sha256:latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.apple_container->harness_closure_digest = "sha256:latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.materialization_root.reset();
    REQUIRE(!validate(invalid_apple).has_value());

    REQUIRE(::chmod(plan->config_path.c_str(), 0644) == 0);
    REQUIRE(!load_config(plan->config_path).has_value());

    temporary_directory cleanup_temporary;
    REQUIRE(!cleanup_temporary.root().empty());
    environment cleanup_values{};
    cleanup_values.home = cleanup_temporary.root().string();
    auto cleanup_setup = plan_setup(setup_options{}, cleanup_values);
    REQUIRE(cleanup_setup.has_value());
    REQUIRE(execute_setup(*cleanup_setup).has_value());
    auto cleanup_preview = plan_setup_cleanup(cleanup_setup->config_path);
    REQUIRE(cleanup_preview.has_value());
    REQUIRE(!cleanup_preview->blocked());
    auto cleanup_digest = setup_ledger_sha256(cleanup_preview->ledger);
    REQUIRE(cleanup_digest.has_value());
    REQUIRE(!execute_setup_cleanup(*cleanup_preview, std::string(64U, '0')).has_value());
    REQUIRE(std::filesystem::exists(cleanup_setup->config_path));
    REQUIRE(execute_setup_cleanup(*cleanup_preview, *cleanup_digest).has_value());
    REQUIRE(!std::filesystem::exists(cleanup_setup->config_path));
    REQUIRE(!std::filesystem::exists(cleanup_preview->ledger.ledger_path));

    temporary_directory adoption_temporary;
    REQUIRE(!adoption_temporary.root().empty());
    environment adoption_values{};
    adoption_values.home = adoption_temporary.root().string();
    auto adoption_setup = plan_setup(setup_options{}, adoption_values);
    REQUIRE(adoption_setup.has_value());
    REQUIRE(execute_setup(*adoption_setup).has_value());
    REQUIRE(std::filesystem::remove(setup_ledger_path(adoption_setup->service)));
    auto adoption = plan_setup_adoption(adoption_setup->config_path);
    REQUIRE(adoption.has_value());
    REQUIRE(std::ranges::none_of(adoption->resources, [](const auto& resource) {
        return resource.owned;
    }));
    REQUIRE(execute_setup_adoption(*adoption).has_value());
    auto adopted = load_setup_ledger(adoption->ledger_path);
    REQUIRE(adopted == adoption);
    auto adopted_cleanup = plan_setup_cleanup(adoption_setup->config_path);
    REQUIRE(adopted_cleanup.has_value());
    REQUIRE(!adopted_cleanup->blocked());
    REQUIRE(std::ranges::all_of(adopted_cleanup->items, [](const auto& item) {
        return !item.resource.owned && !item.removable;
    }));

    temporary_directory changed_temporary;
    REQUIRE(!changed_temporary.root().empty());
    environment changed_values{};
    changed_values.home = changed_temporary.root().string();
    auto changed_setup = plan_setup(setup_options{}, changed_values);
    REQUIRE(changed_setup.has_value());
    REQUIRE(execute_setup(*changed_setup).has_value());
    {
        std::ofstream changed{changed_setup->config_path, std::ios::app};
        changed << ' ';
    }
    auto changed_preview = plan_setup_cleanup(changed_setup->config_path);
    REQUIRE(changed_preview.has_value());
    REQUIRE(changed_preview->blocked());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
