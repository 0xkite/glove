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

    // An explicit config path must not assume the separate XDG config child
    // used for path-exposure policy already exists.
    const auto isolated_config_home = temporary.root() / "isolated-config";
    const auto isolated_state_home = temporary.root() / "isolated-state";
    const auto isolated_data_home = temporary.root() / "isolated-data";
    const auto isolated_runtime_home = temporary.root() / "isolated-runtime";
    const auto explicit_config_parent = temporary.root() / "explicit-config";
    for (const auto& directory : {
             isolated_config_home,
             isolated_state_home,
             isolated_data_home,
             isolated_runtime_home,
             explicit_config_parent,
         }) {
        REQUIRE(std::filesystem::create_directory(directory));
        REQUIRE(::chmod(directory.c_str(), 0700) == 0);
    }
    auto isolated_values = values;
    isolated_values.xdg_config_home = isolated_config_home.string();
    isolated_values.xdg_state_home = isolated_state_home.string();
    isolated_values.xdg_data_home = isolated_data_home.string();
    isolated_values.xdg_runtime_dir = isolated_runtime_home.string();
    setup_options explicit_config_options{};
    explicit_config_options.protected_root = project_root;
    explicit_config_options.config_path = explicit_config_parent / "glove.json";
    auto explicit_config_plan = plan_setup(explicit_config_options, isolated_values);
    REQUIRE(explicit_config_plan.has_value());
    REQUIRE(execute_setup(*explicit_config_plan).has_value());
    REQUIRE(
        std::filesystem::is_regular_file(
            isolated_config_home / "glove" / "path-exposure-policy.json"
        )
    );

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

    const auto proxy_path = temporary.root() / ".config/glove/local-services.json";
    auto proxy_config = managed_plan->service;
    proxy_config.apple_container.reset();
    proxy_config.local_service_proxy = local_service_proxy_config{
        .io_timeout_ms = 2'500,
        .max_concurrency = 3,
        .guest_channel_adapter =
            guest_channel_adapter_config{
                .adapter_id = "sage-observation",
                .channel_schema_id = "sage.glove-observation.v1",
            },
        .endpoints = {
            local_service_proxy_endpoint{
                .alias = "sage-observe",
                .socket_path = temporary.root() / "services/sage.sock",
                .runtime_ids = {"codex", "pi"},
            },
            local_service_proxy_endpoint{
                .alias = "tooling.v1",
                .socket_path = temporary.root() / "services/tooling.sock",
                .runtime_ids = {"pi"},
            },
        },
    };
    REQUIRE(validate(proxy_config).has_value());
    REQUIRE(write_config_exclusive(proxy_path, proxy_config).has_value());
    REQUIRE(load_config(proxy_path) == proxy_config);
    auto generic_proxy_config = proxy_config;
    generic_proxy_config.local_service_proxy->guest_channel_adapter.reset();
    REQUIRE(validate(generic_proxy_config).has_value());

    const auto local_service_audit =
        proxy_config.receipt_journal.parent_path() / local_service_audit_filename;
    const auto rejects_local_service_audit_collision = [&](config candidate) {
        auto result = validate(candidate);
        return !result.has_value() && result.error() == "configuration paths must be distinct" &&
               result.error().find(temporary.root().string()) == std::string::npos;
    };
    auto audit_collision = proxy_config;
    audit_collision.receipt_journal = local_service_audit;
    REQUIRE(rejects_local_service_audit_collision(std::move(audit_collision)));
    audit_collision = proxy_config;
    audit_collision.audit_key = local_service_audit;
    REQUIRE(rejects_local_service_audit_collision(std::move(audit_collision)));
    audit_collision = proxy_config;
    audit_collision.session_store = local_service_audit;
    REQUIRE(rejects_local_service_audit_collision(std::move(audit_collision)));

    // The derived control delivery journal (control-audit.jsonl next to the
    // receipt journal) is always registered in the configured-path set: no
    // configured path may alias it.
    const auto control_audit_path =
        proxy_config.receipt_journal.parent_path() / control_audit_filename;
    auto control_collision = proxy_config;
    control_collision.receipt_journal = control_audit_path;
    REQUIRE(rejects_local_service_audit_collision(std::move(control_collision)));
    control_collision = proxy_config;
    control_collision.audit_key = control_audit_path;
    REQUIRE(rejects_local_service_audit_collision(std::move(control_collision)));
    control_collision = proxy_config;
    control_collision.session_store = control_audit_path;
    REQUIRE(rejects_local_service_audit_collision(std::move(control_collision)));
    audit_collision = proxy_config;
    audit_collision.local_service_proxy->endpoints.front().socket_path = local_service_audit;
    auto endpoint_audit_collision = validate(audit_collision);
    REQUIRE(!endpoint_audit_collision.has_value());
    REQUIRE(endpoint_audit_collision.error().find(temporary.root().string()) == std::string::npos);

    auto proxy_json = encode_config(proxy_config);
    REQUIRE(proxy_json.has_value());
    const auto endpoints_marker = proxy_json->find("\"endpoints\":[");
    REQUIRE(endpoints_marker != std::string::npos);
    const auto write_rejected_shape = [&](std::string name, std::string field) {
        auto rejected = *proxy_json;
        rejected.insert(endpoints_marker + std::string_view{"\"endpoints\":["}.size() + 1U, field);
        const auto path = temporary.root() / ".config/glove" / name;
        std::ofstream output{path, std::ios::binary};
        output << rejected;
        output.close();
        if (!output.good() || ::chmod(path.c_str(), 0600) != 0) {
            return false;
        }
        return !load_config(path).has_value();
    };
    REQUIRE(write_rejected_shape("proxy-tcp.json", "\"tcp_port\":443,"));
    REQUIRE(
        write_rejected_shape("proxy-guest-target.json", "\"guest_target\":\"/run/host.sock\",")
    );
    REQUIRE(write_rejected_shape("proxy-token.json", "\"token\":\"secret\","));

    auto invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->io_timeout_ms = 0;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->max_concurrency = 0;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->max_concurrency = 17;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.clear();
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    const auto repeated_endpoint = invalid_proxy.local_service_proxy->endpoints.front();
    invalid_proxy.local_service_proxy->endpoints.resize(17U, repeated_endpoint);
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().alias = "../escape";
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.back().alias = "sage-observe";
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.back().socket_path =
        invalid_proxy.local_service_proxy->endpoints.front().socket_path;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().socket_path = "relative.sock";
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().runtime_ids.clear();
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().runtime_ids = {"pi", "codex"};
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().runtime_ids = {"pi", "pi"};
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    std::ranges::swap(
        invalid_proxy.local_service_proxy->endpoints.front(),
        invalid_proxy.local_service_proxy->endpoints.back()
    );
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().alias = "non-ascii-\xC3\xA9";
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().alias = std::string{"nul\0alias", 9U};
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    auto nul_path = invalid_proxy.local_service_proxy->endpoints.front().socket_path.string();
    nul_path.append("\0hidden", 7U);
    invalid_proxy.local_service_proxy->endpoints.front().socket_path = nul_path;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->guest_channel_adapter->adapter_id =
        std::string{"sage\0hidden", 11U};
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().socket_path =
        *invalid_proxy.materialization_root / "service.sock";
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.local_service_proxy->endpoints.front().socket_path =
        *invalid_proxy.materialization_root;
    REQUIRE(!validate(invalid_proxy).has_value());
    invalid_proxy = proxy_config;
    invalid_proxy.remote_backend = remote_backend_config{};
    REQUIRE(!validate(invalid_proxy).has_value());

    const auto malformed_path = temporary.root() / ".config/glove/malformed-secret.json";
    const std::string secret_path = "/operator/private/endpoint.sock";
    {
        std::ofstream malformed{malformed_path, std::ios::binary};
        malformed << "{\"local_service_proxy\":{\"endpoint\":\"" << secret_path;
    }
    REQUIRE(::chmod(malformed_path.c_str(), 0600) == 0);
    auto malformed = load_config(malformed_path);
    REQUIRE(!malformed.has_value());
    REQUIRE(malformed.error() == "configuration JSON is invalid");
    REQUIRE(malformed.error().find(secret_path) == std::string::npos);

#if defined(__linux__)
    temporary_directory preservation_temporary;
    REQUIRE(!preservation_temporary.root().empty());
    environment preservation_values{};
    preservation_values.home = preservation_temporary.root().string();
    const auto preservation_policy = preservation_temporary.root() / "session-policy.json";
    setup_options preservation_options{};
    preservation_options.session_policy = preservation_policy;
    auto preservation_plan = plan_setup(preservation_options, preservation_values);
    REQUIRE(preservation_plan.has_value());
    preservation_plan->service.local_service_proxy = proxy_config.local_service_proxy;
    preservation_plan->service.local_service_proxy->endpoints.front().socket_path =
        preservation_temporary.root() / "services/sage.sock";
    preservation_plan->service.local_service_proxy->endpoints.back().socket_path =
        preservation_temporary.root() / "services/tooling.sock";
    REQUIRE(std::filesystem::create_directories(preservation_plan->config_path.parent_path()));
    REQUIRE(::chmod(preservation_plan->config_path.parent_path().c_str(), 0700) == 0);
    REQUIRE(write_config_exclusive(preservation_plan->config_path, preservation_plan->service)
                .has_value());
    auto replanned = plan_setup(preservation_options, preservation_values);
    REQUIRE(replanned.has_value());
    REQUIRE(
        replanned->service.local_service_proxy == preservation_plan->service.local_service_proxy
    );
#endif

    const auto apple_path = temporary.root() / ".config/glove/apple.json";
    auto apple = managed_plan->service;
    apple.apple_container = apple_container_config{
        .cli = "/usr/local/bin/container",
        .image = "ghcr.io/sage-protocol/glove-agent-runtime@sha256:" + std::string(64U, 'a'),
        .image_digest = "sha256:" + std::string(64U, 'a'),
        .harness_closure_digest = "sha256:" + std::string(64U, 'b'),
        .sage_guest = sage_guest_config{
            .binary_digest = "sha256:" + std::string(64U, 'c'),
            .source_revision = std::string(40U, 'd'),
            .policy_schema_version = 1,
            .library_projection_schema = "sage_bundle_v1",
        },
    };
    REQUIRE(write_config_exclusive(apple_path, apple).has_value());
    REQUIRE(load_config(apple_path) == apple);
    auto invalid_apple = apple;
    invalid_apple.apple_container->image_digest = "sha256:latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.apple_container->image = "ghcr.io/sage-protocol/glove-agent-runtime:latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.apple_container->harness_closure_digest = "sha256:latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.apple_container->sage_guest->library_projection_schema = "latest";
    REQUIRE(!validate(invalid_apple).has_value());
    invalid_apple = apple;
    invalid_apple.apple_container->harness_closure_digest.reset();
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
