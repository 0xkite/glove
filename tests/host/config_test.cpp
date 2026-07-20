#include "glove/host/config.hpp"
#include "glove/host/doctor.hpp"
#include "glove/host/setup.hpp"
#include "glove/supervisor/path_exposure.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
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
    const environment values{.home = temporary.root().string()};
    auto directories = resolve_directories(values);
    REQUIRE(directories.has_value());
    REQUIRE(directories->config == temporary.root() / ".config/glove");
    REQUIRE(directories->state == temporary.root() / ".local/state/glove");
    REQUIRE(directories->runtime == temporary.root() / ".local/state/glove/runtime");

    const auto session_policy = temporary.root() / "session-policy.json";
    auto managed_plan = plan_setup(
        setup_options{
            .session_policy = session_policy,
            .dry_run = true,
        },
        values
    );
    REQUIRE(managed_plan.has_value());
    REQUIRE(managed_plan->service.session_policy == session_policy);
    REQUIRE(managed_plan->service.session_store == directories->state / "sessions.journal");
    REQUIRE(managed_plan->service.materialization_root == directories->state / "materializations");
    REQUIRE(managed_plan->service.library_bundle_root == directories->data / "library-bundles");

    const auto project_root = temporary.root() / "projects\"quoted";
    const auto project = project_root / "sage-protocol";
    REQUIRE(std::filesystem::create_directories(project));
    setup_options options{
        .protected_root = project_root,
        .dry_run = true,
    };
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
    REQUIRE(std::filesystem::remove(plan->config_path));
    REQUIRE(execute_setup(*plan).has_value());
    REQUIRE(load_config(plan->config_path).has_value());

    const auto report = diagnose(plan->config_path);
    REQUIRE(report.healthy());
    REQUIRE(report.checks.size() >= 5U);

    REQUIRE(::chmod(plan->config_path.c_str(), 0644) == 0);
    REQUIRE(!load_config(plan->config_path).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
