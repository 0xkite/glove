#include "glove/host/onboarding_plan.hpp"

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
        std::string pattern = "/tmp/glove-onboarding-plan-test-XXXXXX";
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

auto write_owner_file(const std::filesystem::path& path, std::string_view contents, mode_t mode)
    -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto run() -> int {
    using namespace glove::host;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto project_root = temporary.root() / "project";
    const auto harness_bin = temporary.root() / "harness-bin";
    REQUIRE(std::filesystem::create_directory(project_root));
    REQUIRE(std::filesystem::create_directory(harness_bin));
    REQUIRE(::chmod(harness_bin.c_str(), 0700) == 0);
    REQUIRE(write_owner_file(harness_bin / "codex", "#!/bin/sh\nexit 0\n", 0700));

    environment values{
        .home = temporary.root().string(),
        .xdg_config_home = std::nullopt,
        .xdg_state_home = std::nullopt,
        .xdg_data_home = std::nullopt,
        .xdg_cache_home = std::nullopt,
        .xdg_runtime_dir = std::nullopt,
        .temporary_directory = std::nullopt,
    };
    onboarding_plan_options options{
        .config_path = std::nullopt,
        .protected_root = project_root,
        .executable_search_paths = {harness_bin},
        .selected_runtime_ids = {"codex"},
        .pi_adoption = std::nullopt,
        .backend = glove::supervisor::sandbox_backend::linux_production,
        .hostile_content_analysis = false,
    };
    auto planned = plan_onboarding(options, values);
    REQUIRE(planned.has_value());
    REQUIRE(planned->setup.dry_run);
    REQUIRE(planned->session_policy.dry_run);
    REQUIRE(planned->setup.config_path.filename() == "config.json");
    REQUIRE(
        planned->session_policy.policy_path ==
        planned->setup.config_path.parent_path() / "session-policy.json"
    );
    REQUIRE(
        planned->protected_harness_root == planned->setup.config_path.parent_path() / "harnesses"
    );
    REQUIRE(planned->session_policy.runtimes.size() == 1U);
    REQUIRE(planned->session_policy.runtimes.front().runtime_id == "codex");
    REQUIRE(planned->setup.runtime_template_ids == std::vector<std::string>{"codex-safe"});
    REQUIRE(
        planned->session_policy.policy_json.find("\"egress_policy_ids\":[\"no-network\"]") !=
        std::string::npos
    );
    REQUIRE(!std::filesystem::exists(planned->setup.config_path));
    REQUIRE(!std::filesystem::exists(planned->session_policy.policy_path));
    REQUIRE(!std::filesystem::exists(planned->protected_harness_root));

    // A prior codex-only setup must not fail the read-only plan before it
    // derives the same codex-only runtime template set.
    REQUIRE(std::filesystem::create_directories(planned->setup.config_path.parent_path()));
    REQUIRE(::chmod(planned->setup.config_path.parent_path().c_str(), 0700) == 0);
    REQUIRE(write_config_exclusive(planned->setup.config_path, planned->setup.service));
    auto rerun = plan_onboarding(options, values);
    REQUIRE(rerun.has_value());
    REQUIRE(rerun->setup.runtime_template_ids == std::vector<std::string>{"codex-safe"});

    auto missing_search_root = options;
    missing_search_root.executable_search_paths.clear();
    auto invalid = plan_onboarding(missing_search_root, values);
    REQUIRE(!invalid.has_value());
    REQUIRE(invalid.error().find("explicit harness search directory") != std::string::npos);

    return 0;
}

} // namespace

int main() {
    return run();
}
