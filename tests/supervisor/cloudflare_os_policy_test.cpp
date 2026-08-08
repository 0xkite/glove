#include "glove/supervisor/native_skill_runtime_adapter.hpp"
#include "glove/supervisor/session_plan.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

constexpr std::string_view fixture_workspace = "/var/lib/glove/cloudflare-os/workspace";
constexpr std::string_view node_executable = "/opt/glove/runtime/cloudflare-os/node-v25/bin/node";
constexpr std::string_view immutable_closure = "/opt/glove/runtime/cloudflare-os/closure";
constexpr std::string_view startup_script =
    "/opt/glove/runtime/cloudflare-os/closure/scripts/run-local.mjs";
constexpr std::string_view adapter_digest =
    "2c3af3985743cc37adbc120a49290f48ac04ddc1e3bde1aa16fee8301a259cee";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-cfos-policy-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
            (void)::chmod(root_.c_str(), 0700);
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

[[nodiscard]] auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] auto replace_once(std::string input, std::string_view before, std::string_view after)
    -> std::string {
    const auto offset = input.find(before);
    if (offset != std::string::npos) {
        input.replace(offset, before.size(), after);
    }
    return input;
}

[[nodiscard]] auto write_policy(const std::filesystem::path& path, std::string_view contents)
    -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), 0600) == 0;
}

[[nodiscard]] auto plan_json() -> std::string {
    return R"({"schema_version":1,"runtime_id":"cloudflare-os","runtime_template_id":"cloudflare-os-dev","adapter_command_digest":")" +
           std::string{adapter_digest} +
           R"(","sandbox_backend":"remote_linux_container","egress_policy_id":"cloudflare-os-loopback","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":4294967296,"ttl_secs":300,"cleanup_policy":"remove"}],"library_projections":[],"secret_handles":[],"limits":{"cpu_time_ms":120000,"memory_bytes":2147483648,"pids":256,"wall_time_ms":300000,"disk_bytes":6442450944,"terminal_output_bytes":16777216},"policy_revision":69,"expires_at_ms":301000})";
}

[[nodiscard]] auto rejected_plan(
    const glove::supervisor::session_plan_validator& validator,
    std::string plan,
    std::string_view before,
    std::string_view after
) -> bool {
    return !validator.validate_json(replace_once(std::move(plan), before, after), 1'000);
}

[[nodiscard]] auto rejected_policy(
    const std::filesystem::path& path,
    std::string policy,
    std::string_view before,
    std::string_view after
) -> bool {
    if (!write_policy(path, replace_once(std::move(policy), before, after))) {
        return false;
    }
    return !glove::supervisor::session_plan_validator::load(path);
}

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto workspace = temporary.root() / "workspace";
    REQUIRE(std::filesystem::create_directory(workspace));
    const auto workspace_scripts = workspace / "scripts";
    REQUIRE(std::filesystem::create_directory(workspace_scripts));
    const auto shadow_script = workspace_scripts / "run-local.mjs";
    {
        std::ofstream output{shadow_script};
        output << "throw new Error('workspace shadow selected');\n";
    }
    REQUIRE(std::filesystem::is_regular_file(shadow_script));

    const std::string fixture = read_file(CLOUDFLARE_OS_POLICY_FIXTURE);
    REQUIRE(!fixture.empty());
    REQUIRE(fixture.find(fixture_workspace) != std::string::npos);
    const auto materialized =
        replace_once(fixture, fixture_workspace, std::filesystem::canonical(workspace).string());
    const auto policy_path = temporary.root() / "cloudflare-os-session-policy.json";
    REQUIRE(write_policy(policy_path, materialized));

    const runtime_launch_template expected_launch{
        .runtime_discovery = "",
        .executable_path = std::string{node_executable},
        .executable_search_paths = {},
        .arguments = {std::string{startup_script}},
        .environment = {},
        .read_only_paths = {std::string{immutable_closure}},
    };
    REQUIRE(std::filesystem::path{startup_script}.is_absolute());
    REQUIRE(std::filesystem::path{startup_script}.parent_path().parent_path() == immutable_closure);
    const auto expected_digest = runtime_launch_template_digest(expected_launch);
    REQUIRE(expected_digest.has_value());
    REQUIRE(*expected_digest == adapter_digest);
    REQUIRE(!native_skill_runtime_adapter_for("cloudflare-os").has_value());

    auto validator = session_plan_validator::load(policy_path);
    if (!validator) {
        std::fprintf(stderr, "fixture policy load failed: %s\n", validator.error().c_str());
    }
    REQUIRE(validator.has_value());

    const auto plan = plan_json();
    const auto validation = validator->validate_json(plan, 1'000);
    REQUIRE(validation.has_value());
    REQUIRE(validation->schema_version == 1);
    REQUIRE(validation->policy_revision == 69);

    const auto launch = validator->resolve_runtime_launch_json(plan, 1'000);
    REQUIRE(launch.has_value());
    REQUIRE(launch->runtime_id == "cloudflare-os");
    REQUIRE(launch->runtime_template_id == "cloudflare-os-dev");
    REQUIRE(launch->adapter_command_digest == adapter_digest);
    REQUIRE(launch->backend == sandbox_backend::remote_linux_container);
    REQUIRE(
        (launch->argv ==
         std::vector<std::string>{std::string{node_executable}, std::string{startup_script}})
    );
    REQUIRE(launch->argv[1] != std::filesystem::canonical(shadow_script).string());
    REQUIRE(launch->environment.empty());
    REQUIRE(launch->read_only_paths == std::vector<std::string>{std::string{immutable_closure}});
    REQUIRE(launch->limits.cpu_time_ms == 120'000);
    REQUIRE(launch->limits.memory_bytes == 2'147'483'648);
    REQUIRE(launch->limits.pids == 256);
    REQUIRE(launch->limits.wall_time_ms == 300'000);
    REQUIRE(launch->limits.disk_bytes == 6'442'450'944);
    REQUIRE(launch->limits.terminal_output_bytes == 16'777'216);
    REQUIRE(launch->egress_policy_id == "cloudflare-os-loopback");
    REQUIRE(launch->egress_targets.size() == 1U);
    REQUIRE(launch->egress_targets.front().host == "127.0.0.1");
    REQUIRE(launch->egress_targets.front().port == 8787);
    REQUIRE(launch->egress_targets.front().allow_private);
    REQUIRE(launch->secret_mounts.empty());
    REQUIRE(!launch->adoption.has_value());

    auto grants = validator->resolve_path_grants_json(plan, 1'000);
    REQUIRE(grants.has_value());
    REQUIRE(grants->size() == 1U);
    REQUIRE(grants->front().alias() == "workspace");
    REQUIRE(grants->front().target_path() == "/workspace");
    REQUIRE(grants->front().access() == path_access::ephemeral_write);
    REQUIRE(grants->front().materialization() == path_materialization::copy);
    REQUIRE(grants->front().create_policy() == path_create_policy::empty_directory);
    REQUIRE(grants->front().cleanup_policy() == path_cleanup_policy::remove);
    REQUIRE(grants->front().ttl_secs() == 300);
    REQUIRE(grants->front().max_bytes() == 4'294'967'296);

    REQUIRE(rejected_plan(
        *validator, plan, R"("runtime_id":"cloudflare-os")", R"("runtime_id":"codex")"
    ));
    REQUIRE(rejected_plan(
        *validator,
        plan,
        R"("runtime_template_id":"cloudflare-os-dev")",
        R"("runtime_template_id":"cloudflare-os-other")"
    ));
    REQUIRE(rejected_plan(
        *validator,
        plan,
        adapter_digest,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    REQUIRE(rejected_plan(*validator, plan, "remote_linux_container", "linux_production"));
    REQUIRE(rejected_plan(
        *validator,
        plan,
        R"("egress_policy_id":"cloudflare-os-loopback")",
        R"("egress_policy_id":"no-network")"
    ));
    REQUIRE(rejected_plan(
        *validator, plan, R"("secret_handles":[])", R"("secret_handles":["cloudflare-token"])"
    ));
    REQUIRE(rejected_plan(*validator, plan, R"("access":"ephemeral_write")", R"("access":"read")"));
    REQUIRE(rejected_plan(
        *validator, plan, R"("access":"ephemeral_write")", R"("access":"direct_write")"
    ));
    REQUIRE(rejected_plan(
        *validator, plan, R"("access":"ephemeral_write")", R"("access":"retained_write")"
    ));
    REQUIRE(rejected_plan(
        *validator, plan, R"("materialization":"copy")", R"("materialization":"bind")"
    ));
    REQUIRE(rejected_plan(
        *validator, plan, R"("cleanup_policy":"remove")", R"("cleanup_policy":"retain")"
    ));
    REQUIRE(
        rejected_plan(*validator, plan, R"("max_bytes":4294967296)", R"("max_bytes":4294967297)")
    );
    REQUIRE(rejected_plan(
        *validator, plan, R"("memory_bytes":2147483648)", R"("memory_bytes":2147483649)"
    ));
    REQUIRE(rejected_plan(
        *validator,
        plan,
        R"("expires_at_ms":301000)",
        R"("executable_path":"/bin/sh","expires_at_ms":301000)"
    ));
    REQUIRE(rejected_plan(
        *validator,
        plan,
        R"("expires_at_ms":301000)",
        R"("egress_targets":[{"host":"0.0.0.0","port":8787,"allow_private":true}],"expires_at_ms":301000)"
    ));

    REQUIRE(rejected_policy(
        temporary.root() / "unknown-field-policy.json",
        materialized,
        R"("schema_version": 1)",
        R"("schema_version": 1, "plan_can_start": true)"
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "changed-node-policy.json",
        materialized,
        node_executable,
        "/opt/glove/runtime/cloudflare-os/node-v26/bin/node"
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "changed-arguments-policy.json",
        materialized,
        startup_script,
        "/opt/glove/runtime/cloudflare-os/closure/scripts/run-other.mjs"
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "relative-startup-policy.json",
        materialized,
        startup_script,
        "scripts/run-local.mjs"
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "workspace-shadow-policy.json",
        materialized,
        startup_script,
        std::filesystem::canonical(shadow_script).string()
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "inherited-environment-policy.json",
        materialized,
        R"("environment": [])",
        R"("environment": ["PATH=/usr/bin:/bin"])"
    ));
    REQUIRE(rejected_policy(
        temporary.root() / "changed-closure-policy.json",
        materialized,
        immutable_closure,
        "/opt/glove/runtime/cloudflare-os/mutable-closure"
    ));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
