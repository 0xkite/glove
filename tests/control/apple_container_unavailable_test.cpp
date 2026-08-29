#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "apple_container_session_runtime.hpp"
#include "apple_worker_start.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view image_digest =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view launch_digest =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr std::string_view unavailable = "Apple Container managed lifecycle is unavailable";
constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-apple-runtime-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

[[nodiscard]] auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

template<typename Result> [[nodiscard]] auto is_unavailable(const Result& result) -> bool {
    return !result && result.error() == unavailable;
}

auto run() -> int {
    using namespace glove::control::apple_detail;

    const auto parsed = parse_apple_container_stats(
        R"([{"id":"apple-unit","memoryUsageBytes":4096,"memoryLimitBytes":8192,"cpuUsageUsec":2500,"networkRxBytes":0,"networkTxBytes":0,"blockReadBytes":64,"blockWriteBytes":128,"numProcesses":3}])",
        "apple-unit"
    );
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->cpu_usage_usec == 2'500U);
    REQUIRE(parsed->memory_usage_bytes == 4'096U);
    REQUIRE(parsed->memory_limit_bytes == 8'192U);
    REQUIRE(parsed->num_processes == 3U);
    REQUIRE(parsed->block_write_bytes == 128U);
    REQUIRE(!parse_apple_container_stats("[]", "apple-unit"));
    REQUIRE(!parse_apple_container_stats(R"([{"id":"aanumProcesses")", "apple-unit"));
    REQUIRE(!parse_apple_container_stats(
        R"([{"id":"other","memoryUsageBytes":1,"memoryLimitBytes":2,"cpuUsageUsec":3,"networkRxBytes":0,"networkTxBytes":0,"blockReadBytes":0,"blockWriteBytes":0,"numProcesses":1}])",
        "apple-unit"
    ));
    REQUIRE(!parse_apple_container_stats(
        R"([{"id":"apple-unit","i\u0064":"other","memoryUsageBytes":1,"memoryLimitBytes":2,"cpuUsageUsec":3,"networkRxBytes":0,"networkTxBytes":0,"blockReadBytes":0,"blockWriteBytes":0,"numProcesses":1}])",
        "apple-unit"
    ));
    REQUIRE(!parse_apple_container_stats(
        R"([{"id":"apple-unit","memoryUsageBytes":1,"memoryLimitBytes":2,"cpuUsageUsec":3,"networkRxBytes":0,"networkTxBytes":0,"blockReadBytes":0,"blockWriteBytes":0,"numProcesses":1,"future":1}])",
        "apple-unit"
    ));
    const auto tmpfs = apple_container_tmpfs_sizes(101U);
    REQUIRE(tmpfs.has_value());
    REQUIRE(tmpfs->first == 50U);
    REQUIRE(tmpfs->second == 51U);
    REQUIRE(tmpfs->first + tmpfs->second == 101U);
    REQUIRE(!apple_container_tmpfs_sizes(1U));

    {
        std::jthread sampler;
        std::jthread finalizer;
        std::atomic_bool sampler_entered{false};
        std::atomic_bool sampler_exited{false};
        std::atomic_bool finalizer_ran{false};
        std::size_t launches = 0;
        auto fail_second_launch = [&]<typename Body>(Body&& body) -> std::jthread {
            ++launches;
            if (launches == 2U) {
                throw std::system_error{
                    std::make_error_code(std::errc::resource_unavailable_try_again)
                };
            }
            return std::jthread{std::forward<Body>(body)};
        };
        auto started = detail::start_sampler_then_finalizer(
            sampler,
            finalizer,
            fail_second_launch,
            [&](std::stop_token stop_token) {
                sampler_entered.store(true);
                while (!stop_token.stop_requested()) {
                    std::this_thread::yield();
                }
                sampler_exited.store(true);
            },
            [&] { finalizer_ran.store(true); }
        );
        REQUIRE(!started.has_value());
        REQUIRE(launches == 2U);
        REQUIRE(sampler_entered.load());
        REQUIRE(sampler_exited.load());
        REQUIRE(!finalizer_ran.load());
        REQUIRE(!sampler.joinable());
        REQUIRE(!finalizer.joinable());
    }
    {
        std::jthread sampler;
        std::jthread finalizer;
        std::size_t launches = 0;
        auto fail_first_launch = [&]<typename Body>(Body&&) -> std::jthread {
            ++launches;
            throw std::system_error{
                std::make_error_code(std::errc::resource_unavailable_try_again)
            };
        };
        auto started = detail::start_sampler_then_finalizer(
            sampler, finalizer, fail_first_launch, [](std::stop_token) {}, [] {}
        );
        REQUIRE(!started.has_value());
        REQUIRE(launches == 1U);
        REQUIRE(!sampler.joinable());
        REQUIRE(!finalizer.joinable());
    }
    {
        std::jthread sampler;
        std::jthread finalizer;
        std::atomic_bool sampler_exited{false};
        std::size_t launches = 0;
        auto fail_second_launch_nonstandard = [&]<typename Body>(Body&& body) -> std::jthread {
            ++launches;
            if (launches == 2U) {
                throw 7;
            }
            return std::jthread{std::forward<Body>(body)};
        };
        auto started = detail::start_sampler_then_finalizer(
            sampler,
            finalizer,
            fail_second_launch_nonstandard,
            [&](std::stop_token stop_token) {
                while (!stop_token.stop_requested()) {
                    std::this_thread::yield();
                }
                sampler_exited.store(true);
            },
            [] {}
        );
        REQUIRE(!started.has_value());
        REQUIRE(started.error() == "unknown Apple worker launch failure");
        REQUIRE(launches == 2U);
        REQUIRE(sampler_exited.load());
        REQUIRE(!sampler.joinable());
        REQUIRE(!finalizer.joinable());
    }

    const apple_image_ownership_expectation simple_image{
        .image_digest = std::string{image_digest},
        .harness_closure_digest = std::nullopt,
        .sage_guest = std::nullopt,
    };
    const std::string exact_image =
        "{\"digest\":\"" + std::string{image_digest} + "\",\"labels\":{}}";
    REQUIRE(validate_image_inspection_json(exact_image, {}, simple_image).has_value());
    REQUIRE(!validate_image_inspection_json(exact_image + "diagnostic", {}, simple_image));
    REQUIRE(!validate_image_inspection_json("{", {}, simple_image));
    REQUIRE(!validate_image_inspection_json(
        "{\"digest\":\"" + std::string{image_digest} + "\",\"digest\":\"" +
            std::string{image_digest} + "\",\"labels\":{}}",
        {},
        simple_image
    ));
    REQUIRE(!validate_image_inspection_json("{\"digest\":7,\"labels\":{}}", {}, simple_image));
    REQUIRE(!validate_image_inspection_json({}, exact_image, simple_image));
    REQUIRE(!validate_image_inspection_json(
        "{\"digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\","
        "\"labels\":{}}",
        {},
        simple_image
    ));

    const sage_guest_runtime_identity sage_identity{
        .binary_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        .source_revision = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        .policy_schema_version = 1,
        .library_projection_schema = "sage_bundle_v1",
    };
    const apple_image_ownership_expectation labeled_image{
        .image_digest = std::string{image_digest},
        .harness_closure_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        .sage_guest = sage_identity,
    };
    const std::string labels =
        "{\"digest\":\"" + std::string{image_digest} +
        "\",\"labels\":{\"dev.sage.glove.harness-closure-schema\":\"1\","
        "\"dev.sage.glove.harness-closure-digest\":"
        "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\","
        "\"dev.sage.glove.sage-guest-binary-digest\":\"" +
        sage_identity.binary_digest + "\",\"dev.sage.glove.sage-source-revision\":\"" +
        sage_identity.source_revision +
        "\",\"dev.sage.glove.sage-guest-policy-schema\":\"1\","
        "\"dev.sage.glove.library-projection-schema\":\"sage_bundle_v1\"}}";
    REQUIRE(validate_image_inspection_json(labels, {}, labeled_image).has_value());
    auto wrong_labels = labels;
    wrong_labels.replace(wrong_labels.find("sage_bundle_v1"), 14U, "wrong_schema__");
    REQUIRE(!validate_image_inspection_json(wrong_labels, {}, labeled_image));

    const apple_instance_ownership_expectation instance{
        .instance_name = "glove-owned",
        .image_digest = std::string{image_digest},
        .launch_identity_digest = std::string{launch_digest},
    };
    const std::string exact_instance =
        "{\"name\":\"glove-owned\",\"image\":{\"digest\":\"" + std::string{image_digest} +
        "\"},\"labels\":{\"dev.sage.glove.launch-digest\":\"" + std::string{launch_digest} + "\"}}";
    REQUIRE(validate_instance_inspection_json(exact_instance, {}, instance).has_value());
    REQUIRE(!validate_instance_inspection_json(
        exact_instance, "stderr identity must not count", instance
    ));
    REQUIRE(!validate_instance_inspection_json(
        "{\"name\":\"glove-reused\",\"image\":{\"digest\":\"" + std::string{image_digest} +
            "\"},\"labels\":{\"dev.sage.glove.launch-digest\":\"" + std::string{launch_digest} +
            "\"}}",
        {},
        instance
    ));
    REQUIRE(!validate_instance_inspection_json(
        "{\"name\":\"glove-owned\",\"image\":{\"digest\":\"" + std::string{image_digest} +
            "\"},\"labels\":{\"dev.sage.glove.launch-digest\":\"unrelated\"}}",
        {},
        instance
    ));
    REQUIRE(!validate_instance_inspection_json(
        "{\"name\":\"glove-owned\",\"name\":\"glove-owned\",\"image\":{\"digest\":\"" +
            std::string{image_digest} + "\"},\"labels\":{\"dev.sage.glove.launch-digest\":\"" +
            std::string{launch_digest} + "\"}}",
        {},
        instance
    ));

    const std::string bundle_digest(64U, '1');
    const std::string fixed_target =
        "/run/glove-projections/sage-bundles/" + bundle_digest + ".json";
    REQUIRE(validate_sage_projection_target("sage-bundles", fixed_target, bundle_digest));
    REQUIRE(!validate_sage_projection_target("other", fixed_target, bundle_digest));
    REQUIRE(!validate_sage_projection_target(
        "sage-bundles", "/run/glove-projections/sage-bundles/other.json", bundle_digest
    ));

    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto session_root = temp.root() / "sessions";
    REQUIRE(std::filesystem::create_directory(session_root));
    REQUIRE(::chmod(session_root.c_str(), 0700) == 0);
    const auto invocation_log = temp.root() / "container.log";
    const auto fake_cli = temp.root() / "container";
    {
        std::ofstream script{fake_cli, std::ios::binary};
        script << "#!/bin/sh\n"
               << "printf '%s\\n' \"$*\" >> '" << invocation_log.string() << "'\n"
               << "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
               << "  printf '%s\\n' '" << exact_image << "'\n"
               << "  exit 0\n"
               << "fi\n"
               << "printf '%s\\n' unexpected >&2\nexit 93\n";
    }
    REQUIRE(::chmod(fake_cli.c_str(), 0700) == 0);

    const glove::supervisor::runtime_launch_template launch{
        .runtime_discovery = {},
        .executable_path = "/bin/true",
        .executable_search_paths = {},
        .arguments = {},
        .environment = {},
        .read_only_paths = {},
    };
    const auto adapter_digest = glove::supervisor::runtime_launch_template_digest(launch);
    REQUIRE(adapter_digest);
    const auto unused_path = temp.root() / "unused";
    REQUIRE(std::filesystem::create_directory(unused_path));
    auto paths = glove::supervisor::path_alias_registry::build({{
        .alias = "unused",
        .host_path = std::filesystem::canonical(unused_path).string(),
        .target_path = "/unused",
        .max_ttl_secs = 120,
        .access = {{
            .access = glove::supervisor::path_access::ephemeral_write,
            .materialization = glove::supervisor::path_materialization::copy,
            .create_policy = glove::supervisor::path_create_policy::empty_directory,
            .cleanup_policy = glove::supervisor::path_cleanup_policy::remove,
            .max_bytes = 1'024,
        }},
    }});
    REQUIRE(paths);
    auto validator = glove::supervisor::session_plan_validator::build(
        {
            .revision = 1,
            .max_plan_ttl_ms = 300'000,
            .runtime_templates = {{
                .runtime_template_id = "apple-construction",
                .runtime_id = "probe",
                .adapter_command_digest = *adapter_digest,
                .backend = glove::supervisor::sandbox_backend::apple_container,
                .allowed_path_aliases = {},
                .allowed_projection_destinations = {},
                .launch = launch,
                .adoption = std::nullopt,
            }},
            .library_projection_destinations = {},
            .resource_profiles = {{
                .cpu_time_ms = 1'000,
                .memory_bytes = 64U * 1024U * 1024U,
                .pids = 8,
                .wall_time_ms = 1'000,
                .disk_bytes = 1'024,
                .terminal_output_bytes = 1'024,
            }},
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"none"},
            .secret_handles = {},
            .egress_policies = {},
            .secret_mounts = {},
        },
        std::move(*paths)
    );
    if (!validator) {
        std::fprintf(stderr, "validator: %s\n", validator.error().c_str());
    }
    REQUIRE(validator);
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto registry_path = temp.root() / "sessions.journal";
    auto registry =
        glove::control::session_registry::open_or_create(registry_path, shared_validator);
    REQUIRE(registry);

    const auto audit_key_path = temp.root() / "audit.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    const auto receipt_path = temp.root() / "receipts.journal";
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = receipt_path,
    });
    REQUIRE(producer);

    const auto registry_before_create = read_file(registry_path);
    const auto receipts_before_create = read_file(receipt_path);
    const auto receipt_anchor_before_create = (*producer)->anchor();
    auto runtime = apple_container_session_runtime::create(
        **registry,
        {
            .container_cli = fake_cli,
            .image_reference = "example.invalid/glove@" + std::string{image_digest},
            .image_digest = std::string{image_digest},
            .harness_closure_digest = std::nullopt,
            .sage_guest = std::nullopt,
            .egress_audit = glove::audit::make_memory_sink(),
            .session_root = session_root,
        }
    );
    REQUIRE(runtime);
    REQUIRE(read_file(invocation_log).empty());
    REQUIRE(read_file(registry_path) == registry_before_create);
    REQUIRE(read_file(receipt_path) == receipts_before_create);
    REQUIRE((*producer)->anchor() == receipt_anchor_before_create);
    REQUIRE(std::filesystem::is_empty(session_root));
    REQUIRE(!(*runtime)->lifecycle_operational());
    REQUIRE((*runtime)->agent_runtime_adapter_schema_version() == 0);
    REQUIRE((*runtime)->managed_runtime_ids().empty());
    REQUIRE(!(*runtime)->resource_capabilities().complete());

    const auto registry_snapshot = read_file(registry_path);
    const auto receipt_snapshot = read_file(receipt_path);
    const auto receipt_anchor_snapshot = (*producer)->anchor();
    const auto no_effects = [&] {
        return read_file(invocation_log).empty() && read_file(registry_path) == registry_snapshot &&
               read_file(receipt_path) == receipt_snapshot &&
               (*producer)->anchor() == receipt_anchor_snapshot &&
               std::filesystem::is_empty(session_root);
    };

    const glove::control::session_start_authorization authorization{};
    REQUIRE(is_unavailable((*runtime)->reconcile(**producer, 1)));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->start(**producer, authorization, "ignored", 1)));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->list()));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->read("ignored", 0, 1)));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->wait_read("ignored", 0, 1, 1)));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->write_input("ignored", "x")));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->resize("ignored", 24, 80)));
    REQUIRE(no_effects());
    REQUIRE(
        is_unavailable((*runtime)->signal("ignored", glove::control::session_signal::terminate))
    );
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->stop("ignored")));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->stop("ignored", "ignored-key")));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->wait("ignored")));
    REQUIRE(no_effects());
    REQUIRE(is_unavailable((*runtime)->cleanup("ignored")));
    REQUIRE(no_effects());
    return 0;
}

} // namespace

int main() {
    return run();
}
