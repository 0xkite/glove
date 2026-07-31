#include "glove/container/digest.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_alias.hpp"

#include "linux_session_preparation.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view controller_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view content_digest =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
constexpr std::string_view canonical_library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-linux-preparation-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto library_digest() -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(canonical_library_bundle.data());
    return glove::container::sha256_hex(std::span{bytes, canonical_library_bundle.size()})
        .value_or("");
}

auto make_inputs(
    const std::filesystem::path& source,
    std::uint64_t page,
    std::uint64_t now_ms,
    glove::supervisor::sandbox_backend backend =
        glove::supervisor::sandbox_backend::linux_production
) -> std::expected<glove::control::session_start_inputs, std::string> {
    using namespace glove::supervisor;
    auto aliases = path_alias_registry::build({
        path_alias_policy{
            .alias = "workspace",
            .host_path = source.string(),
            .target_path = "/workspace",
            .max_ttl_secs = 60,
            .access = {
                path_access_policy{
                    .access = path_access::ephemeral_write,
                    .materialization = path_materialization::copy,
                    .create_policy = path_create_policy::empty_directory,
                    .cleanup_policy = path_cleanup_policy::remove,
                    .max_bytes = page * 4U,
                },
            },
        },
    });
    if (!aliases) {
        return std::unexpected(aliases.error());
    }
    auto grant = aliases->resolve({
        .alias = "workspace",
        .access = path_access::ephemeral_write,
        .ttl_secs = 60,
        .max_bytes = page * 4U,
    });
    if (!grant) {
        return std::unexpected(grant.error());
    }
    resource_limits limits{
        .cpu_time_ms = 10'000,
        .memory_bytes = std::uint64_t{128} * 1024U * 1024U,
        .pids = 16,
        .wall_time_ms = 5'000,
        .disk_bytes = page * 16U,
        .terminal_output_bytes = std::uint64_t{1024} * 1024U,
    };
    std::vector<resolved_path_grant> grants;
    grants.push_back(std::move(*grant));
    return glove::control::session_start_inputs{
        .session =
            {
                .schema_version = 1,
                .session_id = "session-preparation",
                .controller_plan_digest = std::string{controller_digest},
                .plan_content_digest = std::string{content_digest},
                .state = glove::control::session_state::preparing,
                .policy_revision = 7,
                .expires_at_ms = now_ms + 60'000,
                .created_at_ms = now_ms - 1,
            },
        .launch =
            {
                .validation = {.schema_version = 1, .policy_revision = 7},
                .runtime_id = "codex",
                .runtime_template_id = "codex-safe",
                .adapter_command_digest = std::string(64, 'a'),
                .backend = backend,
                .argv = {"/usr/bin/true", "--version"},
                .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
                .read_only_paths = {},
                .limits = limits,
                .expires_at_ms = now_ms + 60'000,
                .requires_direct_write_approval = false,
                .egress_policy_id = "",
                .egress_targets = {},
                .secret_mounts = {},
                .refinement = std::nullopt,
            },
        .path_grants = std::move(grants),
        .library_projections = {},
        .authorization_id = "approval-session-preparation",
        .authorization_expires_at_ms = now_ms + 30'000,
    };
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto source = tree.root() / "source";
    const auto materializations = tree.root() / "materializations";
    const auto library_root = tree.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(materializations));
    REQUIRE(std::filesystem::create_directory(library_root));
    REQUIRE(::chmod(materializations.c_str(), 0700) == 0);
    REQUIRE(::chmod(library_root.c_str(), 0700) == 0);
    std::ofstream{source / "tracked.txt"} << "host-owned\n";
    const auto library_path = library_root / (library_digest() + ".json");
    std::ofstream{library_path, std::ios::binary | std::ios::trunc} << canonical_library_bundle;
    REQUIRE(::chmod(library_path.c_str(), 0600) == 0);
    auto library_store = glove::supervisor::library_bundle_store::open(library_root);
    REQUIRE(library_store.has_value());
    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const auto page = static_cast<std::uint64_t>(page_size);
    const auto now_ms = epoch_ms();

    auto preparer =
        glove::control::linux_detail::linux_session_preparer::create(materializations.string());
    if (!preparer) {
        std::fprintf(
            stderr, "Linux preparation topology unavailable: %s\n", preparer.error().c_str()
        );
        return 77;
    }

    auto wrong_backend =
        make_inputs(source, page, now_ms, glove::supervisor::sandbox_backend::apple_container);
    REQUIRE(wrong_backend.has_value());
    REQUIRE(!preparer->prepare(std::move(*wrong_backend), now_ms).has_value());
    REQUIRE(std::filesystem::is_empty(materializations));

    auto expired = make_inputs(source, page, now_ms);
    REQUIRE(expired.has_value());
    expired->authorization_expires_at_ms = now_ms;
    REQUIRE(!preparer->prepare(std::move(*expired), now_ms).has_value());
    REQUIRE(std::filesystem::is_empty(materializations));

    auto malformed_projection = make_inputs(source, page, now_ms);
    REQUIRE(malformed_projection.has_value());
    malformed_projection->launch.adapter_command_digest = "not-a-digest";
    REQUIRE(!preparer->prepare(std::move(*malformed_projection), now_ms).has_value());
    REQUIRE(std::filesystem::is_empty(materializations));

    auto missing_executable = make_inputs(source, page, now_ms);
    REQUIRE(missing_executable.has_value());
    missing_executable->launch.argv.front() = "/usr/bin/glove-no-such-agent-runtime";
    REQUIRE(!preparer->prepare(std::move(*missing_executable), now_ms).has_value());
    REQUIRE(std::filesystem::is_empty(materializations));

    {
        auto inputs = make_inputs(source, page, now_ms);
        REQUIRE(inputs.has_value());
        std::vector<glove::supervisor::resolved_library_projection_target> targets;
        targets.push_back({
            .projection =
                {
                    .projection_id = "sage-core",
                    .content_digest = library_digest(),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        });
        auto projections = library_store->resolve_projections(targets);
        REQUIRE(projections.has_value());
        inputs->library_projections = std::move(*projections);
        auto prepared = preparer->prepare(std::move(*inputs), now_ms);
        REQUIRE(prepared.has_value());
        REQUIRE(prepared->session_id == "session-preparation");
        REQUIRE(prepared->authorization_id == "approval-session-preparation");
        REQUIRE(prepared->controller_plan_digest == controller_digest);
        REQUIRE(prepared->plan_content_digest == content_digest);
        REQUIRE(prepared->profile.required_limits.has_value());
        REQUIRE(prepared->profile.required_limits->disk_bytes == page * 16U);
        REQUIRE(prepared->profile.work_dir == "/workspace");
        REQUIRE(
            prepared->profile.environment == std::vector<std::string>({
                                                 "PATH=/usr/bin:/bin",
                                                 "TERM=xterm-256color",
                                                 "CODEX_HOME=/home/agent/.codex",
                                             })
        );
        REQUIRE(prepared->profile.managed_home_dir == "/home/agent");
        REQUIRE(prepared->argv == std::vector<std::string>({"/usr/bin/true", "--version"}));
        REQUIRE(prepared->binding.controller_plan_digest == controller_digest);
        REQUIRE(prepared->binding.profile_digest.size() == 64);
        REQUIRE(prepared->filesystem_identity.schema_version == 1);
        REQUIRE(prepared->filesystem_identity.disk_limit_bytes == page * 16U);
        REQUIRE(prepared->filesystem_identity.partitions.size() == 1);
        REQUIRE(prepared->filesystem_identity.partitions.front().alias == "workspace");
        REQUIRE(prepared->filesystem_identity.partitions.front().quota_bytes == page * 4U);
        REQUIRE(
            (prepared->execution_binding() ==
             glove::control::session_execution_binding{
                 .schema_version = 1,
                 .session_id = "session-preparation",
                 .controller_plan_digest = std::string{controller_digest},
                 .plan_content_digest = std::string{content_digest},
                 .authorization_id = "approval-session-preparation",
                 .profile_digest = prepared->binding.profile_digest,
                 .cgroup_identity = prepared->cgroup_identity,
                 .filesystem_identity = prepared->filesystem_identity,
             })
        );
        REQUIRE(prepared->lifecycle != nullptr);
        REQUIRE(prepared->lifecycle->cgroup_fd() >= 0);
        const auto prepared_mounts = prepared->lifecycle->mounts();
        REQUIRE(prepared_mounts.size() == 5);
        const auto library_mount = std::ranges::find(
            prepared_mounts,
            "/opt/sage/library-bundles/" + library_digest() + ".json",
            &glove::supervisor::linux_detail::session_mount::target_path
        );
        REQUIRE(library_mount != prepared_mounts.end());
        REQUIRE(library_mount->source_content_digest == library_digest());
        const auto runtime_home_mount = std::ranges::find(
            prepared_mounts,
            "/home/agent",
            &glove::supervisor::linux_detail::session_mount::target_path
        );
        REQUIRE(runtime_home_mount != prepared_mounts.end());
        REQUIRE(runtime_home_mount->runtime_adapter_id == "codex");
        REQUIRE(runtime_home_mount->runtime_context_digest.has_value());
        REQUIRE(!std::filesystem::is_empty(materializations));
    }
    REQUIRE(std::filesystem::is_empty(materializations));
    REQUIRE(std::filesystem::exists(source / "tracked.txt"));

    const auto credential_source = tree.root() / "codex-auth.json";
    std::ofstream{credential_source, std::ios::binary | std::ios::trunc}
        << R"({"tokens":{"refresh_token":"source-v1"}})";
    REQUIRE(::chmod(credential_source.c_str(), 0600) == 0);
    const auto add_credential = [&](glove::control::session_start_inputs& inputs) {
        inputs.launch.secret_mounts.push_back({
            .handle = "codex-auth",
            .runtime_id = "codex",
            .source_path = credential_source.string(),
            .target_path = "/home/agent/.codex/auth.json",
        });
    };

    auto first_credentialed = make_inputs(source, page, now_ms);
    REQUIRE(first_credentialed.has_value());
    first_credentialed->session.session_id = "credential-lease-first";
    first_credentialed->authorization_id = "approval-credential-lease-first";
    add_credential(*first_credentialed);
    auto first_prepared = preparer->prepare(std::move(*first_credentialed), now_ms);
    REQUIRE(first_prepared.has_value());
    const auto credential_mounts = first_prepared->lifecycle->mounts();
    const auto credential_mount = std::ranges::find(
        credential_mounts,
        "/home/agent/.codex/auth.json",
        &glove::supervisor::linux_detail::session_mount::target_path
    );
    REQUIRE(credential_mount != credential_mounts.end());
    REQUIRE(credential_mount->writable);
    REQUIRE(credential_mount->secret_handle == "codex-auth");

    const auto lease_root = materializations / ".credential-leases";
    REQUIRE(std::filesystem::is_directory(lease_root));
    std::vector<std::filesystem::path> leases;
    for (const auto& entry : std::filesystem::directory_iterator{lease_root}) {
        if (entry.is_regular_file()) {
            leases.push_back(entry.path());
        }
    }
    REQUIRE(leases.size() == 1);
    struct stat lease_status{};
    REQUIRE(::lstat(leases.front().c_str(), &lease_status) == 0);
    REQUIRE((static_cast<unsigned int>(lease_status.st_mode) & 0777U) == 0600U);

    auto competing_credentialed = make_inputs(source, page, now_ms);
    REQUIRE(competing_credentialed.has_value());
    competing_credentialed->session.session_id = "credential-lease-competing";
    competing_credentialed->authorization_id = "approval-credential-lease-competing";
    add_credential(*competing_credentialed);
    auto competing = preparer->prepare(std::move(*competing_credentialed), now_ms);
    REQUIRE(!competing.has_value());
    REQUIRE(competing.error().find("already in use") != std::string::npos);

    std::ofstream{leases.front(), std::ios::binary | std::ios::trunc}
        << R"({"tokens":{"refresh_token":"rotated-by-agent"}})";
    first_prepared->lifecycle.reset();

    auto resumed_credentialed = make_inputs(source, page, now_ms);
    REQUIRE(resumed_credentialed.has_value());
    resumed_credentialed->session.session_id = "credential-lease-resumed";
    resumed_credentialed->authorization_id = "approval-credential-lease-resumed";
    add_credential(*resumed_credentialed);
    auto resumed = preparer->prepare(std::move(*resumed_credentialed), now_ms);
    REQUIRE(resumed.has_value());
    std::ifstream resumed_lease{leases.front(), std::ios::binary};
    const std::string resumed_content{
        std::istreambuf_iterator<char>{resumed_lease}, std::istreambuf_iterator<char>{}
    };
    REQUIRE(resumed_content.find("rotated-by-agent") != std::string::npos);
    resumed->lifecycle.reset();

    // A deliberate operator re-login changes the protected source content and
    // therefore selects a fresh immutable lease identity.
    std::ofstream{credential_source, std::ios::binary | std::ios::trunc}
        << R"({"tokens":{"refresh_token":"source-v2"}})";
    auto replaced_credentialed = make_inputs(source, page, now_ms);
    REQUIRE(replaced_credentialed.has_value());
    replaced_credentialed->session.session_id = "credential-lease-replaced";
    replaced_credentialed->authorization_id = "approval-credential-lease-replaced";
    add_credential(*replaced_credentialed);
    auto replaced = preparer->prepare(std::move(*replaced_credentialed), now_ms);
    REQUIRE(replaced.has_value());
    replaced->lifecycle.reset();
    leases.clear();
    for (const auto& entry : std::filesystem::directory_iterator{lease_root}) {
        if (entry.is_regular_file()) {
            leases.push_back(entry.path());
        }
    }
    REQUIRE(leases.size() == 2);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
