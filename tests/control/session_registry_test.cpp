#include "glove/container/digest.hpp"
#include "glove/control/guest_channel.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "session_reconciliation.hpp"
#include "session_registry_recovery.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
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
constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-session-registry-test-XXXXXX";
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

auto library_bundle_digest() -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(library_bundle.data());
    return glove::container::sha256_hex(std::span{bytes, library_bundle.size()}).value_or("");
}

auto replace_after_marker(
    const std::filesystem::path& path,
    std::string_view marker,
    std::string_view from,
    std::string_view to
) -> bool {
    if (from.size() != to.size()) {
        return false;
    }
    std::ifstream input{path, std::ios::binary};
    std::string bytes(static_cast<std::size_t>(std::filesystem::file_size(path)), '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!input.good()) {
        return false;
    }
    const auto marker_offset = bytes.find(marker);
    const auto value_offset =
        marker_offset == std::string::npos ? std::string::npos : bytes.find(from, marker_offset);
    if (value_offset == std::string::npos) {
        return false;
    }
    std::fstream output{path, std::ios::binary | std::ios::in | std::ios::out};
    output.seekp(static_cast<std::streamoff>(value_offset));
    output.write(to.data(), static_cast<std::streamsize>(to.size()));
    output.flush();
    return output.good();
}

auto rewrite_observation_record_and_rechain(
    const std::filesystem::path& path,
    const std::function<bool(const glove::control::wire::persisted_session&)>& select,
    const std::function<void(glove::control::wire::persisted_session&)>& mutate
) -> bool {
    using namespace glove::control;
    std::ifstream input{path, std::ios::binary};
    std::string bytes(static_cast<std::size_t>(std::filesystem::file_size(path)), '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!input.good() || bytes.size() < registry_magic.size() ||
        !std::equal(registry_magic.begin(), registry_magic.end(), bytes.begin())) {
        return false;
    }

    std::vector<wire::persisted_session> records;
    std::size_t offset = registry_magic.size();
    while (offset < bytes.size()) {
        if (bytes.size() - offset < 8U) {
            return false;
        }
        std::array<unsigned char, 4> prefix{};
        std::copy_n(
            reinterpret_cast<const unsigned char*>(bytes.data() + offset), 4, prefix.begin()
        );
        const auto payload_size = static_cast<std::size_t>(wire::decode_u32(prefix));
        if (payload_size == 0 || payload_size > bytes.size() - offset - 8U) {
            return false;
        }
        auto decoded =
            wire::decode_record(std::string_view{bytes}.substr(offset + 4U, payload_size));
        if (!decoded) {
            return false;
        }
        records.push_back(std::move(*decoded));
        offset += payload_size + 8U;
    }

    auto found = std::ranges::find_if(records, select);
    if (found == records.end()) {
        return false;
    }
    mutate(*found);

    std::vector<unsigned char> rewritten(registry_magic.begin(), registry_magic.end());
    std::string previous_hash(digest_hex_bytes, '0');
    for (auto& record : records) {
        record.previous_hash = previous_hash;
        record.this_hash.clear();
        auto record_hash = wire::hash_record(record);
        if (!record_hash) {
            return false;
        }
        record.this_hash = *record_hash;
        previous_hash = *record_hash;
        auto encoded = wire::encode_record(record);
        if (!encoded) {
            return false;
        }
        rewritten.insert(rewritten.end(), encoded->begin(), encoded->end());
    }

    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(
        reinterpret_cast<const char*>(rewritten.data()),
        static_cast<std::streamsize>(rewritten.size())
    );
    output.flush();
    return output.good();
}

auto file_contains(
    const std::filesystem::path& path, std::string_view needle, std::size_t max_bytes = 1U << 20U
) -> bool {
    if (needle.empty()) {
        return true;
    }
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        return false;
    }
    std::string bytes(max_bytes, '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<std::size_t>(input.gcount()));
    return bytes.find(needle) != std::string::npos;
}

auto launch_template() -> glove::supervisor::runtime_launch_template {
    return {
        .runtime_discovery = {},
        .executable_path = "/usr/bin/true",
        .executable_search_paths = {},
        .arguments = {"--version"},
        .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
        .read_only_paths = {},
    };
}

auto runtime_digest() -> std::string {
    return glove::supervisor::runtime_launch_template_digest(launch_template()).value_or("");
}

auto valid_plan() -> std::string {
    return R"({"schema_version":1,"runtime_id":"codex","runtime_template_id":"codex-safe","adapter_command_digest":")" +
           runtime_digest() +
           R"(","sandbox_backend":"linux_production","egress_policy_id":"no-network","tool_policy_id":"sage-readonly","path_grants":[{"alias":"workspace","access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove"}],"library_projections":[{"projection_id":"sage-core","content_digest":")" +
           library_bundle_digest() +
           R"(","destination_alias":"libraries"}],"secret_handles":["codex-token"],"limits":{"cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576},"policy_revision":7,"expires_at_ms":61000})";
}

auto valid_plan_at(std::uint64_t now_ms) -> std::string {
    auto plan = valid_plan();
    constexpr std::string_view original = R"("expires_at_ms":61000)";
    const auto replacement = std::string{"\"expires_at_ms\":"} + std::to_string(now_ms + 120'000);
    const auto offset = plan.find(original);
    if (offset != std::string::npos) {
        plan.replace(offset, original.size(), replacement);
    }
    return plan;
}

auto sage_guest_plan_at(std::uint64_t now_ms) -> std::string {
    auto plan = valid_plan_at(now_ms);
    for (const auto& [from, to] : {
             std::pair{
                 std::string_view{"\"runtime_id\":\"codex\""},
                 std::string_view{"\"runtime_id\":\"sage-guest\""}
             },
             std::pair{
                 std::string_view{"\"runtime_template_id\":\"codex-safe\""},
                 std::string_view{"\"runtime_template_id\":\"sage-guest-safe\""}
             },
             std::pair{
                 std::string_view{"\"secret_handles\":[\"codex-token\"]"},
                 std::string_view{"\"secret_handles\":[]"}
             },
         }) {
        const auto offset = plan.find(from);
        if (offset != std::string::npos) {
            plan.replace(offset, from.size(), to);
        }
    }
    return plan;
}

auto managed_plan() -> std::string {
    auto plan = valid_plan();
    const auto offset = plan.find(R"("sandbox_backend":"linux_production")");
    if (offset != std::string::npos) {
        plan.replace(
            offset,
            std::string_view{R"("sandbox_backend":"linux_production")"}.size(),
            R"("sandbox_backend":"apple_container")"
        );
    }
    return plan;
}

auto direct_write_plan() -> std::string {
    auto plan = valid_plan();
    const std::string ephemeral =
        R"("access":"ephemeral_write","materialization":"copy","max_bytes":1048576,"ttl_secs":60,"cleanup_policy":"remove")";
    const std::string direct =
        R"("access":"direct_write","materialization":"bind","max_bytes":0,"ttl_secs":60,"cleanup_policy":"retain")";
    const auto offset = plan.find(ephemeral);
    if (offset != std::string::npos) {
        plan.replace(offset, ephemeral.size(), direct);
    }
    return plan;
}

auto terminal_receipt(
    std::string profile_digest, std::uint64_t started_at_ms, std::uint64_t finished_at_ms
) -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::move(profile_digest),
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 1'000,
                .memory_bytes = 67'108'864,
                .pids = 16,
                .wall_time_ms = 2'000,
                .disk_bytes = 2'097'152,
                .terminal_output_bytes = 1'048'576,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 10,
                .peak_memory_bytes = 1'048'576,
                .peak_pids = 2,
                .wall_time_ms = finished_at_ms - started_at_ms,
                .disk_bytes = 4'096,
                .terminal_output_bytes = 128,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = started_at_ms,
        .finished_at_ms = finished_at_ms,
        .library_projections = {},
        .retained_changes = {},
    };
}

auto process_identity(std::uint32_t pid) -> glove::control::linux_process_identity {
    return {
        .schema_version = 1,
        .pid = pid,
        .boot_id = "12345678-1234-1234-1234-123456789abc",
        .start_time_ticks = 10'000U + pid,
        .cgroup_device = 42,
        .cgroup_inode = 20'000U + pid,
        .cgroup_path_digest = std::string(64, 'd'),
    };
}

auto cgroup_identity(std::uint32_t pid) -> glove::control::linux_cgroup_recovery_identity {
    return {
        .schema_version = 1,
        .device = 42,
        .inode = 20'000U + pid,
    };
}

auto filesystem_identity() -> glove::control::linux_filesystem_recovery_identity {
    return {
        .schema_version = 1,
        .disk_limit_bytes = 2'097'152,
        .partitions = {{.alias = "workspace", .quota_bytes = 1'048'576}},
    };
}

constexpr std::string_view test_observation_schema = "test.observation.v1";
constexpr std::string_view test_proposal_schema = "test.proposal.v1";

auto accepts_test_observation(const glove::control::glove_observation_body&) noexcept -> bool {
    return true;
}

auto accepts_test_proposal(const glove::control::glove_observation_body& body) noexcept -> bool {
    return body.observation == "retired-proposal" && body.item_count == 1U;
}

auto rejects_first_intent(const glove::control::glove_observation_body& body) noexcept -> bool {
    return body.intent_id != "intent-1";
}

// Registration example: the host owns payload semantics; Glove core only
// enforces structural invariants and the registered bounds.
auto test_channel_host() -> std::shared_ptr<const glove::control::channel_host> {
    auto host = std::make_shared<glove::control::channel_host>();
    if (!host->register_channel({
            .schema_id = std::string{test_observation_schema},
            .body_validator = &accepts_test_observation,
            .bounds = {
                .max_items = 4'096,
                .max_body_bytes = 8'192,
                .max_ttl_ms = 600'000,
                .max_skew_ms = 30'000,
            },
        })) {
        return {};
    }
    if (!host->register_channel({
            .schema_id = std::string{test_proposal_schema},
            .body_validator = &accepts_test_proposal,
            .bounds = {
                .max_items = 1,
                .max_body_bytes = 1'024,
                .max_ttl_ms = 600'000,
                .max_skew_ms = 30'000,
            },
        })) {
        return {};
    }
    if (!host->freeze()) {
        return {};
    }
    return host;
}

// Tight bounds to exercise descriptor-level rejection paths.
auto tight_channel_host() -> std::shared_ptr<const glove::control::channel_host> {
    auto host = std::make_shared<glove::control::channel_host>();
    if (!host->register_channel({
            .schema_id = std::string{test_observation_schema},
            .body_validator = &accepts_test_observation,
            .bounds =
                {
                    .max_items = 1,
                    .max_body_bytes = 512,
                    .max_ttl_ms = 50'000,
                    .max_skew_ms = 1'000,
                },
        }) ||
        !host->freeze()) {
        return {};
    }
    return host;
}

// Changed payload semantics with the original broad bounds.
auto rejecting_channel_host() -> std::shared_ptr<const glove::control::channel_host> {
    auto host = std::make_shared<glove::control::channel_host>();
    if (!host->register_channel({
            .schema_id = std::string{test_observation_schema},
            .body_validator = &rejects_first_intent,
            .bounds =
                {
                    .max_items = 4'096,
                    .max_body_bytes = 8'192,
                    .max_ttl_ms = 600'000,
                    .max_skew_ms = 30'000,
                },
        }) ||
        !host->freeze()) {
        return {};
    }
    return host;
}

auto validator_for(
    const std::filesystem::path& source,
    glove::supervisor::sandbox_backend backend =
        glove::supervisor::sandbox_backend::linux_production
) -> glove::supervisor::result<glove::supervisor::session_plan_validator> {
    using namespace glove::supervisor;
    auto paths = path_alias_registry::build({
        path_alias_policy{
            .alias = "workspace",
            .host_path = std::filesystem::canonical(source).string(),
            .target_path = "/workspace",
            .max_ttl_secs = 120,
            .access = {
                path_access_policy{
                    .access = path_access::ephemeral_write,
                    .materialization = path_materialization::copy,
                    .create_policy = path_create_policy::empty_directory,
                    .cleanup_policy = path_cleanup_policy::remove,
                    .max_bytes = 2'097'152,
                },
                path_access_policy{
                    .access = path_access::direct_write,
                    .materialization = path_materialization::bind,
                    .create_policy = path_create_policy::never,
                    .cleanup_policy = path_cleanup_policy::retain,
                    .max_bytes = 0,
                },
            },
        },
    });
    if (!paths) {
        return std::unexpected(paths.error());
    }
    return session_plan_validator::build(
        session_plan_policy{
            .revision = 7,
            .max_plan_ttl_ms = 120'000,
            .runtime_templates =
                {
                    runtime_template_policy{
                        .runtime_template_id = "codex-safe",
                        .runtime_id = "codex",
                        .adapter_command_digest = runtime_digest(),
                        .backend = backend,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = launch_template(),
                        .adoption = std::nullopt,
                    },
                    runtime_template_policy{
                        .runtime_template_id = "sage-guest-safe",
                        .runtime_id = "sage-guest",
                        .adapter_command_digest = runtime_digest(),
                        .backend = backend,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {"libraries"},
                        .launch = launch_template(),
                        .adoption = std::nullopt,
                    },
                },
            .library_projection_destinations =
                {
                    library_projection_destination_policy{
                        .alias = "libraries",
                        .target_path = "/opt/sage/library-bundles",
                    },
                },
            .resource_profiles =
                {
                    resource_limits{
                        .cpu_time_ms = 1'000,
                        .memory_bytes = 67'108'864,
                        .pids = 16,
                        .wall_time_ms = 2'000,
                        .disk_bytes = 2'097'152,
                        .terminal_output_bytes = 1'048'576,
                    },
                },
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles = {"codex-token"},
            .egress_policies = {},
            .secret_mounts =
                {
                    secret_mount_policy{
                        .handle = "codex-token",
                        .runtime_id = "codex",
                        .source_path = (source / "codex-auth.json").string(),
                        .target_path = "/home/agent/.codex/auth.json",
                    },
                },
        },
        std::move(*paths)
    );
}

auto run() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    std::ofstream{source / "tracked.txt"} << "host-owned\n";

    auto validator = validator_for(source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto bundle_root = temp.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(bundle_root));
    REQUIRE(::chmod(bundle_root.c_str(), 0700) == 0);
    const auto bundle_path = bundle_root / (library_bundle_digest() + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary};
        output.write(library_bundle.data(), static_cast<std::streamsize>(library_bundle.size()));
    }
    REQUIRE(::chmod(bundle_path.c_str(), 0600) == 0);
    auto opened_bundle_store = glove::supervisor::library_bundle_store::open(bundle_root);
    REQUIRE(opened_bundle_store.has_value());
    auto shared_bundle_store = std::make_shared<const glove::supervisor::library_bundle_store>(
        std::move(*opened_bundle_store)
    );

    auto empty_catalog = std::make_shared<glove::control::channel_host>();
    const auto empty_catalog_path = temp.root() / "empty-catalog-sessions.journal";
    auto empty_catalog_registry = glove::control::session_registry::open_or_create(
        empty_catalog_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        empty_catalog
    );
    REQUIRE(!empty_catalog_registry.has_value());
    REQUIRE(
        empty_catalog_registry.error().code ==
        glove::control::session_registry_error_code::invalid_request
    );
    REQUIRE(!std::filesystem::exists(empty_catalog_path));

    auto mutable_catalog = std::make_shared<glove::control::channel_host>();
    REQUIRE(mutable_catalog->register_channel({
        .schema_id = "test.mutable.v1",
        .body_validator = &accepts_test_observation,
        .bounds = {
            .max_items = 1,
            .max_body_bytes = 128,
            .max_ttl_ms = 1'000,
            .max_skew_ms = 100,
        },
    }));
    const auto mutable_catalog_path = temp.root() / "mutable-catalog-sessions.journal";
    auto mutable_catalog_registry = glove::control::session_registry::open_or_create(
        mutable_catalog_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        mutable_catalog
    );
    REQUIRE(!mutable_catalog_registry.has_value());
    REQUIRE(
        mutable_catalog_registry.error().code ==
        glove::control::session_registry_error_code::invalid_request
    );
    REQUIRE(!std::filesystem::exists(mutable_catalog_path));

    const auto store_path = temp.root() / "sessions.journal";
    auto registry = glove::control::session_registry::open_or_create(
        store_path, shared_validator, shared_bundle_store
    );
    REQUIRE(registry.has_value());
    REQUIRE((*registry)->record_count() == 0);

    auto locked = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(!locked.has_value());

    auto created = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 1'000
    );
    REQUIRE(created.has_value());
    REQUIRE(created->schema_version == 1);
    REQUIRE(created->session_id == "session-1");
    REQUIRE(created->controller_plan_digest == controller_digest);
    REQUIRE(created->plan_content_digest.size() == 64);
    REQUIRE(created->state == glove::control::session_state::created);
    REQUIRE(created->policy_revision == 7);
    REQUIRE(created->expires_at_ms == 61'000);
    REQUIRE(created->created_at_ms == 1'000);
    REQUIRE((*registry)->record_count() == 1);

    auto replay = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 1'001
    );
    REQUIRE(replay.has_value());
    REQUIRE(*replay == *created);
    REQUIRE((*registry)->record_count() == 1);

    auto expired_replay = (*registry)->create(
        "session-1", controller_digest, valid_plan(), "create-session-1", 62'000
    );
    REQUIRE(expired_replay.has_value());
    REQUIRE(*expired_replay == *created);
    REQUIRE((*registry)->record_count() == 1);

    auto changed_request = (*registry)->create(
        "session-2", controller_digest, valid_plan(), "create-session-1", 1'001
    );
    REQUIRE(!changed_request.has_value());
    auto changed_session = (*registry)->create(
        "session-1", std::string(64, 'd'), valid_plan(), "create-session-2", 1'001
    );
    REQUIRE(!changed_session.has_value());
    auto invalid_plan = (*registry)->create(
        "session-2", controller_digest, "{\"schema_version\":1}", "create-session-2", 1'001
    );
    REQUIRE(!invalid_plan.has_value());
    REQUIRE((*registry)->record_count() == 1);

    auto status = (*registry)->status("session-1");
    REQUIRE(status.has_value());
    REQUIRE(*status == *created);
    REQUIRE(!(*registry)->status("missing").has_value());
    auto canonical = (*registry)->canonical_plan("session-1");
    REQUIRE(canonical.has_value());
    REQUIRE(*canonical == valid_plan());

    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-1",
        .session_id = "session-1",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = 1'001,
        .expires_at_ms = 2'001,
    };
    auto wrong_authorization = authorization;
    wrong_authorization.plan_content_digest = std::string(64, 'd');
    REQUIRE(!(*registry)
                 ->reserve_start(wrong_authorization, "reserve-session-wrong-digest", 1'002)
                 .has_value());
    auto expired_authorization = authorization;
    expired_authorization.expires_at_ms = 1'002;
    REQUIRE(!(*registry)
                 ->reserve_start(expired_authorization, "reserve-session-expired", 1'002)
                 .has_value());
    REQUIRE((*registry)->record_count() == 1);

    auto reserved = (*registry)->reserve_start(authorization, "reserve-session-1", 1'002);
    if (!reserved) {
        std::fprintf(stderr, "reserve_start failed: %s\n", reserved.error().message.c_str());
    }
    REQUIRE(reserved.has_value());
    REQUIRE(reserved->session.state == glove::control::session_state::preparing);
    REQUIRE(reserved->authorization_id == authorization.authorization_id);
    REQUIRE(reserved->authorization_expires_at_ms == authorization.expires_at_ms);
    REQUIRE(reserved->launch.runtime_template_id == "codex-safe");
    REQUIRE(
        reserved->launch.argv == std::vector<std::string>({
                                     "/usr/bin/true",
                                     "--version",
                                     "--dangerously-bypass-approvals-and-sandbox",
                                 })
    );
    REQUIRE((*registry)->record_count() == 2);
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-wrong", 1'002).has_value()
    );
    auto start_inputs = (*registry)->resolve_start_inputs("session-1", "approval-session-1", 1'002);
    REQUIRE(start_inputs.has_value());
    REQUIRE(start_inputs->session == reserved->session);
    REQUIRE(start_inputs->launch == reserved->launch);
    REQUIRE(start_inputs->path_grants.size() == 1);
    REQUIRE(start_inputs->path_grants.front().alias() == "workspace");
    REQUIRE(start_inputs->path_grants.front().descriptor_fd() >= 0);
    REQUIRE(start_inputs->path_grants.front().verify_identity().has_value());
    REQUIRE(start_inputs->library_projections.size() == 1U);
    REQUIRE(start_inputs->library_projections.front().projection_id == "sage-core");
    REQUIRE(
        start_inputs->library_projections.front().bundle.content_digest() == library_bundle_digest()
    );
    REQUIRE(start_inputs->library_projections.front().destination_alias == "libraries");
    REQUIRE(
        start_inputs->library_projections.front().target_path ==
        "/opt/sage/library-bundles/" + library_bundle_digest() + ".json"
    );
    REQUIRE(start_inputs->library_projections.front().bundle.verify_identity().has_value());
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-1", 2'001).has_value()
    );
    auto reserved_replay = (*registry)->reserve_start(authorization, "reserve-session-1", 3'000);
    REQUIRE(reserved_replay.has_value());
    REQUIRE(reserved_replay->session == reserved->session);
    REQUIRE(reserved_replay->launch == reserved->launch);
    REQUIRE(reserved_replay->authorization_id == reserved->authorization_id);
    REQUIRE(reserved_replay->authorization_expires_at_ms == reserved->authorization_expires_at_ms);
    REQUIRE((*registry)->record_count() == 2);
    auto changed_reservation = authorization;
    changed_reservation.authorization_id = "approval-session-1-changed";
    REQUIRE(
        !(*registry)->reserve_start(changed_reservation, "reserve-session-1", 1'003).has_value()
    );
    REQUIRE((*registry)->status("session-1")->state == glove::control::session_state::preparing);

    auto duplicate_start = authorization;
    duplicate_start.authorization_id = "approval-session-1-second";
    REQUIRE(!(*registry)->reserve_start(duplicate_start, "reserve-session-2", 1'003).has_value());

    const glove::control::session_execution_binding execution_binding{
        .schema_version = 1,
        .session_id = "session-1",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = "approval-session-1",
        .profile_digest = std::string(64, 'e'),
        .cgroup_identity = cgroup_identity(4242),
        .filesystem_identity = filesystem_identity(),
    };
    const auto audit_key_path = temp.root() / "receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
        output.flush();
        REQUIRE(output.good());
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = audit_key_path,
        .journal_path = temp.root() / "receipts.journal",
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    auto receipt_reservation = (*producer)->reserve_terminal(
        execution_binding.session_id,
        execution_binding.controller_plan_digest,
        execution_binding.profile_digest
    );
    REQUIRE(receipt_reservation.has_value());
    auto malformed_execution = execution_binding;
    malformed_execution.profile_digest = "not-a-digest";
    REQUIRE(!(*registry)
                 ->mark_starting(
                     malformed_execution, *receipt_reservation, "starting-session-malformed", 1'003
                 )
                 .has_value());
    auto malformed_cgroup_execution = execution_binding;
    malformed_cgroup_execution.cgroup_identity.inode = 0;
    REQUIRE(!(*registry)
                 ->mark_starting(
                     malformed_cgroup_execution,
                     *receipt_reservation,
                     "starting-session-malformed-cgroup",
                     1'003
                 )
                 .has_value());
    auto wrong_execution_authorization = execution_binding;
    wrong_execution_authorization.authorization_id = "approval-session-wrong";
    REQUIRE(!(*registry)
                 ->mark_starting(
                     wrong_execution_authorization,
                     *receipt_reservation,
                     "starting-session-wrong-approval",
                     1'003
                 )
                 .has_value());
    REQUIRE(!(*registry)
                 ->mark_starting(
                     execution_binding, *receipt_reservation, "starting-session-expired", 2'001
                 )
                 .has_value());
    REQUIRE((*registry)->record_count() == 2);

    auto starting = (*registry)->mark_starting(
        execution_binding, *receipt_reservation, "starting-session-1", 1'003
    );
    REQUIRE(starting.has_value());
    REQUIRE(starting->session.state == glove::control::session_state::starting);
    REQUIRE(starting->authorization_id == execution_binding.authorization_id);
    REQUIRE(starting->authorization_expires_at_ms == authorization.expires_at_ms);
    REQUIRE(starting->profile_digest == execution_binding.profile_digest);
    REQUIRE(starting->starting_at_ms == 1'003);
    REQUIRE(starting->cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(starting->filesystem_identity == execution_binding.filesystem_identity);
    REQUIRE((*registry)->record_count() == 3);
    REQUIRE((*registry)->status("session-1") == starting->session);
    REQUIRE((*registry)->starting_status("session-1") == starting);
    auto starting_candidates = (*registry)->recovery_candidates();
    REQUIRE(starting_candidates.has_value());
    REQUIRE(starting_candidates->size() == 1);
    REQUIRE(starting_candidates->front().session == starting->session);
    REQUIRE(starting_candidates->front().authorization_id == starting->authorization_id);
    REQUIRE(starting_candidates->front().profile_digest == starting->profile_digest);
    REQUIRE(starting_candidates->front().starting_at_ms == starting->starting_at_ms);
    REQUIRE(starting_candidates->front().cgroup_identity == starting->cgroup_identity);
    REQUIRE(starting_candidates->front().filesystem_identity == starting->filesystem_identity);
    REQUIRE(starting_candidates->front().running_at_ms == 0);
    REQUIRE(!starting_candidates->front().process_identity.has_value());
    REQUIRE(
        !(*registry)->resolve_start_inputs("session-1", "approval-session-1", 1'004).has_value()
    );

    auto starting_replay = (*registry)->mark_starting(
        execution_binding, *receipt_reservation, "starting-session-1", 3'000
    );
    REQUIRE(starting_replay == starting);
    REQUIRE((*registry)->record_count() == 3);
    auto changed_execution = execution_binding;
    changed_execution.profile_digest = std::string(64, 'f');
    REQUIRE(
        !(*registry)
             ->mark_starting(changed_execution, *receipt_reservation, "starting-session-1", 1'004)
             .has_value()
    );
    auto changed_cgroup_execution = execution_binding;
    ++changed_cgroup_execution.cgroup_identity.inode;
    REQUIRE(!(*registry)
                 ->mark_starting(
                     changed_cgroup_execution, *receipt_reservation, "starting-session-1", 1'004
                 )
                 .has_value());
    REQUIRE(!(*registry)
                 ->mark_starting(
                     execution_binding, *receipt_reservation, "starting-session-duplicate", 1'004
                 )
                 .has_value());

    const glove::control::session_running_commitment running_commitment{
        .schema_version = 1,
        .session_id = execution_binding.session_id,
        .controller_plan_digest = execution_binding.controller_plan_digest,
        .plan_content_digest = execution_binding.plan_content_digest,
        .authorization_id = execution_binding.authorization_id,
        .profile_digest = execution_binding.profile_digest,
        .process_identity = process_identity(4242),
        .filesystem_identity = filesystem_identity(),
    };
    auto wrong_running = running_commitment;
    wrong_running.process_identity.pid = 0;
    REQUIRE(
        !(*registry)
             ->mark_running(wrong_running, *receipt_reservation, "running-session-invalid", 1'004)
             .has_value()
    );
    auto wrong_running_cgroup = running_commitment;
    ++wrong_running_cgroup.process_identity.cgroup_inode;
    REQUIRE(
        !(*registry)
             ->mark_running(
                 wrong_running_cgroup, *receipt_reservation, "running-session-invalid-cgroup", 1'004
             )
             .has_value()
    );
    auto wrong_filesystem = running_commitment;
    wrong_filesystem.filesystem_identity.partitions.front().quota_bytes =
        wrong_filesystem.filesystem_identity.disk_limit_bytes;
    REQUIRE(
        !(*registry)
             ->mark_running(
                 wrong_filesystem, *receipt_reservation, "running-session-invalid-filesystem", 1'004
             )
             .has_value()
    );
    auto running = (*registry)->mark_running(
        running_commitment, *receipt_reservation, "running-session-1", 1'004
    );
    REQUIRE(running.has_value());
    REQUIRE(running->session.state == glove::control::session_state::running);
    REQUIRE(running->profile_digest == execution_binding.profile_digest);
    REQUIRE(running->starting_at_ms == starting->starting_at_ms);
    REQUIRE(running->running_at_ms == 1'004);
    REQUIRE(running->process_identity == running_commitment.process_identity);
    REQUIRE(running->filesystem_identity == running_commitment.filesystem_identity);
    REQUIRE((*registry)->running_status("session-1") == running);
    REQUIRE(!(*registry)->starting_status("session-1").has_value());
    REQUIRE((*registry)->record_count() == 4);
    auto running_candidates = (*registry)->recovery_candidates();
    REQUIRE(running_candidates.has_value());
    REQUIRE(running_candidates->size() == 1);
    REQUIRE(running_candidates->front().session == running->session);
    REQUIRE(running_candidates->front().running_at_ms == running->running_at_ms);
    REQUIRE(running_candidates->front().process_identity == running->process_identity);
    REQUIRE(running_candidates->front().cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(running_candidates->front().filesystem_identity == running->filesystem_identity);
    REQUIRE(
        (*registry)->mark_running(
            running_commitment, *receipt_reservation, "running-session-1", 3'000
        ) == running
    );

    auto direct_created = (*registry)->create(
        "session-direct", controller_digest, direct_write_plan(), "create-session-direct", 1'003
    );
    REQUIRE(direct_created.has_value());
    const glove::control::session_start_authorization direct_authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-direct",
        .session_id = "session-direct",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = direct_created->plan_content_digest,
        .approved_at_ms = 1'004,
        .expires_at_ms = 2'004,
    };
    auto direct_reservation =
        (*registry)->reserve_start(direct_authorization, "reserve-session-direct", 1'005);
    REQUIRE(!direct_reservation.has_value());
    REQUIRE(
        direct_reservation.error().code ==
        glove::control::session_registry_error_code::invalid_authorization
    );
    REQUIRE((*registry)->status("session-direct")->state == glove::control::session_state::created);
    REQUIRE((*registry)->record_count() == 5);

    registry->reset();
    auto recovered = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(recovered.has_value());
    REQUIRE((*recovered)->record_count() == 5);
    REQUIRE((*recovered)->status("session-1") == running->session);
    REQUIRE((*recovered)->running_status("session-1") == running);
    REQUIRE(!(*recovered)->starting_status("session-1").has_value());
    REQUIRE((*recovered)->canonical_plan("session-1") == canonical);
    REQUIRE((*recovered)->reserve_start(authorization, "reserve-session-1", 3'000) == reserved);
    REQUIRE(
        (*recovered)
            ->mark_starting(execution_binding, *receipt_reservation, "starting-session-1", 3'000) ==
        starting
    );
    REQUIRE(
        (*recovered)
            ->create("session-1", controller_digest, valid_plan(), "create-session-1", 62'000) ==
        created
    );
    bool observed_committed_identity = false;
    const glove::control::session_process_observer mismatch_observer =
        [&](
            const glove::control::session_recovery_record& candidate
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        observed_committed_identity = candidate.process_identity == running->process_identity;
        return glove::control::session_process_observation::mismatch;
    };
    auto mismatched = glove::control::reconcile_session_registry(
        **recovered, **producer, 3'000, mismatch_observer
    );
    REQUIRE(mismatched.has_value());
    REQUIRE(observed_committed_identity);
    REQUIRE(mismatched->inspected == 1);
    REQUIRE(mismatched->recovered_exited == 0);
    REQUIRE(mismatched->recovered_failed == 0);
    REQUIRE(mismatched->unresolved_running_session_ids.empty());
    REQUIRE(mismatched->live_running_session_ids.empty());
    REQUIRE(mismatched->identity_mismatch_session_ids == std::vector<std::string>{"session-1"});
    REQUIRE((*recovered)->running_status("session-1") == running);

    const glove::control::session_process_observer exact_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::exact;
    };
    auto live =
        glove::control::reconcile_session_registry(**recovered, **producer, 3'000, exact_observer);
    REQUIRE(live.has_value());
    REQUIRE(live->inspected == 1);
    REQUIRE(live->recovered_exited == 0);
    REQUIRE(live->recovered_failed == 0);
    REQUIRE(live->unresolved_running_session_ids.empty());
    REQUIRE(live->live_running_session_ids == std::vector<std::string>{"session-1"});
    REQUIRE(live->identity_mismatch_session_ids.empty());
    REQUIRE((*recovered)->running_status("session-1") == running);

    const glove::control::session_failure_commitment abandoned_failure{
        .schema_version = 1,
        .session_id = execution_binding.session_id,
        .controller_plan_digest = execution_binding.controller_plan_digest,
        .plan_content_digest = execution_binding.plan_content_digest,
        .authorization_id = execution_binding.authorization_id,
        .profile_digest = execution_binding.profile_digest,
        .code = glove::control::session_failure_code::supervisor_error,
    };
    auto wrong_failure = abandoned_failure;
    wrong_failure.profile_digest = std::string(64, 'f');
    REQUIRE(
        !(*recovered)->mark_failed(wrong_failure, "fail-session-wrong-profile", 3'001).has_value()
    );
    auto wrong_running_failure = abandoned_failure;
    wrong_running_failure.code = glove::control::session_failure_code::launch_failed;
    REQUIRE(!(*recovered)
                 ->mark_failed(wrong_running_failure, "fail-session-wrong-running-code", 3'001)
                 .has_value());
    const glove::control::session_process_observer terminated_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::terminated;
    };
    auto terminated = glove::control::reconcile_session_registry(
        **recovered, **producer, 3'001, terminated_observer
    );
    REQUIRE(terminated.has_value());
    REQUIRE(terminated->inspected == 1);
    REQUIRE(terminated->recovered_failed == 1);
    REQUIRE(terminated->recovered_terminated == 1);
    auto failed = (*recovered)->failed_status("session-1");
    REQUIRE(failed.has_value());
    REQUIRE(failed->session.state == glove::control::session_state::failed);
    REQUIRE(failed->profile_digest == execution_binding.profile_digest);
    REQUIRE(failed->starting_at_ms == starting->starting_at_ms);
    REQUIRE(failed->running_at_ms == running->running_at_ms);
    REQUIRE(failed->process_identity == running->process_identity);
    REQUIRE(failed->cgroup_identity == execution_binding.cgroup_identity);
    REQUIRE(failed->filesystem_identity == running->filesystem_identity);
    REQUIRE(failed->failed_at_ms == 3'001);
    REQUIRE(failed->code == glove::control::session_failure_code::recovered_terminated);
    REQUIRE((*recovered)->failed_status("session-1") == failed);
    REQUIRE(!(*recovered)->starting_status("session-1").has_value());
    REQUIRE((*recovered)->record_count() == 6);
    auto changed_failure = abandoned_failure;
    changed_failure.code = glove::control::session_failure_code::launch_failed;
    REQUIRE(!(*recovered)->mark_failed(changed_failure, "fail-session-1", 3'002).has_value());
    REQUIRE(
        !(*recovered)->mark_failed(abandoned_failure, "fail-session-duplicate", 3'002).has_value()
    );

    auto terminal_created = (*recovered)
                                ->create(
                                    "session-terminal",
                                    controller_digest,
                                    valid_plan_at(3'002),
                                    "create-session-terminal",
                                    3'002
                                );
    REQUIRE(terminal_created.has_value());
    const glove::control::session_start_authorization terminal_authorization{
        .schema_version = 1,
        .authorization_id = "approval-session-terminal",
        .session_id = "session-terminal",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = terminal_created->plan_content_digest,
        .approved_at_ms = 3'003,
        .expires_at_ms = 4'003,
    };
    auto terminal_start =
        (*recovered)->reserve_start(terminal_authorization, "reserve-session-terminal", 3'004);
    REQUIRE(terminal_start.has_value());
    const glove::control::session_execution_binding terminal_binding{
        .schema_version = 1,
        .session_id = "session-terminal",
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = terminal_created->plan_content_digest,
        .authorization_id = terminal_authorization.authorization_id,
        .profile_digest = std::string(64, 'a'),
        .cgroup_identity = cgroup_identity(4343),
        .filesystem_identity = filesystem_identity(),
    };
    auto terminal_reservation = (*producer)->reserve_terminal(
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_binding.profile_digest
    );
    REQUIRE(terminal_reservation.has_value());
    auto terminal_starting =
        (*recovered)
            ->mark_starting(
                terminal_binding, *terminal_reservation, "starting-session-terminal", 3'005
            );
    REQUIRE(terminal_starting.has_value());
    const glove::control::session_running_commitment terminal_running_commitment{
        .schema_version = 1,
        .session_id = terminal_binding.session_id,
        .controller_plan_digest = terminal_binding.controller_plan_digest,
        .plan_content_digest = terminal_binding.plan_content_digest,
        .authorization_id = terminal_binding.authorization_id,
        .profile_digest = terminal_binding.profile_digest,
        .process_identity = process_identity(4343),
        .filesystem_identity = filesystem_identity(),
    };
    auto terminal_running = (*recovered)
                                ->mark_running(
                                    terminal_running_commitment,
                                    *terminal_reservation,
                                    "running-session-terminal",
                                    3'006
                                );
    REQUIRE(terminal_running.has_value());
    auto wrong_stopping_commitment = terminal_running_commitment;
    ++wrong_stopping_commitment.process_identity.start_time_ticks;
    REQUIRE(
        !(*recovered)
             ->mark_stopping(wrong_stopping_commitment, "stopping-session-terminal-wrong", 3'007)
             .has_value()
    );
    auto terminal_stopping =
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 3'007);
    REQUIRE(terminal_stopping.has_value());
    REQUIRE(terminal_stopping->session.state == glove::control::session_state::stopping);
    REQUIRE(terminal_stopping->profile_digest == terminal_running->profile_digest);
    REQUIRE(terminal_stopping->starting_at_ms == terminal_running->starting_at_ms);
    REQUIRE(terminal_stopping->running_at_ms == terminal_running->running_at_ms);
    REQUIRE(terminal_stopping->stopping_at_ms == 3'007);
    REQUIRE(terminal_stopping->process_identity == terminal_running->process_identity);
    REQUIRE(terminal_stopping->filesystem_identity == terminal_running->filesystem_identity);
    REQUIRE((*recovered)->stopping_status("session-terminal") == terminal_stopping);
    REQUIRE(!(*recovered)->running_status("session-terminal").has_value());
    auto stopping_candidates = (*recovered)->recovery_candidates();
    REQUIRE(stopping_candidates.has_value());
    REQUIRE(stopping_candidates->size() == 1);
    REQUIRE(stopping_candidates->front().session == terminal_stopping->session);
    REQUIRE(stopping_candidates->front().stopping_at_ms == terminal_stopping->stopping_at_ms);
    REQUIRE(stopping_candidates->front().process_identity == terminal_stopping->process_identity);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );
    auto changed_stopping_commitment = terminal_running_commitment;
    ++changed_stopping_commitment.process_identity.cgroup_inode;
    REQUIRE(!(*recovered)
                 ->mark_stopping(changed_stopping_commitment, "stopping-session-terminal", 3'008)
                 .has_value());
    REQUIRE(!(*recovered)
                 ->mark_stopping(
                     terminal_running_commitment, "stopping-session-terminal-duplicate", 3'008
                 )
                 .has_value());
    auto terminal = (*producer)->commit_terminal(
        std::move(*terminal_reservation),
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_receipt(terminal_binding.profile_digest, 3'005, 3'500)
    );
    REQUIRE(terminal.has_value());
    auto forged_terminal = *terminal;
    forged_terminal.this_hmac = std::string(64, 'f');
    REQUIRE(!(*recovered)
                 ->mark_exited(forged_terminal, **producer, "exited-session-terminal-forged")
                 .has_value());
    auto terminal_lookup = (*producer)->terminal_for_execution(
        terminal_binding.session_id,
        terminal_binding.controller_plan_digest,
        terminal_binding.profile_digest
    );
    REQUIRE(terminal_lookup.has_value());
    REQUIRE(terminal_lookup->has_value());
    REQUIRE(**terminal_lookup == *terminal);
    auto reconciled = glove::control::reconcile_session_registry(**recovered, **producer, 3'501);
    REQUIRE(reconciled.has_value());
    REQUIRE(reconciled->inspected == 1);
    REQUIRE(reconciled->recovered_exited == 1);
    REQUIRE(reconciled->recovered_failed == 0);
    REQUIRE(reconciled->unresolved_running_session_ids.empty());
    auto exited = (*recovered)->exited_status("session-terminal");
    REQUIRE(exited.has_value());
    REQUIRE(exited->session.state == glove::control::session_state::exited);
    REQUIRE(exited->profile_digest == terminal_binding.profile_digest);
    REQUIRE(exited->starting_at_ms == terminal_starting->starting_at_ms);
    REQUIRE(exited->running_at_ms == terminal_running->running_at_ms);
    REQUIRE(exited->stopping_at_ms == terminal_stopping->stopping_at_ms);
    REQUIRE(exited->process_identity == terminal_running->process_identity);
    REQUIRE(exited->filesystem_identity == terminal_running->filesystem_identity);
    REQUIRE(exited->finished_at_ms == terminal->receipt.finished_at_ms);
    REQUIRE(exited->receipt_sequence == terminal->sequence);
    REQUIRE(exited->receipt_key_id == terminal->key_id);
    REQUIRE(exited->receipt_digest == terminal->receipt_digest);
    REQUIRE(exited->receipt_hmac == terminal->this_hmac);
    REQUIRE(exited->exit_code == terminal->receipt.exit_code);
    REQUIRE((*recovered)->exited_status("session-terminal") == exited);
    REQUIRE((*recovered)->record_count() == 12);
    REQUIRE((*recovered)->mark_exited(*terminal, **producer, "recovery-exit-1") == exited);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );
    REQUIRE(!(*recovered)
                 ->mark_exited(*terminal, **producer, "exited-session-terminal-duplicate")
                 .has_value());
    REQUIRE(!(*recovered)
                 ->mark_running(
                     terminal_running_commitment,
                     *receipt_reservation,
                     "running-session-terminal-after-exit",
                     3'501
                 )
                 .has_value());

    recovered->reset();
    recovered = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(recovered.has_value());
    REQUIRE((*recovered)->record_count() == 12);
    REQUIRE((*recovered)->status("session-1") == failed->session);
    REQUIRE((*recovered)->failed_status("session-1") == failed);
    REQUIRE((*recovered)->status("session-terminal") == exited->session);
    REQUIRE((*recovered)->exited_status("session-terminal") == exited);
    REQUIRE(
        (*recovered)
            ->mark_stopping(terminal_running_commitment, "stopping-session-terminal", 4'500) ==
        terminal_stopping
    );

    const auto recovery_store_path = temp.root() / "recovery-sessions.journal";
    auto recovery_registry =
        glove::control::session_registry::open_or_create(recovery_store_path, shared_validator);
    REQUIRE(recovery_registry.has_value());
    auto recovery_created = (*recovery_registry)
                                ->create(
                                    "session-starting-recovery",
                                    controller_digest,
                                    valid_plan_at(4'000),
                                    "create-starting-recovery",
                                    4'000
                                );
    REQUIRE(recovery_created.has_value());
    const glove::control::session_start_authorization recovery_authorization{
        .schema_version = 1,
        .authorization_id = "approval-starting-recovery",
        .session_id = recovery_created->session_id,
        .controller_plan_digest = recovery_created->controller_plan_digest,
        .plan_content_digest = recovery_created->plan_content_digest,
        .approved_at_ms = 4'001,
        .expires_at_ms = 5'001,
    };
    REQUIRE((*recovery_registry)
                ->reserve_start(recovery_authorization, "reserve-starting-recovery", 4'002)
                .has_value());
    const glove::control::session_execution_binding recovery_binding{
        .schema_version = 1,
        .session_id = recovery_created->session_id,
        .controller_plan_digest = recovery_created->controller_plan_digest,
        .plan_content_digest = recovery_created->plan_content_digest,
        .authorization_id = recovery_authorization.authorization_id,
        .profile_digest = std::string(64, 'b'),
        .cgroup_identity = cgroup_identity(4545),
        .filesystem_identity = filesystem_identity(),
    };
    auto recovery_receipt_reservation = (*producer)->reserve_terminal(
        recovery_binding.session_id,
        recovery_binding.controller_plan_digest,
        recovery_binding.profile_digest
    );
    REQUIRE(recovery_receipt_reservation.has_value());
    REQUIRE((*recovery_registry)
                ->mark_starting(
                    recovery_binding, *recovery_receipt_reservation, "starting-recovery", 4'003
                )
                .has_value());
    auto recovered_starting =
        glove::control::reconcile_session_registry(**recovery_registry, **producer, 4'004);
    REQUIRE(recovered_starting.has_value());
    REQUIRE(recovered_starting->inspected == 1);
    REQUIRE(recovered_starting->recovered_exited == 0);
    REQUIRE(recovered_starting->recovered_failed == 1);
    REQUIRE(recovered_starting->unresolved_running_session_ids.empty());
    auto recovered_failure = (*recovery_registry)->failed_status("session-starting-recovery");
    REQUIRE(recovered_failure.has_value());
    REQUIRE(
        recovered_failure->code == glove::control::session_failure_code::recovered_without_process
    );
    REQUIRE(recovered_failure->running_at_ms == 0);
    REQUIRE(!recovered_failure->process_identity.has_value());
    REQUIRE(recovered_failure->cgroup_identity == recovery_binding.cgroup_identity);
    REQUIRE(recovered_failure->filesystem_identity == recovery_binding.filesystem_identity);
    REQUIRE((*recovery_registry)->record_count() == 4);
    auto recovery_replay =
        glove::control::reconcile_session_registry(**recovery_registry, **producer, 4'005);
    REQUIRE(recovery_replay.has_value());
    REQUIRE(recovery_replay->inspected == 0);
    REQUIRE((*recovery_registry)->record_count() == 4);

    auto absent_created = (*recovery_registry)
                              ->create(
                                  "session-absent-recovery",
                                  controller_digest,
                                  valid_plan_at(5'000),
                                  "create-absent-recovery",
                                  5'000
                              );
    REQUIRE(absent_created.has_value());
    const glove::control::session_start_authorization absent_authorization{
        .schema_version = 1,
        .authorization_id = "approval-absent-recovery",
        .session_id = absent_created->session_id,
        .controller_plan_digest = absent_created->controller_plan_digest,
        .plan_content_digest = absent_created->plan_content_digest,
        .approved_at_ms = 5'001,
        .expires_at_ms = 6'001,
    };
    REQUIRE((*recovery_registry)
                ->reserve_start(absent_authorization, "reserve-absent-recovery", 5'002)
                .has_value());
    const glove::control::session_execution_binding absent_binding{
        .schema_version = 1,
        .session_id = absent_created->session_id,
        .controller_plan_digest = absent_created->controller_plan_digest,
        .plan_content_digest = absent_created->plan_content_digest,
        .authorization_id = absent_authorization.authorization_id,
        .profile_digest = std::string(64, 'e'),
        .cgroup_identity = cgroup_identity(4444),
        .filesystem_identity = filesystem_identity(),
    };
    auto absent_receipt_reservation = (*producer)->reserve_terminal(
        absent_binding.session_id,
        absent_binding.controller_plan_digest,
        absent_binding.profile_digest
    );
    REQUIRE(absent_receipt_reservation.has_value());
    REQUIRE((*recovery_registry)
                ->mark_starting(
                    absent_binding, *absent_receipt_reservation, "starting-absent-recovery", 5'003
                )
                .has_value());
    const glove::control::session_running_commitment absent_running_commitment{
        .schema_version = 1,
        .session_id = absent_binding.session_id,
        .controller_plan_digest = absent_binding.controller_plan_digest,
        .plan_content_digest = absent_binding.plan_content_digest,
        .authorization_id = absent_binding.authorization_id,
        .profile_digest = absent_binding.profile_digest,
        .process_identity = process_identity(4444),
        .filesystem_identity = filesystem_identity(),
    };
    REQUIRE((*recovery_registry)
                ->mark_running(
                    absent_running_commitment,
                    *absent_receipt_reservation,
                    "running-absent-recovery",
                    5'004
                )
                .has_value());
    auto absent_stopping =
        (*recovery_registry)
            ->mark_stopping(absent_running_commitment, "stopping-absent-recovery", 5'005);
    REQUIRE(absent_stopping.has_value());
    const glove::control::session_process_observer absent_observer =
        [](
            const glove::control::session_recovery_record&
        ) -> std::expected<glove::control::session_process_observation, std::string> {
        return glove::control::session_process_observation::absent;
    };
    auto absent_reconciled = glove::control::reconcile_session_registry(
        **recovery_registry, **producer, 5'006, absent_observer
    );
    REQUIRE(absent_reconciled.has_value());
    REQUIRE(absent_reconciled->inspected == 1);
    REQUIRE(absent_reconciled->recovered_exited == 0);
    REQUIRE(absent_reconciled->recovered_failed == 1);
    REQUIRE(absent_reconciled->unresolved_running_session_ids.empty());
    REQUIRE(absent_reconciled->live_running_session_ids.empty());
    REQUIRE(absent_reconciled->identity_mismatch_session_ids.empty());
    auto absent_failure = (*recovery_registry)->failed_status(absent_running_commitment.session_id);
    REQUIRE(absent_failure.has_value());
    REQUIRE(
        absent_failure->code == glove::control::session_failure_code::recovered_without_process
    );
    REQUIRE(absent_failure->process_identity == absent_running_commitment.process_identity);
    REQUIRE(absent_failure->filesystem_identity == absent_running_commitment.filesystem_identity);
    REQUIRE(absent_failure->stopping_at_ms == absent_stopping->stopping_at_ms);
    REQUIRE((*recovery_registry)->record_count() == 10);

    {
        std::ofstream output{store_path, std::ios::binary | std::ios::app};
        output.put('x');
    }
    REQUIRE(!(*recovered)->status("session-1").has_value());

    recovered->reset();
    REQUIRE(::chmod(store_path.c_str(), 0644) == 0);
    REQUIRE(
        !glove::control::session_registry::open_or_create(store_path, shared_validator).has_value()
    );
    REQUIRE(::chmod(store_path.c_str(), 0600) == 0);
    const auto insecure_parent = temp.root() / "insecure-parent";
    REQUIRE(std::filesystem::create_directory(insecure_parent));
    REQUIRE(::chmod(insecure_parent.c_str(), 0755) == 0);
    const auto insecure_store = insecure_parent / "sessions.journal";
    REQUIRE(!glove::control::session_registry::open_or_create(insecure_store, shared_validator)
                 .has_value());
    REQUIRE(!std::filesystem::exists(insecure_store));
    REQUIRE(
        !glove::control::session_registry::open_or_create(store_path, shared_validator).has_value()
    );
    return 0;
}

auto run_managed_runtime_registry() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    auto validator = validator_for(source, glove::supervisor::sandbox_backend::apple_container);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto store_path = temp.root() / "managed-sessions.journal";
    auto registry = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    auto created = (*registry)->create(
        "managed-session", controller_digest, managed_plan(), "managed-create", 1'000
    );
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "managed-approval",
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = 1'001,
        .expires_at_ms = 5'000,
    };
    REQUIRE((*registry)->reserve_start(authorization, "managed-reserve", 1'002).has_value());

    const auto audit_key_path = temp.root() / "managed-receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = temp.root() / "managed-receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
    const glove::control::managed_runtime_recovery_identity runtime_identity{
        .schema_version = 1,
        .backend = "apple_container",
        .instance_id = "glove-managed-session",
        .launch_identity_digest = std::string(64, '7'),
    };
    const glove::control::managed_session_execution_binding binding{
        .schema_version = 1,
        .session_id = created->session_id,
        .controller_plan_digest = created->controller_plan_digest,
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = std::string(64, '8'),
        .runtime_identity = runtime_identity,
    };
    auto receipt_reservation = (*producer)->reserve_terminal(
        binding.session_id, binding.controller_plan_digest, binding.profile_digest
    );
    REQUIRE(receipt_reservation.has_value());
    auto starting = (*registry)->mark_managed_starting(
        binding, *receipt_reservation, "managed-starting", 1'003
    );
    REQUIRE(starting.has_value());
    REQUIRE(starting->runtime_identity == runtime_identity);
    REQUIRE((*registry)->managed_recovery_candidates()->size() == 1);
    REQUIRE((*registry)->recovery_candidates()->empty());
    REQUIRE(
        (*registry)->mark_managed_starting(
            binding, *receipt_reservation, "managed-starting", 9'000
        ) == starting
    );
    auto changed_binding = binding;
    changed_binding.runtime_identity.instance_id = "changed-instance";
    REQUIRE(!(*registry)
                 ->mark_managed_starting(
                     changed_binding, *receipt_reservation, "managed-starting", 1'004
                 )
                 .has_value());

    const glove::control::managed_session_running_commitment running_commitment{
        .schema_version = 1,
        .session_id = binding.session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = binding.profile_digest,
        .runtime_identity = runtime_identity,
    };
    auto running = (*registry)->mark_managed_running(
        running_commitment, *receipt_reservation, "managed-running", 1'004
    );
    REQUIRE(running.has_value());
    REQUIRE(running->session.state == glove::control::session_state::running);
    auto stopping =
        (*registry)->mark_managed_stopping(running_commitment, "managed-stopping", 1'005);
    REQUIRE(stopping.has_value());
    REQUIRE(stopping->session.state == glove::control::session_state::stopping);

    registry->reset();
    registry = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    auto recovered = (*registry)->managed_recovery_candidates();
    REQUIRE(recovered.has_value());
    REQUIRE(recovered->size() == 1);
    REQUIRE(recovered->front() == *stopping);

    auto receipt = terminal_receipt(binding.profile_digest, 1'003, 1'006);
    receipt.backend = glove::container::sandbox_backend::apple_container;
    receipt.backend_id = "apple-container:vm-v1";
    auto terminal = (*producer)->commit_terminal(
        std::move(*receipt_reservation),
        binding.session_id,
        binding.controller_plan_digest,
        std::move(receipt)
    );
    REQUIRE(terminal.has_value());
    auto exited = (*registry)->mark_managed_exited(*terminal, **producer, "managed-exited");
    REQUIRE(exited.has_value());
    REQUIRE(exited->lifecycle.runtime_identity == runtime_identity);
    REQUIRE(exited->termination_cause == glove::container::resource_termination_cause::exited);
    REQUIRE((*registry)->managed_recovery_candidates()->empty());

    registry->reset();
    registry = glove::control::session_registry::open_or_create(store_path, shared_validator);
    REQUIRE(registry.has_value());
    REQUIRE((*registry)->record_count() == 6);
    REQUIRE(
        (*registry)->managed_lifecycle_status(binding.session_id)->session.state ==
        glove::control::session_state::exited
    );
    return 0;
}

auto run_intent_queue_contract() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    auto validator = validator_for(source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));

    const auto bundle_root = temp.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(bundle_root));
    REQUIRE(::chmod(bundle_root.c_str(), 0700) == 0);
    const auto bundle_path = bundle_root / (library_bundle_digest() + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary};
        output.write(library_bundle.data(), static_cast<std::streamsize>(library_bundle.size()));
    }
    REQUIRE(::chmod(bundle_path.c_str(), 0600) == 0);
    auto opened_bundle_store = glove::supervisor::library_bundle_store::open(bundle_root);
    REQUIRE(opened_bundle_store.has_value());
    auto shared_bundle_store = std::make_shared<const glove::supervisor::library_bundle_store>(
        std::move(*opened_bundle_store)
    );

    const auto audit_key_path = temp.root() / "intent-receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = temp.root() / "intent-receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());

    const auto store_path = temp.root() / "intent-sessions.journal";
    auto registry = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(registry.has_value());

    const auto start_session =
        [&](
            std::string session_id, std::uint64_t start_ms, std::uint32_t pid, char profile_byte
        ) -> std::expected<glove::control::session_running_commitment, std::string> {
        auto created = (*registry)->create(
            session_id,
            controller_digest,
            sage_guest_plan_at(start_ms),
            "create-" + session_id,
            start_ms
        );
        if (!created) {
            return std::unexpected(created.error().message);
        }
        const glove::control::session_start_authorization authorization{
            .schema_version = 1,
            .authorization_id = "approval-" + session_id,
            .session_id = session_id,
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .approved_at_ms = start_ms + 1U,
            .expires_at_ms = start_ms + 60'000U,
        };
        auto reserved =
            (*registry)->reserve_start(authorization, "reserve-" + session_id, start_ms + 2U);
        if (!reserved) {
            return std::unexpected(reserved.error().message);
        }
        const glove::control::session_execution_binding binding{
            .schema_version = 1,
            .session_id = session_id,
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .authorization_id = authorization.authorization_id,
            .profile_digest = std::string(64, profile_byte),
            .cgroup_identity = cgroup_identity(pid),
            .filesystem_identity = filesystem_identity(),
        };
        auto reservation = (*producer)->reserve_terminal(
            binding.session_id, binding.controller_plan_digest, binding.profile_digest
        );
        if (!reservation) {
            return std::unexpected(reservation.error());
        }
        auto starting = (*registry)->mark_starting(
            binding, *reservation, "starting-" + session_id, start_ms + 3U
        );
        if (!starting) {
            return std::unexpected(starting.error().message);
        }
        glove::control::session_running_commitment running{
            .schema_version = 1,
            .session_id = session_id,
            .controller_plan_digest = binding.controller_plan_digest,
            .plan_content_digest = binding.plan_content_digest,
            .authorization_id = binding.authorization_id,
            .profile_digest = binding.profile_digest,
            .process_identity = process_identity(pid),
            .filesystem_identity = binding.filesystem_identity,
        };
        auto marked = (*registry)->mark_running(
            running, *reservation, "running-" + session_id, start_ms + 4U
        );
        if (!marked) {
            return std::unexpected(marked.error().message);
        }
        return running;
    };

    auto running_a = start_session("sage-session-a", 10'000, 6001, 'a');
    auto running_b = start_session("sage-session-b", 20'000, 6002, 'b');
    REQUIRE(running_a.has_value());
    REQUIRE(running_b.has_value());

    const glove::control::glove_observation_body body{
        .schema = std::string{test_observation_schema},
        .intent_id = "intent-1",
        .observation = "guest-capability-inventory",
        .value_digest = std::string(64, 'a'),
        .item_count = 4,
    };
    const glove::control::observation_intent_context context_a{
        .session_id = running_a->session_id,
        .controller_plan_digest = running_a->controller_plan_digest,
        .profile_digest = running_a->profile_digest,
        .runtime_id = "sage-guest",
        .projection_digest = std::string(64, 'c'),
        .policy_revision = 7,
        .channel_id = "sage-session-a-observation-v1",
        .channel_generation = 1,
        .issued_at_ms = 30'000,
        .expires_at_ms = 40'000,
    };

    auto enqueued = (*registry)->enqueue_observation_intent(body, context_a, 30'000);
    REQUIRE(enqueued.has_value());
    REQUIRE(enqueued->body == body);
    REQUIRE(enqueued->context == context_a);
    REQUIRE(enqueued->disposition == glove::control::intent_disposition::pending);
    REQUIRE(
        enqueued->intent_digest ==
        "9cbc0bb0de2ed9d104318e9b5a5c8641af770c672511e5102e0ba4b61549b6b2"
    );
    const auto count_after_enqueue = (*registry)->record_count();

    auto replayed = (*registry)->enqueue_observation_intent(body, context_a, 30'001);
    REQUIRE(replayed == enqueued);
    REQUIRE((*registry)->record_count() == count_after_enqueue);
    auto replayed_after_expiry =
        (*registry)->enqueue_observation_intent(body, context_a, context_a.expires_at_ms);
    REQUIRE(replayed_after_expiry == enqueued);
    REQUIRE((*registry)->record_count() == count_after_enqueue);

    // Durable replay excludes only reconstructed timestamps. Every immutable
    // security-context field must still match the first accepted enqueue.
    for (const auto& drifted : {
             [&] {
                 auto value = context_a;
                 value.controller_plan_digest = std::string(64, 'd');
                 return value;
             }(),
             [&] {
                 auto value = context_a;
                 value.profile_digest = std::string(64, 'f');
                 return value;
             }(),
             [&] {
                 auto value = context_a;
                 value.runtime_id = "other-guest";
                 return value;
             }(),
             [&] {
                 auto value = context_a;
                 value.projection_digest = std::string(64, 'e');
                 return value;
             }(),
             [&] {
                 auto value = context_a;
                 value.policy_revision += 1U;
                 return value;
             }(),
             [&] {
                 auto value = context_a;
                 value.channel_id = "sage-session-a-observation-drifted";
                 return value;
             }(),
         }) {
        auto conflict = (*registry)->enqueue_observation_intent(body, drifted, 30'001);
        REQUIRE(!conflict.has_value());
        REQUIRE(
            conflict.error().code ==
            glove::control::session_registry_error_code::idempotency_conflict
        );
    }
    REQUIRE((*registry)->record_count() == count_after_enqueue);

    auto changed_body = body;
    changed_body.item_count = 5;
    auto body_conflict = (*registry)->enqueue_observation_intent(changed_body, context_a, 30'001);
    REQUIRE(!body_conflict.has_value());
    REQUIRE(
        body_conflict.error().code ==
        glove::control::session_registry_error_code::idempotency_conflict
    );
    auto body_conflict_after_expiry = (*registry)->enqueue_observation_intent(
        changed_body, context_a, context_a.expires_at_ms + 1U
    );
    REQUIRE(!body_conflict_after_expiry.has_value());
    REQUIRE(
        body_conflict_after_expiry.error().code ==
        glove::control::session_registry_error_code::idempotency_conflict
    );

    auto cross_session = context_a;
    cross_session.session_id = running_b->session_id;
    cross_session.profile_digest = running_b->profile_digest;
    cross_session.channel_id = "sage-session-b-observation-v1";
    auto enqueued_cross_session =
        (*registry)->enqueue_observation_intent(body, cross_session, 30'001);
    REQUIRE(enqueued_cross_session.has_value());
    REQUIRE(enqueued_cross_session->sequence != enqueued->sequence);
    REQUIRE(enqueued_cross_session->context.session_id == running_b->session_id);

    auto next_generation = context_a;
    next_generation.channel_generation = 2;
    next_generation.channel_id = "sage-session-a-observation-v2";
    auto enqueued_next_generation =
        (*registry)->enqueue_observation_intent(body, next_generation, 30'002);
    REQUIRE(enqueued_next_generation.has_value());
    REQUIRE(enqueued_next_generation->sequence != enqueued->sequence);

    auto invalid_body = body;
    invalid_body.schema = "test.observation.v2";
    REQUIRE(!(*registry)->enqueue_observation_intent(invalid_body, context_a, 30'002).has_value());
    invalid_body = body;
    invalid_body.intent_id = std::string(129, 'i');
    REQUIRE(!(*registry)->enqueue_observation_intent(invalid_body, context_a, 30'002).has_value());
    invalid_body = body;
    invalid_body.value_digest = "not-a-digest";
    REQUIRE(!(*registry)->enqueue_observation_intent(invalid_body, context_a, 30'002).has_value());
    invalid_body = body;
    invalid_body.item_count = 4'097;
    REQUIRE(!(*registry)->enqueue_observation_intent(invalid_body, context_a, 30'002).has_value());

    auto unseen_body = body;
    unseen_body.intent_id = "intent-context-validation";
    auto mismatched_context = context_a;
    mismatched_context.profile_digest = std::string(64, 'f');
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());
    mismatched_context = context_a;
    mismatched_context.runtime_id = "codex";
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());
    mismatched_context = context_a;
    mismatched_context.policy_revision = 8;
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());
    mismatched_context = context_a;
    mismatched_context.channel_generation = 0;
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());
    mismatched_context = context_a;
    mismatched_context.expires_at_ms = mismatched_context.issued_at_ms + 600'001U;
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());
    mismatched_context = context_a;
    mismatched_context.expires_at_ms = 29'999;
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(unseen_body, mismatched_context, 30'002)
                 .has_value());

    auto second_body = body;
    second_body.intent_id = "intent-2";
    second_body.value_digest = std::string(64, 'd');
    auto second_context = context_a;
    second_context.issued_at_ms = 30'003;
    second_context.expires_at_ms = 30'100;
    auto second = (*registry)->enqueue_observation_intent(second_body, second_context, 30'003);
    REQUIRE(second.has_value());

    auto first_page = (*registry)->pending_observation_intents(0, 2, 30'004);
    REQUIRE(first_page.has_value());
    REQUIRE(first_page->items.size() == 2U);
    REQUIRE(first_page->items[0].sequence < first_page->items[1].sequence);
    REQUIRE(first_page->next_after_sequence.has_value());
    auto second_page =
        (*registry)->pending_observation_intents(*first_page->next_after_sequence, 2, 30'004);
    REQUIRE(second_page.has_value());
    REQUIRE(!second_page->items.empty());
    REQUIRE(second_page->items.front().sequence > first_page->items.back().sequence);
    REQUIRE(!(*registry)->pending_observation_intents(0, 0, 30'004).has_value());
    REQUIRE(!(*registry)
                 ->pending_observation_intents(
                     0, glove::control::max_pending_intent_page_size + 1U, 30'004
                 )
                 .has_value());

    const glove::control::observation_intent_disposition accepted{
        .session_id = context_a.session_id,
        .channel_generation = context_a.channel_generation,
        .intent_id = body.intent_id,
        .intent_digest = enqueued->intent_digest,
        .disposition = glove::control::intent_disposition::accepted,
        .decided_at_ms = 30'005,
    };
    auto accepted_result = (*registry)->set_observation_intent_disposition(accepted);
    REQUIRE(accepted_result.has_value());
    REQUIRE(accepted_result->disposition == glove::control::intent_disposition::accepted);
    const auto count_after_accept = (*registry)->record_count();
    auto reconstructed_context = context_a;
    reconstructed_context.issued_at_ms = 50'000;
    reconstructed_context.expires_at_ms = 60'000;
    auto replayed_after_disposition =
        (*registry)->enqueue_observation_intent(body, reconstructed_context, 50'000);
    REQUIRE(replayed_after_disposition == accepted_result);
    REQUIRE(replayed_after_disposition->context == context_a);
    REQUIRE((*registry)->record_count() == count_after_accept);
    REQUIRE((*registry)->set_observation_intent_disposition(accepted) == accepted_result);
    REQUIRE((*registry)->record_count() == count_after_accept);
    auto changed_disposition = accepted;
    changed_disposition.disposition = glove::control::intent_disposition::rejected;
    auto disposition_conflict =
        (*registry)->set_observation_intent_disposition(changed_disposition);
    REQUIRE(!disposition_conflict.has_value());
    REQUIRE(
        disposition_conflict.error().code ==
        glove::control::session_registry_error_code::idempotency_conflict
    );

    const glove::control::observation_intent_disposition rejected{
        .session_id = cross_session.session_id,
        .channel_generation = cross_session.channel_generation,
        .intent_id = body.intent_id,
        .intent_digest = enqueued_cross_session->intent_digest,
        .disposition = glove::control::intent_disposition::rejected,
        .decided_at_ms = 30'006,
    };
    REQUIRE((*registry)->set_observation_intent_disposition(rejected).has_value());

    auto expiring_body = body;
    expiring_body.intent_id = "intent-expired";
    expiring_body.value_digest = std::string(64, 'e');
    auto expiring_context = context_a;
    expiring_context.issued_at_ms = 30'007;
    expiring_context.expires_at_ms = 30'020;
    auto expiring =
        (*registry)->enqueue_observation_intent(expiring_body, expiring_context, 30'007);
    REQUIRE(expiring.has_value());
    const glove::control::observation_intent_disposition accepted_at_expiry{
        .session_id = expiring_context.session_id,
        .channel_generation = expiring_context.channel_generation,
        .intent_id = expiring_body.intent_id,
        .intent_digest = expiring->intent_digest,
        .disposition = glove::control::intent_disposition::accepted,
        .decided_at_ms = expiring_context.expires_at_ms,
    };
    REQUIRE(!(*registry)->set_observation_intent_disposition(accepted_at_expiry).has_value());
    auto accepted_after_expiry = accepted_at_expiry;
    accepted_after_expiry.decided_at_ms = expiring_context.expires_at_ms + 1U;
    REQUIRE(!(*registry)->set_observation_intent_disposition(accepted_after_expiry).has_value());
    auto rejected_at_expiry = accepted_at_expiry;
    rejected_at_expiry.disposition = glove::control::intent_disposition::rejected;
    REQUIRE(!(*registry)->set_observation_intent_disposition(rejected_at_expiry).has_value());
    auto rejected_after_expiry = rejected_at_expiry;
    rejected_after_expiry.decided_at_ms = expiring_context.expires_at_ms + 1U;
    REQUIRE(!(*registry)->set_observation_intent_disposition(rejected_after_expiry).has_value());
    auto expired_before_expiry = accepted_at_expiry;
    expired_before_expiry.disposition = glove::control::intent_disposition::expired;
    expired_before_expiry.decided_at_ms = expiring_context.expires_at_ms - 1U;
    REQUIRE(!(*registry)->set_observation_intent_disposition(expired_before_expiry).has_value());

    const glove::control::observation_intent_disposition expired{
        .session_id = expiring_context.session_id,
        .channel_generation = expiring_context.channel_generation,
        .intent_id = expiring_body.intent_id,
        .intent_digest = expiring->intent_digest,
        .disposition = glove::control::intent_disposition::expired,
        .decided_at_ms = expiring_context.expires_at_ms,
    };
    auto expired_result = (*registry)->set_observation_intent_disposition(expired);
    REQUIRE(expired_result.has_value());
    REQUIRE(expired_result->disposition == glove::control::intent_disposition::expired);
    REQUIRE((*registry)->set_observation_intent_disposition(expired) == expired_result);

    const glove::control::glove_observation_body retired_proposal{
        .schema = std::string{test_proposal_schema},
        .intent_id = "proposal-1",
        .observation = "retired-proposal",
        .value_digest = std::string(64, 'a'),
        .item_count = 1,
    };
    auto proposal_context = context_a;
    proposal_context.issued_at_ms = 30'101;
    proposal_context.expires_at_ms = 30'201;
    auto proposed =
        (*registry)->enqueue_observation_intent(retired_proposal, proposal_context, 30'101);
    REQUIRE(proposed.has_value());
    REQUIRE(
        proposed->intent_digest ==
        "1ec5cd4e47e46feb63e3b2cc9836e320c2fe6fa5fca6dd022275631ccc3a81f9"
    );
    auto altered_proposal = retired_proposal;
    altered_proposal.item_count = 2;
    REQUIRE(!(*registry)
                 ->enqueue_observation_intent(altered_proposal, proposal_context, 30'101)
                 .has_value());
    const glove::control::observation_intent_disposition proposal_accepted{
        .session_id = proposal_context.session_id,
        .channel_generation = proposal_context.channel_generation,
        .intent_id = retired_proposal.intent_id,
        .intent_digest = proposed->intent_digest,
        .disposition = glove::control::intent_disposition::accepted,
        .decided_at_ms = 30'102,
    };
    REQUIRE((*registry)->set_observation_intent_disposition(proposal_accepted).has_value());

    auto pending_after_terminal_dispositions =
        (*registry)->pending_observation_intents(0, 16, 30'103);
    REQUIRE(pending_after_terminal_dispositions.has_value());
    REQUIRE(std::ranges::all_of(pending_after_terminal_dispositions->items, [](const auto& item) {
        return item.disposition == glove::control::intent_disposition::pending;
    }));
    REQUIRE(std::ranges::any_of(pending_after_terminal_dispositions->items, [](const auto& item) {
        return item.body.intent_id == "intent-2";
    }));

    registry->reset();
    registry = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(registry.has_value());
    auto recovered_page = (*registry)->pending_observation_intents(0, 16, 30'103);
    REQUIRE(recovered_page.has_value());
    REQUIRE(recovered_page->items.size() == 2U);
    REQUIRE(recovered_page->items[0].sequence < recovered_page->items[1].sequence);
    REQUIRE((*registry)->set_observation_intent_disposition(accepted) == accepted_result);
    REQUIRE((*registry)->set_observation_intent_disposition(expired) == expired_result);
    auto replayed_after_reopen =
        (*registry)->enqueue_observation_intent(body, reconstructed_context, 55'000);
    REQUIRE(replayed_after_reopen == accepted_result);
    REQUIRE(replayed_after_reopen->context == context_a);
    auto expiring_reconstructed_context = expiring_context;
    expiring_reconstructed_context.issued_at_ms = 60'000;
    expiring_reconstructed_context.expires_at_ms = 60'100;
    auto replayed_expired_after_reopen = (*registry)->enqueue_observation_intent(
        expiring_body, expiring_reconstructed_context, 60'000
    );
    REQUIRE(replayed_expired_after_reopen == expired_result);
    REQUIRE(replayed_expired_after_reopen->context == expiring_context);

    // Generalized admission: enqueue on a non-sage runtime binds to the
    // session's parsed runtime_id instead of a hardcoded guest identity.
    {
        auto created = (*registry)->create(
            "codex-session", controller_digest, valid_plan_at(40'000), "create-codex", 40'000
        );
        if (!created) {
            std::fprintf(stderr, "codex create error: %s\n", created.error().message.c_str());
        }
        REQUIRE(created.has_value());
        const glove::control::session_start_authorization codex_authorization{
            .schema_version = 1,
            .authorization_id = "approval-codex-session",
            .session_id = "codex-session",
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .approved_at_ms = 40'001,
            .expires_at_ms = 100'000,
        };
        REQUIRE(
            (*registry)->reserve_start(codex_authorization, "reserve-codex", 40'002).has_value()
        );
        const glove::control::session_execution_binding codex_binding{
            .schema_version = 1,
            .session_id = "codex-session",
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .authorization_id = codex_authorization.authorization_id,
            .profile_digest = std::string(64, '7'),
            .cgroup_identity = cgroup_identity(7001),
            .filesystem_identity = filesystem_identity(),
        };
        auto codex_reservation = (*producer)->reserve_terminal(
            codex_binding.session_id,
            codex_binding.controller_plan_digest,
            codex_binding.profile_digest
        );
        REQUIRE(codex_reservation.has_value());
        REQUIRE((*registry)
                    ->mark_starting(codex_binding, *codex_reservation, "starting-codex", 40'003)
                    .has_value());
        const glove::control::session_running_commitment codex_running{
            .schema_version = 1,
            .session_id = "codex-session",
            .controller_plan_digest = codex_binding.controller_plan_digest,
            .plan_content_digest = codex_binding.plan_content_digest,
            .authorization_id = codex_binding.authorization_id,
            .profile_digest = codex_binding.profile_digest,
            .process_identity = process_identity(7001),
            .filesystem_identity = filesystem_identity(),
        };
        REQUIRE((*registry)
                    ->mark_running(codex_running, *codex_reservation, "running-codex", 40'004)
                    .has_value());
        const glove::control::observation_intent_context codex_context{
            .session_id = "codex-session",
            .controller_plan_digest = codex_binding.controller_plan_digest,
            .profile_digest = codex_binding.profile_digest,
            .runtime_id = "codex",
            .projection_digest = std::string(64, 'c'),
            .policy_revision = 7,
            .channel_id = "codex-session-observation-v1",
            .channel_generation = 1,
            .issued_at_ms = 40'010,
            .expires_at_ms = 40'100,
        };
        auto codex_enqueued = (*registry)->enqueue_observation_intent(body, codex_context, 40'010);
        REQUIRE(codex_enqueued.has_value());
        auto wrong_runtime = codex_context;
        wrong_runtime.runtime_id = "other-guest";
        auto wrong_runtime_replay =
            (*registry)->enqueue_observation_intent(body, wrong_runtime, 40'011);
        REQUIRE(!wrong_runtime_replay.has_value());
        REQUIRE(
            wrong_runtime_replay.error().code ==
            glove::control::session_registry_error_code::idempotency_conflict
        );
        auto unseen_codex_body = body;
        unseen_codex_body.intent_id = "codex-unseen-intent";
        REQUIRE(!(*registry)
                     ->enqueue_observation_intent(unseen_codex_body, wrong_runtime, 40'011)
                     .has_value());
    }

    const auto legacy_store = temp.root() / "legacy-observation-intent-sessions.journal";
    std::string legacy_plan_digest;
    {
        auto legacy_registry = glove::control::session_registry::open_or_create(
            legacy_store, shared_validator, shared_bundle_store
        );
        REQUIRE(legacy_registry.has_value());
        auto legacy_created = (*legacy_registry)
                                  ->create(
                                      "legacy-session",
                                      controller_digest,
                                      valid_plan_at(50'000),
                                      "create-legacy-session",
                                      50'000
                                  );
        REQUIRE(legacy_created.has_value());
        legacy_plan_digest = legacy_created->plan_content_digest;
        legacy_registry->reset();
    }
    REQUIRE(!file_contains(legacy_store, "observation_intent"));
    auto reopened_legacy = glove::control::session_registry::open_or_create(
        legacy_store, shared_validator, shared_bundle_store
    );
    REQUIRE(reopened_legacy.has_value());
    auto legacy_status = (*reopened_legacy)->status("legacy-session");
    REQUIRE(legacy_status.has_value());
    REQUIRE(legacy_status->session_id == "legacy-session");
    REQUIRE(legacy_status->controller_plan_digest == controller_digest);
    REQUIRE(legacy_status->plan_content_digest == legacy_plan_digest);
    REQUIRE(legacy_status->state == glove::control::session_state::created);
    REQUIRE(legacy_status->created_at_ms == 50'000);

    // Raw byte mutation only validates hash-corruption rejection, not semantic recovery behavior.
    const auto hash_corrupted_schema_store = temp.root() / "hash-corrupted-schema.journal";
    REQUIRE(std::filesystem::copy_file(store_path, hash_corrupted_schema_store));
    REQUIRE(::chmod(hash_corrupted_schema_store.c_str(), 0600) == 0);
    REQUIRE(replace_after_marker(
        hash_corrupted_schema_store,
        R"("operation":"enqueue_observation_intent_v1")",
        "test.observation.v1",
        "test.observation.v2"
    ));
    REQUIRE(!glove::control::session_registry::open_or_create(
                 hash_corrupted_schema_store,
                 shared_validator,
                 shared_bundle_store,
                 glove::control::default_session_registry_bytes,
                 test_channel_host()
    )
                 .has_value());

    const auto hash_corrupted_session_store = temp.root() / "hash-corrupted-session.journal";
    REQUIRE(std::filesystem::copy_file(store_path, hash_corrupted_session_store));
    REQUIRE(::chmod(hash_corrupted_session_store.c_str(), 0600) == 0);
    REQUIRE(replace_after_marker(
        hash_corrupted_session_store,
        R"("operation":"enqueue_observation_intent_v1")",
        "sage-session-a",
        "sage-session-b"
    ));
    REQUIRE(!glove::control::session_registry::open_or_create(
                 hash_corrupted_session_store,
                 shared_validator,
                 shared_bundle_store,
                 glove::control::default_session_registry_bytes,
                 test_channel_host()
    )
                 .has_value());

    // Fully re-chained corruption must still fail before historical data can
    // enter quarantine. Selectors keep each mutation focused on one commitment.
    const auto enqueue_record = [](const auto& record) {
        return record.operation == "enqueue_observation_intent_v1";
    };
    const auto accepted_disposition_record = [](const auto& record) {
        return record.operation == "set_observation_intent_disposition_v1" &&
               record.observation_intent && record.observation_intent->intent_id == "intent-1" &&
               record.observation_intent->disposition == "accepted";
    };
    const auto rechained_recovery_rejected =
        [&](std::string_view filename, const auto& select, const auto& mutate) {
            const auto corrupted_store = temp.root() / filename;
            return std::filesystem::copy_file(store_path, corrupted_store) &&
                   ::chmod(corrupted_store.c_str(), 0600) == 0 &&
                   rewrite_observation_record_and_rechain(corrupted_store, select, mutate) &&
                   !glove::control::session_registry::open_or_create(
                        corrupted_store,
                        shared_validator,
                        shared_bundle_store,
                        glove::control::default_session_registry_bytes,
                        nullptr
                   )
                        .has_value();
        };

    REQUIRE(rechained_recovery_rejected(
        "body-commitment-corrupt.journal", enqueue_record, [](auto& record) {
            record.observation_intent->item_count += 1U;
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "request-commitment-corrupt.journal", enqueue_record, [](auto& record) {
            record.request_digest = std::string(64, 'f');
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "session-binding-corrupt.journal", enqueue_record, [](auto& record) {
            record.launch_profile_digest = std::string(64, 'f');
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "enqueue-structural-corrupt.journal", enqueue_record, [](auto& record) {
            record.observation_intent->schema_version = 2;
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "disposition-link-corrupt.journal", accepted_disposition_record, [](auto& record) {
            record.observation_intent->profile_digest = std::string(64, 'f');
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "disposition-time-corrupt.journal", accepted_disposition_record, [](auto& record) {
            record.observation_intent->decided_at_ms += 1U;
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "disposition-request-corrupt.journal", accepted_disposition_record, [](auto& record) {
            record.request_digest = std::string(64, 'f');
        }
    ));
    REQUIRE(rechained_recovery_rejected(
        "duplicate-quarantine-key.journal",
        [](const auto& record) {
            return record.operation == "enqueue_observation_intent_v1" &&
                   record.observation_intent && record.observation_intent->intent_id == "intent-2";
        },
        [](auto& record) {
            using namespace glove::control;
            auto& intent = *record.observation_intent;
            intent.intent_id = "intent-1";
            const glove_observation_body duplicate_body{
                .schema = intent.schema,
                .intent_id = intent.intent_id,
                .observation = intent.observation,
                .value_digest = intent.value_digest,
                .item_count = intent.item_count,
            };
            const observation_intent_context duplicate_context{
                .session_id = record.session_id,
                .controller_plan_digest = record.controller_plan_digest,
                .profile_digest = intent.profile_digest,
                .runtime_id = intent.runtime_id,
                .projection_digest = intent.projection_digest,
                .policy_revision = record.policy_revision,
                .channel_id = intent.channel_id,
                .channel_generation = intent.channel_generation,
                .issued_at_ms = intent.issued_at_ms,
                .expires_at_ms = intent.expires_at_ms,
            };
            intent.intent_digest = wire::hash_observation_intent_body(duplicate_body).value_or("");
            record.request_digest =
                wire::hash_observation_intent_request(duplicate_body, duplicate_context)
                    .value_or("");
            record.idempotency_key = "intent-enqueue:" + record.request_digest;
        }
    ));

    const auto torn_store = temp.root() / "torn-intent-sessions.journal";
    REQUIRE(std::filesystem::copy_file(store_path, torn_store));
    REQUIRE(::chmod(torn_store.c_str(), 0600) == 0);
    {
        std::ofstream output{torn_store, std::ios::binary | std::ios::app};
        output.put('x');
    }
    REQUIRE(!glove::control::session_registry::open_or_create(
                 torn_store,
                 shared_validator,
                 shared_bundle_store,
                 glove::control::default_session_registry_bytes,
                 test_channel_host()
    )
                 .has_value());

    const glove::control::session_failure_commitment terminal_failure{
        .schema_version = 1,
        .session_id = running_a->session_id,
        .controller_plan_digest = running_a->controller_plan_digest,
        .plan_content_digest = running_a->plan_content_digest,
        .authorization_id = running_a->authorization_id,
        .profile_digest = running_a->profile_digest,
        .code = glove::control::session_failure_code::supervisor_error,
    };
    REQUIRE(
        (*registry)->mark_failed(terminal_failure, "terminal-sage-session-a", 30'060).has_value()
    );
    auto terminal_body = body;
    terminal_body.intent_id = "intent-after-terminal";
    REQUIRE(!(*registry)->enqueue_observation_intent(terminal_body, context_a, 30'061).has_value());

    registry->reset();
    const auto durable_size = std::filesystem::file_size(store_path);
    registry = glove::control::session_registry::open_or_create(
        store_path, shared_validator, shared_bundle_store, durable_size, test_channel_host()
    );
    REQUIRE(registry.has_value());
    auto capacity_body = body;
    capacity_body.intent_id = "intent-capacity";
    auto capacity_context = cross_session;
    capacity_context.issued_at_ms = 30'070;
    capacity_context.expires_at_ms = 30'170;
    auto capacity =
        (*registry)->enqueue_observation_intent(capacity_body, capacity_context, 30'070);
    REQUIRE(!capacity.has_value());
    REQUIRE(capacity.error().code == glove::control::session_registry_error_code::capacity);

    // Descriptor bounds: ttl, skew, and item count beyond the registered
    // channel bounds are rejected even when inside core ceilings.
    {
        auto tight = glove::control::session_registry::open_or_create(
            temp.root() / "tight-sessions.journal",
            shared_validator,
            shared_bundle_store,
            glove::control::default_session_registry_bytes,
            tight_channel_host()
        );
        REQUIRE(tight.has_value());
        auto created = (*tight)->create(
            "tight-session", controller_digest, sage_guest_plan_at(60'000), "create-tight", 60'000
        );
        REQUIRE(created.has_value());
        const glove::control::session_start_authorization tight_authorization{
            .schema_version = 1,
            .authorization_id = "approval-tight",
            .session_id = "tight-session",
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .approved_at_ms = 60'001,
            .expires_at_ms = 160'000,
        };
        REQUIRE((*tight)->reserve_start(tight_authorization, "reserve-tight", 60'002).has_value());
        const glove::control::session_execution_binding tight_binding{
            .schema_version = 1,
            .session_id = "tight-session",
            .controller_plan_digest = std::string{controller_digest},
            .plan_content_digest = created->plan_content_digest,
            .authorization_id = tight_authorization.authorization_id,
            .profile_digest = std::string(64, '8'),
            .cgroup_identity = cgroup_identity(7201),
            .filesystem_identity = filesystem_identity(),
        };
        auto tight_reservation = (*producer)->reserve_terminal(
            tight_binding.session_id,
            tight_binding.controller_plan_digest,
            tight_binding.profile_digest
        );
        REQUIRE(tight_reservation.has_value());
        REQUIRE((*tight)
                    ->mark_starting(tight_binding, *tight_reservation, "starting-tight", 60'003)
                    .has_value());
        const glove::control::session_running_commitment tight_running{
            .schema_version = 1,
            .session_id = "tight-session",
            .controller_plan_digest = tight_binding.controller_plan_digest,
            .plan_content_digest = tight_binding.plan_content_digest,
            .authorization_id = tight_binding.authorization_id,
            .profile_digest = tight_binding.profile_digest,
            .process_identity = process_identity(7201),
            .filesystem_identity = filesystem_identity(),
        };
        REQUIRE((*tight)
                    ->mark_running(tight_running, *tight_reservation, "running-tight", 60'004)
                    .has_value());
        const glove::control::observation_intent_context tight_context{
            .session_id = "tight-session",
            .controller_plan_digest = tight_binding.controller_plan_digest,
            .profile_digest = tight_binding.profile_digest,
            .runtime_id = "sage-guest",
            .projection_digest = std::string(64, 'c'),
            .policy_revision = 7,
            .channel_id = "tight-observation",
            .channel_generation = 1,
            .issued_at_ms = 60'010,
            .expires_at_ms = 60'050,
        };
        // Within the tight bounds: accepted (body respects max_items=1).
        auto tight_body = body;
        tight_body.item_count = 1;
        REQUIRE(
            (*tight)->enqueue_observation_intent(tight_body, tight_context, 60'010).has_value()
        );
        // Beyond the registered ttl bound (but inside the core ceiling).
        auto long_ttl_body = tight_body;
        long_ttl_body.intent_id = "tight-long-ttl";
        auto long_ttl = tight_context;
        long_ttl.issued_at_ms = 60'060;
        long_ttl.expires_at_ms = 60'060 + 600'000U;
        REQUIRE(!(*tight)->enqueue_observation_intent(long_ttl_body, long_ttl, 60'060).has_value());
        // Beyond the registered skew bound.
        auto skew_body = tight_body;
        skew_body.intent_id = "tight-skew";
        skew_body.value_digest = std::string(64, 'b');
        auto skewed = tight_context;
        skewed.issued_at_ms = 60'010 + 2'000U;
        skewed.expires_at_ms = skewed.issued_at_ms + 1'000U;
        REQUIRE(!(*tight)->enqueue_observation_intent(skew_body, skewed, 60'010).has_value());
        // Beyond the registered item bound (2 items against max_items=1).
        auto multi_body = tight_body;
        multi_body.intent_id = "tight-items";
        multi_body.value_digest = std::string(64, 'd');
        multi_body.item_count = 2;
        REQUIRE(
            !(*tight)->enqueue_observation_intent(multi_body, tight_context, 60'012).has_value()
        );
    }

    // Historical integrity is independent of the current catalog. Retiring
    // schemas quarantines only their authentic observation records and does
    // not block unrelated session recovery.
    const auto unadmitted_store = temp.root() / "unadmitted-copy.journal";
    REQUIRE(std::filesystem::copy_file(store_path, unadmitted_store));
    REQUIRE(::chmod(unadmitted_store.c_str(), 0600) == 0);
    auto unadmitted = glove::control::session_registry::open_or_create(
        unadmitted_store, shared_validator, shared_bundle_store
    );
    REQUIRE(unadmitted.has_value());
    REQUIRE((*unadmitted)->status("sage-session-b").has_value());
    auto unavailable_page = (*unadmitted)->quarantined_observation_intents(0, 1);
    REQUIRE(unavailable_page.has_value());
    REQUIRE(unavailable_page->items.size() == 1U);
    REQUIRE(unavailable_page->items[0].closed_reason == "schema_unavailable");
    REQUIRE(unavailable_page->next_after_sequence.has_value());
    auto unavailable_next =
        (*unadmitted)->quarantined_observation_intents(*unavailable_page->next_after_sequence, 256);
    REQUIRE(unavailable_next.has_value());
    REQUIRE(!unavailable_next->items.empty());
    REQUIRE(std::ranges::all_of(unavailable_next->items, [](const auto& entry) {
        return entry.closed_reason == glove::control::observation_schema_unavailable;
    }));
    REQUIRE(!(*unadmitted)->quarantined_observation_intents(0, 0).has_value());
    REQUIRE(!(*unadmitted)
                 ->quarantined_observation_intents(
                     0, glove::control::max_observation_quarantine_page_size + 1U
                 )
                 .has_value());
    auto unavailable_pending = (*unadmitted)->pending_observation_intents(0, 256, 30'080);
    REQUIRE(unavailable_pending.has_value());
    REQUIRE(unavailable_pending->items.empty());
    auto quarantined_replay = (*unadmitted)->enqueue_observation_intent(body, context_a, 30'080);
    REQUIRE(!quarantined_replay.has_value());
    REQUIRE(
        quarantined_replay.error().code ==
        glove::control::session_registry_error_code::invalid_state
    );
    auto reused_body = body;
    reused_body.item_count += 1U;
    auto quarantined_key_reuse =
        (*unadmitted)->enqueue_observation_intent(reused_body, context_a, 30'080);
    REQUIRE(!quarantined_key_reuse.has_value());
    REQUIRE(
        quarantined_key_reuse.error().code ==
        glove::control::session_registry_error_code::invalid_state
    );
    auto quarantined_disposition = (*unadmitted)->set_observation_intent_disposition(accepted);
    REQUIRE(!quarantined_disposition.has_value());
    REQUIRE(
        quarantined_disposition.error().code ==
        glove::control::session_registry_error_code::invalid_state
    );
    unadmitted->reset();

    // A present schema with changed bounds/validation is incompatible, while
    // an unknown historical schema remains unavailable. Interleaved terminal
    // dispositions recover but never reactivate either quarantined key.
    auto incompatible = glove::control::session_registry::open_or_create(
        unadmitted_store,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        tight_channel_host()
    );
    REQUIRE(incompatible.has_value());
    auto incompatible_page = (*incompatible)->quarantined_observation_intents(0, 256);
    REQUIRE(incompatible_page.has_value());
    REQUIRE(std::ranges::any_of(incompatible_page->items, [](const auto& entry) {
        return entry.schema_id == test_observation_schema &&
               entry.closed_reason == glove::control::observation_schema_incompatible;
    }));
    REQUIRE(std::ranges::any_of(incompatible_page->items, [](const auto& entry) {
        return entry.schema_id == test_proposal_schema &&
               entry.closed_reason == glove::control::observation_schema_unavailable;
    }));
    REQUIRE(std::ranges::any_of(incompatible_page->items, [&](const auto& entry) {
        return entry.intent_id == accepted.intent_id && entry.session_id == accepted.session_id;
    }));
    incompatible->reset();

    auto validator_incompatible = glove::control::session_registry::open_or_create(
        unadmitted_store,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        rejecting_channel_host()
    );
    REQUIRE(validator_incompatible.has_value());
    auto validator_incompatible_page =
        (*validator_incompatible)->quarantined_observation_intents(0, 256);
    REQUIRE(validator_incompatible_page.has_value());
    REQUIRE(std::ranges::any_of(validator_incompatible_page->items, [&](const auto& entry) {
        return entry.intent_id == accepted.intent_id && entry.session_id == accepted.session_id &&
               entry.closed_reason == glove::control::observation_schema_incompatible;
    }));
    validator_incompatible->reset();

    // Re-enabling the original frozen catalog fully rehydrates the same file;
    // no journal migration or rewrite is needed.
    auto readmitted = glove::control::session_registry::open_or_create(
        unadmitted_store,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(readmitted.has_value());
    auto readmitted_quarantine = (*readmitted)->quarantined_observation_intents(0, 256);
    REQUIRE(readmitted_quarantine.has_value());
    REQUIRE(readmitted_quarantine->items.empty());
    REQUIRE((*readmitted)->set_observation_intent_disposition(accepted) == accepted_result);

    // Unregistered schema enqueue fails closed.
    auto unregistered_body = body;
    unregistered_body.schema = "test.observation.v2";
    REQUIRE(
        !(*registry)->enqueue_observation_intent(unregistered_body, context_a, 30'080).has_value()
    );

    return 0;
}

// F1/HIGH regression: durable intent and disposition records embed a frozen
// full session snapshot. Lifecycle progression (running -> stopping ->
// exited) and policy revision bumps must never read as a binding crossing on
// recovery, while any other frozen-field difference still must.
auto run_intent_recovery_transitions() -> int {
    using glove::control::wire::persisted_session;

    // Snapshot-identity unit test: lifecycle-mutable fields are neutralized;
    // everything else remains a binding crossing.
    const persisted_session identity{
        .schema_version = 1,
        .sequence = 4,
        .operation = "mark_running",
        .idempotency_key = "running-session-1",
        .session_id = "session-1",
        .controller_plan_digest = std::string(64, 'c'),
        .request_digest = std::string(64, 'a'),
        .plan_content_digest = std::string(64, 'b'),
        .state = "running",
        .policy_revision = 7,
        .expires_at_ms = 61'000,
        .created_at_ms = 1'000,
        .authorization_id = {},
        .authorized_at_ms = 1'001,
        .authorization_expires_at_ms = 2'001,
        .launch_profile_digest = std::string(64, 'e'),
        .starting_at_ms = 1'003,
        .running_at_ms = 1'004,
        .stopping_at_ms = 0,
        .process_identity_schema_version = 0,
        .process_pid = 0,
        .process_boot_id = {},
        .process_start_time_ticks = 0,
        .process_cgroup_device = 0,
        .process_cgroup_inode = 0,
        .process_cgroup_path_digest = {},
        .cgroup_identity = std::nullopt,
        .filesystem_identity = std::nullopt,
        .managed_runtime_identity = std::nullopt,
        .failure_code = {},
        .finished_at_ms = 0,
        .receipt_started_at_ms = 0,
        .receipt_key_id = {},
        .receipt_sequence = 0,
        .receipt_digest = {},
        .receipt_previous_hmac = {},
        .receipt_hmac = {},
        .termination_cause = {},
        .exit_code = std::nullopt,
        .canonical_plan_json = {},
        .previous_hash = {},
        .this_hash = {},
        .observation_intent = std::nullopt,
    };
    auto transitioned = identity;
    transitioned.state = "exited";
    transitioned.running_at_ms = 9'999;
    transitioned.policy_revision = 99;
    transitioned.stopping_at_ms = 5'000;
    transitioned.finished_at_ms = 6'000;
    // state/running_at_ms/policy_revision neutralization is intentional; a
    // frozen snapshot with additional transition markers (stopping_at_ms,
    // finished_at_ms) still crosses, so journal order stays authoritative.
    REQUIRE(
        glove::control::same_session_snapshot(transitioned, identity) ==
        (transitioned.stopping_at_ms == 0 && transitioned.finished_at_ms == 0)
    );
    auto crossed = transitioned;
    crossed.stopping_at_ms = 0;
    crossed.finished_at_ms = 0;
    REQUIRE(glove::control::same_session_snapshot(crossed, identity));
    auto tampered = identity;
    tampered.launch_profile_digest = std::string(64, 'f');
    REQUIRE(!glove::control::same_session_snapshot(tampered, identity));
    auto crossed_session = identity;
    crossed_session.session_id = "session-2";
    REQUIRE(!glove::control::same_session_snapshot(crossed_session, identity));

    // End-to-end: enqueue -> stopping -> exited -> destroy -> reopen must
    // recover, per state transition.
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto source = temp.root() / "source";
    REQUIRE(std::filesystem::create_directory(source));
    auto validator = validator_for(source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));
    const auto bundle_root = temp.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(bundle_root));
    REQUIRE(::chmod(bundle_root.c_str(), 0700) == 0);
    const auto bundle_path = bundle_root / (library_bundle_digest() + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary};
        output.write(library_bundle.data(), static_cast<std::streamsize>(library_bundle.size()));
    }
    REQUIRE(::chmod(bundle_path.c_str(), 0600) == 0);
    auto opened_bundle_store = glove::supervisor::library_bundle_store::open(bundle_root);
    REQUIRE(opened_bundle_store.has_value());
    auto shared_bundle_store = std::make_shared<const glove::supervisor::library_bundle_store>(
        std::move(*opened_bundle_store)
    );
    const auto audit_key_path = temp.root() / "transition-receipt.key";
    {
        std::ofstream output{audit_key_path, std::ios::binary | std::ios::trunc};
        output << audit_key << '\n';
    }
    REQUIRE(::chmod(audit_key_path.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = audit_key_path,
        .journal_path = temp.root() / "transition-receipts.journal",
    });
    REQUIRE(producer.has_value());
    REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());

    const auto store_path = temp.root() / "transition-sessions.journal";
    auto registry = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(registry.has_value());

    const std::uint64_t start_ms = 10'000;
    const std::string session_id = "recovery-transition-session";
    auto created = (*registry)->create(
        session_id, controller_digest, sage_guest_plan_at(start_ms), "create-transition", start_ms
    );
    REQUIRE(created.has_value());
    const glove::control::session_start_authorization authorization{
        .schema_version = 1,
        .authorization_id = "approval-transition",
        .session_id = session_id,
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .approved_at_ms = start_ms + 1U,
        .expires_at_ms = start_ms + 60'000U,
    };
    REQUIRE(
        (*registry)->reserve_start(authorization, "reserve-transition", start_ms + 2U).has_value()
    );
    const glove::control::session_execution_binding binding{
        .schema_version = 1,
        .session_id = session_id,
        .controller_plan_digest = std::string{controller_digest},
        .plan_content_digest = created->plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = std::string(64, 'a'),
        .cgroup_identity = cgroup_identity(7101),
        .filesystem_identity = filesystem_identity(),
    };
    auto reservation = (*producer)->reserve_terminal(
        binding.session_id, binding.controller_plan_digest, binding.profile_digest
    );
    REQUIRE(reservation.has_value());
    REQUIRE((*registry)
                ->mark_starting(binding, *reservation, "starting-transition", start_ms + 3U)
                .has_value());
    const glove::control::session_running_commitment running{
        .schema_version = 1,
        .session_id = session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = binding.profile_digest,
        .process_identity = process_identity(7101),
        .filesystem_identity = binding.filesystem_identity,
    };
    REQUIRE((*registry)
                ->mark_running(running, *reservation, "running-transition", start_ms + 4U)
                .has_value());

    const glove::control::glove_observation_body body{
        .schema = std::string{test_observation_schema},
        .intent_id = "transition-intent-1",
        .observation = "guest-capability-inventory",
        .value_digest = std::string(64, 'a'),
        .item_count = 4,
    };
    const glove::control::observation_intent_context context{
        .session_id = session_id,
        .controller_plan_digest = running.controller_plan_digest,
        .profile_digest = running.profile_digest,
        .runtime_id = "sage-guest",
        .projection_digest = std::string(64, 'c'),
        .policy_revision = 7,
        .channel_id = "recovery-transition-observation-v1",
        .channel_generation = 1,
        .issued_at_ms = start_ms + 10U,
        .expires_at_ms = start_ms + 30'000U,
    };
    auto enqueued = (*registry)->enqueue_observation_intent(body, context, start_ms + 10U);
    REQUIRE(enqueued.has_value());

    // Transition 1: running -> stopping with the intent still pending.
    REQUIRE((*registry)->mark_stopping(running, "stopping-transition", start_ms + 20U).has_value());
    registry->reset();
    registry = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(registry.has_value());

    // Transition 2: stopping -> exited with the intent still pending.
    auto terminal = (*producer)->commit_terminal(
        std::move(*reservation),
        binding.session_id,
        binding.controller_plan_digest,
        terminal_receipt(binding.profile_digest, start_ms + 3U, start_ms + 30U)
    );
    REQUIRE(terminal.has_value());
    REQUIRE((*registry)->mark_exited(*terminal, **producer, "exited-transition").has_value());

    // A late host disposition decided after exit freezes the exited snapshot.
    const glove::control::observation_intent_disposition accepted{
        .session_id = session_id,
        .channel_generation = 1,
        .intent_id = body.intent_id,
        .intent_digest = enqueued->intent_digest,
        .disposition = glove::control::intent_disposition::accepted,
        .decided_at_ms = start_ms + 40U,
    };
    REQUIRE((*registry)->set_observation_intent_disposition(accepted).has_value());

    registry->reset();
    registry = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(registry.has_value());
    REQUIRE((*registry)->set_observation_intent_disposition(accepted).has_value());

    // The interleaved enqueue/disposition remains authentic when the schema
    // is retired, but neither record is reactivated.
    registry->reset();
    auto retired = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        nullptr
    );
    REQUIRE(retired.has_value());
    auto retired_page = (*retired)->quarantined_observation_intents(0, 16);
    REQUIRE(retired_page.has_value());
    REQUIRE(retired_page->items.size() == 1U);
    REQUIRE(retired_page->items[0].sequence == enqueued->sequence);
    REQUIRE(retired_page->items[0].session_id == session_id);
    REQUIRE(retired_page->items[0].schema_id == body.schema);
    REQUIRE(retired_page->items[0].intent_id == body.intent_id);
    REQUIRE(retired_page->items[0].channel_generation == 1U);
    REQUIRE(retired_page->items[0].closed_reason == "schema_unavailable");
    auto retired_pending = (*retired)->pending_observation_intents(0, 16, start_ms + 50U);
    REQUIRE(retired_pending.has_value());
    REQUIRE(retired_pending->items.empty());
    REQUIRE(!(*retired)->set_observation_intent_disposition(accepted).has_value());
    retired->reset();

    auto reenabled = glove::control::session_registry::open_or_create(
        store_path,
        shared_validator,
        shared_bundle_store,
        glove::control::default_session_registry_bytes,
        test_channel_host()
    );
    REQUIRE(reenabled.has_value());
    REQUIRE((*reenabled)->set_observation_intent_disposition(accepted).has_value());

    return 0;
}

} // namespace

int main() {
    if (const auto result = run(); result != 0) {
        return result;
    }
    if (const auto result = run_intent_queue_contract(); result != 0) {
        return result;
    }
    if (const auto result = run_intent_recovery_transitions(); result != 0) {
        return result;
    }
    return run_managed_runtime_registry();
}
