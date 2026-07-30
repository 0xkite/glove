#include "glove/supervisor/path_exposure.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

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
        std::string pattern = "/tmp/glove-path-exposure-test-XXXXXX";
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

auto read_mode() -> glove::supervisor::path_exposure_mode {
    return {
        .access = glove::supervisor::path_access::read,
        .materialization = glove::supervisor::path_materialization::bind,
        .max_bytes = 0,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
    };
}

auto retained_mode(std::uint64_t max_bytes) -> glove::supervisor::path_exposure_mode {
    return {
        .access = glove::supervisor::path_access::retained_write,
        .materialization = glove::supervisor::path_materialization::copy,
        .max_bytes = max_bytes,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
    };
}

auto retained_worktree_mode(std::uint64_t max_bytes) -> glove::supervisor::path_exposure_mode {
    return {
        .access = glove::supervisor::path_access::retained_write,
        .materialization = glove::supervisor::path_materialization::git_worktree,
        .max_bytes = max_bytes,
        .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
    };
}

auto create_request(
    const std::filesystem::path& source, std::string request_id, std::string exposure_id
) -> glove::supervisor::path_exposure_create_request {
    return {
        .request_id = std::move(request_id),
        .exposure_id = std::move(exposure_id),
        .root_id = "projects",
        .host_path = source.string(),
        .display_label = "Sage protocol",
        .allowed_modes = {retained_mode(33'554'432), read_mode()},
        .ttl_secs = 3'600,
        .allowed_runtime_template_ids = {"pi-safe", "codex-safe"},
    };
}

auto root_policy(const std::filesystem::path& protected_root)
    -> glove::supervisor::path_exposure_root_policy {
    return {
        .root_id = "projects",
        .host_root = protected_root.string(),
        .allowed_modes = {read_mode(), retained_mode(67'108'864)},
        .max_ttl_secs = 7'200,
        .allowed_runtime_template_ids = {"codex-safe", "pi-safe"},
    };
}

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto protected_root = temporary.root() / "projects";
    const auto source = protected_root / "sage-protocol";
    const auto outside = temporary.root() / "outside";
    REQUIRE(std::filesystem::create_directories(source));
    REQUIRE(std::filesystem::create_directory(outside));
    std::ofstream{source / "README.md"} << "bounded source\n";
    const auto canonical_root = std::filesystem::canonical(protected_root);
    const auto canonical_source = std::filesystem::canonical(source);
    const auto canonical_outside = std::filesystem::canonical(outside);

    auto registry = path_exposure_registry::build({root_policy(canonical_root)});
    if (!registry) {
        std::fprintf(stderr, "registry build failed: %s\n", registry.error().c_str());
    }
    REQUIRE(registry.has_value());
    auto unsupported_policy = root_policy(canonical_root);
    unsupported_policy.allowed_modes = {retained_worktree_mode(33'554'432)};
    REQUIRE(!path_exposure_registry::build({std::move(unsupported_policy)}).has_value());

    auto request = create_request(canonical_source, "request-1", "sage-workspace");
    REQUIRE(registry->validate_create_policy(request).has_value());
    auto wrong_root = request;
    wrong_root.root_id = "unknown";
    auto root_mismatch = registry->validate_create_policy(wrong_root);
    REQUIRE(!root_mismatch.has_value());
    REQUIRE(root_mismatch.error().find("allowed roots: projects") != std::string::npos);
    auto excessive_ttl = request;
    excessive_ttl.ttl_secs = 7'201;
    auto ttl_mismatch = registry->validate_create_policy(excessive_ttl);
    REQUIRE(!ttl_mismatch.has_value());
    REQUIRE(ttl_mismatch.error().find("maximum 7200 seconds") != std::string::npos);
    auto excessive_mode = request;
    excessive_mode.allowed_modes = {retained_mode(67'108'865)};
    auto mode_mismatch = registry->validate_create_policy(excessive_mode);
    REQUIRE(!mode_mismatch.has_value());
    REQUIRE(mode_mismatch.error().find("max_bytes=67108865") != std::string::npos);
    REQUIRE(mode_mismatch.error().find("retained_write(max_bytes=67108864)") != std::string::npos);
    auto unknown_runtime = request;
    unknown_runtime.allowed_runtime_template_ids = {"opencode-safe"};
    auto runtime_mismatch = registry->validate_create_policy(unknown_runtime);
    REQUIRE(!runtime_mismatch.has_value());
    REQUIRE(runtime_mismatch.error().find("opencode-safe") != std::string::npos);
    REQUIRE(runtime_mismatch.error().find("codex-safe, pi-safe") != std::string::npos);

    auto created = registry->create(request, 1'000);
    REQUIRE(created.has_value());
    REQUIRE(created->generation == 1);
    REQUIRE(created->scope_digest.size() == 64U);
    REQUIRE(created->source_identity_digest.size() == 64U);
    REQUIRE(created->allowed_modes.front() == read_mode());
    REQUIRE(
        created->allowed_runtime_template_ids == std::vector<std::string>({"codex-safe", "pi-safe"})
    );

    auto replay = registry->create(request, 2'000);
    REQUIRE(replay.has_value());
    REQUIRE(*replay == *created);
    request.display_label = "changed";
    REQUIRE(!registry->create(request, 2'000).has_value());

    const path_exposure_grant retained{
        .exposure_id = created->exposure_id,
        .generation = created->generation,
        .scope_digest = created->scope_digest,
        .access = path_access::retained_write,
        .materialization = path_materialization::copy,
        .max_bytes = 33'554'432,
        .ttl_secs = 60,
        .cleanup_policy = path_cleanup_policy::retain,
    };
    REQUIRE(registry->validate_grant(retained, "codex-safe", 2'000).has_value());
    auto excessive = retained;
    excessive.max_bytes = 67'108'864;
    REQUIRE(!registry->validate_grant(excessive, "codex-safe", 2'000).has_value());
    auto stale_scope = retained;
    stale_scope.scope_digest.front() = stale_scope.scope_digest.front() == 'a' ? 'b' : 'a';
    REQUIRE(!registry->validate_grant(stale_scope, "codex-safe", 2'000).has_value());
    REQUIRE(!registry->validate_grant(retained, "unknown-runtime", 2'000).has_value());

    const auto inventory = registry->list(2'000);
    REQUIRE(inventory.size() == 1U);
    REQUIRE(inventory.front().exposure_id == "sage-workspace");
    REQUIRE(inventory.front().scope_digest == created->scope_digest);
    REQUIRE(
        !registry
             ->create(
                 create_request(canonical_source, "request-active-replacement", "sage-workspace"),
                 2'500
             )
             .has_value()
    );

    REQUIRE(registry->revoke("revoke-1", "sage-workspace", 1, 3'000).has_value());
    REQUIRE(registry->revoke("revoke-1", "sage-workspace", 1, 3'000).has_value());
    REQUIRE(!registry->validate_grant(retained, "codex-safe", 3'000).has_value());
    REQUIRE(registry->list(3'000).front().state == path_exposure_state::revoked);
    auto revoked_recovery = registry->resolve_recovery_target(
        created->exposure_id,
        created->generation,
        created->scope_digest,
        created->source_identity_digest
    );
    REQUIRE(revoked_recovery.has_value());
    REQUIRE(revoked_recovery->basename() == "sage-protocol");
    REQUIRE(revoked_recovery->source_identity_digest() == created->source_identity_digest);
    struct stat recovered_status{};
    REQUIRE(
        ::fstatat(
            revoked_recovery->parent_descriptor_fd(),
            std::string{revoked_recovery->basename()}.c_str(),
            &recovered_status,
            AT_SYMLINK_NOFOLLOW
        ) == 0
    );
    REQUIRE(S_ISDIR(recovered_status.st_mode));
    auto wrong_recovery_scope = created->scope_digest;
    wrong_recovery_scope.front() = wrong_recovery_scope.front() == 'a' ? 'b' : 'a';
    REQUIRE(!registry
                 ->resolve_recovery_target(
                     created->exposure_id,
                     created->generation,
                     wrong_recovery_scope,
                     created->source_identity_digest
                 )
                 .has_value());

    auto generation_two =
        registry->create(create_request(canonical_source, "request-2", "sage-workspace"), 4'000);
    REQUIRE(generation_two.has_value());
    REQUIRE(generation_two->generation == 2);
    REQUIRE(generation_two->scope_digest != created->scope_digest);

    auto outside_request = create_request(canonical_outside, "request-3", "outside");
    REQUIRE(!registry->create(outside_request, 5'000).has_value());
    const auto symlink_source = canonical_root / "linked";
    REQUIRE(::symlink(canonical_source.c_str(), symlink_source.c_str()) == 0);
    auto symlink_request = create_request(symlink_source, "request-4", "linked");
    REQUIRE(!registry->create(symlink_request, 5'000).has_value());

    auto expired = create_request(canonical_source, "request-5", "expiring");
    expired.ttl_secs = 1;
    auto expiring = registry->create(expired, 6'000);
    REQUIRE(expiring.has_value());
    const auto after_expiry = registry->list(7'000);
    const auto expired_projection = std::ranges::find_if(after_expiry, [](const auto& exposure) {
        return exposure.exposure_id == "expiring";
    });
    REQUIRE(expired_projection != after_expiry.end());
    REQUIRE(expired_projection->state == path_exposure_state::expired);

    const auto nested_parent = canonical_root / "nested";
    const auto nested_source = nested_parent / "workspace";
    REQUIRE(std::filesystem::create_directories(nested_source));
    auto nested = registry->create(
        create_request(
            std::filesystem::canonical(nested_source), "nested-request-1", "nested-workspace"
        ),
        7'100
    );
    REQUIRE(nested.has_value());
    REQUIRE(registry->revoke("nested-revoke-1", nested->exposure_id, nested->generation, 7'200));
    REQUIRE(registry
                ->resolve_recovery_target(
                    nested->exposure_id,
                    nested->generation,
                    nested->scope_digest,
                    nested->source_identity_digest
                )
                .has_value());
    const auto original_nested_parent = canonical_root / "nested-original";
    std::filesystem::rename(nested_parent, original_nested_parent);
    REQUIRE(std::filesystem::create_directories(nested_source));
    REQUIRE(!registry
                 ->resolve_recovery_target(
                     nested->exposure_id,
                     nested->generation,
                     nested->scope_digest,
                     nested->source_identity_digest
                 )
                 .has_value());

    const auto journal_path = temporary.root() / "exposures.journal";
    path_exposure_descriptor durable_descriptor;
    {
        auto durable = path_exposure_registry::open(
            {root_policy(canonical_root)}, journal_path, std::uint64_t{8} * 1024U * 1024U
        );
        REQUIRE(durable.has_value());
        auto durable_request =
            create_request(canonical_source, "durable-request-1", "durable-workspace");
        auto durable_created = durable->create(durable_request, 8'000);
        REQUIRE(durable_created.has_value());
        durable_descriptor = *durable_created;
        REQUIRE(durable->revoke("durable-revoke-1", "durable-workspace", 1, 9'000).has_value());
        auto second_request =
            create_request(canonical_source, "durable-request-2", "durable-workspace");
        auto second = durable->create(second_request, 10'000);
        REQUIRE(second.has_value());
        REQUIRE(second->generation == 2);
        durable_descriptor = *second;
    }
    {
        auto replayed = path_exposure_registry::open(
            {root_policy(canonical_root)}, journal_path, std::uint64_t{8} * 1024U * 1024U
        );
        REQUIRE(replayed.has_value());
        const auto replayed_inventory = replayed->list(11'000);
        REQUIRE(replayed_inventory.size() == 2U);
        REQUIRE(replayed_inventory.front().state == path_exposure_state::revoked);
        REQUIRE(replayed_inventory.back().generation == 2);
        auto replayed_grant = retained;
        replayed_grant.exposure_id = durable_descriptor.exposure_id;
        replayed_grant.generation = durable_descriptor.generation;
        replayed_grant.scope_digest = durable_descriptor.scope_digest;
        REQUIRE(replayed->validate_grant(replayed_grant, "codex-safe", 11'000).has_value());
        auto replayed_recovery = replayed->resolve_recovery_target(
            durable_descriptor.exposure_id,
            durable_descriptor.generation,
            durable_descriptor.scope_digest,
            durable_descriptor.source_identity_digest
        );
        REQUIRE(replayed_recovery.has_value());
        REQUIRE(replayed_recovery->basename() == "sage-protocol");
        auto idempotent = replayed->create(
            create_request(canonical_source, "durable-request-2", "durable-workspace"), 12'000
        );
        REQUIRE(idempotent.has_value());
        REQUIRE(*idempotent == durable_descriptor);
    }

    const auto policy_path = temporary.root() / "exposure-policy.json";
    const auto policy_journal_path = temporary.root() / "policy-exposures.journal";
    {
        std::ofstream policy{policy_path};
        policy
            << R"({"schema_version":1,"roots":[{"root_id":"projects","host_root":")"
            << canonical_root.string()
            << R"(","allowed_modes":[{"access":"read","materialization":"bind","max_bytes":0,"cleanup_policy":"retain"},{"access":"retained_write","materialization":"copy","max_bytes":67108864,"cleanup_policy":"retain"}],"max_ttl_secs":7200,"allowed_runtime_template_ids":["codex-safe","pi-safe"]}]})";
    }
    REQUIRE(::chmod(policy_path.c_str(), 0600) == 0);
    {
        auto loaded = path_exposure_registry::load(
            std::filesystem::canonical(policy_path),
            policy_journal_path,
            std::uint64_t{8} * 1024U * 1024U
        );
        REQUIRE(loaded.has_value());
        auto loaded_create = loaded->create(
            create_request(canonical_source, "loaded-request-1", "loaded-workspace"), 12'000
        );
        REQUIRE(loaded_create.has_value());
    }
    REQUIRE(::chmod(policy_path.c_str(), 0644) == 0);
    REQUIRE(!path_exposure_registry::load(
                 std::filesystem::canonical(policy_path),
                 policy_journal_path,
                 std::uint64_t{8} * 1024U * 1024U
    )
                 .has_value());
    REQUIRE(::chmod(policy_path.c_str(), 0600) == 0);

    auto generation_two_grant = retained;
    generation_two_grant.generation = generation_two->generation;
    generation_two_grant.scope_digest = generation_two->scope_digest;
    REQUIRE(registry->validate_grant(generation_two_grant, "codex-safe", 7'000).has_value());
    const auto original_source = canonical_root / "sage-protocol-original";
    std::filesystem::rename(canonical_source, original_source);
    REQUIRE(std::filesystem::create_directory(canonical_source));
    REQUIRE(!registry->validate_grant(generation_two_grant, "codex-safe", 8'000).has_value());
    const auto replaced_inventory = registry->list(8'000);
    const auto replaced = std::ranges::find_if(replaced_inventory, [](const auto& exposure) {
        return exposure.exposure_id == "sage-workspace" && exposure.generation == 2;
    });
    REQUIRE(replaced != replaced_inventory.end());
    REQUIRE(replaced->state == path_exposure_state::revoked);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
