#include "glove/container/profile.hpp"
#include "glove/container/receipt_chain.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/container/digest.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/linux_session_filesystem.hpp"
#include "glove/supervisor/path_alias.hpp"

#include "cgroup_v2.hpp"
#include "linux_managed_session.hpp"
#include "linux_resource_lifecycle.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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

using glove::container::profile;
using glove::container::resource_enforcement_receipt;
using glove::container::resource_limits;
using glove::container::resource_termination_cause;
using glove::container::linux_detail::cgroup_v2_root;
using glove::container::linux_detail::linux_resource_lifecycle;
using glove::supervisor::linux_detail::linux_session_filesystem;

constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

struct requested_alias {
    std::string alias;
    std::filesystem::path source;
    std::string target;
    glove::supervisor::path_access access = glove::supervisor::path_access::ephemeral_write;
};

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-managed-session-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

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

auto policy_for(const requested_alias& requested, std::uint64_t quota)
    -> glove::supervisor::path_alias_policy {
    const bool read_only = requested.access == glove::supervisor::path_access::read;
    return {
        .alias = requested.alias,
        .host_path = requested.source.string(),
        .target_path = requested.target,
        .max_ttl_secs = 300,
        .access = {{
            .access = requested.access,
            .materialization = read_only ? glove::supervisor::path_materialization::bind
                                         : glove::supervisor::path_materialization::copy,
            .create_policy = read_only ? glove::supervisor::path_create_policy::never
                                       : glove::supervisor::path_create_policy::empty_directory,
            .cleanup_policy = read_only ? glove::supervisor::path_cleanup_policy::retain
                                        : glove::supervisor::path_cleanup_policy::remove,
            .max_bytes = read_only ? 0 : quota,
        }},
    };
}

auto make_lifecycle(
    cgroup_v2_root& root,
    const std::filesystem::path& materialization_root,
    std::span<const requested_alias> requested_aliases,
    std::string_view session_id,
    const resource_limits& limits,
    std::vector<glove::supervisor::resolved_library_projection>&& library_projections = {},
    std::string_view runtime_id = {}
) -> std::expected<std::unique_ptr<linux_resource_lifecycle>, std::string> {
    std::vector<glove::supervisor::resolved_path_grant> grants;
    if (!requested_aliases.empty()) {
        const auto alias_quota = limits.disk_bytes / 4U;
        std::vector<glove::supervisor::path_alias_policy> policies;
        policies.reserve(requested_aliases.size());
        for (const auto& requested : requested_aliases) {
            policies.push_back(policy_for(requested, alias_quota));
        }
        auto registry = glove::supervisor::path_alias_registry::build(std::move(policies));
        if (!registry) {
            return std::unexpected(registry.error());
        }
        grants.reserve(requested_aliases.size());
        for (const auto& requested : requested_aliases) {
            auto grant = registry->resolve({
                .alias = requested.alias,
                .access = requested.access,
                .ttl_secs = 300,
                .max_bytes =
                    requested.access == glove::supervisor::path_access::read ? 0 : alias_quota,
            });
            if (!grant) {
                return std::unexpected(grant.error());
            }
            grants.push_back(std::move(*grant));
        }
    }
    auto filesystem = linux_session_filesystem::create(
        materialization_root.string(),
        session_id,
        limits.disk_bytes,
        std::move(grants),
        std::move(library_projections),
        runtime_id
    );
    if (!filesystem) {
        return std::unexpected(filesystem.error());
    }
    auto cgroup = root.create_session(session_id, limits);
    if (!cgroup) {
        return std::unexpected(cgroup.error());
    }
    return linux_resource_lifecycle::create(
        std::move(*cgroup), std::move(*filesystem), limits, epoch_ms()
    );
}

auto limits_for(std::uint64_t disk_bytes) -> resource_limits {
    return {
        .cpu_time_ms = 10'000,
        .memory_bytes = std::uint64_t{128} * 1024U * 1024U,
        .pids = 16,
        .wall_time_ms = 5'000,
        .disk_bytes = disk_bytes,
        .terminal_output_bytes = std::uint64_t{1024} * 1024U,
    };
}

auto launch_profile(const resource_limits& limits) -> profile {
    profile value;
    value.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin"};
    value.required_limits = limits;
    return value;
}

auto digest_for(std::string_view value) -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    return glove::container::sha256_hex(std::span{bytes, value.size()}).value_or("");
}

auto execute_managed(
    const profile& prof,
    const std::vector<std::string>& argv,
    std::unique_ptr<linux_resource_lifecycle> lifecycle
) -> std::expected<resource_enforcement_receipt, std::string> {
    if (!lifecycle) {
        return std::unexpected(std::string{"test lifecycle is required"});
    }
    auto binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, *lifecycle, controller_plan_digest
    );
    if (!binding) {
        return std::unexpected(binding.error());
    }
    return glove::container::linux_detail::exec_managed_session(
        prof, argv, *binding, std::move(lifecycle)
    );
}

// The local REQUIRE macro expands each assertion into branches; the scenario
// itself remains a single linear launch contract.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
auto mounted_copy_is_isolated_test(
    cgroup_v2_root& root,
    const std::filesystem::path& materialization_root,
    const std::filesystem::path& source,
    const std::filesystem::path& file_source,
    const std::filesystem::path& reference_source,
    std::uint64_t page
) -> int {
    const auto limits = limits_for(page * 64U);
    const std::vector aliases = {
        requested_alias{"project", source, "/workspace/project"},
        requested_alias{"single", file_source, "/workspace/single.txt"},
        requested_alias{
            "reference",
            reference_source,
            "/workspace/reference",
            glove::supervisor::path_access::read,
        },
    };
    auto lifecycle = make_lifecycle(root, materialization_root, aliases, "managed-copy", limits);
    REQUIRE(lifecycle.has_value());
    std::string script = "set -eu; ";
    script += "test \"$(cat /workspace/project/input.txt)\" = seed; ";
    script += "printf child > /workspace/project/output.txt; ";
    script += "test \"$(cat /workspace/project/output.txt)\" = child; ";
    script += "test \"$(cat /workspace/single.txt)\" = standalone; ";
    script += "printf changed > /workspace/single.txt; ";
    script += "test \"$(cat /workspace/single.txt)\" = changed; ";
    script += "test \"$(cat /workspace/reference/reference.txt)\" = trusted; ";
    script += "if (printf denied > /workspace/reference/blocked) 2>/dev/null; then exit 81; fi; ";
    script += "test -w /tmp; test -w /var/tmp; ";
    script += "test \"$(stat -c %d /tmp)\" = \"$(stat -c %d /var/tmp)\"; ";
    script += "test ! -e '" + source.string() + "'; ";
    script += "printf alpha; printf beta >&2";
    const auto prof = launch_profile(limits);
    const std::vector argv = {std::string{"/usr/bin/sh"}, std::string{"-c"}, script};
    auto binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **lifecycle, controller_plan_digest
    );
    REQUIRE(binding.has_value());
    const auto producer_key_path = materialization_root.parent_path() / "managed-audit.key";
    const auto producer_journal_path =
        materialization_root.parent_path() / "managed-receipts.journal";
    {
        std::ofstream key{producer_key_path, std::ios::binary | std::ios::trunc};
        key << audit_key << '\n';
        key.flush();
        REQUIRE(key.good());
    }
    REQUIRE(::chmod(producer_key_path.c_str(), 0600) == 0);
    const glove::container::receipt_audit_producer_config producer_config{
        .key_path = producer_key_path,
        .journal_path = producer_journal_path,
    };
    auto producer = glove::container::receipt_audit_producer::initialize(producer_config);
    REQUIRE(producer.has_value());
    const auto producer_genesis = (*producer)->anchor();
    REQUIRE((*producer)->acknowledge_bootstrap(producer_genesis).has_value());
    auto terminal = glove::container::linux_detail::exec_managed_session_authenticated(
        prof, argv, "managed-copy", *binding, std::move(*lifecycle), **producer
    );
    REQUIRE(terminal.has_value());
    const auto durable_anchor = (*producer)->anchor();
    REQUIRE(durable_anchor.sequence == 1);
    producer->reset();
    auto recovered =
        glove::container::receipt_audit_producer::recover(producer_config, producer_genesis);
    REQUIRE(recovered.has_value());
    auto pending = (*recovered)->page_after(producer_genesis, 10);
    REQUIRE(pending.has_value());
    REQUIRE(pending->envelopes.size() == 1);
    REQUIRE(pending->envelopes[0] == *terminal);
    REQUIRE(terminal->receipt.profile_digest == binding->profile_digest);
    REQUIRE(terminal->receipt.termination_cause == resource_termination_cause::exited);
    REQUIRE(terminal->receipt.exit_code == 0);
    REQUIRE(terminal->receipt.observed.disk_bytes > 0);
    REQUIRE(terminal->receipt.observed.disk_bytes <= limits.disk_bytes);
    REQUIRE(terminal->receipt.observed.terminal_output_bytes == 9);
    auto anchor = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(anchor.has_value());
    REQUIRE(
        glove::container::verify_receipt_audit_envelope(
            *terminal, audit_key, "managed-copy", controller_plan_digest, **anchor
        )
            .has_value()
    );
    REQUIRE(
        glove::container::validate_resource_enforcement_receipt(
            terminal->receipt,
            limits,
            glove::container::linux_detail::managed_session_capabilities(),
            glove::container::sandbox_backend::linux_production,
            binding->profile_digest
        )
            .has_value()
    );
    auto tampered_digest = terminal->receipt;
    tampered_digest.profile_digest[0] = tampered_digest.profile_digest[0] == 'a' ? 'b' : 'a';
    REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                 tampered_digest,
                 limits,
                 glove::container::linux_detail::managed_session_capabilities(),
                 glove::container::sandbox_backend::linux_production,
                 binding->profile_digest
    )
                 .has_value());
    auto tampered_mechanisms = terminal->receipt;
    tampered_mechanisms.mechanisms.disk = glove::container::enforcement_mechanism::unavailable;
    REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                 tampered_mechanisms,
                 limits,
                 glove::container::linux_detail::managed_session_capabilities(),
                 glove::container::sandbox_backend::linux_production,
                 binding->profile_digest
    )
                 .has_value());
    auto tampered_limits = terminal->receipt;
    ++tampered_limits.configured_limits.wall_time_ms;
    REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                 tampered_limits,
                 limits,
                 glove::container::linux_detail::managed_session_capabilities(),
                 glove::container::sandbox_backend::linux_production,
                 binding->profile_digest
    )
                 .has_value());
    auto tampered_envelope = *terminal;
    ++tampered_envelope.receipt.observed.disk_bytes;
    auto tamper_anchor = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(tamper_anchor.has_value());
    REQUIRE(
        !glove::container::verify_receipt_audit_envelope(
             tampered_envelope, audit_key, "managed-copy", controller_plan_digest, **tamper_anchor
        )
             .has_value()
    );
    REQUIRE(!std::filesystem::exists(source / "output.txt"));
    REQUIRE(!std::filesystem::exists(reference_source / "blocked"));
    {
        std::ifstream original{file_source};
        std::string contents;
        original >> contents;
        REQUIRE(contents == "standalone");
    }
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto managed_policy_rejection_test(
    cgroup_v2_root& root,
    const std::filesystem::path& materialization_root,
    const std::filesystem::path& source,
    std::uint64_t page
) -> int {
    const auto limits = limits_for(page * 32U);
    auto raw_path_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-raw-path", limits);
    REQUIRE(raw_path_lifecycle.has_value());
    auto raw_path_profile = launch_profile(limits);
    raw_path_profile.filesystem.push_back({.path = source.string(), .writable = false});
    auto raw_path =
        execute_managed(raw_path_profile, {"/usr/bin/true"}, std::move(*raw_path_lifecycle));
    REQUIRE(!raw_path.has_value());
    REQUIRE(raw_path.error().find("lifecycle mount set") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto runtime_path_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-runtime-path", limits);
    REQUIRE(runtime_path_lifecycle.has_value());
    auto runtime_path_profile = launch_profile(limits);
    runtime_path_profile.runtime_filesystem.push_back({.path = source.string(), .writable = false});
    auto runtime_path = execute_managed(
        runtime_path_profile,
        {"/bin/sh", "-c", "test -f " + (source / "input.txt").string()},
        std::move(*runtime_path_lifecycle)
    );
    REQUIRE(runtime_path.has_value());
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto unmanaged_home_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-unbound-home", limits);
    REQUIRE(unmanaged_home_lifecycle.has_value());
    auto unmanaged_home_profile = launch_profile(limits);
    unmanaged_home_profile.managed_home_dir = "/home/agent";
    auto unmanaged_home = execute_managed(
        unmanaged_home_profile, {"/usr/bin/true"}, std::move(*unmanaged_home_lifecycle)
    );
    REQUIRE(!unmanaged_home.has_value());
    REQUIRE(unmanaged_home.error().find("exact scratch projections") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto mismatched_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-limit-mismatch", limits);
    REQUIRE(mismatched_lifecycle.has_value());
    auto mismatched_limits = limits;
    ++mismatched_limits.wall_time_ms;
    auto mismatched_profile = launch_profile(mismatched_limits);
    auto mismatch =
        execute_managed(mismatched_profile, {"/usr/bin/true"}, std::move(*mismatched_lifecycle));
    REQUIRE(!mismatch.has_value());
    REQUIRE(mismatch.error().find("resource limits mismatch") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto tampered_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-binding-tamper", limits);
    REQUIRE(tampered_lifecycle.has_value());
    const auto prof = launch_profile(limits);
    const std::vector argv = {std::string{"/usr/bin/true"}};
    auto binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **tampered_lifecycle, controller_plan_digest
    );
    REQUIRE(binding.has_value());
    binding->profile_digest[0] = binding->profile_digest[0] == 'a' ? 'b' : 'a';
    auto tampered = glove::container::linux_detail::exec_managed_session(
        prof, argv, *binding, std::move(*tampered_lifecycle)
    );
    REQUIRE(!tampered.has_value());
    REQUIRE(tampered.error().find("launch binding mismatch") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto codex_runtime_context_test(
    cgroup_v2_root& root,
    const std::filesystem::path& materialization_root,
    const std::filesystem::path& library_root,
    std::uint64_t page
) -> int {
    constexpr std::string_view bundle =
        R"({"schema_version":1,"source_library_ref":"bafy-codex","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[{"key":"sage-core","kind":"skill","content_digest":"a8095aa5472d84253e87441d7438235d2b13c13e09de63cbb88609931b8b8947","content":"# Sage core\n"}]})";
    const auto bundle_digest = digest_for(bundle);
    REQUIRE(bundle_digest.size() == 64U);
    const auto bundle_path = library_root / (bundle_digest + ".json");
    {
        std::ofstream output{bundle_path, std::ios::binary | std::ios::trunc};
        output << bundle;
    }
    REQUIRE(::chmod(bundle_path.c_str(), 0600) == 0);
    auto store = glove::supervisor::library_bundle_store::open(library_root);
    REQUIRE(store.has_value());
    auto projections = store->resolve_projections({{
        .projection = {
            .projection_id = "sage-codex",
            .content_digest = bundle_digest,
            .destination_alias = "libraries",
        },
        .target_path = "/opt/sage/library-bundles",
    }});
    REQUIRE(projections.has_value());
    const auto limits = limits_for(page * 32U);
    auto lifecycle = make_lifecycle(
        root,
        materialization_root,
        {},
        "managed-codex-context",
        limits,
        std::move(*projections),
        "codex"
    );
    REQUIRE(lifecycle.has_value());
    auto prof = launch_profile(limits);
    prof.environment.push_back("CODEX_HOME=/home/agent/.codex");
    prof.managed_home_dir = "/home/agent";
    const std::vector argv = {
        std::string{"/usr/bin/sh"},
        std::string{"-c"},
        std::string{
            "test \"$HOME\" = /home/agent; test \"$CODEX_HOME\" = /home/agent/.codex; "
            "test -f /home/agent/.codex/skills/sage-codex-sage-core/SKILL.md; "
            "test \"$(cat /home/agent/.codex/skills/sage-codex-sage-core/SKILL.md)\" = '# Sage core'"
        },
    };
    auto binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **lifecycle, controller_plan_digest
    );
    REQUIRE(binding.has_value());
    auto terminal = glove::container::linux_detail::exec_managed_session(
        prof, argv, *binding, std::move(*lifecycle)
    );
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->exit_code == 0);
    REQUIRE(terminal->profile_digest == binding->profile_digest);
    REQUIRE(terminal->library_projections.size() == 1U);
    REQUIRE(terminal->library_projections.front().content_digest == bundle_digest);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    struct native_runtime_case {
        std::string_view runtime_id;
        std::string_view skill_directory;
        std::string_view managed_environment;
    };
    for (const native_runtime_case runtime : {
             native_runtime_case{"claude-code", ".claude/skills", ""},
             native_runtime_case{"pi", ".pi/agent/skills", ""},
             native_runtime_case{"copilot", ".copilot/skills", "COPILOT_HOME=/home/agent/.copilot"},
             native_runtime_case{
                 "opencode", ".config/opencode/skills", "XDG_CONFIG_HOME=/home/agent/.config"
             },
         }) {
        auto native_projections = store->resolve_projections({{
            .projection = {
                .projection_id = "sage-codex",
                .content_digest = bundle_digest,
                .destination_alias = "libraries",
            },
            .target_path = "/opt/sage/library-bundles",
        }});
        REQUIRE(native_projections.has_value());
        auto native_lifecycle = make_lifecycle(
            root,
            materialization_root,
            {},
            std::string{"managed-"} + std::string{runtime.runtime_id} + "-context",
            limits,
            std::move(*native_projections),
            runtime.runtime_id
        );
        REQUIRE(native_lifecycle.has_value());
        auto native_profile = launch_profile(limits);
        native_profile.managed_home_dir = "/home/agent";
        if (!runtime.managed_environment.empty()) {
            native_profile.environment.push_back(std::string{runtime.managed_environment});
        }
        std::string command = "test \"$HOME\" = /home/agent; test -f /home/agent/" +
                              std::string{runtime.skill_directory} +
                              "/sage-codex-sage-core/SKILL.md";
        if (!runtime.managed_environment.empty()) {
            const auto separator = runtime.managed_environment.find('=');
            command += "; test \"$" + std::string{runtime.managed_environment.substr(0, separator)} +
                       "\" = \"" + std::string{runtime.managed_environment.substr(separator + 1)} + "\"";
        }
        const std::vector native_argv = {
            std::string{"/usr/bin/sh"},
            std::string{"-c"},
            std::move(command),
        };
        auto native_binding = glove::container::linux_detail::bind_managed_session(
            native_profile, native_argv, **native_lifecycle, controller_plan_digest
        );
        REQUIRE(native_binding.has_value());
        auto native_terminal = glove::container::linux_detail::exec_managed_session(
            native_profile, native_argv, *native_binding, std::move(*native_lifecycle)
        );
        REQUIRE(native_terminal.has_value());
        REQUIRE(native_terminal->exit_code == 0);
        REQUIRE(std::filesystem::is_empty(materialization_root));
    }
    return 0;
}

auto child_release_is_gated_by_durable_callback_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root, std::uint64_t page
) -> int {
    const auto limits = limits_for(page * 16U);
    const auto prof = launch_profile(limits);
    const std::vector argv = {std::string{"/usr/bin/true"}};

    auto denied_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-start-denied", limits);
    REQUIRE(denied_lifecycle.has_value());
    auto denied_binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **denied_lifecycle, controller_plan_digest
    );
    REQUIRE(denied_binding.has_value());
    bool denied_callback_called = false;
    auto denied = glove::container::linux_detail::exec_managed_session(
        prof,
        argv,
        *denied_binding,
        std::move(*denied_lifecycle),
        [&](::pid_t child) -> std::expected<void, std::string> {
            denied_callback_called = child > 0;
            return std::unexpected(std::string{"durable running append rejected"});
        }
    );
    REQUIRE(!denied.has_value());
    REQUIRE(denied_callback_called);
    REQUIRE(denied.error().find("durable running append rejected") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto accepted_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-start-accepted", limits);
    REQUIRE(accepted_lifecycle.has_value());
    auto accepted_binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **accepted_lifecycle, controller_plan_digest
    );
    REQUIRE(accepted_binding.has_value());
    bool accepted_callback_called = false;
    auto accepted = glove::container::linux_detail::exec_managed_session(
        prof,
        argv,
        *accepted_binding,
        std::move(*accepted_lifecycle),
        [&](::pid_t child) -> std::expected<void, std::string> {
            accepted_callback_called = child > 0;
            return {};
        }
    );
    REQUIRE(accepted.has_value());
    REQUIRE(accepted_callback_called);
    REQUIRE(accepted->termination_cause == resource_termination_cause::exited);
    REQUIRE(accepted->exit_code == 0);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto child_disk_exhaustion_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root, std::uint64_t page
) -> int {
    const auto limits = limits_for(page * 16U);
    auto lifecycle = make_lifecycle(root, materialization_root, {}, "managed-disk", limits);
    REQUIRE(lifecycle.has_value());
    const std::string script =
        "dd if=/dev/urandom of=/tmp/pressure bs=4096 count=100000 status=none 2>/dev/null; "
        "sleep 10";
    auto terminal = execute_managed(
        launch_profile(limits), {"/usr/bin/sh", "-c", script}, std::move(*lifecycle)
    );
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::disk_limit);
    REQUIRE(!terminal->exit_code.has_value());
    REQUIRE(terminal->observed.disk_bytes > 0);
    REQUIRE(terminal->observed.disk_bytes <= limits.disk_bytes);
    REQUIRE(terminal->observed.wall_time_ms < limits.wall_time_ms);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto child_output_exhaustion_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root, std::uint64_t page
) -> int {
    auto limits = limits_for(page * 16U);
    limits.terminal_output_bytes = 64;
    auto lifecycle = make_lifecycle(root, materialization_root, {}, "managed-output", limits);
    REQUIRE(lifecycle.has_value());
    const std::string script = "printf '%0128d' 0; sleep 10";
    auto terminal = execute_managed(
        launch_profile(limits), {"/usr/bin/sh", "-c", script}, std::move(*lifecycle)
    );
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::terminal_output_limit);
    REQUIRE(!terminal->exit_code.has_value());
    REQUIRE(terminal->observed.terminal_output_bytes > limits.terminal_output_bytes);
    REQUIRE(terminal->observed.wall_time_ms < limits.wall_time_ms);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto interactive_pty_attach_and_stop_test(
    cgroup_v2_root& root, const std::filesystem::path& materialization_root, std::uint64_t page
) -> int {
    auto limits = limits_for(page * 16U);
    limits.wall_time_ms = 10'000;
    const auto prof = launch_profile(limits);
    const std::vector argv = {std::string{"/usr/bin/cat"}};
    auto ungated_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-pty-ungated", limits);
    REQUIRE(ungated_lifecycle.has_value());
    auto ungated_binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **ungated_lifecycle, controller_plan_digest
    );
    REQUIRE(ungated_binding.has_value());
    auto ungated = glove::container::linux_detail::start_managed_pty_session(
        prof,
        argv,
        *ungated_binding,
        std::move(*ungated_lifecycle),
        {},
        glove::container::linux_detail::managed_session_start_gate{}
    );
    REQUIRE(!ungated.has_value());
    REQUIRE(ungated.error().find("child-release gate") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto denied_lifecycle =
        make_lifecycle(root, materialization_root, {}, "managed-pty-denied", limits);
    REQUIRE(denied_lifecycle.has_value());
    auto denied_binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **denied_lifecycle, controller_plan_digest
    );
    REQUIRE(denied_binding.has_value());
    auto denied = glove::container::linux_detail::start_managed_pty_session(
        prof,
        argv,
        *denied_binding,
        std::move(*denied_lifecycle),
        {},
        [](::pid_t) -> std::expected<void, std::string> {
            return std::unexpected(std::string{"durable PTY running append rejected"});
        }
    );
    REQUIRE(!denied.has_value());
    REQUIRE(denied.error().find("durable PTY running append rejected") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto lifecycle = make_lifecycle(root, materialization_root, {}, "managed-pty", limits);
    REQUIRE(lifecycle.has_value());
    auto binding = glove::container::linux_detail::bind_managed_session(
        prof, argv, **lifecycle, controller_plan_digest
    );
    REQUIRE(binding.has_value());
    bool gate_called = false;
    auto session = glove::container::linux_detail::start_managed_pty_session(
        prof,
        argv,
        *binding,
        std::move(*lifecycle),
        {
            .transcript_bytes = page,
            .max_read_bytes = page,
            .max_input_frame_bytes = page,
            .input_timeout_ms = 1'000,
            .initial_rows = 24,
            .initial_columns = 80,
        },
        [&](::pid_t child) -> std::expected<void, std::string> {
            gate_called = child > 0;
            return {};
        }
    );
    REQUIRE(session.has_value());
    REQUIRE(gate_called);
    REQUIRE((*session)->pid() > 0);
    REQUIRE((*session)->write_input("hello from pty\n").has_value());
    auto output = (*session)->wait_read(0, page, 1'000);
    REQUIRE(output.has_value());
    REQUIRE(output->bytes.find("hello from pty") != std::string::npos);
    REQUIRE(!output->truncated);
    REQUIRE((*session)->resize(48, 132).has_value());
    bool stop_gate_called = false;
    const glove::container::linux_detail::managed_session_stop_gate before_stop =
        [&]() -> std::expected<void, std::string> {
        stop_gate_called = true;
        return {};
    };
    REQUIRE((*session)->stop(before_stop).has_value());
    REQUIRE(stop_gate_called);
    REQUIRE((*session)->stop(before_stop).has_value());
    auto terminal = (*session)->wait();
    REQUIRE(terminal.has_value());
    REQUIRE(terminal->termination_cause == resource_termination_cause::signaled);
    REQUIRE(!terminal->exit_code.has_value());
    REQUIRE(terminal->observed.terminal_output_bytes >= output->bytes.size());
    REQUIRE((*session)->wait() == terminal);
    stop_gate_called = false;
    REQUIRE((*session)->stop(before_stop).has_value());
    REQUIRE(!stop_gate_called);
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto materialization_root = tree.root() / "materializations";
    const auto source = tree.root() / "source";
    const auto file_source = tree.root() / "single-source.txt";
    const auto reference_source = tree.root() / "reference";
    const auto library_root = tree.root() / "library";
    REQUIRE(std::filesystem::create_directory(materialization_root));
    REQUIRE(::chmod(materialization_root.c_str(), 0700) == 0);
    REQUIRE(std::filesystem::create_directory(source));
    REQUIRE(std::filesystem::create_directory(reference_source));
    REQUIRE(std::filesystem::create_directory(library_root));
    REQUIRE(::chmod(library_root.c_str(), 0700) == 0);
    {
        std::ofstream input{source / "input.txt"};
        input << "seed\n";
        std::ofstream single{file_source};
        single << "standalone\n";
        std::ofstream reference{reference_source / "reference.txt"};
        reference << "trusted\n";
    }
    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const auto page = static_cast<std::uint64_t>(page_size);

    auto root = cgroup_v2_root::prepare_for_current_process();
    if (!root) {
        std::fprintf(stderr, "managed-session topology unavailable: %s\n", root.error().c_str());
        return 77;
    }
    REQUIRE(
        mounted_copy_is_isolated_test(
            *root, materialization_root, source, file_source, reference_source, page
        ) == 0
    );
    REQUIRE(managed_policy_rejection_test(*root, materialization_root, source, page) == 0);
    REQUIRE(codex_runtime_context_test(*root, materialization_root, library_root, page) == 0);
    REQUIRE(
        child_release_is_gated_by_durable_callback_test(*root, materialization_root, page) == 0
    );
    REQUIRE(child_disk_exhaustion_test(*root, materialization_root, page) == 0);
    REQUIRE(child_output_exhaustion_test(*root, materialization_root, page) == 0);
    REQUIRE(interactive_pty_attach_and_stop_test(*root, materialization_root, page) == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
