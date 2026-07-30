#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/supervisor/linux_session_filesystem.hpp"

#include "linux_managed_session.hpp"
#include "linux_resource_lifecycle.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <expected>
#include <ranges>
#include <string>
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
using glove::container::resource_limits;
using glove::container::linux_detail::managed_launch_binding;
using glove::supervisor::linux_detail::session_mount;

constexpr std::string_view controller_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

auto limits() -> resource_limits {
    return {
        .cpu_time_ms = 10'000,
        .memory_bytes = std::uint64_t{128} * 1024U * 1024U,
        .pids = 16,
        .wall_time_ms = 20'000,
        .disk_bytes = std::uint64_t{16} * 1024U * 1024U,
        .terminal_output_bytes = std::uint64_t{1024} * 1024U,
    };
}

auto launch_profile() -> profile {
    profile result;
    result.environment = {"TERM=xterm-256color", "PATH=/usr/bin:/bin"};
    result.required_limits = limits();
    return result;
}

auto mounts() -> std::vector<session_mount> {
    const auto scratch_quota = limits().disk_bytes * 3U / 4U;
    const auto project_quota = limits().disk_bytes - scratch_quota;
    return {
        {
            .descriptor_fd = 12,
            .target_path = "/var/tmp",
            .alias = "__scratch_var_tmp",
            .quota_partition = "__scratch",
            .quota_bytes = scratch_quota,
            .source_identity = std::nullopt,
            .source_content_digest = std::nullopt,
            .projection_id = std::nullopt,
            .projection_destination_alias = std::nullopt,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .secret_handle = std::nullopt,
            .secret_runtime_id = std::nullopt,
            .writable = true,
            .directory = true,
        },
        {
            .descriptor_fd = 11,
            .target_path = "/tmp",
            .alias = "__scratch_tmp",
            .quota_partition = "__scratch",
            .quota_bytes = scratch_quota,
            .source_identity = std::nullopt,
            .source_content_digest = std::nullopt,
            .projection_id = std::nullopt,
            .projection_destination_alias = std::nullopt,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .secret_handle = std::nullopt,
            .secret_runtime_id = std::nullopt,
            .writable = true,
            .directory = true,
        },
        {
            .descriptor_fd = 13,
            .target_path = "/workspace/project",
            .alias = "project",
            .quota_partition = "project",
            .quota_bytes = project_quota,
            .source_identity =
                glove::supervisor::path_identity{
                    .device = 7,
                    .inode = 11,
                    .mode = static_cast<std::uint32_t>(S_IFDIR | 0700),
                },
            .source_content_digest = std::nullopt,
            .projection_id = std::nullopt,
            .projection_destination_alias = std::nullopt,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .secret_handle = std::nullopt,
            .secret_runtime_id = std::nullopt,
            .writable = true,
            .directory = true,
        },
        {
            .descriptor_fd = 14,
            .target_path = "/workspace/reference",
            .alias = "reference",
            .quota_partition = "",
            .quota_bytes = 0,
            .source_identity =
                glove::supervisor::path_identity{
                    .device = 7,
                    .inode = 12,
                    .mode = static_cast<std::uint32_t>(S_IFDIR | 0755),
                },
            .source_content_digest = std::nullopt,
            .projection_id = std::nullopt,
            .projection_destination_alias = std::nullopt,
            .runtime_adapter_id = std::nullopt,
            .runtime_context_digest = std::nullopt,
            .secret_handle = std::nullopt,
            .secret_runtime_id = std::nullopt,
            .writable = false,
            .directory = true,
        },
    };
}

auto make_binding(
    const profile& prof,
    const std::vector<std::string>& argv,
    const std::vector<session_mount>& projection,
    std::string_view plan_digest = controller_digest
) -> std::expected<managed_launch_binding, std::string> {
    return glove::container::linux_detail::bind_managed_launch_projection(
        prof, argv, projection, plan_digest
    );
}

auto run() -> int {
    auto first_profile = launch_profile();
    const std::vector argv = {std::string{"/usr/bin/true"}, std::string{"--version"}};
    auto first_mounts = mounts();
    auto first = make_binding(first_profile, argv, first_mounts);
    REQUIRE(first.has_value());
    REQUIRE(first->controller_plan_digest == controller_digest);
    REQUIRE(first->profile_digest.size() == 64);
    REQUIRE(first->library_projections.empty());

    std::ranges::reverse(first_profile.environment);
    std::ranges::reverse(first_mounts);
    auto reordered = make_binding(first_profile, argv, first_mounts);
    REQUIRE(reordered == first);

    auto changed_argv = argv;
    changed_argv.push_back("different");
    auto argv_binding = make_binding(first_profile, changed_argv, first_mounts);
    REQUIRE(argv_binding.has_value());
    REQUIRE(argv_binding->profile_digest != first->profile_digest);

    auto workspace_profile = first_profile;
    workspace_profile.work_dir = "/workspace";
    auto workspace_binding = make_binding(workspace_profile, argv, first_mounts);
    REQUIRE(workspace_binding.has_value());
    REQUIRE(workspace_binding->profile_digest != first->profile_digest);

    auto invalid_work_dir = first_profile;
    invalid_work_dir.work_dir = "/tmp";
    REQUIRE(!make_binding(invalid_work_dir, argv, first_mounts).has_value());

    auto unbacked_work_dir_mounts = first_mounts;
    for (auto& mount : unbacked_work_dir_mounts) {
        if (mount.target_path == "/workspace/project") {
            mount.target_path = "/project";
        } else if (mount.target_path == "/workspace/reference") {
            mount.target_path = "/reference";
        }
    }
    REQUIRE(!make_binding(workspace_profile, argv, unbacked_work_dir_mounts).has_value());

    auto changed_mounts = first_mounts;
    changed_mounts[0].target_path = "/workspace/tmp";
    auto mount_binding = make_binding(first_profile, argv, changed_mounts);
    REQUIRE(mount_binding.has_value());
    REQUIRE(mount_binding->profile_digest != first->profile_digest);

    auto writable_reference = first_mounts;
    const auto writable_reference_entry =
        std::ranges::find(writable_reference, std::string{"reference"}, &session_mount::alias);
    REQUIRE(writable_reference_entry != writable_reference.end());
    writable_reference_entry->writable = true;
    REQUIRE(!make_binding(first_profile, argv, writable_reference).has_value());

    auto quota_bearing_reference = first_mounts;
    const auto quota_bearing_reference_entry =
        std::ranges::find(quota_bearing_reference, std::string{"reference"}, &session_mount::alias);
    REQUIRE(quota_bearing_reference_entry != quota_bearing_reference.end());
    quota_bearing_reference_entry->quota_partition = "reference";
    quota_bearing_reference_entry->quota_bytes = 4096U;
    REQUIRE(!make_binding(first_profile, argv, quota_bearing_reference).has_value());

    auto changed_quota = first_mounts;
    for (auto& mount : changed_quota) {
        if (mount.quota_partition == "__scratch") {
            mount.quota_bytes -= 4096U;
        } else if (mount.writable) {
            mount.quota_bytes += 4096U;
        }
    }
    auto quota_binding = make_binding(first_profile, argv, changed_quota);
    REQUIRE(quota_binding.has_value());
    REQUIRE(quota_binding->profile_digest != first->profile_digest);

    auto library_mounts = first_mounts;
    const std::string library_digest(64U, 'd');
    library_mounts.push_back({
        .descriptor_fd = 15,
        .target_path = "/opt/sage/library-bundles/" + library_digest + ".json",
        .alias = "library:sage-core",
        .quota_partition = "",
        .quota_bytes = 0,
        .source_identity =
            glove::supervisor::path_identity{
                .device = 7,
                .inode = 13,
                .mode = static_cast<std::uint32_t>(S_IFREG | 0600),
            },
        .source_content_digest = library_digest,
        .projection_id = "sage-core",
        .projection_destination_alias = "libraries",
        .runtime_adapter_id = std::nullopt,
        .runtime_context_digest = std::nullopt,
        .secret_handle = std::nullopt,
        .secret_runtime_id = std::nullopt,
        .writable = false,
        .directory = false,
    });
    auto library_binding = make_binding(first_profile, argv, library_mounts);
    REQUIRE(library_binding.has_value());
    REQUIRE(library_binding->profile_digest != first->profile_digest);
    REQUIRE(library_binding->library_projections.size() == 1U);
    REQUIRE(library_binding->library_projections.front().projection_id == "sage-core");
    REQUIRE(library_binding->library_projections.front().destination_alias == "libraries");
    REQUIRE(library_binding->library_projections.front().content_digest == library_digest);
    REQUIRE(
        library_binding->library_projections.front().target_path ==
        "/opt/sage/library-bundles/" + library_digest + ".json"
    );
    library_mounts.back().source_content_digest = std::string(64U, 'e');
    REQUIRE(!make_binding(first_profile, argv, library_mounts).has_value());

    auto inconsistent_quota = first_mounts;
    ++inconsistent_quota[0].quota_bytes;
    REQUIRE(!make_binding(first_profile, argv, inconsistent_quota).has_value());

    auto changed_plan = make_binding(
        first_profile,
        argv,
        first_mounts,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    REQUIRE(changed_plan.has_value());
    REQUIRE(changed_plan->profile_digest != first->profile_digest);

    auto online_profile = first_profile;
    online_profile.proxy = glove::container::proxy_settings{
        .port = 43117,
        .url = "http://glove:ephemeral-a@127.0.0.1:43117",
    };
    auto online_binding = make_binding(online_profile, argv, first_mounts);
    REQUIRE(online_binding.has_value());
    REQUIRE(online_binding->profile_digest != first->profile_digest);
    online_profile.proxy->url = "http://glove:ephemeral-b@127.0.0.1:43117";
    auto changed_egress_capability = make_binding(online_profile, argv, first_mounts);
    REQUIRE(changed_egress_capability.has_value());
    REQUIRE(changed_egress_capability->profile_digest != online_binding->profile_digest);

    auto credentialed_profile = first_profile;
    credentialed_profile.managed_home_dir = "/home/agent";
    auto credentialed_mounts = first_mounts;
    credentialed_mounts.push_back({
        .descriptor_fd = 16,
        .target_path = "/home/agent",
        .alias = "__runtime_home_codex",
        .quota_partition = "__scratch",
        .quota_bytes = limits().disk_bytes * 3U / 4U,
        .source_identity = std::nullopt,
        .source_content_digest = std::nullopt,
        .projection_id = std::nullopt,
        .projection_destination_alias = std::nullopt,
        .runtime_adapter_id = "codex",
        .runtime_context_digest = std::string(64U, 'c'),
        .secret_handle = std::nullopt,
        .secret_runtime_id = std::nullopt,
        .writable = true,
        .directory = true,
    });
    credentialed_mounts.push_back({
        .descriptor_fd = 17,
        .target_path = "/home/agent/.codex/auth.json",
        .alias = "secret:codex-auth",
        .quota_partition = "",
        .quota_bytes = 0,
        .source_identity =
            glove::supervisor::path_identity{
                .device = 7,
                .inode = 14,
                .mode = static_cast<std::uint32_t>(S_IFREG | 0600),
            },
        .source_content_digest = std::nullopt,
        .projection_id = std::nullopt,
        .projection_destination_alias = std::nullopt,
        .runtime_adapter_id = std::nullopt,
        .runtime_context_digest = std::nullopt,
        .secret_handle = "codex-auth",
        .secret_runtime_id = "codex",
        .writable = true,
        .directory = false,
    });
    auto credentialed_binding = make_binding(credentialed_profile, argv, credentialed_mounts);
    REQUIRE(credentialed_binding.has_value());
    REQUIRE(credentialed_binding->profile_digest != first->profile_digest);
    credentialed_profile.work_dir = "/home/agent";
    auto private_home_binding = make_binding(credentialed_profile, argv, credentialed_mounts);
    REQUIRE(private_home_binding.has_value());
    REQUIRE(private_home_binding->profile_digest != credentialed_binding->profile_digest);
    credentialed_profile.work_dir = "/tmp";
    REQUIRE(!make_binding(credentialed_profile, argv, credentialed_mounts).has_value());

    auto mismatched_secret = credentialed_mounts;
    mismatched_secret.back().secret_runtime_id = "claude";
    REQUIRE(!make_binding(credentialed_profile, argv, mismatched_secret).has_value());

    auto secret_outside_home = credentialed_mounts;
    secret_outside_home.back().target_path = "/run/secrets/codex-auth";
    REQUIRE(!make_binding(credentialed_profile, argv, secret_outside_home).has_value());

    std::string executable_pattern = "/tmp/glove-launch-binding-exec-XXXXXX";
    const int executable_fd = ::mkstemp(executable_pattern.data());
    REQUIRE(executable_fd >= 0);
    REQUIRE(::fchmod(executable_fd, 0700) == 0);
    REQUIRE(::write(executable_fd, "first", 5) == 5);
    const std::vector executable_argv = {executable_pattern};
    auto executable_before = make_binding(first_profile, executable_argv, first_mounts);
    REQUIRE(executable_before.has_value());
    REQUIRE(::write(executable_fd, "-changed", 8) == 8);
    auto executable_after = make_binding(first_profile, executable_argv, first_mounts);
    REQUIRE(executable_after.has_value());
    REQUIRE(executable_after->profile_digest != executable_before->profile_digest);
    auto pinned_before = glove::container::linux_detail::bind_managed_launch_projection_from_fd(
        first_profile, executable_argv, first_mounts, controller_digest, executable_fd
    );
    REQUIRE(pinned_before.has_value());
    const std::string original_path = executable_pattern + "-original";
    REQUIRE(::rename(executable_pattern.c_str(), original_path.c_str()) == 0);
    auto pinned_after_rename =
        glove::container::linux_detail::bind_managed_launch_projection_from_fd(
            first_profile, executable_argv, first_mounts, controller_digest, executable_fd
        );
    REQUIRE(pinned_after_rename.has_value());
    const int replacement_fd =
        ::open(executable_pattern.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    REQUIRE(replacement_fd >= 0);
    REQUIRE(::write(replacement_fd, "replacement", 11) == 11);
    REQUIRE(::close(replacement_fd) == 0);
    auto pinned_after = glove::container::linux_detail::bind_managed_launch_projection_from_fd(
        first_profile, executable_argv, first_mounts, controller_digest, executable_fd
    );
    REQUIRE(pinned_after.has_value());
    // Rename updates ctime, which is deliberately committed by the binding.
    // Replacing the old path must not affect a descriptor pinned after rename.
    REQUIRE(pinned_after == pinned_after_rename);
    auto pinned_repeated = glove::container::linux_detail::bind_managed_launch_projection_from_fd(
        first_profile, executable_argv, first_mounts, controller_digest, executable_fd
    );
    REQUIRE(pinned_repeated == pinned_after);
    auto replacement = make_binding(first_profile, executable_argv, first_mounts);
    REQUIRE(replacement.has_value());
    REQUIRE(replacement->profile_digest != pinned_after->profile_digest);
    REQUIRE(::close(executable_fd) == 0);
    REQUIRE(::unlink(executable_pattern.c_str()) == 0);
    REQUIRE(::unlink(original_path.c_str()) == 0);

    REQUIRE(!make_binding(first_profile, argv, first_mounts, "not-a-digest").has_value());
    REQUIRE(glove::container::linux_detail::managed_session_capabilities().complete());
    auto public_spawner = glove::container::make_default_spawner();
    REQUIRE(public_spawner != nullptr);
    REQUIRE(!public_spawner->resource_capabilities().complete());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
