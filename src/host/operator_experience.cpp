#include "glove/host/operator_experience.hpp"

namespace glove::host {
namespace {

#if defined(__APPLE__)
auto macos_guidance() -> setup_guidance {
    return {
        .platform = "macos",
        .recommended_path = "macos-apple-container",
        .paths = {
            {
                .id = "macos-apple-container",
                .goal = "Build, test, and ship Glove for macOS.",
                .isolation = "Apple Container VM coverage plus the native macOS sandbox runtime.",
                .cost = "Container image storage and VM startup in the shipping lane.",
                .receipts = "Portable Glove tests, outer VM resource/filesystem/network evidence, "
                            "and native macOS runtime tests.",
                .limitation = "Apple guests do not currently expose nested procfs/cgroup controls; "
                              "those Linux-only capabilities remain explicit.",
                .next_command = "./scripts/macos-shipping-lane.sh",
#    if defined(__aarch64__) || defined(__arm64__)
                .eligible = true,
                .recommended = true,
#    else
                .eligible = false,
                .recommended = false,
#    endif
            },
            {
                .id = "macos-local",
                .goal = "Iterate quickly on local harness behavior before the shipping lane.",
                .isolation = "Native macOS sandbox profile (experimental).",
                .cost = "Low startup and storage overhead.",
                .receipts = "Glove process and terminal evidence; no Linux cgroup receipts.",
                .limitation = "Fast development mode, not the complete macOS shipping gate.",
                .next_command = "glove setup --dry-run",
                .eligible = true,
                .recommended = false,
            },
            {
                .id = "linux-production",
                .goal = "Run managed agent sessions with delegated kernel controls.",
                .isolation = "Linux namespaces, seccomp, mounts, and delegated cgroups.",
                .cost = "Requires a suitable Linux host and service configuration.",
                .receipts = "Filesystem, network, resource, terminal, lifecycle, and cleanup "
                            "receipts.",
                .limitation = "Unavailable on this macOS host.",
                .next_command = "glove setup guide --json",
                .eligible = false,
                .recommended = false,
            },
        },
    };
}
#endif

#if defined(__linux__)
auto linux_guidance() -> setup_guidance {
    return {
        .platform = "linux",
        .recommended_path = "linux-production",
        .paths = {
            {
                .id = "linux-production",
                .goal = "Run managed agent sessions with delegated kernel controls.",
                .isolation = "Linux namespaces, seccomp, mounts, and delegated cgroups.",
                .cost = "Requires user namespaces, mount support, and delegated cpu, memory, and "
                        "pids controllers.",
                .receipts = "Filesystem, network, resource, terminal, lifecycle, and cleanup "
                            "receipts.",
                .limitation = "Setup does not waive failed kernel or service preflight checks.",
                .next_command = "glove setup --dry-run",
                .eligible = true,
                .recommended = true,
            },
            {
                .id = "macos-apple-container",
                .goal = "Build, test, and ship Glove for macOS.",
                .isolation = "Apple Container VM coverage plus the native macOS sandbox runtime.",
                .cost = "Requires a separate Apple Silicon macOS 26+ host.",
                .receipts = "Portable, outer-VM, and native macOS runtime evidence.",
                .limitation = "Unavailable on this Linux host.",
                .next_command = "glove setup guide --json",
                .eligible = false,
                .recommended = false,
            },
            {
                .id = "macos-local",
                .goal = "Fast local harness development and compatibility checks.",
                .isolation = "Native macOS sandbox profile (experimental).",
                .cost = "Requires a separate macOS host.",
                .receipts = "No Linux cgroup receipts.",
                .limitation = "Unavailable on this Linux host.",
                .next_command = "glove setup guide --json",
                .eligible = false,
                .recommended = false,
            },
        },
    };
}
#endif

} // namespace

auto operator_setup_guidance() -> setup_guidance {
#if defined(__APPLE__)
    return macos_guidance();
#elif defined(__linux__)
    return linux_guidance();
#else
    return {
        .platform = "unsupported",
        .recommended_path = {},
        .paths = {},
    };
#endif
}

auto parse_project_purpose(std::string_view value) -> project_purpose {
    if (value == "experiment") {
        return project_purpose::experiment;
    }
    if (value == "retain") {
        return project_purpose::retain;
    }
    return project_purpose::inspect;
}

auto defaults_for(project_purpose purpose) -> project_purpose_defaults {
    constexpr std::uint64_t gibibyte = std::uint64_t{1024} * 1024U * 1024U;
    switch (purpose) {
    case project_purpose::inspect:
        return {
            .access = project_access::read,
            .max_bytes = 0,
            .ttl_secs = 3'600,
            .write_scope = "none",
            .cleanup = "No writable project copy is created.",
        };
    case project_purpose::experiment:
        return {
            .access = project_access::ephemeral_write,
            .max_bytes = gibibyte,
            .ttl_secs = 3'600,
            .write_scope = "isolated copy, up to 1 GiB",
            .cleanup = "The writable copy is removed after the session.",
        };
    case project_purpose::retain:
        return {
            .access = project_access::retained_write,
            .max_bytes = gibibyte,
            .ttl_secs = 86'400,
            .write_scope = "isolated copy, up to 1 GiB",
            .cleanup = "The writable copy is retained for explicit review and apply.",
        };
    }
    return {};
}

auto project_purpose_name(project_purpose purpose) -> std::string_view {
    switch (purpose) {
    case project_purpose::inspect:
        return "inspect";
    case project_purpose::experiment:
        return "experiment";
    case project_purpose::retain:
        return "retain";
    }
    return "inspect";
}

} // namespace glove::host
