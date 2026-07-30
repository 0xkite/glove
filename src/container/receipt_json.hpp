#pragma once

#include "glove/container/profile.hpp"

#include <glaze/core/common.hpp>

template<> struct glz::meta<glove::container::sandbox_backend> {
    using enum glove::container::sandbox_backend;
    static constexpr auto value = enumerate(
        "linux_production",
        linux_production,
        "apple_container",
        apple_container,
        "macos_experimental",
        macos_experimental
    );
};

template<> struct glz::meta<glove::container::enforcement_mechanism> {
    using enum glove::container::enforcement_mechanism;
    static constexpr auto value = enumerate(
        "unavailable",
        unavailable,
        "rlimit",
        rlimit,
        "cgroup_v2",
        cgroup_v2,
        "watchdog",
        watchdog,
        "filesystem_quota",
        filesystem_quota,
        "byte_counter",
        byte_counter
    );
};

template<> struct glz::meta<glove::container::resource_termination_cause> {
    using enum glove::container::resource_termination_cause;
    static constexpr auto value = enumerate(
        "exited",
        exited,
        "signaled",
        signaled,
        "cpu_time_limit",
        cpu_time_limit,
        "memory_limit",
        memory_limit,
        "pid_limit",
        pid_limit,
        "wall_time_limit",
        wall_time_limit,
        "disk_limit",
        disk_limit,
        "terminal_output_limit",
        terminal_output_limit,
        "supervisor_error",
        supervisor_error
    );
};
