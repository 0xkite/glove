#pragma once

#include "glove/host/runtime_policy.hpp"

#include <tuple>

namespace glove::run::detail {

// Protected loaders independently admit files/snapshots around every read. This
// comparison binds the complete approved record content without dropping fields.
inline auto same_native_runtime_binding(
    const host::staged_runtime_harness& left, const host::staged_runtime_harness& right
) -> bool {
    const auto binding = [](const host::staged_runtime_harness& runtime) {
        return std::tie(
            runtime.runtime_id,
            runtime.executable_name,
            runtime.source_executable,
            runtime.canonical_source_executable,
            runtime.source_launch_executable,
            runtime.source_read_only_paths,
            runtime.protected_entry_point,
            runtime.launch_executable,
            runtime.launch_arguments,
            runtime.read_only_paths,
            runtime.snapshot_digest,
            runtime.adoption_manifest_digest,
            runtime.snapshot_logical_bytes,
            runtime.snapshot_entries
        );
    };
    return binding(left) == binding(right);
}

} // namespace glove::run::detail
