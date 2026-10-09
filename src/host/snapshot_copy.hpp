#pragma once

#include "glove/host/config.hpp"

#include <cstdint>
#include <filesystem>
#include <vector>

namespace glove::host::snapshot {

// Writes only beneath an existing owner-0700 empty payload. Root wrappers are
// excluded from the entry budget, matching snapshot_closure_digest. Failure
// leaves partial output for the caller to remove; publication and final digest
// verification remain the caller's responsibility. Paths must be bounded,
// canonical absolute non-root paths. Safe relative links are retained; bounded
// chains are checked by descriptor traversal. Dangling/escaping links fail.
[[nodiscard]] auto copy_runtime_closure(
    const std::vector<std::filesystem::path>& source_roots,
    const std::filesystem::path& existing_empty_payload,
    std::uint64_t planned_bytes,
    std::uint64_t planned_entries
) -> result<void>;

} // namespace glove::host::snapshot
