#pragma once

#include "glove/host/config.hpp"

#include <string_view>

namespace glove::host::snapshot {

// Private rollback seam: both descriptors are borrowed, pinned by the caller
// immediately after exclusive creation, and must stay open through cleanup.
// The parent must be owner-0700; name is one component, not a path. Removes only
// the matching owner-private staging tree, including partially sealed trees.
// Failure is explicit and may leave a partially removed, owner-writable tree.
// No publication or original-operation error handling belongs to this helper.
// Same-UID concurrent namespace mutation is outside the strong integrity
// boundary: identity checks detect drift, not an atomic compare-and-unlink.
[[nodiscard]] auto
remove_owned_staging_tree(int parent_fd, std::string_view name, int owned_root_fd) -> result<void>;

} // namespace glove::host::snapshot
