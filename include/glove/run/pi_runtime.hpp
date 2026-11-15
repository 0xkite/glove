#pragma once

#include "glove/host/runtime_policy.hpp"
#include "glove/run/pi_selection.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace glove::run {

struct pi_runtime_selection {
    pi_model_selection model;
    host::staged_runtime_harness runtime;
};

// A credential-free operator record, not project configuration. Loading checks
// protected file identity and the approved source/snapshot binding; it never
// runs discovery commands or refreshes a runtime implicitly. Missing is distinct
// from malformed/unsafe/drifted. The parent must be an owner-0700 directory.
[[nodiscard]] auto load_pi_runtime_selection(const std::filesystem::path& path)
    -> std::expected<std::optional<pi_runtime_selection>, std::string>;

// Requires separate setup consent. Exclusive publication by default; replacing
// a different existing record additionally requires explicit refresh consent.
// All writes are descriptor-relative under a pinned protected parent. Existing
// unsafe files are never overwritten, even with refresh consent.
[[nodiscard]] auto store_pi_runtime_selection(
    const std::filesystem::path& path,
    const pi_runtime_selection& selection,
    bool approved,
    bool replace_existing = false
) -> std::expected<bool, std::string>;

// Derives only snapshot-local library directories, never original Homebrew
// paths. The caller must supply its own minimal environment and private home.
[[nodiscard]] auto pi_runtime_library_environment(const pi_runtime_selection& selection)
    -> std::expected<std::vector<std::string>, std::string>;

} // namespace glove::run
