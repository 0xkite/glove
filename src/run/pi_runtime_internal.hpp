#pragma once

#include "glove/run/pi_runtime.hpp"

#include <span>

namespace glove::run::detail {

// Native composition adds trusted deny-only source policy before every runtime
// hash. These variants preserve all public/default record and snapshot checks.
auto load_pi_runtime_with_exclusions(
    const std::filesystem::path& path, std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::optional<pi_runtime_selection>, std::string>;

auto store_pi_runtime_with_exclusions(
    const std::filesystem::path& path,
    const pi_runtime_selection& selection,
    bool approved,
    bool replace_existing,
    std::span<const std::filesystem::path> source_exclusions
) -> std::expected<bool, std::string>;

auto pi_library_environment_with_exclusions(
    const pi_runtime_selection& selection, std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::vector<std::string>, std::string>;

// Read-only optional host control data, capped at 1 MiB. Descriptor ancestry,
// owner-private leaf/parent admission and repeated binding/bytes checks only;
// callers must decode these bytes, never reopen the path or treat them as a
// runtime selection. Missing ancestry/file is optional only for genuine ENOENT.
[[nodiscard]] auto read_pi_operator_file(const std::filesystem::path& path)
    -> std::expected<std::optional<std::string>, std::string>;

// Setup/refresh admission only: proves the protected operator record and codec,
// not its old source/snapshot binding. Never use this result as launch authority.
[[nodiscard]] auto inspect_pi_operator_record(const std::filesystem::path& path)
    -> std::expected<std::optional<pi_runtime_selection>, std::string>;

} // namespace glove::run::detail
