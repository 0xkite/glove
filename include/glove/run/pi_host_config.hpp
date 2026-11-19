#pragma once

#include <expected>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run {

// A local Pi package declaration from host `settings.json` (`packages`), as
// written and as resolved against the directory holding that settings file.
// npm, git, and URL sources are not local and are never returned.
struct pi_local_package {
    std::string declared;
    std::filesystem::path resolved;

    auto operator==(const pi_local_package&) const -> bool = default;
};

// Local package sources start with `./`, `../`, `/`, or `~`, either as a
// string entry or as the `source` of an object entry. Relative sources resolve
// from `settings_dir`; `~` expands to `home`. Resolution is lexical only; the
// caller decides whether a resolved path may be exposed.
[[nodiscard]] auto pi_local_package_sources(
    std::string_view settings_json,
    const std::filesystem::path& settings_dir,
    const std::filesystem::path& home
) -> std::expected<std::vector<pi_local_package>, std::string>;

// Whether a resolved local package may be exposed read-only to a sandboxed Pi.
// It must exist, be a directory or regular file owned by the effective user
// (including after symlink resolution), and must not be or contain `home`,
// contain `pi_agent_dir` (which holds `auth.json`), or name a credential store.
// Returns the canonical path to expose, or why it is refused.
[[nodiscard]] auto pi_package_exposure(
    const std::filesystem::path& resolved,
    const std::filesystem::path& home,
    const std::filesystem::path& pi_agent_dir
) -> std::expected<std::filesystem::path, std::string>;

// Rewrite the guest copy of `settings.json`: each local package whose declared
// source is a key of `exposed` is replaced by the mapped absolute path, and
// every other local package entry is removed so Pi does not abort on a path the
// sandbox cannot read. Non-local entries and all other settings are preserved.
[[nodiscard]] auto rewrite_pi_settings_packages(
    std::string_view settings_json, const std::map<std::string, std::string>& exposed
) -> std::expected<std::string, std::string>;

// Remove provider credentials from the guest copy of `models.json`. `apiKey`
// and header values are kept only when they are an environment reference
// (`$NAME` / `${NAME}`, resolved from the sandbox's own environment) or when the
// provider's `baseUrl` is a loopback host, where they are local dummy keys.
// Literal remote keys and `!command` values are removed.
[[nodiscard]] auto scrub_pi_models_credentials(std::string_view models_json)
    -> std::expected<std::string, std::string>;

} // namespace glove::run
