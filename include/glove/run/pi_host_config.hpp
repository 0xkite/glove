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

// Local sources follow Pi's `isLocalPath`: after trimming, anything that is not
// an npm, git, GitHub, URL, ssh, or builtin source is a path (`file:` URLs
// included). They come from `packages` (string or object `source`) and from the
// top-level `extensions`, `skills`, `prompts`, and `themes` arrays, whose
// entries may carry a `!`/`-`/`+` prefix. Relative paths resolve from
// `settings_dir`; `~` expands to `home`. `!`/`-` exclusions and `*`/`?`
// patterns are not returned: they match agent-relative paths and stay as
// written. Resolution is lexical only.
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

// Read host `<pi_agent_dir>/settings.json` under the same rules the runner
// uses to stage it: owned by the effective user, at most 4 MiB, and, when it is
// a symlink, resolving to a `settings.json` regular file inside `~/.pi`, a
// dotfiles tree (`~/Documents/depend/dotfiles`, `~/.dotfiles`), or the agent
// directory. A target inside any `agent_writable` path is refused: sandboxed
// code must not choose which host paths a later launch exposes.
[[nodiscard]] auto read_host_pi_settings(
    const std::filesystem::path& pi_agent_dir,
    const std::filesystem::path& home,
    const std::vector<std::filesystem::path>& agent_writable
) -> std::expected<std::string, std::string>;

// Rewrite the guest copy of `settings.json`. `exposed` maps a declared entry to
// the absolute path that replaces it (a resource entry keeps its prefix). Local
// package and resource entries that are not mapped are removed so Pi does not
// abort on a path the sandbox cannot read; exclusions and patterns are kept
// as written.
// Non-local entries and all other settings are preserved.
[[nodiscard]] auto rewrite_pi_settings_packages(
    std::string_view settings_json, const std::map<std::string, std::string>& exposed
) -> std::expected<std::string, std::string>;

// Remove credentials from the guest copy of `models.json`. Every `apiKey` and
// `headers` value at any depth (providers, `models[]`, `modelOverrides`) is kept
// only when it is an environment reference (`$NAME`, `${NAME}`, or an auth
// scheme followed by one, such as `Bearer ${NAME}`), or a literal sent only to
// loopback endpoints (the object's effective `baseUrl`, and for a provider every
// model `baseUrl`, is loopback). Loopback literals are kept because local model
// servers need dummy keys; a real local proxy key is therefore visible to the
// sandbox. `!command` values are always removed.
[[nodiscard]] auto scrub_pi_models_credentials(std::string_view models_json)
    -> std::expected<std::string, std::string>;

} // namespace glove::run
