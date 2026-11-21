#pragma once

// Launch profiles: operator-authored YAML files under
// <XDG_CONFIG_HOME>/glove/profiles/<name>.yaml that describe one sandboxed
// launch (workspace, filesystem grants, environment, egress, MCP upstreams,
// tool policy). Glove reads them on the host before the sandbox exists; the
// sandbox can neither read nor write them (see protected_glove_roots).
//
// The file is a strict YAML subset, checked before decoding: block mappings
// and sequences, one-line flow collections, plain or quoted scalars, and
// comments. Anchors, aliases, tags, block scalars, multiple documents,
// directives, tabs, control bytes, and duplicate keys are refused, so the
// file a reviewer reads is the policy glove applies.

#include "glove/net/egress_proxy.hpp"
#include "glove/policy/engine.hpp"
#include "glove/run/runner.hpp"
#include "glove/run/secret_reference.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run {

inline constexpr std::uint32_t launch_profile_version = 1;
inline constexpr std::size_t max_launch_profile_bytes = 64UZ * 1024UZ;
inline constexpr std::size_t max_launch_profile_lines = 4096;
inline constexpr std::size_t max_launch_profile_entries = 256; // per list or map
inline constexpr std::size_t max_launch_profile_string = 4096;
inline constexpr std::size_t max_launch_profile_env_value = 32UZ * 1024UZ;

// One environment variable for the sandbox: a literal value, or (when
// `value` is empty) the host's value of the same name at launch.
struct profile_env_entry {
    std::string name;
    std::optional<std::string> value;

    auto operator==(const profile_env_entry&) const -> bool = default;
};

struct launch_profile {
    // Paths are absolute or start with "~/" (the invoking user's home).
    std::optional<std::string> workspace;
    std::optional<std::string> agent;
    std::vector<std::string> read;
    std::vector<std::string> write;
    std::vector<profile_env_entry> env; // sorted by name, unique
    std::vector<glove::net::egress_rule> egress;
    std::vector<upstream_spec> mcp;
    std::vector<std::string> allow;
    std::vector<glove::policy::argument_prefix_rule> allow_arg;
    std::optional<std::uint16_t> bridge_port;
    // secrets.provider: the agent preset's provider credential.
    std::optional<secret_reference> provider_secret;
    // decoys: canary files planted outside the sandbox for each launch.
    std::vector<std::string> decoys;
    // Opt-in host system services, catalog names only; unknown names fail at
    // load. See container/system_services.hpp.
    std::vector<std::string> system_services;
};

[[nodiscard]] auto operator==(const launch_profile& a, const launch_profile& b) -> bool;

// Strict parse of profile text. Never touches the filesystem.
[[nodiscard]] auto parse_launch_profile(std::string_view text)
    -> std::expected<launch_profile, std::string>;

// Canonical YAML that parse_launch_profile accepts and decodes to an equal
// profile.
[[nodiscard]] auto encode_launch_profile(const launch_profile& profile) -> std::string;

// A commented starter profile that parses.
[[nodiscard]] auto launch_profile_template() -> std::string_view;

// <XDG_CONFIG_HOME>/glove/profiles, created owner-only if missing; every
// ancestor must be owned by the user or root and not group/other writable.
[[nodiscard]] auto launch_profile_directory() -> std::expected<std::filesystem::path, std::string>;

// The profile file for NAME (letters, digits, '-', '_', '.'; at most 64).
[[nodiscard]] auto launch_profile_path(std::string_view name)
    -> std::expected<std::filesystem::path, std::string>;

// Reads PATH through one descriptor: a regular, single-link file owned by
// the user with mode 0600, no larger than max_launch_profile_bytes.
// The raw text, with those file checks.
[[nodiscard]] auto read_launch_profile_text(const std::filesystem::path& path)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto load_launch_profile_file(const std::filesystem::path& path)
    -> std::expected<launch_profile, std::string>;

[[nodiscard]] auto load_launch_profile(std::string_view name)
    -> std::expected<launch_profile, std::string>;

// The launch options for PROFILE with CLI on top: CLI workspace, agent, and
// bridge port replace the profile's; CLI lists are appended. "~/" expands to
// HOME, which must be absolute when the profile uses it.
[[nodiscard]] auto apply_launch_profile(
    const launch_profile& profile, const options& cli, const std::filesystem::path& home
) -> std::expected<options, std::string>;

// Glove's own configuration and state roots. No launch may expose a path
// inside one of them, or one of them inside an exposed path: an agent that
// could read them learns policy and decoy layout, and one that could write
// them chooses its next sandbox.
[[nodiscard]] auto protected_glove_roots() -> std::vector<std::filesystem::path>;

// Refuses when any EXPOSED path lies inside one of ROOTS or contains one,
// comparing lexical and symlink-resolved forms.
[[nodiscard]] auto refuse_glove_root_exposure(
    std::span<const std::string> exposed, std::span<const std::filesystem::path> roots
) -> std::expected<void, std::string>;

// The account's home directory from the user database (not $HOME), or empty.
[[nodiscard]] auto invoking_user_home() -> std::filesystem::path;

} // namespace glove::run
