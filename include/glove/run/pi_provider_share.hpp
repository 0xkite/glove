#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run {

// A Pi provider whose host credential can be mediated for a sandboxed Pi
// (`glove shell --agent pi --share-credential <provider>`). Everything here is
// derived from Pi's own data; no field is chosen per provider in code.
struct pi_shared_provider {
    std::string name;
    std::string host;
    std::uint16_t port = 443;
    // Upstream path prefix from the provider base URL, without a trailing
    // slash ("" or e.g. "/v1beta").
    std::string base_path;
    // Upstream request paths the endpoint forwards (`/*` suffix = subtree),
    // from the method/path limits of each supported Pi API type in use.
    std::vector<std::string> allowed_paths;

    auto operator==(const pi_shared_provider&) const -> bool = default;
};

// Lowercase ASCII letters, digits, `.`, `_`, and `-`, starting with a letter
// or digit, at most 64 bytes: safe as a catalog file name and a URL segment.
[[nodiscard]] auto valid_pi_provider_name(std::string_view name) -> bool;

// Resolve a provider from Pi's built-in catalog file for that provider
// (`{api: {key: {provider, api, baseUrl}}}`, may be empty) and host
// models.json (may be empty). A models.json provider `baseUrl` replaces the
// catalog base URLs, as it does in Pi. The provider must have exactly one
// HTTPS base URL that is not loopback, templated, or carrying userinfo, query,
// fragment, or dot segments, and at least one supported API type. Other API
// types and multiple base URLs are refused by name.
[[nodiscard]] auto resolve_pi_shared_provider(
    std::string_view name, std::string_view catalog_json, std::string_view models_json
) -> std::expected<pi_shared_provider, std::string>;

using pi_environment_lookup = std::function<std::optional<std::string>(std::string_view)>;

// The host secret for a provider, as Pi would find it: host auth.json
// `{type: "api_key", key}` first, then the models.json provider `apiKey`
// (`$NAME`/`${NAME}` from the host environment, or a literal). Subscription
// (OAuth) logins, `!command` keys, unset variables, and values with control
// bytes are refused. The secret is never included in an error.
[[nodiscard]] auto pi_shared_provider_secret(
    std::string_view name,
    std::string_view auth_json,
    std::string_view models_json,
    const pi_environment_lookup& environment
) -> std::expected<std::string, std::string>;

} // namespace glove::run
