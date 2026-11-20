#include "glove/run/pi_provider_share.hpp"

#include "glove/run/pi_host_config.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <set>
#include <string>
#include <utility>

namespace glove::run {

namespace {

constexpr std::size_t max_config_bytes = 4U * 1024U * 1024U;
constexpr std::size_t max_secret_bytes = 8192U;

// Method/path limits per Pi API type, relative to the provider base path.
// Keyed by the wire protocol, not by provider: every provider that speaks one
// of these shares its row. An API type absent here cannot be shared.
struct api_route {
    std::string_view api;
    std::string_view path;
};

// `/*:suffix` admits one model segment ending in that method, so a shared
// Google key reaches generation and token counting only, not batch, embedding,
// or media endpoints under the same collection.
constexpr std::array<api_route, 6> api_routes{{
    {"openai-completions", "/chat/completions"},
    {"openai-responses", "/responses"},
    {"anthropic-messages", "/v1/messages"},
    {"google-generative-ai", "/models/*:generateContent"},
    {"google-generative-ai", "/models/*:streamGenerateContent"},
    {"google-generative-ai", "/models/*:countTokens"},
}};

auto parse_object(std::string_view json, std::string_view what)
    -> std::expected<glz::generic, std::string> {
    if (json.size() > max_config_bytes) {
        return std::unexpected(std::string{what} + " exceeds the configuration size limit");
    }
    const auto first = json.find_first_not_of(" \t\r\n");
    std::string buffer{first == std::string_view::npos ? std::string_view{"{}"} : json};
    glz::generic parsed{};
    if (const auto error = glz::read_json(parsed, buffer); error || !parsed.is_object()) {
        return std::unexpected(std::string{what} + " is not a JSON object");
    }
    return parsed;
}

auto string_field(const glz::generic::object_t& object, std::string_view key)
    -> std::optional<std::string> {
    const auto found = object.find(key);
    if (found == object.end() || !found->second.is_string()) {
        return std::nullopt;
    }
    return found->second.get_string();
}

auto object_field(const glz::generic::object_t& object, std::string_view key)
    -> const glz::generic::object_t* {
    const auto found = object.find(key);
    if (found == object.end() || !found->second.is_object()) {
        return nullptr;
    }
    return &found->second.get_object();
}

struct upstream {
    std::string host;
    std::uint16_t port = 443;
    std::string path;

    auto operator<=>(const upstream&) const = default;
};

auto is_loopback_host(std::string_view host) -> bool {
    return host == "localhost" || host.ends_with(".localhost") || host.starts_with("127.") ||
           host == "0.0.0.0";
}

// HTTPS only; a host name of [a-z0-9.-] with at least one dot; an optional
// numeric port; a path of non-empty, non-dot segments. Anything a client or an
// upstream could read differently (templates, userinfo, query, fragment,
// backslash, whitespace, controls) is refused rather than normalised.
auto parse_base_url(std::string_view url) -> std::expected<upstream, std::string> {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme)) {
        return std::unexpected(std::string{"base URL is not https"});
    }
    for (const char ch : url) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte <= 0x20U || byte >= 0x7FU || ch == '{' || ch == '}' || ch == '@' || ch == '?' ||
            ch == '#' || ch == '\\' || ch == '%') {
            return std::unexpected(std::string{"base URL is templated or ambiguous"});
        }
    }
    const auto rest = url.substr(scheme.size());
    const auto slash = rest.find('/');
    const auto authority = rest.substr(0, slash);
    std::string_view path =
        slash == std::string_view::npos ? std::string_view{} : rest.substr(slash);
    upstream out;
    const auto colon = authority.find(':');
    std::string host{authority.substr(0, colon)};
    std::ranges::transform(host, host.begin(), [](char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    });
    // A DNS name: dotted, no trailing dot, and a top-level label with a
    // letter, which excludes dotted-decimal, hex, and octal IPv4 forms.
    const auto top_label = host.substr(host.rfind('.') + 1);
    if (host.empty() || host.find('.') == std::string::npos || host.ends_with('.') ||
        host.starts_with('.') || host.find("..") != std::string::npos ||
        !std::ranges::any_of(top_label, [](char c) { return c >= 'a' && c <= 'z'; }) ||
        !std::ranges::all_of(host, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
        })) {
        return std::unexpected(std::string{"base URL host is not a DNS name"});
    }
    if (is_loopback_host(host)) {
        return std::unexpected(
            std::string{"base URL is loopback; a local provider needs no shared credential"}
        );
    }
    if (colon != std::string_view::npos) {
        const auto digits = authority.substr(colon + 1);
        unsigned value = 0;
        const auto* end = digits.data() + digits.size();
        const auto [ptr, ec] = std::from_chars(digits.data(), end, value);
        if (digits.empty() || ec != std::errc{} || ptr != end || value == 0 || value > 65535) {
            return std::unexpected(std::string{"base URL port is invalid"});
        }
        out.port = static_cast<std::uint16_t>(value);
    }
    while (path.ends_with('/')) {
        path.remove_suffix(1);
    }
    std::size_t start = 0;
    while (start < path.size()) {
        const auto next = path.find('/', start + 1);
        const auto segment =
            path.substr(start + 1, next == std::string_view::npos ? next : next - start - 1);
        if (segment.empty() || segment == "." || segment == "..") {
            return std::unexpected(std::string{"base URL path has an empty or dot segment"});
        }
        start = next == std::string_view::npos ? path.size() : next;
    }
    out.host = std::move(host);
    out.path = std::string{path};
    return out;
}

auto is_env_reference(std::string_view value) -> std::optional<std::string_view> {
    if (!value.starts_with('$')) {
        return std::nullopt;
    }
    auto name = value.substr(1);
    if (name.starts_with('{')) {
        if (!name.ends_with('}')) {
            return std::nullopt;
        }
        name = name.substr(1, name.size() - 2);
    }
    if (name.empty() || (name.front() >= '0' && name.front() <= '9') ||
        !std::ranges::all_of(name, [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '_';
        })) {
        return std::nullopt;
    }
    return name;
}

auto checked_secret(
    std::string value, std::string_view name, std::optional<std::string> variable = std::nullopt
) -> std::expected<pi_shared_secret, std::string> {
    if (value.empty() || value.size() > max_secret_bytes || !std::ranges::all_of(value, [](char c) {
            const auto byte = static_cast<unsigned char>(c);
            return byte > 0x20U && byte < 0x7FU;
        })) {
        return std::unexpected(
            "the API key for Pi provider '" + std::string{name} +
            "' is empty, too long, or contains whitespace or control bytes"
        );
    }
    return pi_shared_secret{.value = std::move(value), .environment_variable = std::move(variable)};
}

// Pi's default variable for most providers: `deepseek` -> `DEEPSEEK_API_KEY`.
auto conventional_key_variable(std::string_view name) -> std::string {
    std::string variable;
    for (const char c : name) {
        variable.push_back(
            (c >= 'a' && c <= 'z')   ? static_cast<char>(c - 'a' + 'A')
            : (c == '-' || c == '.') ? '_'
                                     : c
        );
    }
    return variable + "_API_KEY";
}

} // namespace

auto valid_pi_provider_name(std::string_view name) -> bool {
    if (name.empty() || name.size() > 64) {
        return false;
    }
    const auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    return alnum(name.front()) &&
           std::ranges::all_of(
               name, [&](char c) { return alnum(c) || c == '.' || c == '_' || c == '-'; }
           ) &&
           name.find("..") == std::string_view::npos;
}

auto resolve_pi_shared_provider(
    std::string_view name, std::string_view catalog_json, std::string_view models_json
) -> std::expected<pi_shared_provider, std::string> {
    if (!valid_pi_provider_name(name)) {
        return std::unexpected("invalid Pi provider name '" + printable(name) + "'");
    }
    auto catalog = parse_object(catalog_json, "the Pi provider catalog");
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    auto models = parse_object(models_json, "models.json");
    if (!models) {
        return std::unexpected(models.error());
    }

    std::set<std::string> base_urls;
    std::set<std::string> apis;
    bool known = false;
    bool from_models_json = false;
    std::vector<std::string> catalog_urls;
    for (const auto& [group, rows] : catalog->get_object()) {
        if (!rows.is_object()) {
            continue;
        }
        for (const auto& [key, row] : rows.get_object()) {
            if (!row.is_object()) {
                continue;
            }
            const auto& fields = row.get_object();
            if (string_field(fields, "provider") != name) {
                continue;
            }
            known = true;
            if (auto api = string_field(fields, "api")) {
                apis.insert(std::move(*api));
            }
            if (auto url = string_field(fields, "baseUrl")) {
                catalog_urls.push_back(std::move(*url));
            }
        }
    }
    const glz::generic::object_t* custom = nullptr;
    if (const auto* providers = object_field(models->get_object(), "providers")) {
        custom = object_field(*providers, name);
    }
    if (custom != nullptr) {
        known = true;
        if (auto url = string_field(*custom, "baseUrl")) {
            base_urls.insert(std::move(*url));
            from_models_json = true;
        } else {
            base_urls.insert(catalog_urls.begin(), catalog_urls.end());
        }
        if (auto api = string_field(*custom, "api")) {
            apis.insert(std::move(*api));
        }
        if (const auto list = custom->find("models");
            list != custom->end() && list->second.is_array()) {
            for (const auto& model : list->second.get_array()) {
                if (!model.is_object()) {
                    continue;
                }
                if (auto api = string_field(model.get_object(), "api")) {
                    apis.insert(std::move(*api));
                }
                if (auto url = string_field(model.get_object(), "baseUrl")) {
                    base_urls.insert(std::move(*url));
                    from_models_json = true;
                }
            }
        }
    } else {
        base_urls.insert(catalog_urls.begin(), catalog_urls.end());
    }
    if (!known) {
        return std::unexpected(
            "Pi provider '" + std::string{name} + "' is not in Pi's catalog or the host models.json"
        );
    }

    std::set<upstream> upstreams;
    for (const auto& url : base_urls) {
        auto parsed = parse_base_url(url);
        if (!parsed) {
            return std::unexpected(
                "Pi provider '" + std::string{name} + "' cannot be shared: " + parsed.error()
            );
        }
        upstreams.insert(std::move(*parsed));
    }
    if (upstreams.size() != 1) {
        return std::unexpected(
            "Pi provider '" + std::string{name} + "' cannot be shared: it has " +
            std::to_string(upstreams.size()) + " base URLs; exactly one is supported"
        );
    }

    pi_shared_provider out;
    out.name = std::string{name};
    out.host = upstreams.begin()->host;
    out.port = upstreams.begin()->port;
    out.base_path = upstreams.begin()->path;
    out.origin_from_models_json = from_models_json;
    std::set<std::string> catalog_host_set;
    for (const auto& url : catalog_urls) {
        if (auto parsed = parse_base_url(url)) {
            catalog_host_set.insert(parsed->host);
        }
    }
    out.catalog_hosts.assign(catalog_host_set.begin(), catalog_host_set.end());
    for (const auto& route : api_routes) {
        if (apis.contains(std::string{route.api})) {
            out.allowed_paths.push_back(out.base_path + std::string{route.path});
        }
    }
    if (out.allowed_paths.empty()) {
        std::string listed;
        for (const auto& api : apis) {
            listed += (listed.empty() ? "" : ", ") + printable(api);
        }
        return std::unexpected(
            "Pi provider '" + std::string{name} + "' cannot be shared: API type(s) [" + listed +
            "] are not supported"
        );
    }
    return out;
}

auto pi_shared_provider_secret(
    std::string_view name,
    std::string_view auth_json,
    std::string_view models_json,
    const pi_environment_lookup& environment
) -> std::expected<pi_shared_secret, std::string> {
    const std::string label = "Pi provider '" + printable(name) + "'";
    auto auth = parse_object(auth_json, "auth.json");
    if (!auth) {
        return std::unexpected(auth.error());
    }
    if (const auto found = auth->get_object().find(name); found != auth->get_object().end()) {
        if (!found->second.is_object()) {
            return std::unexpected(label + " has a malformed auth.json entry");
        }
        const auto& entry = found->second.get_object();
        const auto type = string_field(entry, "type");
        if (type == "oauth") {
            return std::unexpected(
                label +
                " is a subscription (OAuth) login; sharing subscription logins is not supported "
                "yet. Use an API key for this provider."
            );
        }
        if (type != "api_key") {
            return std::unexpected(label + " has an unsupported auth.json credential type");
        }
        auto key = string_field(entry, "key");
        if (!key) {
            return std::unexpected(label + " has no API key in auth.json");
        }
        return checked_secret(std::move(*key), name);
    }

    auto models = parse_object(models_json, "models.json");
    if (!models) {
        return std::unexpected(models.error());
    }
    const glz::generic::object_t* custom = nullptr;
    if (const auto* providers = object_field(models->get_object(), "providers")) {
        custom = object_field(*providers, name);
    }
    const auto api_key = custom != nullptr ? string_field(*custom, "apiKey") : std::nullopt;
    if (!api_key) {
        const auto variable = conventional_key_variable(name);
        if (auto value = environment ? environment(variable) : std::nullopt) {
            return checked_secret(std::move(*value), name, variable);
        }
        return std::unexpected(label + " has no API key in auth.json, models.json, or " + variable);
    }
    if (api_key->starts_with('!')) {
        return std::unexpected(label + " uses a command-provided API key, which is not shared");
    }
    if (const auto variable = is_env_reference(*api_key)) {
        auto value = environment ? environment(*variable) : std::nullopt;
        if (!value) {
            return std::unexpected(
                label + " names environment variable " + std::string{*variable} +
                ", which is not set on the host"
            );
        }
        return checked_secret(std::move(*value), name, std::string{*variable});
    }
    if (api_key->starts_with('$')) {
        return std::unexpected(label + " has an API key template that is not a plain variable");
    }
    return checked_secret(*api_key, name);
}

} // namespace glove::run
