#include "glove/run/pi_host_config.hpp"

#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <utility>

namespace glove::run {
namespace {

namespace fs = std::filesystem;

// Host settings and models files are small; anything larger is not a Pi
// configuration file and is refused instead of parsed.
constexpr std::size_t max_config_bytes = 4U * 1024U * 1024U;

auto parse_object(std::string_view json, std::string_view what)
    -> std::expected<glz::generic, std::string> {
    if (json.size() > max_config_bytes) {
        return std::unexpected(std::string{what} + " exceeds the configuration size limit");
    }
    std::string buffer{json};
    glz::generic parsed{};
    if (const auto error = glz::read_json(parsed, buffer); error) {
        return std::unexpected(std::string{what} + " is not valid JSON");
    }
    if (!parsed.is_object()) {
        return std::unexpected(std::string{what} + " must be a JSON object");
    }
    return parsed;
}

auto write_object(const glz::generic& value, std::string_view what)
    -> std::expected<std::string, std::string> {
    std::string out;
    if (const auto error = glz::write_json(value, out); error) {
        return std::unexpected("cannot serialize " + std::string{what});
    }
    return out;
}

// Pi treats a source as a local path when it starts like a filesystem path;
// `npm:`, `git:`, and URL sources are installed or cloned instead.
auto is_local_source(std::string_view source) -> bool {
    return source.starts_with("./") || source.starts_with("../") || source.starts_with('/') ||
           source == "~" || source.starts_with("~/") || source == "." || source == "..";
}

// The declared source of a package entry: a string, or an object's `source`.
auto entry_source(const glz::generic& entry) -> std::optional<std::string> {
    if (entry.is_string()) {
        return entry.get_string();
    }
    if (entry.is_object()) {
        const auto& object = entry.get_object();
        if (const auto it = object.find("source"); it != object.end() && it->second.is_string()) {
            return it->second.get_string();
        }
    }
    return std::nullopt;
}

auto resolve_source(std::string_view source, const fs::path& settings_dir, const fs::path& home)
    -> fs::path {
    fs::path resolved;
    if (source == "~") {
        resolved = home;
    } else if (source.starts_with("~/")) {
        resolved = home / fs::path{source.substr(2)};
    } else if (source.starts_with('/')) {
        resolved = fs::path{source};
    } else {
        resolved = settings_dir / fs::path{source};
    }
    resolved = resolved.lexically_normal();
    if (!resolved.has_filename() && resolved.has_parent_path() &&
        resolved != resolved.root_path()) {
        resolved = resolved.parent_path();
    }
    return resolved;
}

auto packages_array(glz::generic& settings) -> std::expected<glz::generic::array_t*, std::string> {
    auto& object = settings.get_object();
    const auto it = object.find("packages");
    if (it == object.end()) {
        return nullptr;
    }
    if (!it->second.is_array()) {
        return std::unexpected(std::string{"settings.json `packages` must be an array"});
    }
    return &it->second.get_array();
}

auto within(const fs::path& candidate, const fs::path& root) -> bool {
    const auto [root_end, candidate_end] = std::ranges::mismatch(root, candidate);
    return root_end == root.end();
}

// Lowercased host of an http(s) URL with any port and IPv6 brackets removed.
auto url_host(std::string_view url) -> std::string {
    const auto scheme = url.find("://");
    if (scheme == std::string_view::npos) {
        return {};
    }
    auto rest = url.substr(scheme + 3);
    rest = rest.substr(0, rest.find_first_of("/?#"));
    if (const auto at = rest.rfind('@'); at != std::string_view::npos) {
        rest = rest.substr(at + 1);
    }
    std::string_view host;
    if (rest.starts_with('[')) {
        const auto close = rest.find(']');
        if (close == std::string_view::npos) {
            return {};
        }
        host = rest.substr(1, close - 1);
    } else {
        host = rest.substr(0, rest.find(':'));
    }
    std::string lowered;
    lowered.reserve(host.size());
    for (const char ch : host) {
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return lowered;
}

auto is_loopback_url(std::string_view url) -> bool {
    const auto host = url_host(url);
    if (host == "localhost" || host == "::1") {
        return true;
    }
    // 127.0.0.0/8 written as a dotted quad; names such as 127.0.0.1.evil.example
    // fail the four-numeric-label check.
    if (!host.starts_with("127.")) {
        return false;
    }
    int labels = 0;
    std::size_t start = 0;
    while (start <= host.size()) {
        const auto dot = host.find('.', start);
        const auto label = std::string_view{host}.substr(
            start, dot == std::string::npos ? std::string::npos : dot - start
        );
        if (label.empty() || label.size() > 3 ||
            !std::ranges::all_of(label, [](char c) { return c >= '0' && c <= '9'; }) ||
            std::stoi(std::string{label}) > 255) {
            return false;
        }
        ++labels;
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    return labels == 4;
}

// `$NAME` or `${NAME}`: Pi resolves it from the sandbox's own environment, so
// the value names a variable rather than carrying a secret.
auto is_env_reference(std::string_view value) -> bool {
    if (!value.starts_with('$')) {
        return false;
    }
    auto name = value.substr(1);
    if (name.starts_with('{')) {
        if (!name.ends_with('}')) {
            return false;
        }
        name = name.substr(1, name.size() - 2);
    }
    if (name.empty() || std::isdigit(static_cast<unsigned char>(name.front())) != 0) {
        return false;
    }
    return std::ranges::all_of(name, [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    });
}

auto is_credential_store_component(const fs::path& component) -> bool {
    static constexpr std::array<std::string_view, 8> names{
        ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", "auth.json"
    };
    const auto name = component.string();
    return std::ranges::find(names, std::string_view{name}) != names.end();
}

} // namespace

auto pi_local_package_sources(
    std::string_view settings_json, const fs::path& settings_dir, const fs::path& home
) -> std::expected<std::vector<pi_local_package>, std::string> {
    auto settings = parse_object(settings_json, "settings.json");
    if (!settings) {
        return std::unexpected(settings.error());
    }
    auto packages = packages_array(*settings);
    if (!packages) {
        return std::unexpected(packages.error());
    }
    std::vector<pi_local_package> found;
    if (*packages == nullptr) {
        return found;
    }
    for (const auto& entry : **packages) {
        const auto source = entry_source(entry);
        if (!source || !is_local_source(*source)) {
            continue;
        }
        found.push_back(
            {.declared = *source, .resolved = resolve_source(*source, settings_dir, home)}
        );
    }
    return found;
}

auto pi_package_exposure(
    const fs::path& resolved, const fs::path& home, const fs::path& pi_agent_dir
) -> std::expected<fs::path, std::string> {
    struct ::stat link_stat{};
    if (::lstat(resolved.c_str(), &link_stat) != 0) {
        return std::unexpected(std::string{"does not exist"});
    }
    if (link_stat.st_uid != ::geteuid()) {
        return std::unexpected(std::string{"is not owned by the current user"});
    }
    std::error_code ec;
    const auto canonical = fs::canonical(resolved, ec);
    if (ec || canonical.empty() || canonical == canonical.root_path()) {
        return std::unexpected(std::string{"cannot be resolved to a non-root path"});
    }
    struct ::stat target_stat{};
    if (::stat(canonical.c_str(), &target_stat) != 0 ||
        (!S_ISDIR(target_stat.st_mode) && !S_ISREG(target_stat.st_mode))) {
        return std::unexpected(std::string{"is not a directory or regular file"});
    }
    if (target_stat.st_uid != ::geteuid()) {
        return std::unexpected(std::string{"resolves to a path not owned by the current user"});
    }
    const auto canonical_home = fs::weakly_canonical(home, ec);
    if (ec || within(canonical_home, canonical)) {
        return std::unexpected(std::string{"is or contains the home directory"});
    }
    const auto canonical_agent = fs::weakly_canonical(pi_agent_dir, ec);
    if (ec || within(canonical_agent, canonical)) {
        return std::unexpected(std::string{"contains the Pi agent directory"});
    }
    for (const auto& component : canonical) {
        if (is_credential_store_component(component)) {
            return std::unexpected(std::string{"is inside a credential store"});
        }
    }
    return canonical;
}

auto rewrite_pi_settings_packages(
    std::string_view settings_json, const std::map<std::string, std::string>& exposed
) -> std::expected<std::string, std::string> {
    auto settings = parse_object(settings_json, "settings.json");
    if (!settings) {
        return std::unexpected(settings.error());
    }
    auto packages = packages_array(*settings);
    if (!packages) {
        return std::unexpected(packages.error());
    }
    if (*packages != nullptr) {
        glz::generic::array_t kept;
        kept.reserve((*packages)->size());
        for (auto& entry : **packages) {
            const auto source = entry_source(entry);
            if (!source || !is_local_source(*source)) {
                kept.push_back(std::move(entry));
                continue;
            }
            const auto it = exposed.find(*source);
            if (it == exposed.end()) {
                continue;
            }
            if (entry.is_string()) {
                entry = it->second;
            } else {
                entry.get_object()["source"] = it->second;
            }
            kept.push_back(std::move(entry));
        }
        **packages = std::move(kept);
    }
    return write_object(*settings, "settings.json");
}

auto scrub_pi_models_credentials(std::string_view models_json)
    -> std::expected<std::string, std::string> {
    auto models = parse_object(models_json, "models.json");
    if (!models) {
        return std::unexpected(models.error());
    }
    auto& root = models->get_object();
    if (const auto it = root.find("providers"); it != root.end() && it->second.is_object()) {
        for (auto& [name, provider] : it->second.get_object()) {
            if (!provider.is_object()) {
                continue;
            }
            auto& fields = provider.get_object();
            bool loopback = false;
            if (const auto base = fields.find("baseUrl");
                base != fields.end() && base->second.is_string()) {
                loopback = is_loopback_url(base->second.get_string());
            }
            const auto keep = [loopback](const glz::generic& value) {
                return value.is_string() && (loopback || is_env_reference(value.get_string()));
            };
            if (const auto key = fields.find("apiKey"); key != fields.end() && !keep(key->second)) {
                fields.erase(key);
            }
            if (const auto headers = fields.find("headers");
                headers != fields.end() && headers->second.is_object()) {
                auto& values = headers->second.get_object();
                for (auto header = values.begin(); header != values.end();) {
                    header = keep(header->second) ? std::next(header) : values.erase(header);
                }
            }
        }
    }
    return write_object(*models, "models.json");
}

} // namespace glove::run
