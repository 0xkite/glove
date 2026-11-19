#include "glove/run/pi_host_config.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
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

auto trim(std::string_view text) -> std::string_view {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

auto percent_decode(std::string_view text) -> std::string {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size() &&
            std::isxdigit(static_cast<unsigned char>(text[i + 1])) != 0 &&
            std::isxdigit(static_cast<unsigned char>(text[i + 2])) != 0) {
            out.push_back(
                static_cast<char>(std::stoi(std::string{text.substr(i + 1, 2)}, nullptr, 16))
            );
            i += 2;
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}

// Mirrors Pi's `isLocalPath`: after trimming, anything that is not an npm,
// git, GitHub, URL, ssh, or builtin source (nor an scp-style git remote) is a
// local path, including bare relative paths. `file:` URLs name local paths.
auto local_path(std::string_view raw) -> std::optional<std::string> {
    const auto source = trim(raw);
    if (source.empty()) {
        return std::nullopt;
    }
    if (source.starts_with("file://")) {
        return percent_decode(source.substr(7));
    }
    if (source.starts_with("file:")) {
        return percent_decode(source.substr(5));
    }
    for (std::string_view remote :
         {"npm:", "git:", "github:", "http:", "https:", "ssh:", "builtin:", "git+"}) {
        if (source.starts_with(remote)) {
            return std::nullopt;
        }
    }
    // user@host:path (scp-style git remote)
    const auto at = source.find('@');
    const auto colon = source.find(':');
    const auto slash = source.find('/');
    if (at != std::string_view::npos && colon != std::string_view::npos && at < colon &&
        (slash == std::string_view::npos || colon < slash)) {
        return std::nullopt;
    }
    return std::string{source};
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

auto is_glob(std::string_view path) -> bool {
    return path.find_first_of("*?[]{}") != std::string_view::npos;
}

// Top-level resource arrays take path patterns with an optional `!`/`-`
// (exclude) or `+` (force include) prefix.
struct resource_entry {
    std::string_view prefix;
    std::string_view path;
};

auto split_resource(std::string_view entry) -> resource_entry {
    if (!entry.empty() && (entry.front() == '!' || entry.front() == '-' || entry.front() == '+')) {
        return {.prefix = entry.substr(0, 1), .path = entry.substr(1)};
    }
    return {.prefix = {}, .path = entry};
}

constexpr std::array<std::string_view, 4> resource_keys{
    "extensions", "skills", "prompts", "themes"
};

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

// Characters on which this parser and a WHATWG URL parser (Node) can disagree
// about the host, for example `https://evil.example\\@127.0.0.1/`.
auto ambiguous_url(std::string_view url) -> bool {
    return std::ranges::any_of(url, [](char c) {
        const auto byte = static_cast<unsigned char>(c);
        return c == '\\' || c == '@' || byte <= 0x20U || byte == 0x7FU;
    });
}

auto is_loopback_url(std::string_view url) -> bool {
    if (ambiguous_url(url)) {
        return false;
    }
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

// A header template whose only literal part is an auth scheme, such as
// `Bearer ${TOKEN}`: Pi interpolates it from the sandbox environment.
auto is_env_template(std::string_view value) -> bool {
    for (std::string_view scheme : {"Bearer ", "Basic ", "Token "}) {
        if (value.starts_with(scheme)) {
            return is_env_reference(value.substr(scheme.size()));
        }
    }
    return false;
}

auto is_credential_store_component(const fs::path& component) -> bool {
    static constexpr std::array<std::string_view, 11> names{
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".password-store",
        ".netrc",
        ".npmrc",
        ".git-credentials",
        "auth.json",
    };
    const auto name = component.string();
    return std::ranges::find(names, std::string_view{name}) != names.end();
}

// Home-relative locations that hold credentials or tokens for many tools. A
// package may neither be inside one nor contain one.
constexpr std::array<std::string_view, 15> home_secret_stores{
    ".config",
    ".local",
    "Library",
    ".pi",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".netrc",
    ".npmrc",
    ".git-credentials",
    ".cargo",
};

// A Pi package directory has a manifest or a conventional resource directory;
// a file package is a single extension module.
auto looks_like_pi_package(const fs::path& path, bool directory) -> bool {
    std::error_code ec;
    if (!directory) {
        static constexpr std::array<std::string_view, 6> extensions{
            ".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"
        };
        const auto extension = path.extension().string();
        return std::ranges::find(extensions, std::string_view{extension}) != extensions.end();
    }
    if (fs::is_regular_file(path / "package.json", ec)) {
        return true;
    }
    for (const char* resource : {"extensions", "skills", "prompts", "themes"}) {
        if (fs::is_directory(path / resource, ec)) {
            return true;
        }
    }
    return false;
}

// A credential value survives only as an environment reference, or as a
// literal sent exclusively to loopback endpoints. Commands never survive: they
// would run inside the sandbox, where a host credential helper is not intended.
auto keep_credential(const glz::generic& value, bool loopback) -> bool {
    if (!value.is_string()) {
        return false;
    }
    const auto& text = value.get_string();
    if (text.starts_with('!')) {
        return false;
    }
    return is_env_reference(text) || is_env_template(text) || loopback;
}

// Every `apiKey` and every `headers` value at any depth is a credential site
// (provider, `models[]`, and `modelOverrides` entries). An object with its own
// `baseUrl` sets the endpoint context for itself and its children; a provider is
// loopback only if every model `baseUrl` beneath it is loopback too. Objects
// with no `baseUrl` anywhere above them (built-in providers, top-level
// `modelOverrides`) are treated as remote.
void scrub_credentials(glz::generic& node, bool loopback, int depth) {
    constexpr int max_depth = 64;
    if (depth > max_depth) {
        node = nullptr;
        return;
    }
    if (node.is_array()) {
        for (auto& element : node.get_array()) {
            scrub_credentials(element, loopback, depth + 1);
        }
        return;
    }
    if (!node.is_object()) {
        return;
    }
    auto& fields = node.get_object();
    bool here = loopback;
    if (const auto base = fields.find("baseUrl"); base != fields.end()) {
        here = base->second.is_string() && is_loopback_url(base->second.get_string());
    }
    if (const auto list = fields.find("models"); list != fields.end() && list->second.is_array()) {
        for (const auto& model : list->second.get_array()) {
            if (!model.is_object()) {
                continue;
            }
            const auto& model_fields = model.get_object();
            if (const auto base = model_fields.find("baseUrl");
                base != model_fields.end() &&
                (!base->second.is_string() || !is_loopback_url(base->second.get_string()))) {
                here = false;
            }
        }
    }
    for (auto field = fields.begin(); field != fields.end();) {
        if (field->first == "apiKey") {
            field = keep_credential(field->second, here) ? std::next(field) : fields.erase(field);
            continue;
        }
        if (field->first == "headers") {
            if (!field->second.is_object()) {
                field = fields.erase(field);
                continue;
            }
            auto& values = field->second.get_object();
            for (auto header = values.begin(); header != values.end();) {
                header = keep_credential(header->second, here) ? std::next(header)
                                                               : values.erase(header);
            }
            ++field;
            continue;
        }
        scrub_credentials(field->second, here, depth + 1);
        ++field;
    }
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
    if (*packages != nullptr) {
        for (const auto& entry : **packages) {
            const auto source = entry_source(entry);
            const auto path = source ? local_path(*source) : std::nullopt;
            if (!path) {
                continue;
            }
            found.push_back(
                {.declared = *source,
                 .resolved = resolve_source(*path, settings_dir, home),
                 .pattern = false}
            );
        }
    }
    auto& object = settings->get_object();
    for (const auto key : resource_keys) {
        const auto it = object.find(key);
        if (it == object.end()) {
            continue;
        }
        if (!it->second.is_array()) {
            return std::unexpected("settings.json `" + std::string{key} + "` must be an array");
        }
        for (const auto& entry : it->second.get_array()) {
            if (!entry.is_string()) {
                continue;
            }
            const auto [prefix, raw] = split_resource(entry.get_string());
            const auto path = local_path(raw);
            if (!path) {
                continue;
            }
            found.push_back(
                {.declared = entry.get_string(),
                 .resolved = resolve_source(*path, settings_dir, home),
                 .pattern = prefix == "!" || prefix == "-" || is_glob(*path)}
            );
        }
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
    for (const auto store : home_secret_stores) {
        const auto secret = canonical_home / fs::path{store};
        if (within(canonical, secret) || within(secret, canonical)) {
            return std::unexpected("overlaps the credential location ~/" + std::string{store});
        }
    }
    for (const auto& component : canonical) {
        if (is_credential_store_component(component)) {
            return std::unexpected(std::string{"is inside a credential store"});
        }
    }
    if (!looks_like_pi_package(canonical, S_ISDIR(target_stat.st_mode))) {
        return std::unexpected(
            std::string{"is not a Pi package (no package.json or resource directory, or not a "
                        "JS/TS extension file)"}
        );
    }
    return canonical;
}

auto read_host_pi_settings(
    const fs::path& pi_agent_dir, const fs::path& home, const std::vector<fs::path>& agent_writable
) -> std::expected<std::string, std::string> {
    const auto path = pi_agent_dir / "settings.json";
    struct ::stat link_stat{};
    if (::lstat(path.c_str(), &link_stat) != 0) {
        return std::unexpected(std::string{"no settings.json"});
    }
    if (link_stat.st_uid != ::geteuid()) {
        return std::unexpected(std::string{"settings.json is not owned by the current user"});
    }
    std::error_code ec;
    const auto target = fs::canonical(path, ec);
    if (ec) {
        return std::unexpected(std::string{"settings.json cannot be resolved"});
    }
    if (S_ISLNK(link_stat.st_mode)) {
        const auto canonical_home = fs::weakly_canonical(home, ec);
        const auto canonical_agent = fs::weakly_canonical(pi_agent_dir, ec);
        const bool approved =
            !ec && target.filename() == "settings.json" &&
            (within(target, canonical_home / ".pi") ||
             within(target, canonical_home / "Documents" / "depend" / "dotfiles") ||
             within(target, canonical_home / ".dotfiles") || within(target, canonical_agent));
        if (!approved) {
            return std::unexpected(std::string{"settings.json symlink target is not approved"});
        }
    }
    for (const auto& writable : agent_writable) {
        const auto canonical_writable = fs::weakly_canonical(writable, ec);
        if (!ec && within(target, canonical_writable)) {
            return std::unexpected(
                std::string{"settings.json resolves into a path the agent can write"}
            );
        }
    }
    const int fd = ::open(target.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(std::string{"settings.json cannot be opened"});
    }
    struct ::stat file_stat{};
    if (::fstat(fd, &file_stat) != 0 || !S_ISREG(file_stat.st_mode) ||
        file_stat.st_uid != ::geteuid() ||
        static_cast<std::size_t>(file_stat.st_size) > max_config_bytes) {
        (void)::close(fd);
        return std::unexpected(std::string{"settings.json is not a small owned regular file"});
    }
    std::string text(static_cast<std::size_t>(file_stat.st_size), '\0');
    std::size_t done = 0;
    while (done < text.size()) {
        const ::ssize_t n = ::read(fd, text.data() + done, text.size() - done);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    (void)::close(fd);
    text.resize(done);
    return text;
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
            if (!source || !local_path(*source)) {
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
    auto& object = settings->get_object();
    for (const auto key : resource_keys) {
        const auto it = object.find(key);
        if (it == object.end() || !it->second.is_array()) {
            continue;
        }
        glz::generic::array_t kept;
        for (auto& entry : it->second.get_array()) {
            if (!entry.is_string()) {
                kept.push_back(std::move(entry));
                continue;
            }
            const auto text = entry.get_string();
            const auto [prefix, raw] = split_resource(text);
            if (!local_path(raw)) {
                kept.push_back(std::move(entry));
                continue;
            }
            if (const auto mapped = exposed.find(text); mapped != exposed.end()) {
                kept.emplace_back(std::string{prefix} + mapped->second);
            } else if (prefix == "!" || prefix == "-") {
                // An unmapped exclusion is harmless and dropping it would widen
                // what a pattern includes, so it is kept as written.
                kept.push_back(std::move(entry));
            }
        }
        it->second = std::move(kept);
    }
    return write_object(*settings, "settings.json");
}

auto scrub_pi_models_credentials(std::string_view models_json)
    -> std::expected<std::string, std::string> {
    auto models = parse_object(models_json, "models.json");
    if (!models) {
        return std::unexpected(models.error());
    }
    scrub_credentials(*models, false, 0);
    return write_object(*models, "models.json");
}

} // namespace glove::run
