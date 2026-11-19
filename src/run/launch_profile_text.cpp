// Launch profile text: the strict YAML subset, the schema, and the
// canonical encoding. No filesystem or host state, so fuzzers link it alone.

#include "glove/run/launch_profile.hpp"

#include "yaml_subset.hpp"

#include <glaze/json.hpp>

#include <algorithm>
#include <map>
#include <ranges>
#include <set>
#include <type_traits>
#include <utility>
#include <variant>

// Glaze reflects these records, which needs external linkage.
namespace glove::run::launch_profile_detail { // NOLINT(misc-use-internal-linkage)

struct env_doc { // NOLINT(misc-use-internal-linkage)
    // A plain integer (PORT: { value: 8080 }) arrives as a number.
    std::optional<std::variant<std::string, std::uint64_t>> value;
    std::optional<std::string> from;
};

struct egress_doc { // NOLINT(misc-use-internal-linkage)
    std::string host;
    std::optional<std::uint16_t> port;
};

struct mcp_doc { // NOLINT(misc-use-internal-linkage)
    std::string name;
    std::vector<std::string> argv;
};

struct allow_arg_doc { // NOLINT(misc-use-internal-linkage)
    std::string tool;
    std::string field;
    std::string prefix;
};

struct profile_doc { // NOLINT(misc-use-internal-linkage)
    std::uint32_t version{};
    std::optional<std::string> workspace;
    std::optional<std::string> agent;
    std::optional<std::vector<std::string>> read;
    std::optional<std::vector<std::string>> write;
    std::optional<std::map<std::string, env_doc>> env;
    std::optional<std::vector<egress_doc>> egress;
    std::optional<std::vector<mcp_doc>> mcp;
    std::optional<std::vector<std::string>> allow;
    std::optional<std::vector<allow_arg_doc>> allow_arg;
    std::optional<std::uint16_t> bridge_port;
};

} // namespace glove::run::launch_profile_detail

namespace glove::run {
namespace {

using launch_profile_detail::profile_doc;

auto is_key_char(char ch) -> bool {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
           ch == '_' || ch == '-' || ch == '.';
}

// Trailing bytes after the object are refused, not ignored.
struct profile_json_opts : glz::opts {
    bool validate_trailing_whitespace = true;
};

constexpr profile_json_opts profile_read_options{
    {.null_terminated = false, .error_on_unknown_keys = true, .error_on_missing_keys = true},
};

constexpr detail::yaml_subset_limits profile_yaml_limits{
    .max_bytes = max_launch_profile_bytes,
    .max_lines = max_launch_profile_lines,
    .max_entries = max_launch_profile_entries,
    .max_depth = 8,
};

// ---------------------------------------------------------------------------
// Semantic validation of the decoded document.

auto clean_string(std::string_view text, std::size_t limit) -> bool {
    return text.size() <= limit && std::ranges::none_of(text, [](char ch) {
               const auto byte = static_cast<unsigned char>(ch);
               return byte < 0x20U || byte == 0x7FU;
           });
}

auto valid_profile_path(std::string_view path) -> bool {
    return !path.empty() && clean_string(path, max_launch_profile_string) &&
           (path.front() == '/' || path == "~" || path.starts_with("~/"));
}

auto valid_env_name(std::string_view name) -> bool {
    if (name.empty() || name.size() > 128U || (name.front() >= '0' && name.front() <= '9')) {
        return false;
    }
    return std::ranges::all_of(name, [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
               ch == '_';
    });
}

auto valid_word(std::string_view word, std::size_t limit) -> bool {
    return !word.empty() && word.size() <= limit && std::ranges::all_of(word, is_key_char);
}

auto valid_host(std::string_view host) -> bool {
    return !host.empty() && host.size() <= 253U &&
           std::ranges::all_of(host, [](char ch) { return is_key_char(ch) && ch != '_'; });
}

template<typename T> auto bounded(const std::optional<std::vector<T>>& list) -> bool {
    return !list || list->size() <= max_launch_profile_entries;
}

auto convert_paths(
    const std::optional<std::vector<std::string>>& paths,
    std::string_view field,
    std::vector<std::string>& out
) -> std::expected<void, std::string> {
    for (const auto& path : paths.value_or(std::vector<std::string>{})) {
        if (!valid_profile_path(path)) {
            return std::unexpected(
                std::string{field} + ": paths must be absolute or start with ~/ ('" +
                (clean_string(path, 256) ? path : std::string{"<unprintable>"}) + "')"
            );
        }
        out.push_back(path);
    }
    return {};
}

auto convert_env(const profile_doc& doc, launch_profile& out) -> std::expected<void, std::string> {
    for (const auto& [name, entry] :
         doc.env.value_or(std::map<std::string, launch_profile_detail::env_doc>{})) {
        if (!valid_env_name(name)) {
            return std::unexpected("env: '" + name + "' is not a variable name");
        }
        if (entry.value.has_value() == entry.from.has_value()) {
            return std::unexpected("env: " + name + " needs exactly one of value or from");
        }
        if (entry.from && *entry.from != "host") {
            return std::unexpected("env: " + name + ": from must be host");
        }
        std::optional<std::string> value;
        if (entry.value) {
            value = std::visit(
                [](const auto& held) -> std::string {
                    if constexpr (std::is_same_v<std::decay_t<decltype(held)>, std::string>) {
                        return held;
                    } else {
                        return std::to_string(held);
                    }
                },
                *entry.value
            );
            if (!clean_string(*value, max_launch_profile_env_value)) {
                return std::unexpected(
                    "env: " + name + ": value has control characters or is too long"
                );
            }
        }
        out.env.push_back({.name = name, .value = std::move(value)});
    }
    return {};
}

auto convert_network(const profile_doc& doc, launch_profile& out)
    -> std::expected<void, std::string> {
    for (const auto& rule : doc.egress.value_or(std::vector<launch_profile_detail::egress_doc>{})) {
        if (!valid_host(rule.host)) {
            return std::unexpected("egress: '" + rule.host + "' is not a host name");
        }
        if (rule.port && *rule.port == 0) {
            return std::unexpected("egress: " + rule.host + ": port must be 1-65535");
        }
        out.egress.push_back({.host = rule.host, .port = rule.port.value_or(443)});
    }
    std::set<std::string> names;
    for (const auto& server : doc.mcp.value_or(std::vector<launch_profile_detail::mcp_doc>{})) {
        if (!valid_word(server.name, 64) || !names.insert(server.name).second) {
            return std::unexpected("mcp: '" + server.name + "' is not a unique server name");
        }
        if (server.argv.empty() || server.argv.size() > max_launch_profile_entries ||
            server.argv.front().empty() ||
            !std::ranges::all_of(server.argv, [](const std::string& arg) {
                return clean_string(arg, max_launch_profile_string);
            })) {
            return std::unexpected("mcp: " + server.name + ": argv needs a command");
        }
        out.mcp.push_back({.name = server.name, .argv = server.argv});
    }
    for (const auto& tool : doc.allow.value_or(std::vector<std::string>{})) {
        if (tool.empty() || !clean_string(tool, 256)) {
            return std::unexpected(std::string{"allow: tool names must be non-empty"});
        }
        out.allow.push_back(tool);
    }
    for (const auto& rule :
         doc.allow_arg.value_or(std::vector<launch_profile_detail::allow_arg_doc>{})) {
        if (rule.tool.empty() || rule.field.empty() || !clean_string(rule.tool, 256) ||
            !clean_string(rule.field, 256) ||
            !clean_string(rule.prefix, max_launch_profile_string)) {
            return std::unexpected(std::string{"allow_arg: tool and field must be non-empty"});
        }
        out.allow_arg.push_back(
            {.tool_name = rule.tool, .field = rule.field, .required_prefix = rule.prefix}
        );
    }
    return {};
}

auto convert(const profile_doc& doc) -> std::expected<launch_profile, std::string> {
    if (doc.version != launch_profile_version) {
        return std::unexpected("unsupported profile version " + std::to_string(doc.version));
    }
    if (!bounded(doc.read) || !bounded(doc.write) || !bounded(doc.egress) || !bounded(doc.mcp) ||
        !bounded(doc.allow) || !bounded(doc.allow_arg) ||
        (doc.env && doc.env->size() > max_launch_profile_entries)) {
        return std::unexpected(std::string{"profile has too many entries in one list"});
    }
    launch_profile out;
    if (doc.workspace) {
        if (!valid_profile_path(*doc.workspace)) {
            return std::unexpected(std::string{"workspace: must be absolute or start with ~/"});
        }
        out.workspace = doc.workspace;
    }
    if (doc.agent) {
        if (!valid_word(*doc.agent, 32)) {
            return std::unexpected(std::string{"agent: not a preset name"});
        }
        out.agent = doc.agent;
    }
    if (doc.bridge_port) {
        if (*doc.bridge_port == 0) {
            return std::unexpected(std::string{"bridge_port: must be 1-65535"});
        }
        out.bridge_port = doc.bridge_port;
    }
    if (auto ok = convert_paths(doc.read, "read", out.read); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = convert_paths(doc.write, "write", out.write); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = convert_env(doc, out); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = convert_network(doc, out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

// ---------------------------------------------------------------------------
// Encoding.

auto quote(std::string_view text) -> std::string {
    std::string out = "\"";
    for (const char ch : text) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

void emit_list(std::string& out, std::string_view key, const std::vector<std::string>& items) {
    if (items.empty()) {
        return;
    }
    out += std::string{key} + ":\n";
    for (const auto& item : items) {
        out += "  - " + quote(item) + "\n";
    }
}

} // namespace

auto operator==(const launch_profile& a, const launch_profile& b) -> bool {
    const auto same_egress = [](const glove::net::egress_rule& x,
                                const glove::net::egress_rule& y) {
        return x.host == y.host && x.port == y.port && x.allow_private == y.allow_private;
    };
    const auto same_mcp = [](const upstream_spec& x, const upstream_spec& y) {
        return x.name == y.name && x.argv == y.argv;
    };
    const auto same_rule = [](const glove::policy::argument_prefix_rule& x,
                              const glove::policy::argument_prefix_rule& y) {
        return x.tool_name == y.tool_name && x.field == y.field &&
               x.required_prefix == y.required_prefix;
    };
    return a.workspace == b.workspace && a.agent == b.agent && a.read == b.read &&
           a.write == b.write && a.env == b.env && a.allow == b.allow &&
           a.bridge_port == b.bridge_port && std::ranges::equal(a.egress, b.egress, same_egress) &&
           std::ranges::equal(a.mcp, b.mcp, same_mcp) &&
           std::ranges::equal(a.allow_arg, b.allow_arg, same_rule);
}

auto parse_launch_profile(std::string_view text) -> std::expected<launch_profile, std::string> {
    auto json = detail::yaml_subset_to_json(text, profile_yaml_limits);
    if (!json) {
        return std::unexpected(json.error());
    }
    profile_doc doc{};
    if (const auto error = glz::read<profile_read_options>(doc, *json)) {
        return std::unexpected("schema: " + glz::format_error(error, *json));
    }
    return convert(doc);
}

auto encode_launch_profile(const launch_profile& profile) -> std::string {
    std::string out = "version: " + std::to_string(launch_profile_version) + "\n";
    if (profile.workspace) {
        out += "workspace: " + quote(*profile.workspace) + "\n";
    }
    if (profile.agent) {
        out += "agent: " + quote(*profile.agent) + "\n";
    }
    emit_list(out, "read", profile.read);
    emit_list(out, "write", profile.write);
    if (!profile.env.empty()) {
        out += "env:\n";
        for (const auto& entry : profile.env) {
            out += "  " + entry.name + ": " +
                   (entry.value ? "{ value: " + quote(*entry.value) + " }" : "{ from: host }") +
                   "\n";
        }
    }
    if (!profile.egress.empty()) {
        out += "egress:\n";
        for (const auto& rule : profile.egress) {
            out +=
                "  - { host: " + quote(rule.host) + ", port: " + std::to_string(rule.port) + " }\n";
        }
    }
    if (!profile.mcp.empty()) {
        out += "mcp:\n";
        for (const auto& server : profile.mcp) {
            out += "  - { name: " + quote(server.name) + ", argv: [";
            for (std::size_t i = 0; i < server.argv.size(); ++i) {
                out += (i == 0 ? "" : ", ") + quote(server.argv[i]);
            }
            out += "] }\n";
        }
    }
    emit_list(out, "allow", profile.allow);
    if (!profile.allow_arg.empty()) {
        out += "allow_arg:\n";
        for (const auto& rule : profile.allow_arg) {
            out += "  - { tool: " + quote(rule.tool_name) + ", field: " + quote(rule.field) +
                   ", prefix: " + quote(rule.required_prefix) + " }\n";
        }
    }
    if (profile.bridge_port) {
        out += "bridge_port: " + std::to_string(*profile.bridge_port) + "\n";
    }
    return out;
}

auto launch_profile_template() -> std::string_view {
    return "# glove launch profile. Glove reads this file on the host; the sandbox\n"
           "# can never read or write it. Paths are absolute or start with ~/.\n"
           "# Check it with: glove profile check <name>\n"
           "version: 1\n"
           "\n"
           "# workspace: ~/src/project       # read-write working directory\n"
           "# agent: claude-code             # mediated provider credentials\n"
           "\n"
           "# read:                          # extra read-only paths\n"
           "#   - /opt/datasets\n"
           "# write:                         # extra read-write paths\n"
           "#   - ~/scratch\n"
           "\n"
           "# env:                           # nothing is inherited by default\n"
           "#   LANG: { value: en_US.UTF-8 }\n"
           "#   CI: { from: host }\n"
           "\n"
           "# egress:                        # outbound HTTPS; none means no network\n"
           "#   - { host: registry.npmjs.org, port: 443 }\n"
           "\n"
           "# mcp:\n"
           "#   - { name: yams, argv: [/usr/local/bin/yams, serve, --quiet] }\n"
           "# allow: [yams.search]\n"
           "# allow_arg:\n"
           "#   - { tool: yams.search, field: path, prefix: /src }\n"
           "\n"
           "# bridge_port: 8080              # host 127.0.0.1 port bridged inside\n";
}

} // namespace glove::run
