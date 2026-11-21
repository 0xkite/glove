#include "glove/container/profile.hpp"

#include "glove/container/system_services.hpp"

#include "sandbox_denial_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

auto canonical_path(std::string_view raw, std::string_view label)
    -> std::expected<std::string, std::string> {
    if (raw.empty()) {
        return std::unexpected(std::string{label} + " has empty path");
    }
    if (raw.find('\0') != std::string_view::npos) {
        return std::unexpected(std::string{label} + " contains NUL byte");
    }
    std::filesystem::path candidate{raw};
    if (!candidate.is_absolute()) {
        return std::unexpected(
            std::string{label} + " must be absolute: '" + std::string{raw} + "'"
        );
    }
    std::error_code ec;
    auto normal = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) {
        return std::unexpected(
            std::string{"cannot canonicalise "} + std::string{label} + " '" + std::string{raw} +
            "': " + ec.message()
        );
    }
    if (normal == normal.root_path()) {
        return std::unexpected(std::string{label} + " may not grant the filesystem root");
    }
    return normal.string();
}

constexpr std::size_t max_link_spellings = 64U;
constexpr std::size_t max_service_ports = 16U;
constexpr std::size_t max_link_spelling_bytes = 4096U;

auto add_link_spelling(std::vector<std::string>& links, std::string link)
    -> std::expected<void, std::string> {
    if (std::ranges::find(links, link) != links.end()) {
        return {};
    }
    if (link.size() > max_link_spelling_bytes) {
        return std::unexpected(std::string{"symlink spelling exceeds 4096 bytes"});
    }
    if (links.size() >= max_link_spellings) {
        return std::unexpected(std::string{"too many symlinks in grant spellings (limit 64)"});
    }
    links.push_back(std::move(link));
    return {};
}

// Records every symlink among the prefixes of the raw spelling, plus symlinks
// reached by following a link's target (at most 8 hops). Errors from the
// filesystem are ignored; canonical_path decides whether the path is usable.
auto collect_link_spellings(std::string_view raw, std::vector<std::string>& links)
    -> std::expected<void, std::string> {
    const std::filesystem::path spelling{raw};
    if (!spelling.is_absolute()) {
        return {};
    }
    std::filesystem::path prefix = spelling.root_path();
    for (const auto& part : spelling.relative_path()) {
        prefix /= part;
        std::error_code ec;
        if (!std::filesystem::is_symlink(prefix, ec) || ec) {
            continue;
        }
        std::filesystem::path link = prefix.lexically_normal();
        for (int hop = 0; hop < 8; ++hop) {
            if (auto added = add_link_spelling(links, link.string()); !added) {
                return added;
            }
            std::error_code link_ec;
            auto target = std::filesystem::read_symlink(link, link_ec);
            if (link_ec) {
                break;
            }
            if (target.is_relative()) {
                target = link.parent_path() / target;
            }
            target = target.lexically_normal();
            std::error_code target_ec;
            if (!std::filesystem::is_symlink(target, target_ec) || target_ec) {
                break;
            }
            link = std::move(target);
        }
    }
    return {};
}

// Checks the selected service names against the catalog, then replaces the
// list with its sorted deduplicated form and derives the canonical read paths
// the selection grants. One bad name refuses the whole list.
auto resolve_system_services(profile& p) -> std::expected<void, std::string> {
    p.system_service_read_paths.clear(); // recomputed from the catalog; never trusted
    if (p.system_services.size() > 64U) {
        return std::unexpected(std::string{"too many system services (limit 64)"});
    }
    for (const auto& name : p.system_services) {
        if (name.empty() || name.size() > 64U) {
            return std::unexpected(std::string{"system service name must be 1-64 bytes"});
        }
        if (name.contains('.')) {
            return std::unexpected(
                "system service '" + name +
                "' looks like a raw platform service name; raw mach service names are not "
                "accepted, select a catalog name"
            );
        }
        if (find_system_service(name) == nullptr) {
            return std::unexpected("unknown system service '" + name + "'");
        }
    }
    std::ranges::sort(p.system_services);
    const auto dup = std::ranges::unique(p.system_services);
    p.system_services.erase(dup.begin(), dup.end());
    for (const auto& name : p.system_services) {
        for (const auto path : find_system_service(name)->macos_read_paths) {
            if (auto links = collect_link_spellings(path, p.link_spellings); !links) {
                return std::unexpected(links.error());
            }
            auto canonical = canonical_path(path, "system service read path");
            if (!canonical) {
                return std::unexpected(canonical.error());
            }
            if (std::ranges::find(p.system_service_read_paths, *canonical) ==
                p.system_service_read_paths.end()) {
                p.system_service_read_paths.push_back(std::move(*canonical));
            }
        }
    }
    return {};
}

auto protected_path(std::string_view raw, std::string_view label, bool directory)
    -> std::expected<void, std::string> {
    if (raw.empty() || raw.size() > 4096U || raw.find('\0') != std::string_view::npos) {
        return std::unexpected(std::string{label} + " must be a bounded path without NUL");
    }
    const std::filesystem::path candidate{raw};
    if (!candidate.is_absolute() || candidate == candidate.root_path()) {
        return std::unexpected(std::string{label} + " must be a non-root absolute path");
    }
    std::error_code ec;
    const auto canonical = std::filesystem::canonical(candidate, ec);
    if (ec || canonical.string() != raw) {
        return std::unexpected(std::string{label} + " must already be canonical and exist");
    }
    if (directory && (!std::filesystem::is_directory(candidate, ec) || ec)) {
        return std::unexpected(std::string{label} + " must be a directory");
    }
    return {};
}

auto reserved_name(std::string_view name) -> bool {
    return !name.empty() && name.size() <= 64U && name != "." && name != ".." &&
           std::ranges::all_of(name, [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_' || c == '.';
           });
}

auto folded_name(std::string name) -> std::string {
    for (auto& c : name) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return name;
}

auto constraint_bounds(const profile& p) -> std::expected<void, std::string> {
    if (p.immutable_files.size() > 16U || p.reserved_entries.size() > 4U) {
        return std::unexpected(
            std::string{"launch constraints exceed file or reserved count bound"}
        );
    }
    std::size_t file_bytes = 0;
    for (const auto& file : p.immutable_files) {
        if (file.size() > 4096U || file.size() > 8192U - file_bytes) {
            return std::unexpected(std::string{"immutable files exceed path byte bounds"});
        }
        file_bytes += file.size();
    }
    std::size_t reserved_bytes = 0;
    for (const auto& entry : p.reserved_entries) {
        if (entry.parent.size() > 4096U || !reserved_name(entry.name) ||
            entry.parent.size() > 16384U - reserved_bytes) {
            return std::unexpected(std::string{"reserved entries exceed path or name bounds"});
        }
        reserved_bytes += entry.parent.size();
        if (entry.name.size() > 16384U - reserved_bytes) {
            return std::unexpected(std::string{"reserved entries exceed aggregate byte bound"});
        }
        reserved_bytes += entry.name.size();
    }
    return {};
}

auto valid_environment_name(std::string_view name) -> bool {
    if (name.empty() ||
        (!(std::isalpha(static_cast<unsigned char>(name.front()))) && name.front() != '_')) {
        return false;
    }
    return std::all_of(name.begin() + 1, name.end(), [](char c) {
        const auto ch = static_cast<unsigned char>(c);
        return std::isalnum(ch) || c == '_';
    });
}

auto valid_bounded_identifier(std::string_view value) -> bool {
    if (value.empty() || value.size() > 128) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char c) {
        const auto ch = static_cast<unsigned char>(c);
        return std::isalnum(ch) || c == '-' || c == '_' || c == ':' || c == '.';
    });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
               return std::isdigit(static_cast<unsigned char>(c)) || (c >= 'a' && c <= 'f');
           });
}

auto covered_by(const std::vector<fs_rule>& rules, const std::string& path, bool needs_write)
    -> bool {
    const std::filesystem::path candidate{path};
    for (const auto& rule : rules) {
        if (needs_write && !rule.writable) {
            continue;
        }
        const std::filesystem::path root{rule.path};
        auto mismatch = std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
        if (mismatch.first == root.end()) {
            return true;
        }
    }
    return false;
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto valid_library_projection_receipts(const std::vector<library_projection_receipt>& projections)
    -> bool {
    if (projections.size() > 128U) {
        return false;
    }
    std::string_view previous_id;
    std::vector<std::filesystem::path> targets;
    targets.reserve(projections.size());
    for (const auto& projection : projections) {
        const std::filesystem::path target{projection.target_path};
        if (!valid_bounded_identifier(projection.projection_id) ||
            !valid_bounded_identifier(projection.destination_alias) ||
            !valid_digest(projection.content_digest) || !target.is_absolute() ||
            target == target.root_path() || target.lexically_normal() != target ||
            target.filename() != projection.content_digest + ".json" ||
            (!previous_id.empty() && previous_id >= projection.projection_id) ||
            std::ranges::any_of(targets, [&](const auto& existing) {
                return path_within(target, existing) || path_within(existing, target);
            })) {
            return false;
        }
        previous_id = projection.projection_id;
        targets.push_back(target);
    }
    return true;
}

auto valid_retained_change_receipts(
    const std::vector<retained_change_receipt>& changes, std::uint64_t disk_bytes
) -> bool {
    if (changes.size() > 64U) {
        return false;
    }
    std::string_view previous_id;
    for (const auto& change : changes) {
        if (!valid_bounded_identifier(change.exposure_id) || change.generation == 0 ||
            !valid_digest(change.scope_digest) || !valid_digest(change.source_identity_digest) ||
            !valid_digest(change.baseline_tree_digest) ||
            !valid_digest(change.staged_tree_digest) || !valid_digest(change.manifest_digest) ||
            (!previous_id.empty() && previous_id >= change.exposure_id) ||
            change.created > 100'000U || change.modified > 100'000U || change.renamed > 100'000U ||
            change.removed > 100'000U ||
            change.created + change.modified + change.renamed + change.removed > 100'000U ||
            change.before_bytes > disk_bytes || change.after_bytes > disk_bytes) {
            return false;
        }
        previous_id = change.exposure_id;
    }
    return true;
}

} // namespace

auto resource_enforcement_capabilities::complete() const noexcept -> bool {
    const auto cpu_supported =
        cpu_time == enforcement_mechanism::rlimit || cpu_time == enforcement_mechanism::cgroup_v2;
    const auto memory_supported =
        memory == enforcement_mechanism::rlimit || memory == enforcement_mechanism::cgroup_v2;
    const auto pids_supported =
        pids == enforcement_mechanism::rlimit || pids == enforcement_mechanism::cgroup_v2;
    return cpu_supported && memory_supported && pids_supported &&
           wall_time == enforcement_mechanism::watchdog &&
           disk == enforcement_mechanism::filesystem_quota &&
           terminal_output == enforcement_mechanism::byte_counter && receipt_schema_version == 1;
}

auto validate(const profile& p) -> std::expected<profile, std::string> {
    if (auto bounded = constraint_bounds(p); !bounded) {
        return std::unexpected(bounded.error());
    }
    profile copy = p;
    // Spellings are recomputed from the grants. Incoming ones are re-admitted only when they are
    // symlinks that resolve to, into, or above a grant, because validate() canonicalizes grant
    // paths and runs more than once on the launch path.
    auto incoming = std::move(copy.link_spellings);
    copy.link_spellings.clear();
    if (copy.denial_tag && !detail::is_denial_tag(*copy.denial_tag)) {
        return std::unexpected(std::string{"denial tag must be 32 lowercase hex characters"});
    }
    std::set<std::string> paths;
    for (auto& rule : copy.filesystem) {
        if (auto links = collect_link_spellings(rule.path, copy.link_spellings); !links) {
            return std::unexpected(links.error());
        }
        auto path = canonical_path(rule.path, "filesystem rule");
        if (!path) {
            return std::unexpected(path.error());
        }
        rule.path = std::move(*path);
        if (!paths.insert(rule.path).second) {
            return std::unexpected(std::string{"duplicate filesystem rule: '"} + rule.path + "'");
        }
    }
    if (copy.unix_socket_endpoint) {
        auto endpoint = canonical_path(*copy.unix_socket_endpoint, "Unix socket endpoint");
        if (!endpoint) {
            return std::unexpected(endpoint.error());
        }
        copy.unix_socket_endpoint = std::move(*endpoint);
    }
    if (auto services = resolve_system_services(copy); !services) {
        return std::unexpected(services.error());
    }
    std::vector<std::filesystem::path> fs_paths;
    fs_paths.reserve(copy.filesystem.size());
    for (const auto& rule : copy.filesystem) {
        fs_paths.emplace_back(rule.path);
    }
    for (std::size_t outer = 0; outer < fs_paths.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < fs_paths.size(); ++inner) {
            if (path_within(fs_paths[outer], fs_paths[inner]) ||
                path_within(fs_paths[inner], fs_paths[outer])) {
                return std::unexpected(
                    std::string{"overlapping filesystem rules are ambiguous: '"} +
                    copy.filesystem[outer].path + "' and '" + copy.filesystem[inner].path + "'"
                );
            }
        }
    }

    // Exact roots plus the overlap rejection above keep the protected parent
    // outside any writable ancestor grant that could replace the parent itself.
    const auto exact_writable_root = [&](const std::string& parent) {
        return std::ranges::any_of(copy.filesystem, [&](const auto& rule) {
            return rule.writable && rule.path == parent;
        });
    };
    std::set<std::string> immutable_paths;
    for (const auto& file : copy.immutable_files) {
        if (auto canonical = protected_path(file, "immutable file", false); !canonical) {
            return std::unexpected(canonical.error());
        }
        if (!immutable_paths.insert(file).second) {
            return std::unexpected(std::string{"duplicate immutable file"});
        }
        if (!exact_writable_root(std::filesystem::path{file}.parent_path().string())) {
            return std::unexpected(
                std::string{"immutable file parent must exactly match a writable filesystem rule"}
            );
        }
    }
    std::set<std::pair<std::string, std::string>> reserved_paths;
    for (const auto& entry : copy.reserved_entries) {
        if (auto canonical = protected_path(entry.parent, "reserved parent", true); !canonical) {
            return std::unexpected(canonical.error());
        }
        if (!exact_writable_root(entry.parent)) {
            return std::unexpected(
                std::string{"reserved parent must exactly match a writable filesystem rule"}
            );
        }
        if (!reserved_paths.emplace(entry.parent, folded_name(entry.name)).second) {
            return std::unexpected(std::string{"duplicate reserved entry (ASCII case alias)"});
        }
    }

    std::set<std::string> runtime_paths;
    for (auto& rule : copy.runtime_filesystem) {
        if (rule.writable) {
            return std::unexpected(std::string{"runtime filesystem rule must be read-only"});
        }
        if (auto links = collect_link_spellings(rule.path, copy.link_spellings); !links) {
            return std::unexpected(links.error());
        }
        auto path = canonical_path(rule.path, "runtime filesystem rule");
        if (!path) {
            return std::unexpected(path.error());
        }
        rule.path = std::move(*path);
        if (!runtime_paths.insert(rule.path).second) {
            return std::unexpected(
                std::string{"duplicate runtime filesystem rule: '"} + rule.path + "'"
            );
        }
        const std::filesystem::path runtime_path{rule.path};
        if (std::ranges::any_of(fs_paths, [&](const auto& filesystem_path) {
                return path_within(runtime_path, filesystem_path) ||
                       path_within(filesystem_path, runtime_path);
            })) {
            return std::unexpected(
                std::string{"runtime and ordinary filesystem rules overlap: '"} + rule.path + "'"
            );
        }
    }
    for (const auto& spelling : incoming) {
        if (spelling.size() > max_link_spelling_bytes || spelling.find('\0') != std::string::npos) {
            continue;
        }
        const std::filesystem::path spelled{spelling};
        if (!spelled.is_absolute() || spelled.lexically_normal().string() != spelling) {
            continue;
        }
        std::error_code link_ec;
        if (!std::filesystem::is_symlink(spelled, link_ec) || link_ec) {
            continue;
        }
        auto resolved = canonical_path(spelling, "link spelling");
        if (!resolved) {
            continue;
        }
        const std::filesystem::path target{*resolved};
        const auto touches_grant = [&](const auto& rules) {
            return std::ranges::any_of(rules, [&](const auto& rule) {
                const std::filesystem::path grant{rule.path};
                return path_within(target, grant) || path_within(grant, target);
            });
        };
        if (!touches_grant(copy.filesystem) && !touches_grant(copy.runtime_filesystem)) {
            continue;
        }
        if (auto added = add_link_spelling(copy.link_spellings, spelling); !added) {
            return std::unexpected(added.error());
        }
    }
    std::vector<std::filesystem::path> runtime_fs_paths;
    runtime_fs_paths.reserve(copy.runtime_filesystem.size());
    for (const auto& rule : copy.runtime_filesystem) {
        runtime_fs_paths.emplace_back(rule.path);
    }
    for (std::size_t outer = 0; outer < runtime_fs_paths.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < runtime_fs_paths.size(); ++inner) {
            if (path_within(runtime_fs_paths[outer], runtime_fs_paths[inner]) ||
                path_within(runtime_fs_paths[inner], runtime_fs_paths[outer])) {
                return std::unexpected(
                    std::string{"overlapping runtime filesystem rules are ambiguous: '"} +
                    copy.runtime_filesystem[outer].path + "' and '" +
                    copy.runtime_filesystem[inner].path + "'"
                );
            }
        }
    }

    auto normalise_optional = [&](std::optional<std::string>& value,
                                  std::string_view label,
                                  bool needs_write) -> std::expected<void, std::string> {
        if (!value) {
            return {};
        }
        auto path = canonical_path(*value, label);
        if (!path) {
            return std::unexpected(path.error());
        }
        *value = std::move(*path);
        if (!covered_by(copy.filesystem, *value, needs_write)) {
            return std::unexpected(
                std::string{label} + " is not covered by an explicit " +
                (needs_write ? "writable" : "filesystem") + " rule"
            );
        }
        return {};
    };
    if (auto out = normalise_optional(copy.home_dir, "home_dir", true); !out) {
        return std::unexpected(out.error());
    }
    if (copy.managed_home_dir) {
        auto path = canonical_path(*copy.managed_home_dir, "managed_home_dir");
        if (!path) {
            return std::unexpected(path.error());
        }
        copy.managed_home_dir = std::move(*path);
    }
    if (auto out = normalise_optional(copy.temp_dir, "temp_dir", true); !out) {
        return std::unexpected(out.error());
    }
    if (auto out = normalise_optional(copy.work_dir, "work_dir", false); !out) {
        return std::unexpected(out.error());
    }

    std::set<std::string> environment_names;
    const std::set<std::string> reserved_names = {
        "ALL_PROXY",
        "GLOVE_SANDBOXED",
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "TMPDIR",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    };
    for (const auto& entry : copy.environment) {
        const auto equals = entry.find('=');
        if (equals == std::string::npos) {
            return std::unexpected(
                std::string{"environment entry must be NAME=VALUE: '"} + entry + "'"
            );
        }
        const std::string_view name{entry.data(), equals};
        if (!valid_environment_name(name)) {
            return std::unexpected(
                std::string{"invalid environment name: '"} + std::string{name} + "'"
            );
        }
        if (reserved_names.contains(std::string{name})) {
            return std::unexpected(
                std::string{"environment name is managed by glove: '"} + std::string{name} + "'"
            );
        }
        if (!environment_names.insert(std::string{name}).second) {
            return std::unexpected(
                std::string{"duplicate environment entry: '"} + std::string{name} + "'"
            );
        }
    }

    if (copy.proxy && (copy.proxy->port == 0 || copy.proxy->url.empty())) {
        return std::unexpected(std::string{"proxy requires a non-zero port and URL"});
    }
    if (copy.proxy && copy.bridge_endpoint) {
        return std::unexpected(
            std::string{"proxy and bridge_endpoint are mutually exclusive: a credentialed "
                        "reverse endpoint must not also be reachable over raw CONNECT egress"}
        );
    }
    if (copy.bridge_endpoint && copy.bridge_endpoint->port == 0) {
        return std::unexpected(std::string{"bridge_endpoint requires a non-zero port"});
    }
    std::ranges::sort(copy.service_ports);
    const auto duplicates = std::ranges::unique(copy.service_ports);
    copy.service_ports.erase(duplicates.begin(), duplicates.end());
    if (!copy.service_ports.empty() && copy.service_ports.front() == 0) {
        return std::unexpected(std::string{"service port must be non-zero"});
    }
    if (copy.service_ports.size() > max_service_ports) {
        return std::unexpected(
            std::string{"at most "} + std::to_string(max_service_ports) + " service ports"
        );
    }
    for (const std::uint16_t port : copy.service_ports) {
        if (copy.bridge_endpoint && copy.bridge_endpoint->port == port) {
            return std::unexpected(
                "service port " + std::to_string(port) + " is the credential bridge port"
            );
        }
        if (copy.proxy && copy.proxy->port == port) {
            return std::unexpected(
                "service port " + std::to_string(port) + " is the egress proxy port"
            );
        }
    }
    if (copy.required_limits) {
        const auto& limits = *copy.required_limits;
        if (limits.cpu_time_ms == 0 || limits.memory_bytes == 0 || limits.pids == 0 ||
            limits.wall_time_ms == 0 || limits.disk_bytes == 0 ||
            limits.terminal_output_bytes == 0) {
            return std::unexpected(std::string{"every required resource limit must be non-zero"});
        }
    }
    return copy;
}

auto require_resource_enforcement(
    const profile& p, const resource_enforcement_capabilities& capabilities
) -> std::expected<void, std::string> {
    if (!p.required_limits) {
        return {};
    }
    if (capabilities.complete()) {
        return {};
    }

    std::string message{"mandatory resource enforcement unavailable: "};
    bool first = true;
    const auto append_missing = [&message, &first](std::string_view capability) {
        if (!first) {
            message.append(", ");
        }
        message.append(capability);
        first = false;
    };
    const auto cpu_supported = capabilities.cpu_time == enforcement_mechanism::rlimit ||
                               capabilities.cpu_time == enforcement_mechanism::cgroup_v2;
    const auto memory_supported = capabilities.memory == enforcement_mechanism::rlimit ||
                                  capabilities.memory == enforcement_mechanism::cgroup_v2;
    if (!cpu_supported) {
        append_missing("cpu_time");
    }
    if (!memory_supported) {
        append_missing("memory");
    }
    if (capabilities.pids != enforcement_mechanism::cgroup_v2) {
        append_missing("pids");
    }
    if (capabilities.wall_time != enforcement_mechanism::watchdog) {
        append_missing("wall_time");
    }
    if (capabilities.disk != enforcement_mechanism::filesystem_quota) {
        append_missing("disk");
    }
    if (capabilities.terminal_output != enforcement_mechanism::byte_counter) {
        append_missing("terminal_output");
    }
    if (capabilities.receipt_schema_version != 1) {
        append_missing("observable_receipts");
    }
    return std::unexpected(std::move(message));
}

auto validate_resource_enforcement_receipt(
    const resource_enforcement_receipt& receipt,
    const resource_limits& expected_limits,
    const resource_enforcement_capabilities& expected_capabilities,
    sandbox_backend expected_backend,
    std::string_view expected_profile_digest
) -> std::expected<void, std::string> {
    if (receipt.backend == sandbox_backend::remote_linux_container ||
        expected_backend == sandbox_backend::remote_linux_container ||
        receipt.observation_authority != receipt_observation_authority::local_enforcement ||
        !receipt.independently_verified) {
        return std::unexpected(
            std::string{"trusted remote claims are not local enforcement receipts"}
        );
    }
    if (receipt.schema_version != 1) {
        return std::unexpected(std::string{"unsupported resource receipt schema"});
    }
    if (!valid_digest(expected_profile_digest) ||
        receipt.profile_digest != expected_profile_digest) {
        return std::unexpected(std::string{"resource receipt profile digest mismatch"});
    }
    if (!valid_bounded_identifier(receipt.backend_id)) {
        return std::unexpected(std::string{"resource receipt has invalid backend identity"});
    }
    if (receipt.backend != expected_backend) {
        return std::unexpected(std::string{"resource receipt sandbox backend mismatch"});
    }
    if (receipt.configured_limits != expected_limits) {
        return std::unexpected(std::string{"resource receipt configured limits mismatch"});
    }
    if (!expected_capabilities.complete() || receipt.mechanisms != expected_capabilities) {
        return std::unexpected(std::string{"resource receipt enforcement mechanisms mismatch"});
    }
    if (!valid_library_projection_receipts(receipt.library_projections)) {
        return std::unexpected(std::string{"resource receipt library projections are invalid"});
    }
    if (!valid_retained_change_receipts(
            receipt.retained_changes, receipt.configured_limits.disk_bytes
        )) {
        return std::unexpected(std::string{"resource receipt retained changes are invalid"});
    }
    if (receipt.started_at_ms == 0 || receipt.finished_at_ms < receipt.started_at_ms) {
        return std::unexpected(std::string{"resource receipt has invalid time bounds"});
    }
    if (receipt.termination_cause == resource_termination_cause::exited) {
        if (!receipt.exit_code || *receipt.exit_code < 0 || *receipt.exit_code > 255) {
            return std::unexpected(std::string{"exited receipt requires a valid exit code"});
        }
    } else if (receipt.exit_code) {
        return std::unexpected(
            std::string{"non-exit termination receipt may not carry an exit code"}
        );
    }
    return {};
}

auto validate_trusted_remote_resource_claim(
    const resource_enforcement_receipt& receipt,
    const resource_limits& expected_limits,
    std::string_view expected_profile_digest
) -> std::expected<void, std::string> {
    if (receipt.backend != sandbox_backend::remote_linux_container ||
        receipt.observation_authority != receipt_observation_authority::trusted_remote_claim ||
        receipt.independently_verified || !receipt.retained_changes.empty()) {
        return std::unexpected(
            std::string{"resource receipt is not a bounded trusted remote claim"}
        );
    }
    auto structurally_local = receipt;
    structurally_local.backend = sandbox_backend::linux_production;
    structurally_local.observation_authority = receipt_observation_authority::local_enforcement;
    structurally_local.independently_verified = true;
    return validate_resource_enforcement_receipt(
        structurally_local,
        expected_limits,
        receipt.mechanisms,
        sandbox_backend::linux_production,
        expected_profile_digest
    );
}

} // namespace glove::container
