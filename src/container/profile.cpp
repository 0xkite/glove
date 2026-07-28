#include "glove/container/profile.hpp"

#include <algorithm>
#include <cctype>
#include <expected>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

namespace {

auto canonical_path(std::string_view raw, std::string_view label)
    -> std::expected<std::string, std::string> {
    if (raw.empty()) {
        return std::unexpected(std::string{label} + " has empty path");
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
    return cpu_supported && memory_supported && pids == enforcement_mechanism::cgroup_v2 &&
           wall_time == enforcement_mechanism::watchdog &&
           disk == enforcement_mechanism::filesystem_quota &&
           terminal_output == enforcement_mechanism::byte_counter && receipt_schema_version == 1;
}

auto validate(const profile& p) -> std::expected<profile, std::string> {
    profile copy = p;
    std::set<std::string> paths;
    for (auto& rule : copy.filesystem) {
        auto path = canonical_path(rule.path, "filesystem rule");
        if (!path) {
            return std::unexpected(path.error());
        }
        rule.path = std::move(*path);
        if (!paths.insert(rule.path).second) {
            return std::unexpected(std::string{"duplicate filesystem rule: '"} + rule.path + "'");
        }
    }
    for (auto outer = copy.filesystem.begin(); outer != copy.filesystem.end(); ++outer) {
        for (auto inner = std::next(outer); inner != copy.filesystem.end(); ++inner) {
            const std::filesystem::path first{outer->path};
            const std::filesystem::path second{inner->path};
            if (path_within(first, second) || path_within(second, first)) {
                return std::unexpected(
                    std::string{"overlapping filesystem rules are ambiguous: '"} + outer->path +
                    "' and '" + inner->path + "'"
                );
            }
        }
    }

    std::set<std::string> runtime_paths;
    for (auto& rule : copy.runtime_filesystem) {
        if (rule.writable) {
            return std::unexpected(std::string{"runtime filesystem rule must be read-only"});
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
        if (std::ranges::any_of(copy.filesystem, [&](const auto& filesystem_rule) {
                const std::filesystem::path filesystem_path{filesystem_rule.path};
                return path_within(runtime_path, filesystem_path) ||
                       path_within(filesystem_path, runtime_path);
            })) {
            return std::unexpected(
                std::string{"runtime and ordinary filesystem rules overlap: '"} + rule.path + "'"
            );
        }
    }
    for (auto outer = copy.runtime_filesystem.begin(); outer != copy.runtime_filesystem.end();
         ++outer) {
        for (auto inner = std::next(outer); inner != copy.runtime_filesystem.end(); ++inner) {
            const std::filesystem::path first{outer->path};
            const std::filesystem::path second{inner->path};
            if (path_within(first, second) || path_within(second, first)) {
                return std::unexpected(
                    std::string{"overlapping runtime filesystem rules are ambiguous: '"} +
                    outer->path + "' and '" + inner->path + "'"
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

    std::string message{"mandatory resource enforcement unavailable: "};
    bool has_missing = false;
    const auto append_missing = [&message, &has_missing](std::string_view capability) {
        if (has_missing) {
            message.append(", ");
        }
        message.append(capability);
        has_missing = true;
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
    if (!has_missing) {
        return {};
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

} // namespace glove::container
