#include "claude_history.hpp"

#include "json_shape.hpp"
#include "native_harness_adapter.hpp"

#include <glaze/glaze.hpp>

#include <map>
#include <optional>
#include <set>
#include <string>

namespace glove::run::detail {
namespace claude_history_wire {

struct entry {
    std::optional<std::string> type;
    std::optional<std::string> uuid;
    std::optional<std::string> parentUuid;
    std::optional<std::string> sessionId;
    std::optional<std::string> version;
};

} // namespace claude_history_wire

namespace {

constexpr glz::opts loose_options{.error_on_unknown_keys = false, .error_on_missing_keys = false};

auto bounded_type(std::string_view type) -> bool {
    if (type.empty() || type.size() > 64) {
        return false;
    }
    for (const char ch : type) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-')) {
            return false;
        }
    }
    return true;
}

} // namespace

auto validate_claude_history(std::string_view bytes, const claude_history_binding& binding)
    -> std::expected<history_summary, std::string> {
    if (!valid_conversation_id(binding.conversation_id) || binding.runtime_version.empty() ||
        binding.runtime_version.size() > 32) {
        return std::unexpected("invalid Claude history binding");
    }
    if (bytes.empty() || bytes.size() > max_checkpoint_bytes || bytes.back() != '\n') {
        return std::unexpected("Claude history is empty, unterminated or exceeds its bound");
    }
    history_summary summary;
    std::set<std::string> seen;
    std::map<std::string, std::string> parent_of;
    bool user = false;
    bool assistant = false;
    std::string_view remaining = bytes;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = remaining.substr(0, newline);
        remaining.remove_prefix(newline + 1);
        if (line.empty() || line.size() > max_checkpoint_line_bytes) {
            return std::unexpected("Claude history line is empty or exceeds its bound");
        }
        if (++summary.entries > max_checkpoint_entries) {
            return std::unexpected("Claude history exceeds its entry bound");
        }
        if (!bounded_json_object(line, 64)) {
            return std::unexpected("Claude history line is not a bounded JSON object");
        }
        claude_history_wire::entry entry;
        if (glz::read<loose_options>(entry, line)) {
            return std::unexpected("Claude history line has malformed typed members");
        }
        if (!entry.type || !bounded_type(*entry.type)) {
            return std::unexpected("Claude history line lacks a bounded type");
        }
        if (entry.sessionId && *entry.sessionId != binding.conversation_id) {
            return std::unexpected("Claude history is bound to another conversation");
        }
        if (entry.version && *entry.version != binding.runtime_version) {
            return std::unexpected("Claude history was produced by an unqualified runtime version");
        }
        if (entry.uuid) {
            if (!valid_conversation_id(*entry.uuid) || !seen.insert(*entry.uuid).second) {
                return std::unexpected("Claude history entry identity is malformed or duplicated");
            }
        }
        if (entry.parentUuid) {
            // Claude appends attachments before the user entry they descend
            // from, so parent links resolve against the whole file (second pass).
            if (!valid_conversation_id(*entry.parentUuid) || !entry.uuid) {
                return std::unexpected("Claude history parent link is malformed");
            }
            parent_of.emplace(*entry.uuid, *entry.parentUuid);
        }
        if (*entry.type == "user") {
            user = true;
        } else if (*entry.type == "assistant") {
            assistant = true;
        }
    }
    // Every parent chain must terminate at a root inside this file: unknown
    // parents and cycles (aliased ancestry) refuse.
    for (const auto& [child, parent] : parent_of) {
        if (!seen.contains(parent)) {
            return std::unexpected("Claude history entry references an unknown parent");
        }
        std::string_view cursor = child;
        for (std::size_t hop = 0; hop <= parent_of.size(); ++hop) {
            const auto next = parent_of.find(std::string{cursor});
            if (next == parent_of.end()) {
                break;
            }
            if (hop == parent_of.size()) {
                return std::unexpected("Claude history parent chain does not terminate");
            }
            cursor = next->second;
        }
    }
    if (!user || !assistant) {
        return std::unexpected("Claude history has no completed user/assistant exchange");
    }
    return summary;
}

auto claude_history_validator(claude_history_binding binding) -> history_validator {
    return [binding = std::move(binding)](std::string_view bytes) {
        return validate_claude_history(bytes, binding);
    };
}

auto claude_project_leaf(std::string_view canonical_workspace)
    -> std::expected<std::string, std::string> {
    if (canonical_workspace.size() < 2 || canonical_workspace.front() != '/' ||
        canonical_workspace.back() == '/' || canonical_workspace.size() > 1024) {
        return std::unexpected("Claude project leaf requires a bounded canonical workspace");
    }
    std::string leaf;
    for (const char ch : canonical_workspace) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_') {
            leaf.push_back(ch);
        } else if (ch == '/' || ch == '.') {
            leaf.push_back('-');
        } else {
            return std::unexpected("Claude project leaf encoding is unqualified for this path");
        }
    }
    return leaf;
}

} // namespace glove::run::detail
