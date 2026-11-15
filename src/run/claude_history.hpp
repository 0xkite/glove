#pragma once

#include "native_session_store.hpp"

#include <expected>
#include <string>
#include <string_view>

namespace glove::run::detail {

// Admission of Claude Code's per-project JSONL transcript as exact bytes.
// This binds the observed 2.1.x layout: one JSON object per line carrying
// `type`, `uuid`, nullable `parentUuid`, `sessionId` and `version`. Unknown
// members are tolerated as opaque data; structural, identity, parent-link,
// session-binding and version drift refuse. A qualified history needs at
// least one user and one assistant entry; a stopped initial turn does not.
struct claude_history_binding {
    std::string conversation_id;
    std::string runtime_version;
};

[[nodiscard]] auto
validate_claude_history(std::string_view bytes, const claude_history_binding& binding)
    -> std::expected<history_summary, std::string>;

[[nodiscard]] auto claude_history_validator(claude_history_binding binding) -> history_validator;

// Claude derives its project directory leaf from the workspace path. Only the
// observed encoding is accepted; an unencodable path refuses.
[[nodiscard]] auto claude_project_leaf(std::string_view canonical_workspace)
    -> std::expected<std::string, std::string>;

} // namespace glove::run::detail
