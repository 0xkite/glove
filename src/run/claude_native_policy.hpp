#pragma once

#include "native_harness_adapter.hpp"

#include <string_view>

namespace glove::run::detail {

// headless: --print JSON output, no tools, no MCP, no slash commands, prompts
// denied. interactive: the same closed surface without print mode, for the
// separately qualified TTY lane. Both are host-selected; neither accepts an
// operator path, endpoint, credential or discovery override.
// headless_write_tool: headless with the built-in Read and Edit tools
// enabled and edits auto-accepted inside the workspace, for the
// tool-interruption lane (2.1.296's bare tool pool has no Write tool).
// interactive additionally generates a writable `.claude.json` carrying only
// onboarding completion and the approval of this generation's own nonce,
// so Claude's first-use API-key prompt is answered by host policy, never by
// imported operator state.
enum class claude_launch_mode { headless, headless_write_tool, interactive };

inline constexpr std::string_view claude_global_config_leaf = ".claude.json";

[[nodiscard]] auto claude_native_startup_policy(claude_launch_mode mode) -> native_startup_policy;

inline constexpr std::string_view claude_runtime_id = "claude";
inline constexpr std::string_view claude_history_format = "claude-code-projects-jsonl-v1";

} // namespace glove::run::detail
