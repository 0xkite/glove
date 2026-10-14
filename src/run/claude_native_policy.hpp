#pragma once

#include "native_harness_adapter.hpp"

#include <string_view>

namespace glove::run::detail {

// headless: --print JSON output, no tools, no MCP, no slash commands, prompts
// denied. interactive: the same closed surface without print mode, for the
// separately qualified TTY lane. Both are host-selected; neither accepts an
// operator path, endpoint, credential or discovery override.
enum class claude_launch_mode { headless, interactive };

[[nodiscard]] auto claude_native_startup_policy(claude_launch_mode mode) -> native_startup_policy;

inline constexpr std::string_view claude_runtime_id = "claude";
inline constexpr std::string_view claude_history_format = "claude-code-projects-jsonl-v1";

} // namespace glove::run::detail
