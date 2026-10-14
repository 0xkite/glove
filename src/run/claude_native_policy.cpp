#include "claude_native_policy.hpp"

namespace glove::run::detail {
namespace {

auto literal(std::string_view value) -> native_argument_binding {
    return {
        .source = native_argument_source::literal,
        .literal = std::string{value},
        .resume_literal = {}
    };
}

auto slot(native_argument_source source) -> native_argument_binding {
    return {.source = source, .literal = {}, .resume_literal = {}};
}

auto fixed(std::string_view name, std::string_view value) -> native_environment_binding {
    return {
        .name = std::string{name},
        .location = native_private_location::agent,
        .source = native_environment_source::literal,
        .literal = std::string{value}
    };
}

} // namespace

auto claude_native_startup_policy(claude_launch_mode mode) -> native_startup_policy {
    native_startup_policy policy{
        .runtime_id = std::string{claude_runtime_id},
        .configuration_names = {"settings.json"},
        .environment =
            {{.name = "CLAUDE_CONFIG_DIR",
              .location = native_private_location::agent,
              .source = native_environment_source::private_location,
              .literal = {}},
             {.name = "ANTHROPIC_BASE_URL",
              .location = native_private_location::agent,
              .source = native_environment_source::endpoint_base_url,
              .literal = {}},
             {.name = "ANTHROPIC_API_KEY",
              .location = native_private_location::agent,
              .source = native_environment_source::endpoint_nonce,
              .literal = {}},
             // Claude's scratch root defaults to the shared /tmp/claude-<uid>;
             // the private cache location keeps it inside the generation.
             {.name = "CLAUDE_CODE_TMPDIR",
              .location = native_private_location::cache,
              .source = native_environment_source::private_location,
              .literal = {}},
             // Auxiliary rails are closed by OS egress denial; these variables
             // only suppress retries/noise and are not an enforcement substitute.
             fixed("DISABLE_TELEMETRY", "1"),
             fixed("DISABLE_AUTOUPDATER", "1"),
             fixed("DISABLE_ERROR_REPORTING", "1"),
             fixed("DISABLE_BUG_COMMAND", "1"),
             fixed("DISABLE_COST_WARNINGS", "1"),
             fixed("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
             fixed("CLAUDE_CODE_DISABLE_TERMINAL_TITLE", "1"),
             fixed("CLAUDE_CODE_RESUME_INTERRUPTED_TURN", "0")},
        .reserved_entries = {".claude", ".mcp.json"},
        .arguments = {}
    };
    // --bare: ANTHROPIC_API_KEY-only authentication, no OAuth/keychain/hook/
    // plugin/CLAUDE.md discovery. Tools, MCP and slash commands are disabled
    // and anything that would prompt is denied.
    policy.arguments = {literal("--bare")};
    if (mode == claude_launch_mode::headless) {
        policy.arguments.push_back(literal("--print"));
        policy.arguments.push_back(literal("--output-format"));
        policy.arguments.push_back(literal("json"));
        policy.arguments.push_back(literal("--permission-prompts"));
        policy.arguments.push_back(literal("none"));
    }
    policy.arguments.push_back(literal("--tools"));
    policy.arguments.push_back(literal(""));
    policy.arguments.push_back(literal("--strict-mcp-config"));
    policy.arguments.push_back(literal("--disable-slash-commands"));
    policy.arguments.push_back(literal("--model"));
    policy.arguments.push_back(slot(native_argument_source::model));
    policy.arguments.push_back(
        {.source = native_argument_source::conversation_selector,
         .literal = "--session-id",
         .resume_literal = "--resume"}
    );
    policy.arguments.push_back(slot(native_argument_source::conversation_id));
    policy.arguments.push_back(literal("--"));
    policy.arguments.push_back(slot(native_argument_source::forwarded_arguments));
    return policy;
}

} // namespace glove::run::detail
