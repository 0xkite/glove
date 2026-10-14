#include "pi_native_policy.hpp"

namespace glove::run::detail {

auto pi_native_startup_policy() -> native_startup_policy {
    return {
        .runtime_id = "pi",
        .configuration_names = {"models.json", "settings.json", "auth.json"},
        .environment =
            {{.name = "PI_CODING_AGENT_DIR", .location = native_private_location::agent},
             {.name = "XDG_CONFIG_HOME", .location = native_private_location::config},
             {.name = "XDG_STATE_HOME", .location = native_private_location::state},
             {.name = "XDG_DATA_HOME", .location = native_private_location::data},
             {.name = "XDG_CACHE_HOME", .location = native_private_location::cache}},
        .reserved_entries = {".pi"},
        .arguments = {
            {.source = native_argument_source::literal, .literal = "--provider"},
            {.source = native_argument_source::provider_name, .literal = {}},
            {.source = native_argument_source::literal, .literal = "--model"},
            {.source = native_argument_source::model, .literal = {}},
            {.source = native_argument_source::literal, .literal = "--offline"},
            {.source = native_argument_source::literal, .literal = "--no-approve"},
            {.source = native_argument_source::literal, .literal = "--no-extensions"},
            {.source = native_argument_source::literal, .literal = "--no-mcp"},
            {.source = native_argument_source::literal, .literal = "--no-skills"},
            {.source = native_argument_source::literal, .literal = "--no-prompt-templates"},
            {.source = native_argument_source::literal, .literal = "--no-themes"},
            {.source = native_argument_source::literal, .literal = "--no-context-files"},
            {.source = native_argument_source::literal, .literal = "--session-dir"},
            {.source = native_argument_source::session_directory, .literal = {}},
            {.source = native_argument_source::forwarded_arguments, .literal = {}}
        }
    };
}

} // namespace glove::run::detail
