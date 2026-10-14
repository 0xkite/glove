#include "native_harness.hpp"

#include "../../run/claude_native_policy.hpp"

#include <cstddef>

namespace glove::run::adapters {

auto claude_harness_adapter::encode_startup(const detail::native_startup_input& input) const
    -> std::expected<detail::native_startup_recipe, std::string> {
    if (auto policy = detail::validate_native_startup_policy(input.policy); !policy) {
        return std::unexpected(policy.error());
    }
    if (input.runtime.runtime_id != detail::claude_runtime_id ||
        input.policy.runtime_id != detail::claude_runtime_id ||
        !input.runtime.launch_arguments.empty()) {
        return std::unexpected(
            std::string{"Claude startup requires the admitted native executable"}
        );
    }
    if (input.provider != net::endpoint_provider::anthropic) {
        return std::unexpected(
            std::string{"Claude startup requires the Anthropic provider surface"}
        );
    }
    if (input.model.empty() || input.model.size() > 128 || input.arguments.size() > 32 ||
        input.endpoint_port == 0 || !detail::valid_conversation_id(input.conversation_id)) {
        return std::unexpected(std::string{"Claude startup selection exceeds bounds"});
    }
    std::size_t remaining = 64U * 1024U;
    for (const auto& argument : input.arguments) {
        if (argument.size() > 16U * 1024U || argument.size() > remaining ||
            argument.find('\0') != std::string::npos) {
            return std::unexpected(std::string{"Claude startup argument bytes exceed bounds"});
        }
        remaining -= argument.size();
    }
    detail::native_startup_recipe recipe;
    recipe.base_url = "http://127.0.0.1:" + std::to_string(input.endpoint_port) + "/anthropic";
    recipe.argv.push_back(input.runtime.launch_executable.string());
    for (const auto& argument : input.policy.arguments) {
        switch (argument.source) {
        case detail::native_argument_source::literal:
            recipe.argv.push_back(argument.literal);
            break;
        case detail::native_argument_source::model:
            recipe.argv.emplace_back(input.model);
            break;
        case detail::native_argument_source::conversation_selector:
            recipe.argv.push_back(input.resume ? argument.resume_literal : argument.literal);
            break;
        case detail::native_argument_source::conversation_id:
            recipe.argv.emplace_back(input.conversation_id);
            break;
        case detail::native_argument_source::forwarded_arguments:
            recipe.argv.insert(recipe.argv.end(), input.arguments.begin(), input.arguments.end());
            break;
        case detail::native_argument_source::provider_name:
        case detail::native_argument_source::session_directory:
            return std::unexpected(std::string{"Claude policy does not bind this argument slot"});
        }
    }
    // Private user settings live in CLAUDE_CONFIG_DIR. The leaf is immutable
    // for the guest; Claude's own mutable state lives beside it.
    recipe.configuration = {
        {.name = "settings.json",
         .bytes =
             "{\"includeCoAuthoredBy\":false,\"permissions\":{\"disableBypassPermissionsMode\":"
             "\"disable\"}}"}
    };
    recipe.environment = input.policy.environment;
    recipe.reserved_entries = input.policy.reserved_entries;
    if (auto checked = detail::validate_native_startup_recipe(input, recipe); !checked) {
        return std::unexpected(checked.error());
    }
    return recipe;
}

} // namespace glove::run::adapters
