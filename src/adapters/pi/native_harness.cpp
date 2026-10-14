#include "native_harness.hpp"

#include "../../run/pi_guest_config.hpp"

#include <cstddef>
#include <utility>

namespace glove::run::adapters {

auto pi_harness_adapter::encode_startup(const detail::native_startup_input& input) const
    -> std::expected<detail::native_startup_recipe, std::string> {
    if (auto policy = detail::validate_native_startup_policy(input.policy); !policy) {
        return std::unexpected(policy.error());
    }
    if (input.runtime.runtime_id != "pi" || input.policy.runtime_id != "pi" ||
        input.runtime.launch_arguments.size() != 1) {
        return std::unexpected(std::string{"Pi startup requires the admitted runtime script"});
    }
    if (input.model.empty() || input.model.size() > 128 || input.arguments.size() > 32) {
        return std::unexpected(std::string{"Pi startup selection exceeds bounds"});
    }
    std::size_t remaining = 64U * 1024U;
    for (const auto& argument : input.arguments) {
        if (argument.size() > 16U * 1024U || argument.size() > remaining ||
            argument.find('\0') != std::string::npos) {
            return std::unexpected(std::string{"Pi startup argument bytes exceed bounds"});
        }
        remaining -= argument.size();
    }
    pi_provider provider;
    switch (input.provider) {
    case net::endpoint_provider::openai:
        provider = pi_provider::openai;
        break;
    case net::endpoint_provider::anthropic:
        provider = pi_provider::anthropic;
        break;
    default:
        return std::unexpected(std::string{"unsupported Pi startup provider"});
    }
    const pi_launch_selection selection{
        .model = {.provider = provider, .model = std::string{input.model}},
        .arguments = {input.arguments.begin(), input.arguments.end()}
    };
    auto config = detail::make_pi_guest_config(
        selection, input.endpoint_port, input.nonce, input.catalog_json
    );
    if (!config) {
        return std::unexpected(config.error());
    }
    detail::native_startup_recipe recipe;
    recipe.base_url = std::move(config->base_url);
    recipe.argv.push_back(input.runtime.launch_executable.string());
    recipe.argv.insert(
        recipe.argv.end(),
        input.runtime.launch_arguments.begin(),
        input.runtime.launch_arguments.end()
    );
    if (config->arguments.size() < selection.arguments.size()) {
        return std::unexpected(std::string{"Pi argument construction lost its approved suffix"});
    }
    const auto controlled = config->arguments.size() - selection.arguments.size();
    recipe.argv.insert(
        recipe.argv.end(),
        config->arguments.begin(),
        config->arguments.begin() + static_cast<std::ptrdiff_t>(controlled)
    );
    recipe.argv.push_back("--session-dir");
    recipe.argv.push_back(input.paths.sessions.string());
    recipe.argv.insert(recipe.argv.end(), selection.arguments.begin(), selection.arguments.end());
    recipe.configuration = {
        {.name = "models.json", .bytes = std::move(config->models_json)},
        {.name = "settings.json", .bytes = std::move(config->settings_json)},
        {.name = "auth.json", .bytes = "{}"}
    };
    recipe.environment = {
        {.name = "PI_CODING_AGENT_DIR", .location = detail::native_private_location::agent},
        {.name = "XDG_CONFIG_HOME", .location = detail::native_private_location::config},
        {.name = "XDG_STATE_HOME", .location = detail::native_private_location::state},
        {.name = "XDG_DATA_HOME", .location = detail::native_private_location::data},
        {.name = "XDG_CACHE_HOME", .location = detail::native_private_location::cache}
    };
    recipe.reserved_entries = {".pi"};
    if (auto checked = detail::validate_native_startup_recipe(input, recipe); !checked) {
        return std::unexpected(checked.error());
    }
    return recipe;
}

} // namespace glove::run::adapters
