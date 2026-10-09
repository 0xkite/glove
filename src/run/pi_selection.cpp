#include "glove/run/pi_selection.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace glove::run {
namespace pi_wire {

struct model_selection {
    std::uint8_t schema_version = 1;
    std::string provider;
    std::string model;
};

} // namespace pi_wire

namespace {

constexpr std::size_t max_selection_bytes = 4096;
constexpr std::size_t max_model_bytes = 128;
constexpr std::size_t max_arguments = 32;
constexpr std::size_t max_argument_bytes = 16 * 1024;
constexpr std::size_t max_total_argument_bytes = 64 * 1024;

auto valid_model(std::string_view model) -> bool {
    if (model.empty() || model.size() > max_model_bytes) {
        return false;
    }
    const auto alphanumeric = [](unsigned char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9');
    };
    if (!alphanumeric(static_cast<unsigned char>(model.front()))) {
        return false;
    }
    return std::ranges::all_of(model, [&](unsigned char character) {
        return alphanumeric(character) || character == '-' || character == '_' || character == '.';
    });
}

auto validate_arguments(std::span<const std::string> arguments)
    -> std::expected<void, std::string> {
    if (arguments.size() > max_arguments) {
        return std::unexpected(std::string{"too many Pi arguments"});
    }
    std::size_t total_bytes = 0;
    for (const auto& argument : arguments) {
        if (argument.size() > max_argument_bytes ||
            argument.size() > max_total_argument_bytes - total_bytes ||
            argument.find('\0') != std::string::npos) {
            return std::unexpected(std::string{"Pi arguments exceed bounds or contain NUL"});
        }
        total_bytes += argument.size();
        // Pi expands @files independently of flag parsing. File/context import
        // needs its own bounded selection instead of a forwarded host pathname.
        if (argument.starts_with('@')) {
            return std::unexpected(std::string{"Pi @file arguments are not supported"});
        }
    }
    bool parse_options = true;
    bool seen_print = false;
    bool seen_thinking = false;
    bool seen_mode = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto& argument = arguments[index];
        if (!parse_options || !argument.starts_with('-')) {
            continue;
        }
        if (argument == "--") {
            parse_options = false;
        } else if (argument == "--print" || argument == "-p") {
            if (seen_print) {
                return std::unexpected(std::string{"duplicate Pi print option"});
            }
            seen_print = true;
        } else if (argument == "--thinking") {
            if (seen_thinking || index + 1 == arguments.size()) {
                return std::unexpected(std::string{"Pi --thinking needs one value"});
            }
            seen_thinking = true;
            constexpr std::array<std::string_view, 7> levels{
                "off", "minimal", "low", "medium", "high", "xhigh", "max"
            };
            if (std::ranges::find(levels, arguments[++index]) == levels.end()) {
                return std::unexpected(std::string{"unsupported Pi thinking level"});
            }
        } else if (argument == "--mode") {
            if (seen_mode || index + 1 == arguments.size()) {
                return std::unexpected(std::string{"Pi --mode needs text or json"});
            }
            seen_mode = true;
            const auto& mode = arguments[++index];
            if (mode != "text" && mode != "json") {
                return std::unexpected(std::string{"Pi mode must be text or json"});
            }
        } else {
            // Unknown flags fail closed, including flags introduced by future
            // Pi releases that might load code or replace adapter configuration.
            return std::unexpected(std::string{"unsupported forwarded Pi option"});
        }
    }
    return {};
}

} // namespace

auto pi_provider_name(pi_provider provider) -> std::string_view {
    switch (provider) {
    case pi_provider::openai:
        return "openai";
    case pi_provider::anthropic:
        return "anthropic";
    }
    return {};
}

auto encode_pi_model_selection(const pi_model_selection& selection)
    -> std::expected<std::string, std::string> {
    auto checked = select_pi_launch({}, selection);
    if (!checked) {
        return std::unexpected(checked.error());
    }
    const pi_wire::model_selection wire{
        .schema_version = 1,
        .provider = std::string{pi_provider_name(selection.provider)},
        .model = selection.model,
    };
    std::string json;
    if (const auto error = glz::write_json(wire, json); error) {
        return std::unexpected(std::string{"could not encode Pi model selection"});
    }
    return json;
}

auto decode_pi_model_selection(std::string_view json)
    -> std::expected<pi_model_selection, std::string> {
    if (json.empty() || json.size() > max_selection_bytes) {
        return std::unexpected(std::string{"Pi model selection exceeds bounds"});
    }
    pi_wire::model_selection wire;
    constexpr glz::opts strict_options{
        .error_on_unknown_keys = true, .error_on_missing_keys = true
    };
    if (const auto error = glz::read<strict_options>(wire, json); error) {
        return std::unexpected(std::string{"malformed Pi model selection"});
    }
    if (wire.schema_version != 1) {
        return std::unexpected(std::string{"unsupported Pi model selection version"});
    }
    auto selection = select_pi_launch({.provider = wire.provider, .model = wire.model});
    if (!selection) {
        return std::unexpected(selection.error());
    }
    // Re-encoding rejects duplicate keys, alternate field orders and trailing
    // data rather than allowing the parser's last assignment to become policy.
    auto canonical = encode_pi_model_selection(selection->model);
    if (!canonical || *canonical != json) {
        return std::unexpected(std::string{"Pi model selection is not canonical"});
    }
    return std::move(selection->model);
}

auto select_pi_launch(
    const pi_launch_options& options, const std::optional<pi_model_selection>& configured
) -> std::expected<pi_launch_selection, std::string> {
    if (configured &&
        (pi_provider_name(configured->provider).empty() || !valid_model(configured->model))) {
        return std::unexpected(std::string{"invalid operator Pi model selection"});
    }
    std::optional<pi_provider> provider;
    if (options.provider) {
        if (*options.provider == "openai") {
            provider = pi_provider::openai;
        } else if (*options.provider == "anthropic") {
            provider = pi_provider::anthropic;
        } else {
            return std::unexpected(
                std::string{"unsupported Pi provider; select openai or anthropic"}
            );
        }
    } else if (configured) {
        provider = configured->provider;
    }
    if (!provider) {
        return std::unexpected(std::string{"select a Pi provider with --provider"});
    }
    std::optional<std::string_view> model;
    if (options.model) {
        model = *options.model;
    } else if (configured && configured->provider == *provider) {
        model = configured->model;
    }
    if (!model) {
        return std::unexpected(std::string{"select a Pi model with --model"});
    }
    if (!valid_model(*model)) {
        return std::unexpected(std::string{"invalid Pi model identifier"});
    }
    if (auto valid = validate_arguments(options.arguments); !valid) {
        return std::unexpected(valid.error());
    }
    return pi_launch_selection{
        .model = {.provider = *provider, .model = std::string{*model}},
        .arguments = options.arguments,
    };
}

} // namespace glove::run
