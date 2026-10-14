#include "native_harness_adapter.hpp"

#include "../container/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace glove::run::detail {
namespace {

constexpr std::size_t max_argv_bytes = 128U * 1024U;
constexpr std::size_t max_configuration_bytes = 32U * 1024U;

auto path_shape(const std::filesystem::path& path) -> bool {
    if (path.native().empty() || path.native().size() > 4096) {
        return false;
    }
    const auto value = path.string();
    return !value.empty() && value.size() <= 4096 && value.find('\0') == std::string::npos &&
           path.is_absolute() && path != path.root_path() && path == path.lexically_normal();
}

auto leaf(std::string_view name) -> bool {
    if (name.empty() || name.size() > 64 || name == "." || name == "..") {
        return false;
    }
    for (const char ch : name) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-' || ch == '.')) {
            return false;
        }
    }
    return true;
}

auto folded_equal(std::string_view left, std::string_view right) -> bool {
    if (left.size() != right.size()) {
        return false;
    }
    const auto lower = [](char ch) { return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch; };
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (lower(left[index]) != lower(right[index])) {
            return false;
        }
    }
    return true;
}

auto environment_name(std::string_view name) -> bool {
    if (name.empty() || name.size() > 64 || name.front() < 'A' || name.front() > 'Z') {
        return false;
    }
    for (const char ch : name) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')) {
            return false;
        }
    }
    constexpr std::array<std::string_view, 11> denied{
        std::string_view{"HOME"},
        "TMPDIR",
        "TMP",
        "TEMP",
        "PATH",
        "LANG",
        "TERM",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY"
    };
    for (const auto reserved : denied) {
        if (name == reserved) {
            return false;
        }
    }
    for (const auto prefix :
         {"LD_", "DYLD_", "GLOVE_", "HERDR_", "OPENAI_", "ANTHROPIC_", "GITHUB_", "AWS_"}) {
        if (name.starts_with(prefix)) {
            return false;
        }
    }
    return name.find("KEY") == std::string_view::npos &&
           name.find("TOKEN") == std::string_view::npos &&
           name.find("SECRET") == std::string_view::npos &&
           name.find("PASSWORD") == std::string_view::npos;
}

auto literal_value(std::string_view value) -> bool {
    if (value.empty() || value.size() > 128) {
        return false;
    }
    for (const char ch : value) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-' || ch == '.' || ch == ':' || ch == '/' || ch == ',')) {
            return false;
        }
    }
    return true;
}

auto endpoint_variable(native_environment_source source, net::endpoint_provider provider)
    -> std::string_view {
    const bool openai = provider == net::endpoint_provider::openai;
    if (source == native_environment_source::endpoint_base_url) {
        return openai ? "OPENAI_BASE_URL" : "ANTHROPIC_BASE_URL";
    }
    return openai ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
}

// Provider-independent shape check. Exact endpoint variable names are bound to
// the provider by validate_native_startup_recipe once the provider is known.
auto environment_binding_valid(const native_environment_binding& binding) -> bool {
    switch (binding.source) {
    case native_environment_source::private_location:
        return environment_name(binding.name) && binding.literal.empty();
    case native_environment_source::endpoint_base_url:
        return (binding.name == "ANTHROPIC_BASE_URL" || binding.name == "OPENAI_BASE_URL") &&
               binding.literal.empty();
    case native_environment_source::endpoint_nonce:
        return (binding.name == "ANTHROPIC_API_KEY" || binding.name == "OPENAI_API_KEY") &&
               binding.literal.empty();
    case native_environment_source::literal:
        return environment_name(binding.name) && literal_value(binding.literal);
    }
    return false;
}

auto location_valid(native_private_location location) -> bool {
    switch (location) {
    case native_private_location::agent:
    case native_private_location::config:
    case native_private_location::state:
    case native_private_location::data:
    case native_private_location::cache:
        return true;
    }
    return false;
}

auto closed_arguments(const native_startup_input& input, const native_startup_recipe& recipe)
    -> bool {
    std::size_t index = input.runtime.launch_arguments.size() + 1;
    const auto accept = [&](std::string_view value) {
        if (index >= recipe.argv.size() || recipe.argv[index] != value) {
            return false;
        }
        ++index;
        return true;
    };
    for (const auto& argument : input.policy.arguments) {
        switch (argument.source) {
        case native_argument_source::literal:
            if (!accept(argument.literal)) {
                return false;
            }
            break;
        case native_argument_source::provider_name:
            if (!accept(
                    input.provider == net::endpoint_provider::openai ? "openai" : "anthropic"
                )) {
                return false;
            }
            break;
        case native_argument_source::model:
            if (!accept(input.model)) {
                return false;
            }
            break;
        case native_argument_source::session_directory:
            if (!accept(input.paths.sessions.string())) {
                return false;
            }
            break;
        case native_argument_source::forwarded_arguments:
            for (const auto& forwarded : input.arguments) {
                if (!accept(forwarded)) {
                    return false;
                }
            }
            break;
        case native_argument_source::conversation_selector:
            if (!accept(input.resume ? argument.resume_literal : argument.literal)) {
                return false;
            }
            break;
        case native_argument_source::conversation_id:
            if (!accept(input.conversation_id)) {
                return false;
            }
            break;
        }
    }
    return index == recipe.argv.size();
}

} // namespace

auto validate_native_configuration_files(std::span<const native_configuration_file> configuration)
    -> std::expected<void, std::string> {
    if (configuration.empty() || configuration.size() > 16) {
        return std::unexpected(std::string{"invalid native configuration bounds"});
    }
    std::size_t remaining = max_configuration_bytes;
    for (std::size_t index = 0; index < configuration.size(); ++index) {
        const auto& file = configuration[index];
        if (!leaf(file.name) || file.bytes.size() > remaining) {
            return std::unexpected(std::string{"invalid native configuration bytes or name"});
        }
        remaining -= file.bytes.size();
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (folded_equal(file.name, configuration[prior].name)) {
                return std::unexpected(std::string{"duplicate native configuration name"});
            }
        }
    }
    return {};
}

auto validate_native_startup_policy(const native_startup_policy& policy)
    -> std::expected<void, std::string> {
    if (!leaf(policy.runtime_id) || policy.configuration_names.empty() ||
        policy.configuration_names.size() > 16 || policy.environment.size() > 16 ||
        policy.reserved_entries.size() > 8 || policy.arguments.empty() ||
        policy.arguments.size() > 64) {
        return std::unexpected(std::string{"invalid native startup policy bounds"});
    }
    for (const auto* names : {&policy.configuration_names, &policy.reserved_entries}) {
        for (std::size_t index = 0; index < names->size(); ++index) {
            if (!leaf((*names)[index])) {
                return std::unexpected(std::string{"invalid native startup policy leaf"});
            }
            for (std::size_t prior = 0; prior < index; ++prior) {
                if (folded_equal((*names)[index], (*names)[prior])) {
                    return std::unexpected(std::string{"duplicate native startup policy leaf"});
                }
            }
        }
    }
    for (std::size_t index = 0; index < policy.environment.size(); ++index) {
        const auto& binding = policy.environment[index];
        if (!environment_binding_valid(binding) || !location_valid(binding.location)) {
            return std::unexpected(std::string{"invalid native startup policy environment"});
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (binding.name == policy.environment[prior].name) {
                return std::unexpected(std::string{"duplicate native startup policy environment"});
            }
        }
    }
    std::array<bool, 6> slots{};
    for (std::size_t index = 0; index < policy.arguments.size(); ++index) {
        const auto& binding = policy.arguments[index];
        std::size_t slot = 0;
        if (binding.source != native_argument_source::conversation_selector &&
            !binding.resume_literal.empty()) {
            return std::unexpected(std::string{"native resume literal outside its selector slot"});
        }
        switch (binding.source) {
        case native_argument_source::literal:
            if (binding.literal.size() > 128 || binding.literal.find('\0') != std::string::npos) {
                return std::unexpected(std::string{"invalid native startup policy literal"});
            }
            continue;
        case native_argument_source::conversation_selector:
            // Both flags are closed literals; the core picks one by launch mode.
            if (binding.literal.empty() || binding.literal.size() > 32 ||
                binding.resume_literal.empty() || binding.resume_literal.size() > 32 ||
                binding.literal.find('\0') != std::string::npos ||
                binding.resume_literal.find('\0') != std::string::npos ||
                !binding.literal.starts_with("--") || !binding.resume_literal.starts_with("--")) {
                return std::unexpected(std::string{"invalid native conversation selector"});
            }
            if (slots[4]) {
                return std::unexpected(std::string{"duplicate native conversation selector"});
            }
            slots[4] = true;
            if (index + 1 >= policy.arguments.size() ||
                policy.arguments[index + 1].source != native_argument_source::conversation_id) {
                return std::unexpected(std::string{"conversation selector must precede its id"});
            }
            continue;
        case native_argument_source::conversation_id:
            slot = 5;
            if (index == 0 || policy.arguments[index - 1].source !=
                                  native_argument_source::conversation_selector) {
                return std::unexpected(std::string{"conversation id requires its selector"});
            }
            break;
        case native_argument_source::provider_name:
            slot = 0;
            break;
        case native_argument_source::model:
            slot = 1;
            break;
        case native_argument_source::session_directory:
            slot = 2;
            break;
        case native_argument_source::forwarded_arguments:
            slot = 3;
            if (index + 1 != policy.arguments.size()) {
                return std::unexpected(std::string{"native forwarded arguments must be last"});
            }
            break;
        default:
            return std::unexpected(std::string{"invalid native startup policy argument source"});
        }
        if (!binding.literal.empty() || slots[slot]) {
            return std::unexpected(
                std::string{"duplicate or malformed native startup policy slot"}
            );
        }
        slots[slot] = true;
    }
    if (!slots[3]) {
        return std::unexpected(std::string{"native startup policy requires a forwarded suffix"});
    }
    return {};
}

auto validate_native_startup_recipe(
    const native_startup_input& input, const native_startup_recipe& recipe
) -> std::expected<void, std::string> {
    if (auto checked = validate_native_startup_policy(input.policy); !checked) {
        return checked;
    }
    if (input.runtime.runtime_id != input.policy.runtime_id || input.model.empty() ||
        input.model.size() > 128 || input.model.find('\0') != std::string_view::npos ||
        input.arguments.size() > 128) {
        return std::unexpected(std::string{"native startup differs from host-selected policy"});
    }
    if (input.provider != net::endpoint_provider::openai &&
        input.provider != net::endpoint_provider::anthropic) {
        return std::unexpected(std::string{"unsupported native provider binding"});
    }
    if (!path_shape(input.runtime.launch_executable) || !path_shape(input.paths.home) ||
        !path_shape(input.paths.agent) || !path_shape(input.paths.sessions) ||
        input.runtime.launch_arguments.size() > 64 || recipe.argv.empty() ||
        recipe.argv.size() > 128 || recipe.configuration.empty() ||
        recipe.configuration.size() > 16 || recipe.environment.size() > 16 ||
        recipe.reserved_entries.size() > 8) {
        return std::unexpected(std::string{"invalid native startup recipe bounds or paths"});
    }
    if (recipe.argv.front() != input.runtime.launch_executable.string() ||
        recipe.argv.size() - 1 < input.runtime.launch_arguments.size()) {
        return std::unexpected(
            std::string{"native startup executable differs from admitted runtime"}
        );
    }
    for (std::size_t index = 0; index < input.runtime.launch_arguments.size(); ++index) {
        if (recipe.argv[index + 1] != input.runtime.launch_arguments[index]) {
            return std::unexpected(
                std::string{"native startup prefix differs from admitted runtime"}
            );
        }
    }
    std::size_t remaining = max_argv_bytes;
    for (const auto& argument : recipe.argv) {
        if (argument.find('\0') != std::string::npos || argument.size() >= remaining) {
            return std::unexpected(std::string{"invalid native startup argument bytes"});
        }
        remaining -= argument.size() + 1;
    }
    if (!closed_arguments(input, recipe)) {
        return std::unexpected(std::string{"native startup arguments differ from host policy"});
    }
    if (recipe.configuration.size() != input.policy.configuration_names.size() ||
        recipe.environment.size() != input.policy.environment.size() ||
        recipe.reserved_entries != input.policy.reserved_entries) {
        return std::unexpected(std::string{"native startup requirements differ from host policy"});
    }
    const auto expected_url =
        "http://127.0.0.1:" + std::to_string(input.endpoint_port) +
        (input.provider == net::endpoint_provider::openai ? "/openai/v1" : "/anthropic");
    if (input.endpoint_port == 0 || recipe.base_url != expected_url) {
        return std::unexpected(
            std::string{"native startup endpoint differs from provider binding"}
        );
    }
    if (auto checked = validate_native_configuration_files(recipe.configuration); !checked) {
        return checked;
    }
    for (std::size_t index = 0; index < recipe.configuration.size(); ++index) {
        if (recipe.configuration[index].name != input.policy.configuration_names[index]) {
            return std::unexpected(std::string{"native configuration differs from host policy"});
        }
    }
    const bool binds_conversation =
        std::ranges::any_of(input.policy.arguments, [](const native_argument_binding& binding) {
            return binding.source == native_argument_source::conversation_id;
        });
    if (binds_conversation != !input.conversation_id.empty() ||
        (binds_conversation && !valid_conversation_id(input.conversation_id))) {
        return std::unexpected(
            std::string{"native conversation identity differs from host policy"}
        );
    }
    if (!binds_conversation && input.resume) {
        return std::unexpected(std::string{"native resume requires a conversation-binding policy"});
    }
    for (std::size_t index = 0; index < recipe.environment.size(); ++index) {
        const auto& binding = recipe.environment[index];
        if (!environment_binding_valid(binding) || !location_valid(binding.location) ||
            binding != input.policy.environment[index]) {
            return std::unexpected(std::string{"invalid native private environment projection"});
        }
        if ((binding.source == native_environment_source::endpoint_base_url ||
             binding.source == native_environment_source::endpoint_nonce) &&
            binding.name != endpoint_variable(binding.source, input.provider)) {
            return std::unexpected(std::string{"native endpoint variable differs from provider"});
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (binding.name == recipe.environment[prior].name) {
                return std::unexpected(std::string{"duplicate native environment name"});
            }
        }
    }
    for (std::size_t index = 0; index < recipe.reserved_entries.size(); ++index) {
        if (!leaf(recipe.reserved_entries[index])) {
            return std::unexpected(std::string{"invalid native reserved entry"});
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (folded_equal(recipe.reserved_entries[index], recipe.reserved_entries[prior])) {
                return std::unexpected(std::string{"duplicate native reserved entry"});
            }
        }
    }
    return {};
}

auto valid_conversation_id(std::string_view value) -> bool {
    if (value.size() != 36) {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        const char ch = value[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != '-') {
                return false;
            }
        } else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

auto native_startup_policy_digest(
    const native_startup_policy& policy, net::endpoint_provider provider, std::string_view model
) -> std::expected<std::string, std::string> {
    if (auto checked = validate_native_startup_policy(policy); !checked) {
        return std::unexpected(checked.error());
    }
    if (model.empty() || model.size() > 128 || model.find('\0') != std::string_view::npos) {
        return std::unexpected(std::string{"invalid native model for policy digest"});
    }
    // Length-prefixed canonical encoding: no field can alias another.
    std::string canonical;
    const auto put = [&](std::string_view field) {
        canonical += std::to_string(field.size());
        canonical += ':';
        canonical += field;
        canonical += ';';
    };
    put("glove.native-startup-policy.v1");
    put(policy.runtime_id);
    put(provider == net::endpoint_provider::openai ? "openai" : "anthropic");
    put(model);
    put(std::to_string(policy.configuration_names.size()));
    for (const auto& name : policy.configuration_names) {
        put(name);
    }
    put(std::to_string(policy.environment.size()));
    for (const auto& binding : policy.environment) {
        put(binding.name);
        put(std::to_string(static_cast<int>(binding.source)));
        put(std::to_string(static_cast<int>(binding.location)));
        put(binding.literal);
    }
    put(std::to_string(policy.reserved_entries.size()));
    for (const auto& entry : policy.reserved_entries) {
        put(entry);
    }
    put(std::to_string(policy.arguments.size()));
    for (const auto& argument : policy.arguments) {
        put(std::to_string(static_cast<int>(argument.source)));
        put(argument.literal);
        put(argument.resume_literal);
    }
    return container::detail::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size()
        }
    );
}

} // namespace glove::run::detail
