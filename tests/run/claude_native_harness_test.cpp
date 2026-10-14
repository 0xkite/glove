#include "adapters/claude/native_harness.hpp"
#include "claude_native_policy.hpp"
#include "native_harness_adapter.hpp"
#include "native_session_model.hpp"
#include "pi_native_policy.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using glove::net::endpoint_provider;
using namespace glove::run::detail;

constexpr std::string_view conversation = "0f3c1a2b-4d5e-4f60-8a71-92b3c4d5e6f7";

struct fixture {
    glove::host::staged_runtime_harness runtime;
    native_startup_policy policy = claude_native_startup_policy(claude_launch_mode::headless);
    std::vector<std::string> arguments{"Reply with the single word pong."};
    std::string nonce = "glove-session-" + std::string(48, 'a');
    std::string conversation_id{conversation};
    bool resume = false;

    fixture() {
        runtime.runtime_id = "claude";
        runtime.launch_executable = "/protected/runtime/claude";
    }

    static auto paths() -> native_private_paths {
        return {
            .home = "/private/run/home",
            .agent = "/private/run/agent",
            .sessions = "/private/run/sessions"
        };
    }

    auto input(endpoint_provider provider = endpoint_provider::anthropic) const
        -> native_startup_input {
        return {
            .runtime = runtime,
            .policy = policy,
            .provider = provider,
            .model = "claude-fixture-model",
            .arguments = arguments,
            .catalog_json = {},
            .endpoint_port = 4242,
            .nonce = nonce,
            .paths = paths(),
            .conversation_id = conversation_id,
            .resume = resume,
            .workspace = "/private/fixture/ws"
        };
    }
};

auto find_value(const std::vector<std::string>& argv, std::string_view flag) -> std::string {
    const auto found = std::ranges::find(argv, flag);
    return found == argv.end() || found + 1 == argv.end() ? std::string{} : *(found + 1);
}

auto policy_shape() -> int {
    for (const auto mode :
         {claude_launch_mode::headless,
          claude_launch_mode::headless_write_tool,
          claude_launch_mode::interactive}) {
        const auto policy = claude_native_startup_policy(mode);
        REQUIRE(validate_native_startup_policy(policy));
        REQUIRE(policy.runtime_id == "claude");
        const bool interactive = mode == claude_launch_mode::interactive;
        REQUIRE(policy.configuration_names.front() == "settings.json");
        REQUIRE(policy.configuration_names.size() == (interactive ? 2U : 1U));
        REQUIRE(policy.writable_configuration_names.size() == (interactive ? 1U : 0U));
        if (interactive) {
            REQUIRE(policy.configuration_names.back() == ".claude.json");
            REQUIRE(policy.writable_configuration_names.front() == ".claude.json");
        }
        REQUIRE(policy.environment.size() == 12);
        REQUIRE(policy.environment[1].source == native_environment_source::endpoint_base_url);
        REQUIRE(policy.environment[2].source == native_environment_source::endpoint_nonce);
        const bool headless = !interactive;
        const auto has = [&](std::string_view literal) {
            return std::ranges::any_of(policy.arguments, [&](const native_argument_binding& b) {
                return b.source == native_argument_source::literal && b.literal == literal;
            });
        };
        REQUIRE(has("--bare") && has("--tools") && has("--strict-mcp-config"));
        REQUIRE(has("--print") == headless && has("--permission-prompts") == headless);
        REQUIRE(!has("--dangerously-skip-permissions") && !has("--continue"));
        const bool write_tool = mode == claude_launch_mode::headless_write_tool;
        REQUIRE(has("Edit,Read") == write_tool && has("acceptEdits") == write_tool);
        REQUIRE(has("bypassPermissions") == false);
    }
    // A policy digest excludes launch mode (start vs resume) but binds the
    // harness mode, model and provider.
    const auto headless = claude_native_startup_policy(claude_launch_mode::headless);
    const auto interactive = claude_native_startup_policy(claude_launch_mode::interactive);
    auto digest = native_startup_policy_digest(headless, endpoint_provider::anthropic, "m1");
    REQUIRE(digest && valid_checkpoint_id(*digest));
    REQUIRE(*digest == *native_startup_policy_digest(headless, endpoint_provider::anthropic, "m1"));
    REQUIRE(*digest != *native_startup_policy_digest(headless, endpoint_provider::anthropic, "m2"));
    REQUIRE(*digest != *native_startup_policy_digest(headless, endpoint_provider::openai, "m1"));
    REQUIRE(
        *digest != *native_startup_policy_digest(interactive, endpoint_provider::anthropic, "m1")
    );
    REQUIRE(
        *digest != *native_startup_policy_digest(
                       pi_native_startup_policy(), endpoint_provider::anthropic, "m1"
                   )
    );
    auto mutated = headless;
    mutated.environment.back().literal = "1";
    REQUIRE(*digest != *native_startup_policy_digest(mutated, endpoint_provider::anthropic, "m1"));

    // Policy refusals specific to the new typed slots.
    for (int mutation = 0; mutation < 8; ++mutation) {
        auto policy = headless;
        const auto selector = std::ranges::find_if(policy.arguments, [](const auto& b) {
            return b.source == native_argument_source::conversation_selector;
        });
        switch (mutation) {
        case 0:
            selector->resume_literal.clear();
            break;
        case 1:
            selector->literal = "resume";
            break;
        case 2:
            policy.arguments.erase(selector + 1);
            break;
        case 3:
            policy.arguments.insert(policy.arguments.begin(), *(selector + 1));
            break;
        case 4:
            policy.arguments.front().resume_literal = "--x";
            break;
        case 5:
            policy.environment[2].name = "ANTHROPIC_AUTH_TOKEN";
            break;
        case 6:
            policy.environment[1].source = native_environment_source::literal;
            policy.environment[1].literal = "http://169.254.169.254/";
            break;
        case 7:
            policy.environment.back().literal = "value with spaces";
            break;
        }
        REQUIRE(!validate_native_startup_policy(policy));
    }
    auto writable = claude_native_startup_policy(claude_launch_mode::interactive);
    writable.writable_configuration_names = {"settings.json", "settings.json"};
    REQUIRE(!validate_native_startup_policy(writable));
    writable.writable_configuration_names = {"auth.json"};
    REQUIRE(!validate_native_startup_policy(writable));
    REQUIRE(
        *native_startup_policy_digest(headless, endpoint_provider::anthropic, "m1") !=
        *native_startup_policy_digest(
            claude_native_startup_policy(claude_launch_mode::headless_write_tool),
            endpoint_provider::anthropic,
            "m1"
        )
    );
    return 0;
}

auto interactive_encoding() -> int {
    fixture f;
    f.policy = claude_native_startup_policy(claude_launch_mode::interactive);
    f.arguments.clear();
    const glove::run::adapters::claude_harness_adapter adapter;
    auto recipe = adapter.encode_startup(f.input());
    if (!recipe) {
        std::fprintf(stderr, "interactive encode: %s\n", recipe.error().c_str());
    }
    REQUIRE(recipe);
    REQUIRE(validate_native_startup_recipe(f.input(), *recipe));
    REQUIRE(recipe->configuration.size() == 2);
    REQUIRE(!recipe->configuration[0].writable);
    REQUIRE(recipe->configuration[1].name == ".claude.json" && recipe->configuration[1].writable);
    // Only the nonce tail that Claude uses to key its approval is embedded,
    // never the whole nonce, and nothing else from the host.
    const auto& bytes = recipe->configuration[1].bytes;
    REQUIRE(bytes.find(f.nonce.substr(f.nonce.size() - 20)) != std::string::npos);
    REQUIRE(bytes.find(f.nonce) == std::string::npos);
    REQUIRE(bytes.find("hasCompletedOnboarding") != std::string::npos);
    REQUIRE(
        bytes.find("\"/private/fixture/ws\":{\"hasTrustDialogAccepted\":true") != std::string::npos
    );
    auto no_workspace = f.input();
    no_workspace.workspace = {};
    REQUIRE(!adapter.encode_startup(no_workspace));
    REQUIRE(bytes.find("oauth") == std::string::npos && bytes.find("/Users") == std::string::npos);
    REQUIRE(std::ranges::find(recipe->argv, "--print") == recipe->argv.end());
    // Writable flag mismatches are refused by the core validator.
    auto mutated = *recipe;
    mutated.configuration[1].writable = false;
    REQUIRE(!validate_native_startup_recipe(f.input(), mutated));
    mutated = *recipe;
    mutated.configuration[0].writable = true;
    REQUIRE(!validate_native_startup_recipe(f.input(), mutated));
    return 0;
}

auto encoding() -> int {
    fixture f;
    const glove::run::adapters::claude_harness_adapter adapter;
    auto start = adapter.encode_startup(f.input());
    REQUIRE(start);
    REQUIRE(validate_native_startup_recipe(f.input(), *start));
    REQUIRE(start->argv.front() == "/protected/runtime/claude");
    REQUIRE(start->argv[1] == "--bare");
    REQUIRE(find_value(start->argv, "--session-id") == conversation);
    REQUIRE(std::ranges::find(start->argv, "--resume") == start->argv.end());
    REQUIRE(find_value(start->argv, "--model") == "claude-fixture-model");
    REQUIRE(find_value(start->argv, "--tools").empty());
    REQUIRE(start->argv.back() == f.arguments.front());
    REQUIRE(*(start->argv.end() - 2) == "--");
    REQUIRE(start->base_url == "http://127.0.0.1:4242/anthropic");
    REQUIRE(start->configuration.size() == 1 && start->configuration[0].name == "settings.json");
    REQUIRE(start->configuration[0].bytes.find(f.nonce) == std::string::npos);
    REQUIRE(start->environment == f.policy.environment);
    const std::vector<std::string> reserved{".claude", ".mcp.json"};
    REQUIRE(start->reserved_entries == reserved);
    // No argv element carries the nonce or an operator path.
    for (const auto& argument : start->argv) {
        REQUIRE(argument.find("glove-session") == std::string::npos);
        REQUIRE(argument.find("/Users/") == std::string::npos);
    }

    f.resume = true;
    auto resume = adapter.encode_startup(f.input());
    REQUIRE(resume);
    REQUIRE(validate_native_startup_recipe(f.input(), *resume));
    REQUIRE(find_value(resume->argv, "--resume") == conversation);
    REQUIRE(std::ranges::find(resume->argv, "--session-id") == resume->argv.end());
    REQUIRE(resume->argv.size() == start->argv.size());
    // A resume recipe is refused against a start input and vice versa.
    f.resume = false;
    REQUIRE(!validate_native_startup_recipe(f.input(), *resume));
    f.resume = true;
    REQUIRE(!validate_native_startup_recipe(f.input(), *start));
    f.resume = false;

    // Refusals.
    REQUIRE(!adapter.encode_startup(f.input(endpoint_provider::openai)));
    f.conversation_id = "not-a-uuid";
    REQUIRE(!adapter.encode_startup(f.input()));
    f.conversation_id = std::string{conversation};
    f.conversation_id[0] = 'F';
    REQUIRE(!adapter.encode_startup(f.input()));
    f.conversation_id = std::string{conversation};
    f.runtime.launch_arguments = {"/host/script"};
    REQUIRE(!adapter.encode_startup(f.input()));
    f.runtime.launch_arguments.clear();
    f.runtime.runtime_id = "pi";
    REQUIRE(!adapter.encode_startup(f.input()));
    f.runtime.runtime_id = "claude";
    f.policy = pi_native_startup_policy();
    REQUIRE(!adapter.encode_startup(f.input()));
    f.policy = claude_native_startup_policy(claude_launch_mode::headless);
    auto input = f.input();
    input.endpoint_port = 0;
    REQUIRE(!adapter.encode_startup(input));
    // The Pi policy never binds a conversation; a conversation id is refused there.
    fixture pi;
    pi.policy = pi_native_startup_policy();
    pi.runtime.runtime_id = "pi";
    pi.runtime.launch_arguments = {"/protected/runtime/package/bin/pi"};
    auto pi_input = pi.input(endpoint_provider::openai);
    native_startup_recipe empty;
    REQUIRE(!validate_native_startup_recipe(pi_input, empty));

    // Recipe mutations refused by the validator.
    for (int mutation = 0; mutation < 9; ++mutation) {
        auto recipe = *start;
        switch (mutation) {
        case 0:
            recipe.argv.insert(recipe.argv.begin() + 1, "--dangerously-skip-permissions");
            break;
        case 1:
            recipe.argv.erase(recipe.argv.begin() + 1);
            break;
        case 2:
            std::ranges::replace(recipe.argv, std::string{"--session-id"}, std::string{"--resume"});
            break;
        case 3:
            std::ranges::replace(
                recipe.argv,
                std::string{conversation},
                std::string{"11111111-1111-4111-8111-111111111111"}
            );
            break;
        case 4:
            recipe.environment[2].name = "ANTHROPIC_AUTH_TOKEN";
            break;
        case 5:
            recipe.environment[1].source = native_environment_source::literal;
            recipe.environment[1].literal = "https://api.anthropic.com";
            break;
        case 6:
            recipe.environment.push_back(
                {.name = "ANTHROPIC_API_KEY",
                 .location = native_private_location::agent,
                 .source = native_environment_source::endpoint_nonce,
                 .literal = {}}
            );
            break;
        case 7:
            recipe.base_url = "http://127.0.0.1:4242/openai/v1";
            break;
        case 8:
            recipe.reserved_entries.clear();
            break;
        }
        REQUIRE(!validate_native_startup_recipe(f.input(), recipe));
    }
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(policy_shape() == 0);
    REQUIRE(encoding() == 0);
    REQUIRE(interactive_encoding() == 0);
    return 0;
}
