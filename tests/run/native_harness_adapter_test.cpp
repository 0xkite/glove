#include "adapters/pi/native_harness.hpp"
#include "native_harness_adapter.hpp"
#include "pi_native_policy.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using glove::net::endpoint_provider;
using namespace glove::run::detail;

constexpr std::string_view openai_catalog =
    R"({"openai-responses":{"chat:fixture-model":{"id":"fixture-model","provider":"openai","api":"openai-responses","type":"chat"}}})";
constexpr std::string_view anthropic_catalog =
    R"({"anthropic-messages":{"chat:fixture-model":{"id":"fixture-model","provider":"anthropic","api":"anthropic-messages","type":"chat"}}})";

struct fixture {
    glove::host::staged_runtime_harness runtime;
    native_startup_policy policy = pi_native_startup_policy();
    std::vector<std::string> arguments{"--print", "--mode", "json", "prompt"};
    std::string nonce = "glove-session-" + std::string(48, 'a');

    fixture() {
        // Pure encoding fixtures; these paths do not establish runtime authority.
        runtime.runtime_id = "pi";
        runtime.launch_executable = "/protected/runtime/node";
        runtime.launch_arguments = {"/protected/runtime/package/bin/pi"};
    }

    auto input(endpoint_provider provider = endpoint_provider::openai) const
        -> native_startup_input {
        return {
            .runtime = runtime,
            .policy = policy,
            .provider = provider,
            .model = "fixture-model",
            .arguments = arguments,
            .catalog_json =
                provider == endpoint_provider::openai ? openai_catalog : anthropic_catalog,
            .endpoint_port = 12345,
            .nonce = nonce,
            .paths = {
                .home = "/private/run/home",
                .agent = "/private/run/agent",
                .sessions = "/private/run/sessions"
            }
        };
    }
};

auto positive_cases() -> int {
    fixture f;
    const glove::run::adapters::pi_harness_adapter pi;
    const native_harness_adapter& adapter = pi;
    for (const auto provider : {endpoint_provider::openai, endpoint_provider::anthropic}) {
        const auto input = f.input(provider);
        auto recipe = adapter.encode_startup(input);
        REQUIRE(recipe);
        REQUIRE(validate_native_startup_recipe(input, *recipe));
        REQUIRE(recipe->argv.front() == f.runtime.launch_executable.string());
        REQUIRE(recipe->argv[1] == f.runtime.launch_arguments.front());
        const auto session = std::ranges::find(recipe->argv, "--session-dir");
        REQUIRE(session != recipe->argv.end());
        REQUIRE(
            std::distance(session, recipe->argv.end()) ==
            static_cast<std::ptrdiff_t>(f.arguments.size() + 2)
        );
        REQUIRE(*(session + 1) == input.paths.sessions.string());
        REQUIRE(std::equal(f.arguments.begin(), f.arguments.end(), session + 2));
        REQUIRE(recipe->configuration.size() == 3);
        REQUIRE(recipe->configuration[0].name == "models.json");
        REQUIRE(recipe->configuration[0].bytes.find(f.nonce) != std::string::npos);
        REQUIRE(recipe->configuration[0].bytes.find("modelOverrides") == std::string::npos);
        REQUIRE(recipe->configuration[1].name == "settings.json");
        REQUIRE(recipe->configuration[2].name == "auth.json");
        REQUIRE(recipe->configuration[2].bytes == "{}");
        REQUIRE(recipe->reserved_entries == std::vector<std::string>{".pi"});
        REQUIRE(recipe->environment.size() == 5);
        REQUIRE(recipe->environment.front().name == "PI_CODING_AGENT_DIR");
        REQUIRE(recipe->environment.front().location == native_private_location::agent);
        const auto saved = recipe->configuration.front().bytes;
        f.nonce.assign(f.nonce.size(), 'z');
        REQUIRE(recipe->configuration.front().bytes == saved);
        f.nonce = "glove-session-" + std::string(48, 'a');
    }
    return 0;
}

auto encoding_refusals() -> int {
    const glove::run::adapters::pi_harness_adapter adapter;
    fixture f;
    REQUIRE(!adapter.encode_startup(f.input(endpoint_provider::github)));
    f.arguments = {"--api-key=untrusted"};
    REQUIRE(!adapter.encode_startup(f.input()));
    f.arguments.clear();
    f.runtime.launch_arguments.clear();
    REQUIRE(!adapter.encode_startup(f.input()));
    f.runtime.launch_arguments = {"/protected/runtime/package/bin/pi", "extra"};
    REQUIRE(!adapter.encode_startup(f.input()));
    f.runtime.launch_arguments.resize(1);
    f.runtime.runtime_id = "codex";
    REQUIRE(!adapter.encode_startup(f.input()));
    f.runtime.runtime_id = "pi";
    auto input = f.input();
    input.endpoint_port = 0;
    REQUIRE(!adapter.encode_startup(input));
    input.endpoint_port = 1;
    input.catalog_json = "{}";
    REQUIRE(!adapter.encode_startup(input));
    input.catalog_json = openai_catalog;
    input.paths.agent = "/";
    REQUIRE(!adapter.encode_startup(input));
    return 0;
}

auto malformed_output_refusals() -> int {
    fixture f;
    const auto input = f.input();
    const glove::run::adapters::pi_harness_adapter adapter;
    const auto good = adapter.encode_startup(input);
    REQUIRE(good);
    // The validator is pure: no credential, endpoint, filesystem or executor
    // capability is available at this seam. Live ordering is tested by the core.
    for (int mutation = 0; mutation < 19; ++mutation) {
        auto recipe = *good;
        switch (mutation) {
        case 0:
            recipe.argv.front() = "/host/unapproved-executable";
            break;
        case 1:
            recipe.argv[1] = "/host/unapproved-script";
            break;
        case 2:
            recipe.argv.assign(129, "arg");
            break;
        case 3:
            recipe.configuration.front().name = "../auth.json";
            break;
        case 4:
            recipe.configuration.back().name = "MODELS.JSON";
            break;
        case 5:
            recipe.configuration.front().bytes.assign(32769, 'x');
            break;
        case 6:
            recipe.configuration.resize(17);
            break;
        case 7:
            recipe.environment.front().name = "OPENAI_API_KEY";
            break;
        case 8:
            recipe.environment.front().location = static_cast<native_private_location>(99);
            break;
        case 9:
            recipe.reserved_entries.push_back(".PI");
            break;
        case 10:
            recipe.reserved_entries = {"../host"};
            break;
        case 11:
            recipe.environment.push_back(
                {.name = "NODE_PATH", .location = native_private_location::agent}
            );
            break;
        case 12:
            recipe.environment.pop_back();
            break;
        case 13:
            recipe.environment.front().location = native_private_location::cache;
            break;
        case 14:
            recipe.argv.erase(recipe.argv.begin() + 8);
            break;
        case 15:
            recipe.argv.push_back("--no-tools");
            break;
        case 16:
            recipe.reserved_entries.clear();
            break;
        case 17:
            recipe.configuration.erase(recipe.configuration.begin() + 1);
            break;
        case 18:
            recipe.configuration.front().name = "extra.json";
            break;
        }
        const auto checked = validate_native_startup_recipe(input, recipe);
        if (checked) {
            std::fprintf(stderr, "accepted malformed startup recipe: mutation=%d\n", mutation);
        }
        REQUIRE(!checked);
    }
    return 0;
}

auto malformed_policy_refusals() -> int {
    REQUIRE(validate_native_startup_policy(pi_native_startup_policy()));
    for (int mutation = 0; mutation < 10; ++mutation) {
        auto policy = pi_native_startup_policy();
        switch (mutation) {
        case 0:
            policy.configuration_names.clear();
            break;
        case 1:
            policy.configuration_names.back() = "MODELS.JSON";
            break;
        case 2:
            policy.environment.front().name = "PATH";
            break;
        case 3:
            policy.environment.back() = policy.environment.front();
            break;
        case 4:
            policy.arguments.back().source = static_cast<native_argument_source>(99);
            break;
        case 5:
            policy.arguments.back().literal = "unapproved-slot-value";
            break;
        case 6:
            policy.arguments.insert(policy.arguments.begin(), policy.arguments.back());
            break;
        case 7:
            policy.arguments.pop_back();
            break;
        case 8:
            policy.reserved_entries.push_back(".PI");
            break;
        case 9:
            policy.arguments.front().literal.assign(129, 'x');
            break;
        }
        REQUIRE(!validate_native_startup_policy(policy));
    }
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(malformed_policy_refusals() == 0);
    REQUIRE(positive_cases() == 0);
    REQUIRE(encoding_refusals() == 0);
    REQUIRE(malformed_output_refusals() == 0);
    return 0;
}
