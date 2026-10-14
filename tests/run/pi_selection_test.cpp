#include "glove/run/pi_selection.hpp"

#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto selection_cases() -> int {
    using namespace glove::run;
    REQUIRE(!select_pi_launch({}));
    REQUIRE(!select_pi_launch({.provider = "openai"}));
    REQUIRE(!select_pi_launch({.model = "gpt-6.1-sol"}));
    const pi_model_selection saved{.provider = pi_provider::openai, .model = "gpt-6.1-sol"};
    auto selected = select_pi_launch({}, saved);
    REQUIRE(selected);
    REQUIRE(selected->model == saved);
    REQUIRE(selected->arguments.empty());
    auto override_model = select_pi_launch({.model = "gpt-5"}, saved);
    REQUIRE(override_model);
    REQUIRE(override_model->model.model == "gpt-5");
    REQUIRE(override_model->model.provider == pi_provider::openai);
    REQUIRE(!select_pi_launch({.provider = "anthropic"}, saved));
    auto anthropic =
        select_pi_launch({.provider = "anthropic", .model = "claude-sonnet-4-6"}, saved);
    REQUIRE(anthropic);
    REQUIRE(anthropic->model.provider == pi_provider::anthropic);
    REQUIRE(anthropic->model.model == "claude-sonnet-4-6");
    REQUIRE(pi_provider_name(anthropic->model.provider) == "anthropic");
    REQUIRE(pi_provider_name(saved.provider) == "openai");
    REQUIRE(!select_pi_launch({.provider = "openai-codex", .model = "gpt-5"}));
    REQUIRE(!select_pi_launch({.provider = "custom", .model = "gpt-5"}));
    REQUIRE(!select_pi_launch({.provider = "OPENAI", .model = "gpt-5"}));
    for (const auto& model : std::vector<std::string>{
             "",
             "../gpt-5",
             "gpt-5:high",
             "https://evil.example/model",
             "!echo secret",
             "gpt 5",
             "gpt\n5",
             std::string{"gpt\0evil", 8},
             std::string(129, 'a')
         }) {
        REQUIRE(!select_pi_launch({.provider = "openai", .model = model}));
    }
    REQUIRE(select_pi_launch({.provider = "openai", .model = std::string(128, 'a')}));
    REQUIRE(
        !select_pi_launch({}, pi_model_selection{.provider = pi_provider::openai, .model = "!bad"})
    );
    REQUIRE(!select_pi_launch(
        {}, pi_model_selection{.provider = static_cast<pi_provider>(99), .model = "gpt-5"}
    ));
    return 0;
}

auto argument_cases() -> int {
    using namespace glove::run;
    const pi_model_selection saved{.provider = pi_provider::openai, .model = "gpt-5"};
    const std::vector<std::string> accepted{
        "--print", "--mode", "json", "--thinking", "high", "Summarize this repository"
    };
    auto launch = select_pi_launch({.arguments = accepted}, saved);
    REQUIRE(launch);
    REQUIRE(launch->arguments == accepted);
    REQUIRE(select_pi_launch({.arguments = {"-p", "A multiline\nprompt"}}, saved));
    REQUIRE(select_pi_launch({.arguments = {"--", "--model is prompt text"}}, saved));
    REQUIRE(select_pi_launch({.arguments = {"--mode", "text", "--thinking", "off"}}, saved));
    for (const auto& argument : std::vector<std::string>{
             "--api-key",
             "--api-key=secret",
             "--provider",
             "--model",
             "--models",
             "--extension",
             "-e",
             "--skill",
             "--tools",
             "--approve",
             "-a",
             "--session",
             "--continue",
             "-c",
             "--session-dir",
             "--session-id",
             "--fork",
             "--system-prompt",
             "--append-system-prompt",
             "--mode=rpc",
             "--offline",
             "--help",
             "@/host/auth.json",
             "-pevil"
         }) {
        REQUIRE(!select_pi_launch({.arguments = {argument}}, saved));
    }
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"--thinking"},
             {"--thinking", "unsafe"},
             {"--mode"},
             {"--mode", "rpc"},
             {"--thinking", "high", "--thinking", "low"},
             {"--mode", "text", "--mode", "json"},
             {"--print", "-p"},
             {std::string{"bad\0arg", 7}},
             {std::string(16385, 'a')},
             std::vector<std::string>(33, "prompt"),
             std::vector<std::string>(5, std::string(16384, 'a'))
         }) {
        REQUIRE(!select_pi_launch({.arguments = arguments}, saved));
    }
    return 0;
}

auto codec_cases() -> int {
    using namespace glove::run;
    const pi_model_selection saved{.provider = pi_provider::openai, .model = "gpt-5"};
    auto encoded = encode_pi_model_selection(saved);
    REQUIRE(encoded);
    REQUIRE(*encoded == R"({"schema_version":1,"provider":"openai","model":"gpt-5"})");
    auto decoded = decode_pi_model_selection(*encoded);
    REQUIRE(decoded);
    REQUIRE(*decoded == saved);
    auto anthropic = decode_pi_model_selection(
        R"({"schema_version":1,"provider":"anthropic","model":"claude-sonnet-4-6"})"
    );
    REQUIRE(anthropic);
    REQUIRE(anthropic->provider == pi_provider::anthropic);
    REQUIRE(!encode_pi_model_selection({.provider = pi_provider::openai, .model = "!secret"}));
    for (const auto& json : std::vector<std::string>{
             "",
             "{}",
             "[]",
             "null",
             R"({"schema_version":2,"provider":"openai","model":"gpt-5"})",
             R"({"schema_version":1,"provider":"custom","model":"gpt-5"})",
             R"({"schema_version":1,"provider":"openai","model":"!command"})",
             R"({"schema_version":1,"provider":"openai","model":"gpt-5","api_key":"secret"})",
             R"({"schema_version":1,"provider":"anthropic","provider":"openai","model":"gpt-5"})",
             R"({"schema_version":1,"provider":"openai","model":"gpt-5","model":"gpt-4"})",
             R"({"provider":"openai","model":"gpt-5"})",
             R"({"schema_version":1,"provider":"openai","model":"gpt-5"} trailing)",
             std::string(4097, ' ')
         }) {
        REQUIRE(!decode_pi_model_selection(json));
    }
    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = selection_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = argument_cases(); failed != 0) {
        return failed;
    }
    return codec_cases();
}
