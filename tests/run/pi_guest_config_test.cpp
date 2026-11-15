#include "pi_guest_config.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::run::pi_launch_selection;
using glove::run::pi_provider;
using glove::run::detail::make_pi_guest_config;

const std::string nonce = "glove-session-" + std::string(48, 'a');
constexpr std::string_view openai_catalog =
    R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat","name":"Fixture only","contextWindow":17,"cost":{"input":99},"future":{"nested":[true,null,"value"]}}}})";
constexpr std::string_view anthropic_catalog =
    R"({"anthropic-messages":{"chat:claude-sonnet-4-6":{"id":"claude-sonnet-4-6","provider":"anthropic","api":"anthropic-messages","type":"chat","reasoning":true,"maxTokens":23}}})";

// Synthetic identity fixtures do not claim live provider/model availability.
auto selection(pi_provider provider = pi_provider::openai) -> pi_launch_selection {
    return {
        .model =
            {.provider = provider,
             .model = provider == pi_provider::openai ? "gpt-5" : "claude-sonnet-4-6"},
        .arguments = {}
    };
}

auto positive_cases() -> int {
    for (const auto provider : {pi_provider::openai, pi_provider::anthropic}) {
        auto selected = selection(provider);
        selected.arguments = {"--print", "--mode", "json", "--thinking", "high", "Summarize"};
        const bool openai = provider == pi_provider::openai;
        const std::string name = openai ? "openai" : "anthropic";
        const std::string url =
            "http://127.0.0.1:12345" + std::string{openai ? "/openai/v1" : "/anthropic"};
        auto result = make_pi_guest_config(
            selected, 12345, nonce, openai ? openai_catalog : anthropic_catalog
        );
        REQUIRE(result);
        REQUIRE(result->base_url == url);
        REQUIRE(
            result->models_json == "{\"providers\":{\"" + name + "\":{\"baseUrl\":\"" + url +
                                       "\",\"apiKey\":\"" + nonce + "\"}}}"
        );
        REQUIRE(
            result->settings_json == "{\"defaultProvider\":\"" + name + "\",\"defaultModel\":\"" +
                                         selected.model.model +
                                         "\",\"packages\":[],\"extensions\":[],\"skills\":[],"
                                         "\"promptTemplates\":[],\"themes\":[]}"
        );
        std::vector<std::string> expected{
            "--provider",
            name,
            "--model",
            selected.model.model,
            "--offline",
            "--no-approve",
            "--no-extensions",
            "--no-mcp",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files"
        };
        expected.insert(expected.end(), selected.arguments.begin(), selected.arguments.end());
        REQUIRE(result->arguments == expected);
        for (const auto field :
             {"models",
              "modelOverrides",
              "contextWindow",
              "cost",
              "api\"",
              "reasoning",
              "maxTokens",
              "--no-tools"}) {
            REQUIRE(result->models_json.find(field) == std::string::npos);
        }
    }
    auto selected = selection();
    selected.arguments = {"--", "--provider", "literal prompt"};
    auto delimited = make_pi_guest_config(selected, 65535, nonce, openai_catalog);
    REQUIRE(delimited);
    REQUIRE(delimited->base_url == "http://127.0.0.1:65535/openai/v1");
    REQUIRE(delimited->arguments[12] == "--");
    REQUIRE(delimited->arguments[13] == "--provider");
    REQUIRE(make_pi_guest_config(selection(), 1, nonce, openai_catalog));
    REQUIRE(make_pi_guest_config(selection(), 1, nonce, std::string{openai_catalog} + " \n\t"));
    return 0;
}

auto catalog_cases() -> int {
    for (
        const auto& catalog : std::vector<std::string>{
            "",
            "{}",
            "[]",
            "null",
            "{",
            std::string{openai_catalog} + " false",
            std::string(1024 * 1024 + 1, ' '),
            R"({"openai-responses":{"chat:gpt-50":{"id":"gpt-50","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":5,"provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"anthropic","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-completions","type":"chat"}}})",
            R"({"wrong-group":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"embedding"}}})",
            R"({"openai-responses":{"chat:alias":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"other","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{},"openai-responses":{}})",
            R"({"openai-responses":{"chat:gpt-5":{},"chat:gpt-5":{}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","\u0069d":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat","future":01}}})",
            R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat","future":{"x":1,"x":2}}}})"
        }) {
        REQUIRE(!make_pi_guest_config(selection(), 12345, nonce, catalog));
    }
    const std::string record =
        R"({"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"})";
    REQUIRE(!make_pi_guest_config(
        selection(),
        1,
        nonce,
        "{\"openai-responses\":{\"chat:gpt-5\":" + record + ",\"chat:alias\":" + record + "}}"
    ));
    REQUIRE(!make_pi_guest_config(
        selection(),
        1,
        nonce,
        "{\"openai-responses\":{\"chat:gpt-5\":" + record +
            "},\"another-api\":{\"chat:gpt-5\":" + record + "}}"
    ));
    REQUIRE(!make_pi_guest_config(
        selection(),
        1,
        nonce,
        "{\"openai-responses\":{\"chat:gpt-5\":" + record + ",\"embedding:gpt-5\":" + record + "}}"
    ));
    std::string groups = "{";
    for (int index = 0; index < 16; ++index) {
        groups += "\"group-" + std::to_string(index) + "\":{},";
    }
    groups += std::string{openai_catalog.substr(1)};
    REQUIRE(!make_pi_guest_config(selection(), 1, nonce, groups));
    std::string entries = "{\"openai-responses\":{\"chat:gpt-5\":" + record;
    const std::string unrelated =
        R"({"id":"other","provider":"openai","api":"openai-responses","type":"chat"})";
    for (int index = 0; index < 4095; ++index) {
        entries += ",\"chat:other-" + std::to_string(index) + "\":" + unrelated;
    }
    REQUIRE(make_pi_guest_config(selection(), 1, nonce, entries + "}}"));
    REQUIRE(!make_pi_guest_config(
        selection(), 1, nonce, entries + ",\"chat:overflow\":" + unrelated + "}}"
    ));
    const auto nested_catalog = [&record](std::size_t arrays) {
        const auto identity = record.substr(0, record.size() - 1);
        return "{\"openai-responses\":{\"chat:gpt-5\":" + identity +
               ",\"future\":" + std::string(arrays, '[') + "0" + std::string(arrays, ']') + "}}}";
    };
    // Root/group/model occupy depths 0/1/2. Sixty-one arrays put the
    // metadata scalar exactly at depth 64, with all identity fields valid.
    REQUIRE(make_pi_guest_config(selection(), 1, nonce, nested_catalog(61)));
    REQUIRE(!make_pi_guest_config(selection(), 1, nonce, nested_catalog(62)));
    return 0;
}

auto launch_cases() -> int {
    REQUIRE(!make_pi_guest_config(selection(), 0, nonce, openai_catalog));
    for (const auto& bad_nonce : std::vector<std::string>{
             "",
             "glove-session-",
             "other-session-" + std::string(48, 'a'),
             "glove-session-" + std::string(47, 'a'),
             "glove-session-" + std::string(49, 'a'),
             "glove-session-" + std::string(48, 'A'),
             "glove-session-" + std::string(48, 'g'),
             "glove-session-" + std::string(47, 'a') + std::string(1, '\0')
         }) {
        REQUIRE(!make_pi_guest_config(selection(), 1, bad_nonce, openai_catalog));
    }
    auto selected = selection();
    selected.model.provider = static_cast<pi_provider>(99);
    REQUIRE(!make_pi_guest_config(selected, 1, nonce, openai_catalog));
    selected = selection();
    selected.model.model = "gpt-5:high";
    REQUIRE(!make_pi_guest_config(selected, 1, nonce, openai_catalog));
    for (const auto& arguments : std::vector<std::vector<std::string>>{
             {"--provider", "anthropic"},
             {"--model", "other"},
             {"--api-key=secret"},
             {"--session-dir", "/host"},
             {"--tools", "read"},
             {"--extension", "/host"},
             {"--", "@/host/auth.json"},
             {"@fixture"},
             {"--mode", "rpc"},
             {"--thinking", "unknown"},
             {"--print", "-p"},
             {std::string{"x\0y", 3}},
             std::vector<std::string>(33, "prompt"),
             {std::string(16385, 'x')},
             std::vector<std::string>(5, std::string(16384, 'x'))
         }) {
        selected = selection();
        selected.arguments = arguments;
        REQUIRE(!make_pi_guest_config(selected, 1, nonce, openai_catalog));
    }
    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = positive_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = catalog_cases(); failed != 0) {
        return failed;
    }
    return launch_cases();
}
