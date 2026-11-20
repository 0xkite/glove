// Resolving a shareable Pi provider from Pi's own data: the built-in catalog,
// host models.json, and host auth.json. Every instance goes through the same
// code; only the data differs.

#include "glove/run/pi_provider_share.hpp"

#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

namespace {

using glove::run::pi_shared_provider_secret;
using glove::run::resolve_pi_shared_provider;
using glove::run::valid_pi_provider_name;

auto catalog(std::string_view provider, std::string_view api, std::string_view base_url)
    -> std::string {
    return std::string{R"({")"} + std::string{api} + R"(":{"chat:m1":{"id":"m1","provider":")" +
           std::string{provider} + R"(","api":")" + std::string{api} + R"(","baseUrl":")" +
           std::string{base_url} + R"("}}})";
}

auto contains(const std::vector<std::string>& values, std::string_view value) -> bool {
    for (const auto& item : values) {
        if (item == value) {
            return true;
        }
    }
    return false;
}

auto resolves_three_credential_shapes() -> int {
    // Bearer (OpenAI-compatible), x-api-key (Anthropic), x-goog-api-key (Google).
    auto deepseek = resolve_pi_shared_provider(
        "deepseek", catalog("deepseek", "openai-completions", "https://api.deepseek.com"), ""
    );
    REQUIRE(deepseek.has_value());
    REQUIRE(deepseek->host == "api.deepseek.com");
    REQUIRE(deepseek->port == 443);
    REQUIRE(deepseek->base_path.empty());
    REQUIRE(deepseek->allowed_paths == std::vector<std::string>{"/chat/completions"});

    auto anthropic = resolve_pi_shared_provider(
        "anthropic", catalog("anthropic", "anthropic-messages", "https://api.anthropic.com"), "{}"
    );
    REQUIRE(anthropic.has_value());
    REQUIRE(anthropic->host == "api.anthropic.com");
    REQUIRE(anthropic->allowed_paths == std::vector<std::string>{"/v1/messages"});

    auto google = resolve_pi_shared_provider(
        "google",
        catalog(
            "google", "google-generative-ai", "https://generativelanguage.googleapis.com/v1beta/"
        ),
        ""
    );
    REQUIRE(google.has_value());
    REQUIRE(google->host == "generativelanguage.googleapis.com");
    REQUIRE(google->base_path == "/v1beta");
    REQUIRE(google->allowed_paths == std::vector<std::string>{"/v1beta/models/*"});
    return 0;
}

auto models_json_overrides_and_custom_providers() -> int {
    // A host models.json baseUrl replaces the catalog origin, as it does in Pi.
    auto proxied = resolve_pi_shared_provider(
        "deepseek",
        catalog("deepseek", "openai-completions", "https://api.deepseek.com"),
        R"({"providers":{"deepseek":{"baseUrl":"https://gw.example.com/deepseek/v1"}}})"
    );
    REQUIRE(proxied.has_value());
    REQUIRE(proxied->host == "gw.example.com");
    REQUIRE(proxied->base_path == "/deepseek/v1");
    REQUIRE(proxied->allowed_paths == std::vector<std::string>{"/deepseek/v1/chat/completions"});

    // A provider defined only in models.json needs no catalog.
    auto custom = resolve_pi_shared_provider(
        "runinfra",
        "",
        R"({"providers":{"runinfra":{"baseUrl":"https://api.runinfra.ai/v1",)"
        R"("api":"openai-completions","models":[{"id":"r1"},{"id":"r2","api":"openai-responses"}]}}})"
    );
    REQUIRE(custom.has_value());
    REQUIRE(custom->host == "api.runinfra.ai");
    REQUIRE(contains(custom->allowed_paths, "/v1/chat/completions"));
    REQUIRE(contains(custom->allowed_paths, "/v1/responses"));
    REQUIRE(custom->allowed_paths.size() == 2);
    return 0;
}

auto refusals() -> int {
    const auto refused = [](std::string_view name, std::string_view cat, std::string_view models) {
        return !resolve_pi_shared_provider(name, cat, models).has_value();
    };
    // Unknown provider, no data.
    REQUIRE(refused("nowhere", "", ""));
    // Name that could escape the catalog directory.
    REQUIRE(!valid_pi_provider_name("../anthropic"));
    REQUIRE(!valid_pi_provider_name(""));
    REQUIRE(!valid_pi_provider_name("Upper"));
    REQUIRE(valid_pi_provider_name("opencode-go"));
    REQUIRE(refused("../anthropic", catalog("../anthropic", "anthropic-messages", "https://a.b"), ""));
    // Templated, plaintext, loopback, userinfo, query, and dot-segment upstreams.
    for (const std::string_view url : {
             "https://gateway.ai.cloudflare.com/v1/{CLOUDFLARE_ACCOUNT_ID}/x",
             "http://api.example.com/v1",
             "https://127.0.0.1:8081/v1",
             "https://localhost/v1",
             "https://user@api.example.com/v1",
             "https://api.example.com/v1?key=x",
             "https://api.example.com/v1/../admin",
             "https://api.example.com:99999/v1",
         }) {
        REQUIRE(refused("p", catalog("p", "openai-completions", url), ""));
    }
    // More than one base URL (one origin, per-API paths) is not expressible
    // through a single provider baseUrl and is refused.
    REQUIRE(refused(
        "opencode",
        R"({"openai-completions":{"a":{"provider":"opencode","api":"openai-completions",)"
        R"("baseUrl":"https://opencode.ai/inference/openai/v1"}},)"
        R"("anthropic-messages":{"b":{"provider":"opencode","api":"anthropic-messages",)"
        R"("baseUrl":"https://opencode.ai/inference/anthropic"}}})",
        ""
    ));
    // Request-signing and other unsupported API types are refused by name.
    REQUIRE(refused(
        "amazon-bedrock",
        catalog(
            "amazon-bedrock",
            "bedrock-converse-stream",
            "https://bedrock-runtime.us-east-1.amazonaws.com"
        ),
        ""
    ));
    REQUIRE(refused(
        "openai-codex",
        catalog("openai-codex", "openai-codex-responses", "https://chatgpt.com/backend-api"),
        ""
    ));
    // Catalog rows for other providers are ignored.
    REQUIRE(refused("deepseek", catalog("other", "openai-completions", "https://x.example"), ""));
    REQUIRE(refused("deepseek", "{not json", ""));
    return 0;
}

auto secrets() -> int {
    const auto no_env = [](std::string_view) -> std::optional<std::string> { return std::nullopt; };
    const auto env = [](std::string_view name) -> std::optional<std::string> {
        if (name == "RUNINFRA_KEY") {
            return std::string{"env-secret"};
        }
        return std::nullopt;
    };
    auto api_key = pi_shared_provider_secret(
        "deepseek", R"({"deepseek":{"type":"api_key","key":"sk-auth"}})", "", no_env
    );
    REQUIRE(api_key.has_value() && *api_key == "sk-auth");

    // Subscription logins cannot be substituted by a nonce yet.
    auto oauth = pi_shared_provider_secret(
        "openai-codex",
        R"({"openai-codex":{"type":"oauth","access":"a","refresh":"r","expires":1}})",
        "",
        no_env
    );
    REQUIRE(!oauth.has_value());
    REQUIRE(oauth.error().find("subscription") != std::string::npos);

    // models.json fallback: an environment reference or a host literal.
    for (const std::string_view ref : {"$RUNINFRA_KEY", "${RUNINFRA_KEY}"}) {
        auto from_env = pi_shared_provider_secret(
            "runinfra",
            "{}",
            std::string{R"({"providers":{"runinfra":{"apiKey":")"} + std::string{ref} + R"("}}})",
            env
        );
        REQUIRE(from_env.has_value() && *from_env == "env-secret");
    }
    auto literal = pi_shared_provider_secret(
        "runinfra", "", R"({"providers":{"runinfra":{"apiKey":"sk-literal"}}})", no_env
    );
    REQUIRE(literal.has_value() && *literal == "sk-literal");

    // Commands, unset variables, framing bytes, and absence are refused.
    REQUIRE(!pi_shared_provider_secret(
                 "runinfra", "", R"({"providers":{"runinfra":{"apiKey":"!pass x"}}})", env
    )
                 .has_value());
    REQUIRE(!pi_shared_provider_secret(
                 "runinfra", "", R"({"providers":{"runinfra":{"apiKey":"$UNSET"}}})", env
    )
                 .has_value());
    REQUIRE(!pi_shared_provider_secret(
                 "deepseek", R"({"deepseek":{"type":"api_key","key":"a\r\nb"}})", "", no_env
    )
                 .has_value());
    REQUIRE(!pi_shared_provider_secret("deepseek", "{}", "{}", no_env).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    for (const auto step :
         {resolves_three_credential_shapes, models_json_overrides_and_custom_providers, refusals,
          secrets}) {
        if (const int rc = step(); rc != 0) {
            return rc;
        }
    }
    return 0;
}
