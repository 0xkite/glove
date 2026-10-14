#include "provider_endpoint.hpp"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace {
auto check_surface(
    glove::run::detail::provider_surface surface,
    glove::net::endpoint_provider provider,
    const std::string& prefix,
    const std::string& host,
    const std::vector<std::string>& paths
) -> bool {
    bool observed = false;
    auto options = glove::run::detail::make_provider_endpoint_options(
        surface,
        "host-secret-sentinel",
        "glove-session-fixture",
        [&observed](const glove::net::endpoint_event&) -> std::expected<void, std::string> {
            observed = true;
            return std::unexpected(std::string{"audit fixture refusal"});
        }
    );
    if (!options || options->endpoints.size() != 1 || !options->forward || !options->on_event ||
        options->upstream_deadline_ms != 600000) {
        return false;
    }
    const auto& rule = options->endpoints.front();
    if (rule.provider != provider || rule.path_prefix != prefix || rule.upstream_host != host ||
        rule.upstream_port != 443 || rule.allowed_methods != std::vector<std::string>{"POST"} ||
        rule.allowed_paths != paths || rule.secret_token != "host-secret-sentinel" ||
        rule.session_nonce != "glove-session-fixture") {
        return false;
    }
    auto event_result = options->on_event({});
    if (!observed || event_result || event_result.error() != "audit fixture refusal") {
        return false;
    }
    // A wrong upstream must be refused before DNS or socket activity. The test
    // never sends a request to the selected live provider.
    glove::net::upstream_request request;
    request.upstream_host = "fixture.invalid";
    request.upstream_port = 443;
    auto denied =
        options->forward(request, {}, std::chrono::steady_clock::now() + std::chrono::seconds{1});
    return !denied && denied.error() == "upstream not in the forwarder allowlist";
}
} // namespace

auto main() -> int {
    using glove::net::endpoint_provider;
    using glove::run::detail::make_provider_endpoint_options;
    using glove::run::detail::provider_surface;
    if (!check_surface(
            provider_surface::legacy_anthropic,
            endpoint_provider::anthropic,
            "/anthropic",
            "api.anthropic.com",
            {"/v1/messages", "/v1/messages/count_tokens"}
        ) ||
        !check_surface(
            provider_surface::legacy_openai,
            endpoint_provider::openai,
            "/openai",
            "api.openai.com",
            {"/v1/chat/completions", "/v1/responses", "/v1/models"}
        ) ||
        !check_surface(
            provider_surface::pi_anthropic,
            endpoint_provider::anthropic,
            "/anthropic",
            "api.anthropic.com",
            {"/v1/messages"}
        ) ||
        !check_surface(
            provider_surface::pi_openai,
            endpoint_provider::openai,
            "/openai",
            "api.openai.com",
            {"/v1/responses"}
        )) {
        std::fprintf(stderr, "fixed provider surface mismatch\n");
        return 1;
    }
    if (make_provider_endpoint_options(static_cast<provider_surface>(255), "secret", "nonce") ||
        make_provider_endpoint_options(provider_surface::pi_openai, "", "nonce") ||
        make_provider_endpoint_options(provider_surface::pi_openai, "secret", "") ||
        make_provider_endpoint_options(
            provider_surface::pi_openai, std::string{"x\0y", 3}, "nonce"
        ) ||
        make_provider_endpoint_options(
            provider_surface::pi_openai, "secret", std::string{"x\0y", 3}
        )) {
        std::fprintf(stderr, "invalid provider endpoint authority accepted\n");
        return 1;
    }
    return 0;
}
