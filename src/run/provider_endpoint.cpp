#include "provider_endpoint.hpp"

#include "glove/net/tls_forwarder.hpp"

#include <utility>

namespace glove::run::detail {

auto make_provider_endpoint_options(
    provider_surface surface, std::string secret, std::string nonce, provider_event_handler on_event
) -> std::expected<net::credentialed_endpoint_options, std::string> {
    if (secret.empty() || nonce.empty() || secret.find('\0') != std::string::npos ||
        nonce.find('\0') != std::string::npos) {
        return std::unexpected(std::string{"provider endpoint requires host secret and nonce"});
    }
    net::credentialed_endpoint_rule rule;
    switch (surface) {
    case provider_surface::legacy_anthropic:
    case provider_surface::pi_anthropic:
        rule.provider = net::endpoint_provider::anthropic;
        rule.path_prefix = "/anthropic";
        rule.upstream_host = "api.anthropic.com";
        rule.allowed_paths = {"/v1/messages"};
        if (surface == provider_surface::legacy_anthropic) {
            rule.allowed_paths.push_back("/v1/messages/count_tokens");
        }
        break;
    case provider_surface::legacy_openai:
    case provider_surface::pi_openai:
        rule.provider = net::endpoint_provider::openai;
        rule.path_prefix = "/openai";
        rule.upstream_host = "api.openai.com";
        rule.allowed_paths =
            surface == provider_surface::legacy_openai
                ? std::vector<std::string>{"/v1/chat/completions", "/v1/responses", "/v1/models"}
                : std::vector<std::string>{"/v1/responses"};
        break;
    default:
        return std::unexpected(std::string{"unsupported provider endpoint surface"});
    }
    rule.upstream_port = 443;
    rule.secret_token = std::move(secret);
    rule.session_nonce = std::move(nonce);
    rule.allowed_methods = {"POST"};
    net::credentialed_endpoint_options options;
    options.forward = net::make_tls_forwarder({
        .allowed_upstreams = {{rule.upstream_host, 443}},
    });
    options.endpoints.push_back(std::move(rule));
    // The response is buffered through the existing transport. Cover one full
    // bounded generation rather than mistaking a slow stream for a dead peer.
    options.upstream_deadline_ms = 10 * 60 * 1000;
    options.on_event = std::move(on_event);
    return options;
}

} // namespace glove::run::detail
