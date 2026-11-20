#pragma once

#include "glove/net/credentialed_endpoint.hpp"
#include "glove/run/pi_provider_share.hpp"

#include <expected>
#include <functional>
#include <string>

namespace glove::run::detail {

// Native API surfaces are independent of the harness startup adapter. Legacy
// routes keep their original ordinals; old Pi names remain compatibility aliases.
enum class provider_surface {
    legacy_anthropic,
    legacy_openai,
    pi_anthropic,
    pi_openai,
    native_anthropic = pi_anthropic,
    native_openai = pi_openai
};

using provider_event_handler =
    std::function<std::expected<void, std::string>(const net::endpoint_event&)>;

// Constructs host-only transport policy; it performs no provider request.
// Credentials and nonces are supplied by the host caller, never child config.
[[nodiscard]] auto make_provider_endpoint_options(
    provider_surface surface,
    std::string secret,
    std::string nonce,
    provider_event_handler on_event = {}
) -> std::expected<net::credentialed_endpoint_options, std::string>;

// One client-placed rule for a Pi provider resolved from Pi's own data: the
// prefix `/p/<name>`, the provider's single upstream origin, and the paths of
// its supported API types. The secret is placed where the client presents
// the nonce, so no provider-specific header knowledge is needed here.
[[nodiscard]] auto make_shared_provider_endpoint_options(
    const pi_shared_provider& provider,
    std::string secret,
    std::string nonce,
    provider_event_handler on_event = {}
) -> std::expected<net::credentialed_endpoint_options, std::string>;

} // namespace glove::run::detail
