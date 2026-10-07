#include "glove/net/tls_forwarder.hpp"

#include "http1_client.hpp"
#include "http_syntax.hpp"
#include "tls_stream.hpp"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace glove::net {

namespace {

auto scheme_for(endpoint_provider provider) -> std::optional<http::credential_scheme> {
    switch (provider) {
    case endpoint_provider::anthropic:
        return http::credential_scheme::x_api_key;
    case endpoint_provider::openai:
    case endpoint_provider::github:
        return http::credential_scheme::bearer;
    case endpoint_provider::custom:
        // No defined credential field, so nothing safe to inject.
        break;
    }
    return std::nullopt;
}

} // namespace

auto make_tls_forwarder(tls_forwarder_options opts) -> upstream_forwarder {
    for (auto& [host, port] : opts.allowed_upstreams) {
        host = http::lower_ascii(std::move(host));
    }
    return [allowed = std::move(opts.allowed_upstreams)](
               const upstream_request& request,
               std::stop_token stop,
               std::chrono::steady_clock::time_point until
           ) -> std::expected<upstream_response, std::string> {
        const auto host = http::lower_ascii(request.upstream_host);
        // Checked before any resolution or dial: a refused destination never
        // sees a packet, let alone the credential.
        const bool permitted = std::ranges::any_of(allowed, [&](const auto& entry) {
            return entry.first == host && entry.second == request.upstream_port;
        });
        if (!permitted) {
            return std::unexpected(std::string{"upstream not in the forwarder allowlist"});
        }
        const auto scheme = scheme_for(request.provider);
        if (!scheme) {
            return std::unexpected(std::string{"provider has no credential scheme"});
        }
        // Serialise first so a malformed request is refused without a dial.
        auto wire = http::serialize_request(request, *scheme);
        if (!wire) {
            return std::unexpected(wire.error());
        }

        auto stream = connect_tls(host, request.upstream_port, stop, until);
        if (!stream) {
            return std::unexpected(stream.error());
        }
        if (auto sent = (*stream)->write_all(*wire, stop, until); !sent) {
            return std::unexpected(sent.error());
        }
        return http::read_response(**stream, request.method, stop, until);
    };
}

} // namespace glove::net
