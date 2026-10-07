#pragma once

#include "glove/net/credentialed_endpoint.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace glove::net {

struct tls_forwarder_options {
    // The only (host, port) pairs this transport will dial. The endpoint already
    // takes the destination from its configured rule; this is a second,
    // independent fence so a misconfigured or future rule cannot widen where a
    // host-held credential is sent.
    std::vector<std::pair<std::string, std::uint16_t>> allowed_upstreams;
};

// The production provider transport for `credentialed_endpoint`: one HTTP/1.1
// exchange per request over a fresh, verified TLS connection using the
// platform's native stack. It injects the provider credential in the field the
// provider expects, follows no redirects, and honours the stop token and
// deadline it is handed.
auto make_tls_forwarder(tls_forwarder_options opts) -> upstream_forwarder;

} // namespace glove::net
