#pragma once

#include "glove/net/credentialed_endpoint.hpp"

#include "byte_stream.hpp"

#include <cstdint>
#include <expected>
#include <stop_token>
#include <string>
#include <string_view>

namespace glove::net::http {

// How the provider expects its credential. The agent's own credential field
// was already stripped by the endpoint; this is the only one the upstream sees.
enum class credential_scheme : std::uint8_t {
    x_api_key,
    bearer,
};

// Serialise one HTTP/1.1 request in origin form with exactly one Host, an
// explicit Content-Length, `Connection: close`, and the injected credential.
// Every field is revalidated here: this is the last point before bytes reach
// the provider, so it does not trust that the caller sanitised them.
auto serialize_request(const upstream_request& request, credential_scheme scheme)
    -> std::expected<std::string, std::string>;

// Read one final response. Interim 1xx responses are skipped, the body is
// de-framed (chunked, Content-Length, or close-delimited) and capped, and
// redirects are returned as-is rather than followed. `request_method` decides
// whether a body may follow at all.
auto read_response(
    byte_stream& stream,
    std::string_view request_method,
    std::stop_token stop,
    byte_stream::deadline until
) -> std::expected<upstream_response, std::string>;

} // namespace glove::net::http
