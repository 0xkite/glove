#pragma once

#include "byte_stream.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <stop_token>
#include <string>

namespace glove::net {

// Open a TLS 1.2+ connection to `host:port` with the platform's native stack
// and trust store: Network.framework on macOS, the system OpenSSL on Linux.
// The peer certificate must chain to a system anchor and match `host` (sent as
// SNI); there is no plaintext fallback and no way to relax verification.
// Errors name the failing phase and never carry request data.
auto connect_tls(
    const std::string& host, std::uint16_t port, std::stop_token stop, byte_stream::deadline until
) -> std::expected<std::unique_ptr<byte_stream>, std::string>;

} // namespace glove::net
