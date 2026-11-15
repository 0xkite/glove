#pragma once

#include <arpa/inet.h>
#include <openssl/ssl.h>

#include <string>

namespace glove::net::detail {

inline auto set_peer_identity(SSL* ssl, const std::string& host) -> int {
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    in_addr ipv4{};
    in6_addr ipv6{};
    if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1 ||
        ::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        return SSL_set1_ipaddr(ssl, host.c_str());
    }
    return SSL_set1_dnsname(ssl, host.c_str());
#else
    return SSL_set1_host(ssl, host.c_str());
#endif
}

} // namespace glove::net::detail
