#include "src/net/tls_peer_identity.hpp"

#include <openssl/x509v3.h>

#include <array>
#include <cstdio>
#include <memory>
#include <utility>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %d\n", #condition, __LINE__);               \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

auto certificate_identity_cases() -> int {
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free
    };
    const std::unique_ptr<X509, decltype(&X509_free)> certificate{X509_new(), X509_free};
    REQUIRE(key && certificate);
    REQUIRE(X509_set_version(certificate.get(), 2) == 1);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60));
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600));
    REQUIRE(X509_set_pubkey(certificate.get(), key.get()) == 1);
    const std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subject{
        X509_NAME_new(), X509_NAME_free
    };
    REQUIRE(subject);
    constexpr unsigned char common_name[] = "fixture.example.test";
    REQUIRE(
        X509_NAME_add_entry_by_txt(subject.get(), "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1
    );
    REQUIRE(X509_set_subject_name(certificate.get(), subject.get()) == 1);
    REQUIRE(X509_set_issuer_name(certificate.get(), subject.get()) == 1);
    const std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> names{
        X509V3_EXT_conf_nid(
            nullptr,
            nullptr,
            NID_subject_alt_name,
            "DNS:peer.example.test,DNS:p*.wild.example.test,IP:127.0.0.1,IP:::1"
        ),
        X509_EXTENSION_free
    };
    REQUIRE(names && X509_add_ext(certificate.get(), names.get(), -1) == 1);
    REQUIRE(X509_sign(certificate.get(), key.get(), nullptr) > 0);

    const std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store{
        X509_STORE_new(), X509_STORE_free
    };
    const std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free
    };
    REQUIRE(store && context);
    REQUIRE(X509_STORE_add_cert(store.get(), certificate.get()) == 1);

    const std::array cases{
        std::pair{"peer.example.test", X509_V_OK},
        std::pair{"other.example.test", X509_V_ERR_HOSTNAME_MISMATCH},
        std::pair{"127.0.0.1", X509_V_OK},
        std::pair{"127.0.0.2", X509_V_ERR_IP_ADDRESS_MISMATCH},
        std::pair{"::1", X509_V_OK},
        std::pair{"::2", X509_V_ERR_IP_ADDRESS_MISMATCH},
        std::pair{"peer.wild.example.test", X509_V_ERR_HOSTNAME_MISMATCH},
    };
    for (const auto& [host, expected_error] : cases) {
        const std::unique_ptr<SSL, decltype(&SSL_free)> ssl{SSL_new(context.get()), SSL_free};
        const std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verification{
            X509_STORE_CTX_new(), X509_STORE_CTX_free
        };
        REQUIRE(ssl && verification);
        SSL_set_hostflags(ssl.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        REQUIRE(glove::net::detail::set_peer_identity(ssl.get(), host) == 1);
        REQUIRE(
            X509_STORE_CTX_init(verification.get(), store.get(), certificate.get(), nullptr) == 1
        );
        auto* parameters = X509_STORE_CTX_get0_param(verification.get());
        REQUIRE(X509_VERIFY_PARAM_set1(parameters, SSL_get0_param(ssl.get())) == 1);
        X509_VERIFY_PARAM_set_depth(parameters, 1);
        REQUIRE(X509_verify_cert(verification.get()) == (expected_error == X509_V_OK ? 1 : 0));
        REQUIRE(X509_STORE_CTX_get_error(verification.get()) == expected_error);
    }
    return 0;
}

} // namespace

auto main() -> int {
    return certificate_identity_cases();
}
