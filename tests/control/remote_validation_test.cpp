#include "glove/control/remote_validation.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

[[nodiscard]] auto base_binding(std::string key) -> glove::control::remote_operation_binding {
    return {
        .session_id = "validation-session",
        .session_epoch = "00112233445566778899aabbccddeeff",
        .descriptor_digest = "sha256:" + std::string(64U, 'd'),
        .idempotency_key = std::move(key),
        .payload_digest = {},
    };
}

template<typename Payload>
[[nodiscard]] auto bind(glove::control::remote_method method, Payload payload)
    -> std::expected<glove::control::remote_validation_payload, std::string> {
    return glove::control::bind_remote_validation_payload(
        method, glove::control::remote_validation_payload{std::move(payload)}
    );
}

} // namespace

auto main() -> int {
    using namespace glove::control;
    std::array<std::pair<remote_method, remote_validation_payload>, 6> payloads{
        std::pair{
            remote_method::remote_prepare,
            remote_validation_payload{remote_prepare_payload{.binding = base_binding("prepare")}},
        },
        std::pair{
            remote_method::remote_start,
            remote_validation_payload{remote_start_payload{.binding = base_binding("start")}},
        },
        std::pair{
            remote_method::remote_read,
            remote_validation_payload{
                remote_read_payload{.binding = base_binding("read"), .cursor = 7, .max_bytes = 1024}
            },
        },
        std::pair{
            remote_method::remote_wait,
            remote_validation_payload{remote_wait_payload{.binding = base_binding("wait")}},
        },
        std::pair{
            remote_method::remote_stop,
            remote_validation_payload{remote_stop_payload{.binding = base_binding("stop")}},
        },
        std::pair{
            remote_method::remote_cleanup,
            remote_validation_payload{remote_cleanup_payload{.binding = base_binding("cleanup")}},
        },
    };

    for (auto& [method, payload] : payloads) {
        auto bound = bind_remote_validation_payload(method, std::move(payload));
        REQUIRE(bound.has_value());
        auto encoded = encode_remote_validation_request("request-1", method, 2'000, *bound);
        REQUIRE(encoded.has_value());
        auto encoded_again = encode_remote_validation_request("request-1", method, 2'000, *bound);
        REQUIRE(encoded_again == encoded);
        auto decoded = decode_remote_validation_request(*encoded);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->id == "request-1");
        REQUIRE(decoded->method == method);
        REQUIRE(decoded->remaining_ttl_ms == 2'000);
        REQUIRE(decoded->payload == *bound);
    }

    auto read = bind(
        remote_method::remote_read,
        remote_read_payload{
            .binding = base_binding("bounded-read"),
            .cursor = 0,
            .max_bytes = max_remote_validation_read_bytes + 1U,
        }
    );
    REQUIRE(!read.has_value());

    auto prepared = bind(
        remote_method::remote_prepare, remote_prepare_payload{.binding = base_binding("tamper")}
    );
    REQUIRE(prepared.has_value());
    auto encoded =
        encode_remote_validation_request("tamper", remote_method::remote_prepare, 2'000, *prepared);
    REQUIRE(encoded.has_value());
    auto tampered = *encoded;
    const auto session = tampered.find("validation-session");
    REQUIRE(session != std::string::npos);
    tampered.replace(session, std::string_view{"validation-session"}.size(), "validation-sessioN");
    REQUIRE(!decode_remote_validation_request(tampered).has_value());

    auto arbitrary = *encoded;
    const auto payload_end = arbitrary.rfind('}');
    REQUIRE(payload_end != std::string::npos);
    arbitrary.insert(payload_end, R"(,"environment":{"HOME":"/root"})");
    REQUIRE(!decode_remote_validation_request(arbitrary).has_value());

    auto wrong_method =
        encode_remote_validation_request("mismatch", remote_method::remote_start, 2'000, *prepared);
    REQUIRE(!wrong_method.has_value());

    auto invalid_epoch = bind(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding = {
                .session_id = "session",
                .session_epoch = "not-an-owner-epoch",
                .descriptor_digest = "sha256:" + std::string(64U, 'd'),
                .idempotency_key = "key",
                .payload_digest = {},
            }
        }
    );
    REQUIRE(!invalid_epoch.has_value());
    return 0;
}
