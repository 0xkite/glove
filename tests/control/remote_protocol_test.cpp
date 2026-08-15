#include "../../include/glove/control/remote_protocol.hpp"

#include <unistd.h>

#include <array>
#include <chrono>
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

class pipe_pair {
public:
    pipe_pair() {
        std::array<int, 2> descriptors{-1, -1};
        if (::pipe(descriptors.data()) == 0) {
            read_ = descriptors[0];
            write_ = descriptors[1];
        }
    }

    pipe_pair(const pipe_pair&) = delete;
    auto operator=(const pipe_pair&) -> pipe_pair& = delete;

    ~pipe_pair() {
        if (read_ >= 0) {
            (void)::close(read_);
        }
        if (write_ >= 0) {
            (void)::close(write_);
        }
    }

    [[nodiscard]] auto read_end() const noexcept -> int { return read_; }

    [[nodiscard]] auto write_end() const noexcept -> int { return write_; }

private:
    int read_ = -1;
    int write_ = -1;
};

auto run() -> int {
    using namespace glove::control;
    constexpr std::array<remote_method, 10> methods{
        remote_method::remote_health,
        remote_method::remote_prepare,
        remote_method::remote_start,
        remote_method::remote_read,
        remote_method::remote_write_input,
        remote_method::remote_resize,
        remote_method::remote_signal,
        remote_method::remote_stop,
        remote_method::remote_wait,
        remote_method::remote_cleanup,
    };
    for (const auto method : methods) {
        const auto name = remote_method_name(method);
        REQUIRE(!name.empty());
        REQUIRE(parse_remote_method(name) == method);
    }
    REQUIRE(!parse_remote_method("remote_shell").has_value());

    const remote_executor_identity identity{
        .executor_digest = "sha256:" + std::string(64U, 'a'),
        .container_image_digest = "sha256:" + std::string(64U, 'b'),
        .workerd_digest = {},
        .descriptor_digest = {},
    };
    auto health = encode_remote_request("health-1", remote_method::remote_health, 5'000);
    REQUIRE(health.has_value());
    const auto receive_started_at = std::chrono::steady_clock::now();
    const auto received_at = receive_started_at + std::chrono::milliseconds{25};
    auto request_deadline = remote_request_deadline(*health, receive_started_at, received_at);
    REQUIRE(request_deadline.has_value());
    REQUIRE(*request_deadline == received_at + std::chrono::milliseconds{4'975});

    // A frame that consumes its request TTL while arriving is already expired.
    // Synthetic monotonic points keep this regression fast and deterministic.
    auto short_ttl = encode_remote_request("slow-health", remote_method::remote_health, 20);
    REQUIRE(short_ttl.has_value());
    auto expired_during_receive =
        remote_request_deadline(*short_ttl, receive_started_at, received_at);
    REQUIRE(!expired_during_receive.has_value());
    REQUIRE(expired_during_receive.error().find("deadline") != std::string::npos);
    auto health_reply = handle_remote_executor_request(*health, identity);
    REQUIRE(health_reply.has_value());
    auto decoded_health = decode_remote_response(*health_reply);
    REQUIRE(decoded_health.has_value());
    REQUIRE(decoded_health->id == "health-1");
    REQUIRE(decoded_health->status == "not_operational");
    REQUIRE(decoded_health->error_code.empty());
    REQUIRE(decoded_health->executor_digest == identity.executor_digest);
    REQUIRE(decoded_health->container_image_digest == identity.container_image_digest);
    REQUIRE(decoded_health->observation_authority == "trusted_remote_claim");
    REQUIRE(!decoded_health->independently_verified);

    for (const auto method : methods) {
        if (method == remote_method::remote_health) {
            continue;
        }
        auto request = encode_remote_request("lifecycle-1", method, 5'000);
        REQUIRE(request.has_value());
        auto reply = handle_remote_executor_request(*request, identity);
        REQUIRE(reply.has_value());
        auto decoded = decode_remote_response(*reply);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->status.empty());
        REQUIRE(decoded->error_code == "method_not_found");
    }
    REQUIRE(!handle_remote_executor_request(*health, {}).has_value());
    REQUIRE(!encode_remote_request("bad id", remote_method::remote_health, 5'000).has_value());
    REQUIRE(!encode_remote_request("health", remote_method::remote_health, 0).has_value());
    REQUIRE(
        !encode_remote_request("health", remote_method::remote_health, max_remote_deadline_ms + 1U)
             .has_value()
    );
    constexpr std::string_view malformed =
        R"({"jsonrpc":"2.0","id":"x","method":"remote_health","deadline_remaining_ms":1,"payload":null,"extra":true})";
    REQUIRE(!handle_remote_executor_request(malformed, identity).has_value());
    REQUIRE(!remote_request_deadline(malformed, receive_started_at, received_at).has_value());
    REQUIRE(!handle_remote_executor_request(
                 *health,
                 remote_executor_identity{
                     .executor_digest = {},
                     .container_image_digest = {},
                     .workerd_digest = {},
                     .descriptor_digest = {},
                 }
    )
                 .has_value());

    pipe_pair framed;
    REQUIRE(framed.read_end() >= 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE(write_remote_frame(framed.write_end(), *health, deadline).has_value());
    auto read = read_remote_frame(framed.read_end(), deadline);
    REQUIRE(read == health);
    REQUIRE(!write_remote_frame(
                 framed.write_end(), std::string(max_remote_frame_bytes + 1U, 'x'), deadline
    )
                 .has_value());

    pipe_pair oversized;
    const std::array<unsigned char, 4> oversized_header{0x00U, 0x10U, 0x00U, 0x01U};
    REQUIRE(
        ::write(oversized.write_end(), oversized_header.data(), oversized_header.size()) ==
        static_cast<ssize_t>(oversized_header.size())
    );
    REQUIRE(!read_remote_frame(
                 oversized.read_end(), std::chrono::steady_clock::now() + std::chrono::seconds{1}
    )
                 .has_value());

    pipe_pair deadline_pipe;
    const auto started = std::chrono::steady_clock::now();
    auto timed_out =
        read_remote_frame(deadline_pipe.read_end(), started + std::chrono::milliseconds{20});
    REQUIRE(!timed_out.has_value());
    REQUIRE(timed_out.error().find("deadline") != std::string::npos);
    REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds{1});
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
