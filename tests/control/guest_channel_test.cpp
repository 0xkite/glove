#include "glove/control/guest_channel.hpp"

#include <atomic>
#include <concepts>
#include <cstdio>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto accepts_observation(const glove::control::glove_observation_body&) noexcept -> bool {
    return true;
}

using body_validator = glove::control::channel_descriptor::body_validator_type;

static_assert(std::is_pointer_v<body_validator>);
static_assert(std::is_nothrow_invocable_r_v<
              bool,
              body_validator,
              const glove::control::glove_observation_body&>);
static_assert(std::is_convertible_v<decltype(&accepts_observation), body_validator>);

constexpr auto capturing_validator = [state = 0](
                                         const glove::control::glove_observation_body&
                                     ) mutable noexcept { return ++state != 0; };
static_assert(!std::is_convertible_v<decltype(capturing_validator), body_validator>);

constexpr auto captureless_validator = [](const glove::control::glove_observation_body&) noexcept {
    return true;
};
static_assert(std::is_convertible_v<decltype(captureless_validator), body_validator>);

template<typename Host>
concept admits_mutable_descriptor = requires(Host& host) {
    host.admits("test.observation.v1")->body_validator = &accepts_observation;
};

static_assert(!admits_mutable_descriptor<glove::control::channel_host>);

static_assert(requires(const glove::control::channel_host& host) {
    {
        host.admits("test.observation.v1")
    } -> std::same_as<const glove::control::channel_descriptor*>;
});

auto descriptor(std::string schema_id) -> glove::control::channel_descriptor {
    return {
        .schema_id = std::move(schema_id),
        .body_validator = &accepts_observation,
        .bounds = {
            .max_items = 4,
            .max_body_bytes = 1'024,
            .max_ttl_ms = 60'000,
            .max_skew_ms = 1'000,
        },
    };
}

} // namespace

int main() {
    glove::control::channel_host empty;
    REQUIRE(empty.empty());
    REQUIRE(empty.size() == 0U);
    REQUIRE(!empty.frozen());
    auto empty_freeze = empty.freeze();
    REQUIRE(!empty_freeze.has_value());
    REQUIRE(!empty.frozen());

    auto missing_schema = descriptor("");
    REQUIRE(!empty.register_channel(std::move(missing_schema)).has_value());
    auto missing_validator = descriptor("test.missing-validator.v1");
    missing_validator.body_validator = {};
    REQUIRE(!empty.register_channel(std::move(missing_validator)).has_value());
    auto invalid_bounds = descriptor("test.invalid-bounds.v1");
    invalid_bounds.bounds.max_items = 0;
    REQUIRE(!empty.register_channel(std::move(invalid_bounds)).has_value());
    REQUIRE(empty.empty());

    REQUIRE(empty.register_channel(descriptor("test.observation.v1")).has_value());
    REQUIRE(!empty.empty());
    REQUIRE(empty.size() == 1U);
    REQUIRE(!empty.register_channel(descriptor("test.observation.v1")).has_value());
    REQUIRE(empty.size() == 1U);
    REQUIRE(empty.freeze().has_value());
    REQUIRE(empty.frozen());
    REQUIRE(empty.freeze().has_value());
    REQUIRE(empty.admits("test.observation.v1") != nullptr);
    REQUIRE(empty.admits("test.unknown.v1") == nullptr);
    REQUIRE(!empty.register_channel(descriptor("test.second.v1")).has_value());
    REQUIRE(empty.size() == 1U);

    const glove::control::channel_host& frozen = empty;
    const glove::control::glove_observation_body body{};
    std::atomic<bool> rejected{false};
    std::vector<std::jthread> readers;
    readers.reserve(8);
    for (std::size_t index = 0; index < 8U; ++index) {
        readers.emplace_back([&] {
            for (std::size_t attempt = 0; attempt < 10'000U; ++attempt) {
                const auto* admitted = frozen.admits("test.observation.v1");
                if (admitted == nullptr || !admitted->body_validator(body)) {
                    rejected.store(true, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    readers.clear();
    REQUIRE(!rejected.load(std::memory_order_relaxed));
    REQUIRE(frozen.size() == 1U);
    return 0;
}
