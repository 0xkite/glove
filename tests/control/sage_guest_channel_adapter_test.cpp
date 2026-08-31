#include "adapters/sage/guest_channel.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

} // namespace

int main() {
    auto built = glove::adapters::sage::guest_channel_host();
    REQUIRE(built.has_value());
    REQUIRE(*built != nullptr);
    REQUIRE((*built)->frozen());
    REQUIRE(!(*built)->empty());
    REQUIRE((*built)->size() == 1U);

    const auto* observation = (*built)->admits("sage.glove-observation.v1");
    REQUIRE(observation != nullptr);
    const glove::control::glove_observation_body observation_body{
        .schema = "sage.glove-observation.v1",
        .intent_id = "test-observation",
        .observation = "capability-inventory",
        .value_digest = std::string(64, 'a'),
        .item_count = 4,
    };
    REQUIRE(observation->body_validator(observation_body));

    auto binding = glove::adapters::sage::resolve_guest_channel_adapter(
        "sage-observation", "sage.glove-observation.v1"
    );
    REQUIRE(binding.has_value());
    REQUIRE((*binding)->adapter_id == "sage-observation");
    REQUIRE((*binding)->channel_schema_id == "sage.glove-observation.v1");
    REQUIRE((*binding)->runtime_ids == std::vector<std::string>{"pi"});
    REQUIRE((*binding)->channels->admits("sage.glove-observation.v1") != nullptr);
    REQUIRE(!glove::adapters::sage::resolve_guest_channel_adapter(
                 "unsupported", "sage.glove-observation.v1"
    )
                 .has_value());
    REQUIRE(
        !glove::adapters::sage::resolve_guest_channel_adapter("sage-observation", "arbitrary.v1")
             .has_value()
    );
    return 0;
}
