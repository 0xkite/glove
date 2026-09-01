#include "adapters/sage/guest_channel.hpp"

#include <cstdio>
#include <optional>
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
    REQUIRE((*binding)->transport_id.empty());
    REQUIRE(!(*binding)->service_alias.has_value());
    REQUIRE(!(*binding)->service_alias_environment.has_value());
    REQUIRE((*binding)->channels->admits("sage.glove-observation.v1") != nullptr);
    auto inherited = glove::adapters::sage::resolve_guest_channel_adapter(
        "sage-observation", "sage.glove-observation.v1", "inherited-stream-v1"
    );
    REQUIRE(inherited.has_value());
    REQUIRE((*inherited)->transport_id == "inherited-stream-v1");
    REQUIRE((*inherited)->service_alias == std::optional<std::string>{"sage-observe"});
    REQUIRE(
        (*inherited)->service_alias_environment ==
        std::optional<std::string>{"GLOVE_GUEST_CHANNEL_SERVICE_ALIAS=sage-observe"}
    );
    REQUIRE(!glove::adapters::sage::resolve_guest_channel_adapter(
                 "sage-observation", "sage.glove-observation.v1", "unknown-v1"
    )
                 .has_value());
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
