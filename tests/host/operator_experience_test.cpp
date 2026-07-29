#include "glove/host/operator_experience.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

auto run() -> int {
    using namespace glove::host;

    const auto guidance = operator_setup_guidance();
    REQUIRE(guidance.schema_version == 1);
    REQUIRE(!guidance.platform.empty());
#if defined(__APPLE__) || defined(__linux__)
    REQUIRE(guidance.paths.size() == 3U);
    REQUIRE(!guidance.recommended_path.empty());
    std::size_t recommendations = 0;
    for (const auto& path : guidance.paths) {
        REQUIRE(!path.id.empty());
        REQUIRE(!path.goal.empty());
        REQUIRE(!path.isolation.empty());
        REQUIRE(!path.cost.empty());
        REQUIRE(!path.receipts.empty());
        REQUIRE(!path.limitation.empty());
        REQUIRE(!path.next_command.empty());
        if (path.recommended) {
            ++recommendations;
            REQUIRE(path.eligible);
            REQUIRE(path.id == guidance.recommended_path);
        }
    }
    REQUIRE(recommendations == 1U);
#endif

    const auto inspect = defaults_for(project_purpose::inspect);
    REQUIRE(inspect.access == project_access::read);
    REQUIRE(inspect.max_bytes == 0);
    REQUIRE(inspect.ttl_secs == 3'600);

    const auto experiment = defaults_for(project_purpose::experiment);
    REQUIRE(experiment.access == project_access::ephemeral_write);
    REQUIRE(experiment.max_bytes == std::uint64_t{1024} * 1024U * 1024U);
    REQUIRE(experiment.ttl_secs == 3'600);

    const auto retain = defaults_for(project_purpose::retain);
    REQUIRE(retain.access == project_access::retained_write);
    REQUIRE(retain.max_bytes == std::uint64_t{1024} * 1024U * 1024U);
    REQUIRE(retain.ttl_secs == 86'400);

    REQUIRE(parse_project_purpose("inspect") == project_purpose::inspect);
    REQUIRE(parse_project_purpose("experiment") == project_purpose::experiment);
    REQUIRE(parse_project_purpose("retain") == project_purpose::retain);
    REQUIRE(project_purpose_name(project_purpose::retain) == "retain");
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
