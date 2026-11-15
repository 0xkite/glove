#include "pi_audit.hpp"
#include "pi_launch_fixture.hpp"

#include <cstdio>
#include <expected>
#include <memory>
#include <optional>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using namespace glove::run::test_support;

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    fixture f{temporary.root() / "audit-capacity"};
    REQUIRE(f.prepare() == 0);
    const auto record_before = read_file(f.record());
    f.context.audit.reset();
    std::size_t accepted = 0;
    bool callback_present = false;
    std::optional<std::string> refusal;
    f.context.start_endpoint = [&](glove::net::credentialed_endpoint_options options)
        -> std::expected<std::unique_ptr<glove::net::credentialed_endpoint>, std::string> {
        ++f.observed.starts;
        callback_present = static_cast<bool>(options.on_event);
        if (callback_present) {
            // No listener, forwarder, worker or child. Both allow/deny observations
            // consume the production audit policy through its actual callback.
            for (std::size_t index = 0; index <= glove::run::detail::pi_audit_max_events; ++index) {
                const auto recorded = options.on_event(
                    {.provider = glove::net::endpoint_provider::openai,
                     .method = "POST",
                     .path = "/v1/responses",
                     .allowed = (index % 2U) == 0U,
                     .detail = std::string{host_key}}
                );
                if (!recorded) {
                    refusal = recorded.error();
                    break;
                }
                ++accepted;
            }
        }
        return std::unexpected(std::string{"audit capacity fixture stop"});
    };
    const auto result = glove::run::detail::launch_pi_with_context(f.request(), f.context);
    REQUIRE(!result && result.error() == "audit capacity fixture stop");
    REQUIRE(callback_present && f.observed.starts == 1 && f.observed.executions == 0);
    REQUIRE(!named(f.observed.runs));
    REQUIRE(read_file(f.record()) == record_before && f.audit->take().empty());
    if (!refusal) {
        std::fprintf(
            stderr, "production audit accepted %zu observations without refusal\n", accepted
        );
    }
    REQUIRE(accepted == glove::run::detail::pi_audit_max_events && refusal);
    REQUIRE(*refusal == "Pi audit capacity reached");
    REQUIRE(refusal->find(host_key) == std::string::npos);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
