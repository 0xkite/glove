#include "pi_launch_fixture.hpp"

#include <cstdio>
#include <expected>
#include <memory>
#include <new>
#include <string>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class exit_failure_sink final : public glove::audit::sink {
public:
    auto record(const glove::audit::event& event) -> std::expected<void, std::string> override {
        if (event.what == glove::audit::action::agent_exit) {
            attempted = true;
            throw std::bad_alloc{};
        }
        return {};
    }

    bool attempted = false;
};

auto run() -> int {
    using namespace glove::run::test_support;
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    fixture f{temporary.root() / "exit-audit"};
    REQUIRE(f.prepare() == 0);
    const auto record_before = read_file(f.record());
    const auto audit = std::make_shared<exit_failure_sink>();
    f.context.audit = audit;
    bool escaped = false;
    std::expected<int, std::string> result{0};
    try {
        result = glove::run::detail::launch_pi_with_context(f.request(), f.context);
    } catch (const std::bad_alloc&) {
        escaped = true;
    }
    // execute_owned and endpoint are childless fixtures. This tests typed audit
    // failure and explicit known-quiescent cleanup, not actual group/worker death.
    REQUIRE(audit->attempted && f.observed.executions == 1 && f.observed.starts == 1);
    REQUIRE(!named(f.observed.root) && named_run_count(f.observed.runs) == 0);
    REQUIRE(read_file(f.record()) == record_before);
    if (escaped) {
        std::fprintf(stderr, "exit audit allocation escaped typed launch result\n");
    }
    REQUIRE(!escaped && !result);
    return 0;
}
} // namespace

auto main() -> int {
    return run();
}
