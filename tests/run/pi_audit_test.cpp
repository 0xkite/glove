#include "pi_audit.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using glove::run::detail::make_pi_audit_sink;
using glove::run::detail::pi_audit_max_bytes;
using glove::run::detail::pi_audit_max_events;

auto egress_event() -> glove::audit::event {
    glove::audit::event event{};
    event.what = glove::audit::action::egress;
    return event;
}

auto bounds_and_count() -> int {
    REQUIRE(!make_pi_audit_sink(0, pi_audit_max_bytes));
    REQUIRE(!make_pi_audit_sink(pi_audit_max_events + 1U, pi_audit_max_bytes));
    REQUIRE(!make_pi_audit_sink(1, sizeof(glove::audit::event) - 1U));
    REQUIRE(!make_pi_audit_sink(1, pi_audit_max_bytes + 1U));
    auto made = make_pi_audit_sink(3, pi_audit_max_bytes);
    REQUIRE(made);
    const auto event = egress_event();
    for (std::size_t index = 0; index < 3U; ++index) {
        REQUIRE((*made)->record(event));
    }
    for (std::size_t index = 0; index < 3U; ++index) {
        const auto refused = (*made)->record(event);
        REQUIRE(!refused && refused.error() == "Pi audit capacity reached");
    }
    return 0;
}

auto byte_capacity() -> int {
    const auto base = sizeof(glove::audit::event);
    auto made = make_pi_audit_sink(4, 2U * base + 5U);
    REQUIRE(made);
    const glove::audit::event populated{
        .what = glove::audit::action::egress,
        .tool_name = "x",
        .arguments_json = "{}",
        .error_message = "no",
    };
    REQUIRE((*made)->record(populated));
    const auto empty = egress_event();
    REQUIRE((*made)->record(empty));
    REQUIRE(!(*made)->record(empty));

    auto rejected_first = make_pi_audit_sink(4, base + 4U);
    REQUIRE(rejected_first);
    REQUIRE(!(*rejected_first)->record(populated));
    // A refused oversized observation cannot consume count or byte authority.
    REQUIRE((*rejected_first)->record(empty));
    REQUIRE(!(*rejected_first)->record(empty));
    return 0;
}

auto concurrent_capacity() -> int {
    constexpr std::size_t limit = 64U;
    constexpr std::size_t workers = 8U;
    constexpr std::size_t attempts = 10U;
    auto made = make_pi_audit_sink(limit, pi_audit_max_bytes);
    REQUIRE(made);
    std::atomic<std::size_t> accepted{0};
    std::atomic<std::size_t> rejected{0};
    std::atomic<std::size_t> unexpected{0};
    {
        std::vector<std::jthread> threads;
        threads.reserve(workers);
        for (std::size_t worker = 0; worker < workers; ++worker) {
            threads.emplace_back([&, sink = *made]() {
                const auto event = egress_event();
                for (std::size_t index = 0; index < attempts; ++index) {
                    const auto result = sink->record(event);
                    if (result) {
                        accepted.fetch_add(1U, std::memory_order_relaxed);
                    } else if (result.error() == "Pi audit capacity reached") {
                        rejected.fetch_add(1U, std::memory_order_relaxed);
                    } else {
                        unexpected.fetch_add(1U, std::memory_order_relaxed);
                    }
                }
            });
        }
    }
    REQUIRE(accepted.load() == limit);
    REQUIRE(rejected.load() == workers * attempts - limit);
    REQUIRE(unexpected.load() == 0U);
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(bounds_and_count() == 0);
    REQUIRE(byte_capacity() == 0);
    REQUIRE(concurrent_capacity() == 0);
    return 0;
}
