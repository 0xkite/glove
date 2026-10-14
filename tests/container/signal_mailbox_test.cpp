#include "signal_mailbox.hpp"

#include <atomic>
#include <cstdio>
#include <latch>
#include <thread>

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto main() -> int {
    glove::container::detail::signal_mailbox mailbox;
    REQUIRE(mailbox.capture() == 0);
    for (int iteration = 0; iteration != 256; ++iteration) {
        REQUIRE(mailbox.arm());
        const auto old = mailbox.capture();
        REQUIRE(old != 0);
        std::latch captured{1}, resume{1};
        std::atomic<bool> published{true};
        std::jthread delayed{[&] {
            captured.count_down();
            resume.wait();
            published.store(mailbox.publish(old, 1));
        }};
        captured.wait();
        mailbox.disarm();
        REQUIRE(mailbox.arm());
        const auto fresh = mailbox.capture();
        REQUIRE(fresh != old);
        resume.count_down();
        delayed.join();
        REQUIRE(!published.load());
        REQUIRE(mailbox.take() == 0);
        REQUIRE(mailbox.publish(fresh, 4));
        REQUIRE(mailbox.publish(fresh, 2));
        REQUIRE(mailbox.take() == 6);
        REQUIRE(mailbox.take() == 0);
        mailbox.disarm();
        REQUIRE(!mailbox.publish(fresh, 8));
    }
    return 0;
}
