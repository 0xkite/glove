#include "glove/container/owned_passthrough.hpp"

#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>

namespace {
using namespace std::chrono_literals;
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto scenario(const std::string& probe, const std::string& root, const std::string& mode) -> int {
    const auto marker = root + "/ready";
    std::error_code ec;
    std::filesystem::remove(marker, ec);
    REQUIRE(!ec);
    glove::container::profile profile;
    profile.filesystem = {{root, true}};
    std::vector<std::string> arguments{probe, mode, marker};
    if (mode == "drift") {
        arguments.push_back(std::to_string(::getpgrp()));
    }
    std::stop_source cancellation;
    std::atomic<bool> ready{false};
    std::jthread trigger{[&](std::stop_token stop) {
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (!stop.stop_requested() && std::chrono::steady_clock::now() < deadline) {
            std::error_code error;
            if (std::filesystem::exists(marker, error) && !error) {
                ready.store(true);
                if (mode == "signal") {
                    ::kill(::getpid(), SIGINT);
                } else if (mode != "descendant") {
                    cancellation.request_stop();
                }
                return;
            }
            std::this_thread::sleep_for(5ms);
        }
        cancellation.request_stop();
    }};
    const auto started = std::chrono::steady_clock::now();
    auto result =
        glove::container::exec_contained_owned(profile, arguments, cancellation.get_token(), 50ms);
    trigger.request_stop();
    trigger.join();
    if (!result) {
        std::fprintf(stderr, "owned lifecycle mode=%s: %s\n", mode.c_str(), result.error().c_str());
    }
    REQUIRE(ready.load());
    REQUIRE(result);
    REQUIRE(std::chrono::steady_clock::now() - started < 4s);
    REQUIRE(
        *result == (mode == "descendant" ? 0
                    : mode == "signal"   ? 128 + SIGINT
                                         : 128 + SIGKILL)
    );
    return 0;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        return 2;
    }
    char pattern[] = "/private/tmp/glove-owned-fixture-XXXXXX";
    if (::mkdtemp(pattern) == nullptr) {
        return 2;
    }
    const auto root = std::filesystem::canonical(pattern).string();
    for (const auto* mode : {"stubborn", "drift", "signal", "descendant"}) {
        if (scenario(argv[1], root, mode) != 0) {
            // Leave fixture state on unresolved ownership rather than assuming
            // a failing launcher necessarily finished cleaning up its child.
            std::fprintf(stderr, "fixture retained: %s\n", root.c_str());
            return 1;
        }
    }
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    return ec ? 1 : 0;
}
