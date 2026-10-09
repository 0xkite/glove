#include "glove/container/owned_passthrough.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <stop_token>
#include <string>
#include <thread>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class descriptor {
public:
    explicit descriptor(int fd) noexcept : fd_{fd} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    ~descriptor() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    auto get() const noexcept -> int { return fd_; }

private:
    int fd_;
};

auto run(const std::string& probe) -> int {
    glove::container::profile profile;
    auto normal = glove::container::exec_contained_owned(profile, {probe, "exit", "17"});
    if (!normal) {
        std::fprintf(stderr, "%s\n", normal.error().c_str());
    }
    REQUIRE(normal && *normal == 17);
    int ends[2]{-1, -1};
    REQUIRE(::pipe(ends) == 0);
    descriptor sentinel{ends[0]};
    descriptor writer{ends[1]};
    REQUIRE(sentinel.get() >= 3);
    REQUIRE(::fcntl(sentinel.get(), F_SETFD, 0) == 0);
    struct stat identity{};
    REQUIRE(::fstat(sentinel.get(), &identity) == 0);
    auto isolated = glove::container::exec_contained_owned(
        profile,
        {probe,
         "fd",
         std::to_string(sentinel.get()),
         std::to_string(identity.st_dev),
         std::to_string(identity.st_ino)}
    );
    if (!isolated) {
        std::fprintf(stderr, "%s\n", isolated.error().c_str());
    }
    REQUIRE(isolated && *isolated == 0);
    REQUIRE(!glove::container::exec_contained_owned(profile, {}));
    REQUIRE(!glove::container::exec_contained_owned(profile, {"/missing/glove-fixture-owned"}));
    std::stop_source already_stopped;
    already_stopped.request_stop();
    auto cancelled = glove::container::exec_contained_owned(
        profile, {probe, "exit", "0"}, already_stopped.get_token()
    );
    REQUIRE(cancelled && *cancelled != 0);
    return 0;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        return 2;
    }
    return run(argv[1]);
}
