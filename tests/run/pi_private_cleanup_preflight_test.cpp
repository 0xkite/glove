#include "pi_private_state.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;

struct fixture {
    fs::path root;

    fixture() {
#if defined(__APPLE__)
        std::string pattern = "/private/tmp/glove-pi-cleanup-preflight-XXXXXX";
#else
        std::string pattern = "/tmp/glove-pi-cleanup-preflight-XXXXXX";
#endif
        if (const auto* created = ::mkdtemp(pattern.data())) {
            root = created;
        }
    }

    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;

    ~fixture() {
        if (!root.empty()) {
            // Exclusive test-owned namespace, never production cleanup authority.
            std::error_code error;
            fs::remove_all(root, error);
        }
    }
};

auto read(const fs::path& path) -> std::string {
    std::ifstream input{path};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

auto same_metadata(const struct stat& before, const struct stat& after) -> bool {
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_uid != after.st_uid || before.st_gid != after.st_gid ||
        before.st_mode != after.st_mode || before.st_nlink != after.st_nlink ||
        before.st_size != after.st_size) {
        return false;
    }
#if defined(__APPLE__)
    return before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    return before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

auto run() -> int {
    fixture f;
    REQUIRE(!f.root.empty());
    const glove::run::detail::pi_guest_config config{
        "{\"providers\":{}}", "{\"extensions\":[],\"skills\":[]}", {}, {}
    };
    auto state = glove::run::detail::pi_private_state::create(f.root, config);
    REQUIRE(state);
    const auto root = state->root();
    const auto lease = root / ".glove-pi-lease";
    const auto lease_before = read(lease);
    // Observe fixed-child traversal order rather than assume alphabetical or
    // insertion order. Adding entries inside children does not reorder root names.
    std::unique_ptr<DIR, decltype(&::closedir)> stream{::opendir(root.c_str()), &::closedir};
    REQUIRE(stream != nullptr);
    std::vector<std::string> children;
    bool enumerated = true;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream.get());
        if (entry == nullptr) {
            enumerated = errno == 0;
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "home" || name == "tmp" || name == "agent" || name == "sessions") {
            children.emplace_back(name);
        }
    }
    const bool closed = ::closedir(stream.release()) == 0;
    REQUIRE(enumerated && closed && children.size() == 4U);
    const auto safe = root / children[0] / "earlier-safe-artifact";
    const auto unsafe = root / children[1] / "later-unsafe-fifo";
    constexpr std::string_view bytes = "fixture-only-sibling\n";
    const int fd = ::open(safe.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0);
    const auto count = ::write(fd, bytes.data(), bytes.size());
    const bool written =
        count == static_cast<ssize_t>(bytes.size()) && ::fchmod(fd, 0644) == 0 && ::fsync(fd) == 0;
    const bool file_closed = ::close(fd) == 0;
    REQUIRE(written && file_closed && ::mkfifo(unsafe.c_str(), 0600) == 0);
    struct stat safe_before{}, unsafe_before{};
    REQUIRE(::lstat(safe.c_str(), &safe_before) == 0);
    REQUIRE(::lstat(unsafe.c_str(), &unsafe_before) == 0 && S_ISFIFO(unsafe_before.st_mode));
    REQUIRE((safe_before.st_mode & 07777U) == 0644U && read(safe) == bytes);
    const auto result = state->cleanup();
    REQUIRE(!result && result.error().find("unsafe/symlink/aliased entry") != std::string::npos);
    struct stat safe_after{}, unsafe_after{};
    REQUIRE(::lstat(safe.c_str(), &safe_after) == 0 && ::lstat(unsafe.c_str(), &unsafe_after) == 0);
    const bool preserved = same_metadata(safe_before, safe_after) &&
                           same_metadata(unsafe_before, unsafe_after) && read(safe) == bytes &&
                           read(lease) == lease_before;
    // Explicit fixture-only repair after capturing the refusal witnesses. No
    // child ran, and removing the injected FIFO lets ordinary cleanup finish.
    REQUIRE(::unlink(unsafe.c_str()) == 0 && state->cleanup());
    REQUIRE(!fs::exists(root));
    if (!preserved) {
        std::fprintf(
            stderr,
            "cleanup refusal changed earlier sibling mode %o -> %o\n",
            static_cast<unsigned>(safe_before.st_mode & 07777U),
            static_cast<unsigned>(safe_after.st_mode & 07777U)
        );
    }
    REQUIRE(preserved);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
