#include "glove/supervisor/change_manifest.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-change-manifest-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

class descriptor {
public:
    explicit descriptor(const std::filesystem::path& path)
        : value_{::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)} {}

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_ = -1;
};

auto run() -> int {
    using namespace glove::supervisor;

    // Fixed-size storage exercises the public string_view boundary without a
    // trailing std::string sentinel. Malformed input must fail closed.
    constexpr std::string_view malformed_manifest =
        "{\"schema_version\":1,\"session_id\":\"session-1\",\"manifest_digest\":\""
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
    std::array<char, malformed_manifest.size()> unterminated{};
    std::ranges::copy(malformed_manifest, unterminated.begin());
    REQUIRE(!decode_retained_change_manifest_json(
                 std::string_view{unterminated.data(), unterminated.size()}
    )
                 .has_value());

    temporary_directory base;
    temporary_directory staged;
    REQUIRE(!base.root().empty());
    REQUIRE(!staged.root().empty());
    std::ofstream{base.root() / "modify.txt"} << "before\n";
    std::ofstream{base.root() / "remove.txt"} << "remove\n";
    std::ofstream{base.root() / "rename.txt"} << "same bytes\n";
    std::filesystem::copy(
        base.root(),
        staged.root(),
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing
    );
    descriptor base_descriptor{base.root()};
    REQUIRE(base_descriptor.get() >= 0);
    auto baseline = snapshot_path_tree(base_descriptor.get(), 1'048'576);
    REQUIRE(baseline.has_value());
    auto unsafe_snapshot = *baseline;
    unsafe_snapshot.front().path = "../escape";
    REQUIRE(!path_snapshot_digest(unsafe_snapshot).has_value());
    auto invalid_mode_snapshot = *baseline;
    invalid_mode_snapshot.front().mode = 01000U;
    REQUIRE(!path_snapshot_digest(invalid_mode_snapshot).has_value());

    std::ofstream{staged.root() / "modify.txt", std::ios::trunc} << "after\n";
    REQUIRE(std::filesystem::remove(staged.root() / "remove.txt"));
    std::filesystem::rename(staged.root() / "rename.txt", staged.root() / "renamed.txt");
    std::ofstream{staged.root() / "create.txt"} << "created\n";
    descriptor staged_descriptor{staged.root()};
    REQUIRE(staged_descriptor.get() >= 0);
    auto current = snapshot_path_tree(staged_descriptor.get(), 1'048'576);
    REQUIRE(current.has_value());
    auto manifest = build_retained_change_manifest(
        "session-1",
        "workspace",
        4,
        std::string(64, 'a'),
        std::string(64, 'b'),
        1'048'576,
        *baseline,
        *current
    );
    REQUIRE(manifest.has_value());
    REQUIRE(manifest->created == 1);
    REQUIRE(manifest->modified == 1);
    REQUIRE(manifest->renamed == 1);
    REQUIRE(manifest->removed == 1);
    REQUIRE(manifest->manifest_digest.size() == 64U);
    REQUIRE(manifest->canonical_json.find("/tmp/") == std::string::npos);
    auto repeated = build_retained_change_manifest(
        "session-1",
        "workspace",
        4,
        std::string(64, 'a'),
        std::string(64, 'b'),
        1'048'576,
        *baseline,
        *current
    );
    REQUIRE(repeated.has_value());
    REQUIRE(repeated->canonical_json == manifest->canonical_json);
    auto decoded = decode_retained_change_manifest_json(manifest->canonical_json);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->manifest_digest == manifest->manifest_digest);

    temporary_directory retained_root;
    const auto stage = retained_root.root() / "glove-retained-s9-session-1-a9-workspace";
    const auto content = stage / "content";
    REQUIRE(std::filesystem::create_directories(content));
    REQUIRE(::chmod(stage.c_str(), 0700) == 0);
    REQUIRE(::chmod(content.c_str(), 0700) == 0);
    std::filesystem::copy(
        staged.root(),
        content,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing
    );
    std::ofstream{stage / "manifest.json"} << manifest->canonical_json;
    const auto retained_root_canonical = std::filesystem::canonical(retained_root.root()).string();
    auto inspected =
        inspect_retained_change_stage(retained_root_canonical, "session-1", "workspace");
    if (!inspected) {
        std::fprintf(stderr, "inspect failed: %s\n", inspected.error().c_str());
    }
    REQUIRE(inspected.has_value());
    REQUIRE(inspected->manifest_digest == manifest->manifest_digest);
    std::ofstream{content / "modify.txt", std::ios::app} << "tamper\n";
    REQUIRE(!inspect_retained_change_stage(retained_root_canonical, "session-1", "workspace")
                 .has_value());

    REQUIRE(::symlink("modify.txt", (staged.root() / "link").c_str()) == 0);
    REQUIRE(!snapshot_path_tree(staged_descriptor.get(), 1'048'576).has_value());
    return 0;
}

} // namespace

int main() {
    return run();
}
