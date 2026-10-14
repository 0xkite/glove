#include "glove/detail/descriptor_acl.hpp"

#include "../../src/host/snapshot_cleanup.hpp"
#include "../support/descriptor_acl_fixture.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class descriptor {
public:
    explicit descriptor(int value) : value_{value} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    auto get() const -> int { return value_; }

    auto release() noexcept -> int { return std::exchange(value_, -1); }

private:
    int value_;
};

class fixture {
public:
    fixture() {
        std::string pattern = "/tmp/glove-snapshot-cleanup-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data())) {
            root = std::filesystem::canonical(created);
        }
    }

    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;

    ~fixture() {
        std::error_code ignored;
        if (root.empty()) {
            return;
        }
        for (std::filesystem::recursive_directory_iterator it{root, ignored}, end;
             it != end && !ignored;
             it.increment(ignored)) {
            if (std::filesystem::is_directory(it->symlink_status(ignored))) {
                (void)::chmod(it->path().c_str(), 0700);
            }
        }
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

auto write_file(const std::filesystem::path& path) -> bool {
    std::ofstream out{path};
    out << "fixture sentinel\n";
    out.close();
    return out.good() && ::chmod(path.c_str(), 0400) == 0;
}

#if defined(__APPLE__)
struct directory_closer {
    void operator()(DIR* value) const noexcept { (void)::closedir(value); }
};

auto same_fixture_entry(const struct stat& before, const struct stat& after) -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
           before.st_mode == after.st_mode && before.st_nlink == after.st_nlink &&
           before.st_size == after.st_size &&
           before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
}

auto acl_preflight_rejection() -> int {
    using glove::detail::acl_scope;
    using glove::detail::check_descriptor_acl;
    using glove::host::snapshot::remove_owned_staging_tree;
    // Also reject read-only grants on the private parent, but not on content.
    for (int scenario = 0; scenario < 6; ++scenario) {
        fixture temporary;
        REQUIRE(!temporary.root.empty());
        const auto tree = temporary.root / "staging";
        REQUIRE(std::filesystem::create_directories(tree / "first"));
        REQUIRE(std::filesystem::create_directory(tree / "second"));
        REQUIRE(::chmod(tree.c_str(), 0700) == 0);
        for (const auto* name : {"first", "second"}) {
            REQUIRE(write_file(tree / name / "file"));
            REQUIRE(::chmod((tree / name).c_str(), 0500) == 0);
        }
        REQUIRE(::chmod(tree.c_str(), 0500) == 0);
        descriptor parent{
            ::open(temporary.root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        };
        descriptor owned{::open(tree.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        REQUIRE(parent.get() >= 0 && owned.get() >= 0);
        // Select the last actual enumeration entry, rather than assuming lexical
        // order. The earlier sibling must survive discovery of a late unsafe ACE.
        descriptor enumeration{::openat(owned.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
        REQUIRE(enumeration.get() >= 0);
        std::unique_ptr<DIR, directory_closer> stream{::fdopendir(enumeration.get())};
        REQUIRE(stream);
        (void)enumeration.release();
        std::array<std::string, 2> order{};
        std::size_t count = 0;
        while (const auto* entry = ::readdir(stream.get())) {
            const std::string name{entry->d_name};
            if (name != "." && name != "..") {
                REQUIRE(count < order.size());
                order[count++] = name;
            }
        }
        REQUIRE(count == order.size());
        const auto late = tree / order.back();
        if (scenario == 5) {
            REQUIRE(::chmod(late.c_str(), 0700) == 0);
            REQUIRE(::unlink((late / "file").c_str()) == 0);
            const auto target = "../" + order.front() + "/file";
            REQUIRE(::symlink(target.c_str(), (late / "file").c_str()) == 0);
            REQUIRE(::chmod(late.c_str(), 0500) == 0);
        }
        const auto unsafe = scenario == 0 || scenario == 4   ? temporary.root
                            : scenario == 1                  ? tree
                            : scenario == 2 || scenario == 5 ? late / "file"
                                                             : late;
        const bool directory = scenario != 2 && scenario != 5;
        REQUIRE(
            glove::test::set_fixture_acl(
                unsafe, directory, ACL_EXTENDED_ALLOW, scenario == 4, scenario == 5
            )
        );
        descriptor unsafe_fd{::open(
            unsafe.c_str(),
            O_RDONLY | O_CLOEXEC | (scenario == 5 ? O_SYMLINK : O_NOFOLLOW) |
                (directory ? O_DIRECTORY : 0)
        )};
        REQUIRE(unsafe_fd.get() >= 0);
        const auto scope =
            scenario == 0 || scenario == 4 ? acl_scope::owner_private : acl_scope::integrity;
        REQUIRE(!check_descriptor_acl(unsafe_fd.get(), scope));
        const std::array<std::filesystem::path, 6> witnesses{
            temporary.root, tree, tree / order[0], tree / order[0] / "file", late, late / "file"
        };
        std::array<struct stat, 6> before{};
        for (std::size_t index = 0; index < witnesses.size(); ++index) {
            REQUIRE(::lstat(witnesses[index].c_str(), &before[index]) == 0);
        }
        const auto removed = remove_owned_staging_tree(parent.get(), "staging", owned.get());
        REQUIRE(!removed);
        for (std::size_t index = 0; index < witnesses.size(); ++index) {
            struct stat after{};
            REQUIRE(::lstat(witnesses[index].c_str(), &after) == 0);
            REQUIRE(same_fixture_entry(before[index], after));
        }
        for (const auto& name : order) {
            std::ifstream input{tree / name / "file"};
            std::string content;
            REQUIRE(std::getline(input, content) && content == "fixture sentinel");
            REQUIRE(input.peek() == std::ifstream::traits_type::eof());
        }
        REQUIRE(!check_descriptor_acl(unsafe_fd.get(), scope));
        REQUIRE(::fcntl(parent.get(), F_GETFD) >= 0 && ::fcntl(owned.get(), F_GETFD) >= 0);
    }
    return 0;
}

auto acl_compatible_cleanup() -> int {
    using glove::host::snapshot::remove_owned_staging_tree;
    for (const bool read_only : {false, true}) {
        fixture temporary;
        REQUIRE(!temporary.root.empty());
        const auto tree = temporary.root / "staging";
        REQUIRE(std::filesystem::create_directories(tree / "nested"));
        REQUIRE(::chmod(tree.c_str(), 0500) == 0);
        REQUIRE(write_file(tree / "nested" / "file"));
        REQUIRE(::symlink("file", (tree / "nested" / "alias").c_str()) == 0);
        REQUIRE(::chmod((tree / "nested").c_str(), 0500) == 0);
        const auto tag = read_only ? ACL_EXTENDED_ALLOW : ACL_EXTENDED_DENY;
        REQUIRE(glove::test::set_fixture_acl(tree, true, tag, read_only));
        REQUIRE(glove::test::set_fixture_acl(tree / "nested", true, tag, read_only));
        REQUIRE(glove::test::set_fixture_acl(tree / "nested" / "file", false, tag, read_only));
        REQUIRE(
            glove::test::set_fixture_acl(tree / "nested" / "alias", false, tag, read_only, true)
        );
        // Private parent accepts deny-only ACEs, never extra read authority.
        REQUIRE(glove::test::set_fixture_acl(temporary.root, true, ACL_EXTENDED_DENY));
        descriptor parent{
            ::open(temporary.root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        };
        descriptor owned{::open(tree.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        REQUIRE(parent.get() >= 0 && owned.get() >= 0);
        REQUIRE(remove_owned_staging_tree(parent.get(), "staging", owned.get()));
        REQUIRE(!std::filesystem::exists(tree));
        REQUIRE(::fcntl(parent.get(), F_GETFD) >= 0 && ::fcntl(owned.get(), F_GETFD) >= 0);
    }
    return 0;
}
#endif

auto run() -> int {
    using glove::host::snapshot::remove_owned_staging_tree;
    fixture temporary;
    REQUIRE(!temporary.root.empty());
    descriptor parent{
        ::open(temporary.root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    };
    REQUIRE(parent.get() >= 0);
    REQUIRE(::mkdirat(parent.get(), "removed-probe", 0700) == 0);
    descriptor probe{
        ::openat(parent.get(), "removed-probe", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    };
    REQUIRE(probe.get() >= 0);
    struct stat probe_before{};
    struct stat probe_after{};
    REQUIRE(::fstat(probe.get(), &probe_before) == 0);
    REQUIRE(::unlinkat(parent.get(), "removed-probe", AT_REMOVEDIR) == 0);
    REQUIRE(::fstat(probe.get(), &probe_after) == 0);
    REQUIRE(probe_before.st_dev == probe_after.st_dev && probe_before.st_ino == probe_after.st_ino);
#if defined(__APPLE__)
    REQUIRE(probe_after.st_nlink == 0 || probe_after.st_nlink == probe_before.st_nlink);
#else
    REQUIRE(probe_after.st_nlink == 0);
#endif
    REQUIRE(!std::filesystem::exists(temporary.root / "removed-probe"));
    const auto tree = temporary.root / "staging";
    REQUIRE(std::filesystem::create_directories(tree / "payload" / "root-0" / "nested"));
    REQUIRE(::chmod(tree.c_str(), 0700) == 0);
    REQUIRE(write_file(tree / "payload" / "root-0" / "nested" / "file"));
    REQUIRE(write_file(temporary.root / "outside"));
    std::filesystem::create_symlink(temporary.root / "outside", tree / "link");
    for (const auto& item : std::filesystem::recursive_directory_iterator(tree)) {
        if (std::filesystem::is_directory(item.symlink_status())) {
            REQUIRE(::chmod(item.path().c_str(), 0500) == 0);
        }
    }
    REQUIRE(::chmod(tree.c_str(), 0500) == 0);
    descriptor owned{::open(tree.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    REQUIRE(owned.get() >= 0);
    if (::geteuid() != 0) {
        REQUIRE(::chmod(tree.c_str(), 0700) == 0);
        std::error_code legacy_error;
        std::filesystem::remove_all(tree, legacy_error);
        REQUIRE(legacy_error);
        REQUIRE(std::filesystem::exists(tree / "payload" / "root-0" / "nested" / "file"));
        REQUIRE(::chmod(tree.c_str(), 0500) == 0);
    }
    auto removed = remove_owned_staging_tree(parent.get(), "staging", owned.get());
    if (!removed) {
        std::fprintf(stderr, "cleanup failed: %s\n", removed.error().c_str());
    }
    REQUIRE(removed);
    REQUIRE(!std::filesystem::exists(tree));
    REQUIRE(std::filesystem::exists(temporary.root / "outside"));
    REQUIRE(std::filesystem::file_size(temporary.root / "outside") == 17U);
    REQUIRE(::fcntl(parent.get(), F_GETFD) >= 0 && ::fcntl(owned.get(), F_GETFD) >= 0);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", owned.get()));
    REQUIRE(!remove_owned_staging_tree(parent.get(), "../outside", owned.get()));
    REQUIRE(!remove_owned_staging_tree(parent.get(), ".", parent.get()));

    REQUIRE(::mkdir(tree.c_str(), 0700) == 0);
    descriptor original{::open(tree.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    REQUIRE(original.get() >= 0);
    REQUIRE(::rename(tree.c_str(), (temporary.root / "moved").c_str()) == 0);
    REQUIRE(::mkdir(tree.c_str(), 0700) == 0);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", original.get()));
    REQUIRE(std::filesystem::exists(tree) && std::filesystem::exists(temporary.root / "moved"));
    REQUIRE(::rmdir(tree.c_str()) == 0);
    std::filesystem::create_symlink(temporary.root / "moved", tree);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", original.get()));
    REQUIRE(::unlink(tree.c_str()) == 0);
    REQUIRE(::rename((temporary.root / "moved").c_str(), tree.c_str()) == 0);
    REQUIRE(::chmod(tree.c_str(), 0770) == 0);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", original.get()));
    REQUIRE(::chmod(tree.c_str(), 0700) == 0);
    REQUIRE(::mkfifo((tree / "fifo").c_str(), 0600) == 0);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", original.get()));
    REQUIRE(::unlink((tree / "fifo").c_str()) == 0);
    REQUIRE(::link((temporary.root / "outside").c_str(), (tree / "hardlink").c_str()) == 0);
    REQUIRE(!remove_owned_staging_tree(parent.get(), "staging", original.get()));
    REQUIRE(::unlink((tree / "hardlink").c_str()) == 0);
    REQUIRE(remove_owned_staging_tree(parent.get(), "staging", original.get()));
    return 0;
}
} // namespace

auto main() -> int {
#if defined(__APPLE__)
    if (acl_preflight_rejection() != 0 || acl_compatible_cleanup() != 0) {
        return 1;
    }
#endif
    return run();
}
