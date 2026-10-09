#include "../support/descriptor_acl_fixture.hpp"
#include "pi_catalog.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

constexpr std::string_view openai_bytes = "{\"fixture\":\"openai\"}\n";
constexpr std::string_view anthropic_bytes = "{\"fixture\":\"anthropic\"}\n";
constexpr std::string_view catalog_suffix =
    "node_modules/@earendil-works/pi-ai/dist/providers/data";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-pi-catalog-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = std::filesystem::canonical(created);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        if (!root_.empty()) {
            for (const auto& entry :
                 std::filesystem::recursive_directory_iterator(root_, ignored)) {
                if (std::filesystem::is_directory(entry.symlink_status(ignored))) {
                    std::filesystem::permissions(
                        entry.path(),
                        std::filesystem::perms::owner_write,
                        std::filesystem::perm_options::add,
                        ignored
                    );
                }
            }
            std::filesystem::remove_all(root_, ignored);
        }
    }

    auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_file(const std::filesystem::path& path, std::string_view contents, mode_t mode = 0600)
    -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

struct fixture {
    std::filesystem::path root;

    auto source() const -> std::filesystem::path { return root / "source"; }

    auto package() const -> std::filesystem::path {
        return source() / "lib/node_modules/@fixture/pi";
    }

    auto catalogs() const -> std::filesystem::path { return package() / catalog_suffix; }

    auto prepare() const -> bool {
        std::filesystem::create_directories(source() / "bin");
        std::filesystem::create_directories(package() / "bin");
        std::filesystem::create_directories(catalogs());
        if (!write_file(source() / "bin/node", "#!/bin/sh\nexit 0\n", 0700) ||
            !write_file(package() / "bin/pi", "#!/usr/bin/env node\n", 0700) ||
            !write_file(package() / "package.json", "{}\n") ||
            !write_file(catalogs() / "openai.json", openai_bytes) ||
            !write_file(catalogs() / "anthropic.json", anthropic_bytes)) {
            return false;
        }
        std::filesystem::create_symlink(
            std::filesystem::relative(package() / "bin/pi", source() / "bin"), source() / "bin/pi"
        );
        return ::chmod(source().c_str(), 0770) == 0;
    }

    auto stage() const -> glove::host::result<glove::host::staged_runtime_harness> {
        // Both executables are script fixtures. Closure derivation needs no
        // dependency command, actual Node installation, or harness execution.
        return glove::host::stage_runtime_harness({
            .runtime_id = "pi",
            .source_executable = source() / "bin/pi",
            .protected_directory = root / "protected/runtime",
            .dry_run = false,
        });
    }
};

auto selection_for(const glove::host::staged_runtime_harness& runtime)
    -> glove::run::pi_runtime_selection {
    return {
        .model = {.provider = glove::run::pi_provider::openai, .model = "fixture"},
        .runtime = runtime
    };
}

auto basic_cases(const std::filesystem::path& root) -> int {
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    fixture input{root / "basic"};
    REQUIRE(input.prepare());
    auto staged = input.stage();
    if (!staged) {
        std::fprintf(stderr, "fixture stage failed: %s\n", staged.error().c_str());
    }
    REQUIRE(staged);
    const auto selection = selection_for(*staged);
    auto openai = load_pi_builtin_catalog(selection, pi_provider::openai);
    auto anthropic = load_pi_builtin_catalog(selection, pi_provider::anthropic);
    REQUIRE(openai && *openai == openai_bytes);
    // Explicit catalog provider intentionally differs from the saved model.
    REQUIRE(anthropic && *anthropic == anthropic_bytes);
    REQUIRE(!load_pi_builtin_catalog(selection, static_cast<pi_provider>(99)));
    auto wrong = selection;
    wrong.runtime.runtime_id = "claude";
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));
    wrong = selection;
    wrong.runtime.snapshot_digest[0] = wrong.runtime.snapshot_digest[0] == 'a' ? 'b' : 'a';
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));
    wrong = selection;
    wrong.runtime.adoption_manifest_digest.assign(64U, '0');
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));
    wrong = selection;
    wrong.runtime.launch_arguments = {(input.package() / "bin/pi").string()};
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));
    wrong = selection;
    wrong.runtime.read_only_paths.push_back(input.package());
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));
    wrong = selection;
    wrong.runtime.read_only_paths = {input.package()};
    REQUIRE(!load_pi_builtin_catalog(wrong, pi_provider::openai));

    const auto copied_package =
        std::filesystem::path{staged->launch_arguments.front()}.parent_path().parent_path();
    const auto copied_catalog = copied_package / catalog_suffix / "openai.json";
    struct stat metadata{};
    REQUIRE(::lstat(copied_catalog.c_str(), &metadata) == 0);
    REQUIRE(S_ISREG(metadata.st_mode) && metadata.st_uid == ::geteuid());
    REQUIRE((metadata.st_mode & 07777U) == 0400U && metadata.st_nlink == 1);
    REQUIRE(::lstat(staged->read_only_paths.front().c_str(), &metadata) == 0);
    REQUIRE((metadata.st_mode & 07777U) == 0500U);
    REQUIRE(::chmod(copied_catalog.c_str(), 0600) == 0);
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(::chmod(copied_catalog.c_str(), 0400) == 0);
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));

    REQUIRE(::chmod(copied_catalog.parent_path().c_str(), 0700) == 0);
    std::filesystem::create_hard_link(copied_catalog, copied_catalog.parent_path() / "hardlink");
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(std::filesystem::remove(copied_catalog.parent_path() / "hardlink"));
    REQUIRE(::chmod(copied_catalog.parent_path().c_str(), 0500) == 0);
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));

    REQUIRE(::chmod(copied_catalog.c_str(), 0600) == 0);
    REQUIRE(write_file(copied_catalog, "snapshot drift\n", 0400));
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(::chmod(copied_catalog.c_str(), 0600) == 0);
    REQUIRE(write_file(copied_catalog, openai_bytes, 0400));
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(write_file(input.catalogs() / "openai.json", "source drift\n"));
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(write_file(input.catalogs() / "openai.json", openai_bytes));
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(write_file(input.source() / "bin/node", "#!/bin/sh\nexit 1\n", 0700));
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(write_file(input.source() / "bin/node", "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));

    REQUIRE(std::filesystem::remove(staged->protected_entry_point));
    std::filesystem::create_symlink(input.package() / "bin/pi", staged->protected_entry_point);
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    return 0;
}

auto acl_cases(const std::filesystem::path& root) -> int {
#if defined(__APPLE__)
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    fixture input{root / "acl"};
    REQUIRE(input.prepare());
    auto staged = input.stage();
    REQUIRE(staged);
    const auto selection = selection_for(*staged);
    const auto copied_package =
        std::filesystem::path{staged->launch_arguments.front()}.parent_path().parent_path();
    const auto catalog = copied_package / catalog_suffix / "openai.json";
    const auto& alias = staged->protected_entry_point;
    const auto target = std::filesystem::read_symlink(alias);
    REQUIRE(glove::test::set_fixture_acl(alias, false, ACL_EXTENDED_ALLOW, false, true));
    struct stat alias_before{}, alias_after{};
    REQUIRE(::lstat(alias.c_str(), &alias_before) == 0 && S_ISLNK(alias_before.st_mode));
    // Pipeline refusal may occur in the host validator before local catalog
    // resolution; this tests the discovery alias contract, not that local seam.
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(
        ::lstat(alias.c_str(), &alias_after) == 0 && alias_before.st_dev == alias_after.st_dev &&
        alias_before.st_ino == alias_after.st_ino && alias_before.st_mode == alias_after.st_mode &&
        alias_before.st_size == alias_after.st_size &&
        alias_before.st_mtimespec.tv_sec == alias_after.st_mtimespec.tv_sec &&
        alias_before.st_mtimespec.tv_nsec == alias_after.st_mtimespec.tv_nsec &&
        alias_before.st_ctimespec.tv_sec == alias_after.st_ctimespec.tv_sec &&
        alias_before.st_ctimespec.tv_nsec == alias_after.st_ctimespec.tv_nsec
    );
    REQUIRE(std::filesystem::read_symlink(alias) == target);
    for (const auto tag : {ACL_EXTENDED_ALLOW, ACL_EXTENDED_DENY}) {
        REQUIRE(glove::test::set_fixture_acl(alias, false, tag, tag == ACL_EXTENDED_ALLOW, true));
        REQUIRE(::lstat(alias.c_str(), &alias_before) == 0);
        auto accepted = load_pi_builtin_catalog(selection, pi_provider::openai);
        REQUIRE(accepted && *accepted == openai_bytes);
        REQUIRE(
            ::lstat(alias.c_str(), &alias_after) == 0 &&
            alias_before.st_dev == alias_after.st_dev &&
            alias_before.st_ino == alias_after.st_ino &&
            alias_before.st_mode == alias_after.st_mode &&
            alias_before.st_size == alias_after.st_size &&
            alias_before.st_mtimespec.tv_sec == alias_after.st_mtimespec.tv_sec &&
            alias_before.st_mtimespec.tv_nsec == alias_after.st_mtimespec.tv_nsec &&
            alias_before.st_ctimespec.tv_sec == alias_after.st_ctimespec.tv_sec &&
            alias_before.st_ctimespec.tv_nsec == alias_after.st_ctimespec.tv_nsec
        );
        REQUIRE(std::filesystem::read_symlink(alias) == target);
    }
    REQUIRE(glove::test::set_fixture_acl(catalog, false, ACL_EXTENDED_ALLOW, true));
    auto readable = load_pi_builtin_catalog(selection, pi_provider::openai);
    REQUIRE(readable && *readable == openai_bytes);
    REQUIRE(glove::test::set_fixture_acl(catalog, false));
    struct stat info{};
    REQUIRE(::lstat(catalog.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0400U);
    // An ACL-only change need not change content digests or POSIX mode bits.
    // Reject it without repairing the already published snapshot.
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
#else
    (void)root;
#endif
    return 0;
}

auto missing_and_oversize(const std::filesystem::path& root) -> int {
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    for (const bool oversize : {false, true}) {
        fixture input{root / (oversize ? "oversize" : "missing")};
        REQUIRE(input.prepare());
        if (oversize) {
            REQUIRE(write_file(input.catalogs() / "openai.json", std::string(1048577U, 'x')));
        } else {
            REQUIRE(std::filesystem::remove(input.catalogs() / "openai.json"));
        }
        auto staged = input.stage();
        REQUIRE(staged);
        REQUIRE(!load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai));
        auto other = load_pi_builtin_catalog(selection_for(*staged), pi_provider::anthropic);
        REQUIRE(other && *other == anthropic_bytes);
    }
    return 0;
}

auto relative_link_case(const std::filesystem::path& root) -> int {
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    fixture input{root / "relative"};
    REQUIRE(input.prepare());
    REQUIRE(write_file(input.catalogs().parent_path() / "stored-openai.json", openai_bytes));
    REQUIRE(std::filesystem::remove(input.catalogs() / "openai.json"));
    std::filesystem::create_symlink("./../stored-openai.json", input.catalogs() / "openai.json");
    auto staged = input.stage();
    REQUIRE(staged);
    auto bytes = load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai);
    REQUIRE(bytes && *bytes == openai_bytes);
#if defined(__APPLE__)
    const auto copied_package =
        std::filesystem::path{staged->launch_arguments.front()}.parent_path().parent_path();
    const auto copied_link = copied_package / catalog_suffix / "openai.json";
    REQUIRE(glove::test::set_fixture_acl(copied_link, false, ACL_EXTENDED_ALLOW, false, true));
    struct stat before{}, after{};
    REQUIRE(::lstat(copied_link.c_str(), &before) == 0 && S_ISLNK(before.st_mode));
    REQUIRE(!load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai));
    REQUIRE(
        ::lstat(copied_link.c_str(), &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
        before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
        before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    );
    REQUIRE(glove::test::set_fixture_acl(copied_link, false, ACL_EXTENDED_ALLOW, true, true));
    REQUIRE(load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai));
    REQUIRE(glove::test::set_fixture_acl(copied_link, false, ACL_EXTENDED_DENY, false, true));
    REQUIRE(load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai));
#endif
    return 0;
}

auto deep_script_case(const std::filesystem::path& root) -> int {
    fixture input{root / "deep-script"};
    REQUIRE(input.prepare());
    auto directory = input.package();
    // package() already contributes four source-relative directory levels.
    for (std::size_t depth = 0; depth < 123U; ++depth) {
        directory /= "d";
        REQUIRE(std::filesystem::create_directory(directory));
    }
    std::filesystem::rename(input.package() / "bin/pi", directory / "pi");
    REQUIRE(std::filesystem::remove(input.source() / "bin/pi"));
    std::filesystem::create_symlink(
        std::filesystem::relative(directory / "pi", input.source() / "bin"),
        input.source() / "bin/pi"
    );
    auto staged = input.stage();
    if (!staged) {
        std::fprintf(stderr, "deep script stage: %s\n", staged.error().c_str());
    }
    REQUIRE(staged);
    auto catalog = glove::run::detail::load_pi_builtin_catalog(
        selection_for(*staged), glove::run::pi_provider::openai
    );
    REQUIRE(catalog && *catalog == openai_bytes);
    return 0;
}

auto nearest_manifest_case(const std::filesystem::path& root) -> int {
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    fixture input{root / "nearest"};
    REQUIRE(input.prepare());
    const auto inner = input.package() / "bin";
    std::filesystem::create_directories(inner / catalog_suffix);
    REQUIRE(write_file(inner / "package.json", "{}\n"));
    REQUIRE(write_file(inner / catalog_suffix / "openai.json", openai_bytes));
    REQUIRE(write_file(input.catalogs() / "openai.json", "outer package decoy\n"));
    auto staged = input.stage();
    REQUIRE(staged);
    const auto selection = selection_for(*staged);
    auto bytes = load_pi_builtin_catalog(selection, pi_provider::openai);
    REQUIRE(bytes && *bytes == openai_bytes);
    // An outer/source catalog does not substitute for a missing nearest one.
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::anthropic));
    const auto manifest =
        std::filesystem::path{staged->launch_arguments.front()}.parent_path() / "package.json";
    REQUIRE(::chmod(manifest.c_str(), 0600) == 0);
    REQUIRE(!load_pi_builtin_catalog(selection, pi_provider::openai));
    REQUIRE(::chmod(manifest.c_str(), 0400) == 0);
    REQUIRE(load_pi_builtin_catalog(selection, pi_provider::openai));
    return 0;
}

auto unsafe_closure_cases(const std::filesystem::path& root) -> int {
    using glove::run::pi_provider;
    using glove::run::detail::load_pi_builtin_catalog;
    for (const auto* kind : {"absolute", "outside", "dangling", "cycle", "fifo"}) {
        fixture input{root / kind};
        REQUIRE(input.prepare());
        const auto catalog = input.catalogs() / "openai.json";
        REQUIRE(std::filesystem::remove(catalog));
        REQUIRE(write_file(input.root / "outside.json", openai_bytes));
        if (std::string_view{kind} == "fifo") {
            REQUIRE(::mkfifo(catalog.c_str(), 0600) == 0);
        } else if (std::string_view{kind} == "absolute") {
            std::filesystem::create_symlink(input.root / "outside.json", catalog);
        } else if (std::string_view{kind} == "outside") {
            std::filesystem::create_symlink(
                std::filesystem::relative(input.root / "outside.json", catalog.parent_path()),
                catalog
            );
        } else if (std::string_view{kind} == "cycle") {
            std::filesystem::create_symlink("openai.json", catalog);
        } else {
            std::filesystem::create_symlink("absent.json", catalog);
        }
        auto staged = input.stage();
        // Admission may reject an unsafe closure before catalog acquisition;
        // that is not evidence that load_pi_builtin_catalog traversed it.
        if (staged) {
            REQUIRE(!load_pi_builtin_catalog(selection_for(*staged), pi_provider::openai));
        }
    }
    return 0;
}

} // namespace

auto main() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    REQUIRE(basic_cases(temporary.root()) == 0);
    REQUIRE(acl_cases(temporary.root()) == 0);
    REQUIRE(missing_and_oversize(temporary.root()) == 0);
    REQUIRE(relative_link_case(temporary.root()) == 0);
    REQUIRE(deep_script_case(temporary.root()) == 0);
    REQUIRE(nearest_manifest_case(temporary.root()) == 0);
    REQUIRE(unsafe_closure_cases(temporary.root()) == 0);
    return 0;
}
