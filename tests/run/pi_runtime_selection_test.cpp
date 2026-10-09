#include "glove/run/pi_runtime.hpp"

#include "../../src/host/dependency_command.hpp"
#include "../support/descriptor_acl_fixture.hpp"
#include "pi_admission_environment.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-pi-selection-store-test-XXXXXX";
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

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_file(const std::filesystem::path& path, std::string_view contents, mode_t mode = 0700)
    -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto contents(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path};
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

auto library_case(
    const std::filesystem::path& root,
    const std::filesystem::path& executable,
    const std::filesystem::path& library
) -> int {
    using namespace glove::run;
    const auto source = root / "library-source";
    const auto package = source / "lib" / "node_modules" / "@fixture" / "pi";
    REQUIRE(std::filesystem::create_directories(source / "bin"));
    REQUIRE(std::filesystem::create_directories(package / "bin"));
    REQUIRE(write_file(package / "package.json", "{}\n", 0600));
    REQUIRE(write_file(package / "bin" / "pi", "#!/usr/bin/env node\n"));
    REQUIRE(std::filesystem::copy_file(executable, source / "bin" / "node"));
    REQUIRE(std::filesystem::copy_file(library, source / "lib" / library.filename()));
    std::filesystem::create_symlink(
        std::filesystem::relative(package / "bin" / "pi", source / "bin"), source / "bin" / "pi"
    );
    auto staged = glove::host::stage_runtime_harness({
        .runtime_id = "pi",
        .source_executable = source / "bin" / "pi",
        .protected_directory = root / "protected" / "library-runtime",
        .dry_run = false,
    });
    REQUIRE(staged);
    const pi_runtime_selection selection{
        .model = {.provider = pi_provider::openai, .model = "gpt-5"}, .runtime = *staged
    };
    auto environment = pi_runtime_library_environment(selection);
    REQUIRE(environment && environment->size() == 1U);
    const auto& variable = environment->front();
    REQUIRE(variable.find(staged->read_only_paths.front().string()) != std::string::npos);
    REQUIRE(variable.find(source.string()) == std::string::npos);
    const auto separator = variable.find('=');
    REQUIRE(separator != std::string::npos);
    const auto name = variable.substr(0, separator);
    const auto value = variable.substr(separator + 1);
    // Snapshot allocation precedes mutation; restore on early returns and throws
    // as well as before checking the capture results on the ordinary path.
    glove::run::admission_test_support::environment_scope scoped{{{name, std::nullopt}}};
    REQUIRE(scoped.ok());
    auto without_library = glove::host::detail::capture_dependency_command(
        staged->launch_executable, staged->launch_arguments
    );
    REQUIRE(::setenv(name.c_str(), value.c_str(), 1) == 0);
    auto relocated = glove::host::detail::capture_dependency_command(
        staged->launch_executable, staged->launch_arguments
    );
    REQUIRE(scoped.restore());
    REQUIRE(!without_library);
    if (!relocated) {
        std::fprintf(stderr, "relocated fixture failed: %s\n", relocated.error().c_str());
    }
    REQUIRE(relocated && *relocated == "snapshot-library-ok\n");
    return 0;
}

auto acl_cases(const glove::run::pi_runtime_selection& selection, const std::filesystem::path& path)
    -> int {
#if defined(__APPLE__)
    using namespace glove::run;
    const auto original = contents(path);
    REQUIRE(glove::test::set_fixture_acl(path, false, ACL_EXTENDED_ALLOW, true));
    struct stat info{};
    REQUIRE(::lstat(path.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0600U);
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(contents(path) == original);
    REQUIRE(glove::test::set_fixture_acl(path, false, ACL_EXTENDED_DENY));
    REQUIRE(load_pi_runtime_selection(path));

    const auto lock = std::filesystem::path{path.string() + ".lock"};
    REQUIRE(glove::test::set_fixture_acl(lock, false, ACL_EXTENDED_ALLOW, true));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(glove::test::set_fixture_acl(lock, false, ACL_EXTENDED_DENY));
    REQUIRE(store_pi_runtime_selection(path, selection, true));

    REQUIRE(glove::test::set_fixture_acl(path.parent_path(), true, ACL_EXTENDED_ALLOW, true));
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(glove::test::set_fixture_acl(path.parent_path(), true, ACL_EXTENDED_DENY));
    REQUIRE(load_pi_runtime_selection(path));

    const auto script = std::filesystem::path{selection.runtime.launch_arguments.front()};
    REQUIRE(glove::test::set_fixture_acl(script, false));
    REQUIRE(!glove::host::validate_pi_runtime_harness(selection.runtime));
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(glove::test::set_fixture_acl(script, false, ACL_EXTENDED_ALLOW, true));
    REQUIRE(glove::host::validate_pi_runtime_harness(selection.runtime));
    REQUIRE(glove::test::set_fixture_acl(script.parent_path(), true));
    REQUIRE(!glove::host::validate_pi_runtime_harness(selection.runtime));
    REQUIRE(glove::test::set_fixture_acl(script.parent_path(), true, ACL_EXTENDED_ALLOW, true));
    REQUIRE(glove::host::validate_pi_runtime_harness(selection.runtime));
    REQUIRE(load_pi_runtime_selection(path));

    const auto& alias = selection.runtime.protected_entry_point;
    const auto target = std::filesystem::read_symlink(alias);
    const auto record_bytes = contents(path);
    struct stat record_before{};
    REQUIRE(::lstat(path.c_str(), &record_before) == 0);
    REQUIRE(glove::test::set_fixture_acl(alias, false, ACL_EXTENDED_ALLOW, false, true));
    struct stat alias_before{};
    REQUIRE(::lstat(alias.c_str(), &alias_before) == 0 && S_ISLNK(alias_before.st_mode));
    // The discovery alias is outside the hashed payload. ACL-only drift must
    // refuse both reads and approved stores without repairing either object.
    for (const bool storing : {false, true}) {
        if (storing) {
            REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
        } else {
            REQUIRE(!load_pi_runtime_selection(path));
        }
        struct stat record_after{}, alias_after{};
        REQUIRE(
            ::lstat(path.c_str(), &record_after) == 0 &&
            record_before.st_dev == record_after.st_dev &&
            record_before.st_ino == record_after.st_ino &&
            record_before.st_mode == record_after.st_mode &&
            record_before.st_size == record_after.st_size &&
            record_before.st_mtimespec.tv_sec == record_after.st_mtimespec.tv_sec &&
            record_before.st_mtimespec.tv_nsec == record_after.st_mtimespec.tv_nsec &&
            record_before.st_ctimespec.tv_sec == record_after.st_ctimespec.tv_sec &&
            record_before.st_ctimespec.tv_nsec == record_after.st_ctimespec.tv_nsec
        );
        REQUIRE(contents(path) == record_bytes);
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
    for (const auto tag : {ACL_EXTENDED_ALLOW, ACL_EXTENDED_DENY}) {
        REQUIRE(glove::test::set_fixture_acl(alias, false, tag, tag == ACL_EXTENDED_ALLOW, true));
        REQUIRE(::lstat(alias.c_str(), &alias_before) == 0);
        auto accepted = load_pi_runtime_selection(path);
        REQUIRE(accepted && *accepted && (*accepted)->model == selection.model);
        auto repeated = store_pi_runtime_selection(path, selection, true, true);
        REQUIRE(repeated && !*repeated);
        REQUIRE(contents(path) == record_bytes);
        struct stat alias_after{};
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
#else
    (void)selection;
    (void)path;
#endif
    return 0;
}

auto run(const std::filesystem::path& executable, const std::filesystem::path& library) -> int {
    using namespace glove::run;
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto source = temporary.root() / "source";
    const auto bin = source / "bin";
    const auto package = source / "lib" / "node_modules" / "@fixture" / "pi";
    REQUIRE(std::filesystem::create_directories(bin));
    REQUIRE(std::filesystem::create_directories(package / "bin"));
    REQUIRE(write_file(bin / "node", "#!/bin/sh\nexit 0\n"));
    REQUIRE(write_file(package / "package.json", "{}\n", 0600));
    REQUIRE(write_file(package / "bin" / "pi", "#!/usr/bin/env node\n"));
    std::filesystem::create_symlink(
        std::filesystem::relative(package / "bin" / "pi", bin), bin / "pi"
    );
    REQUIRE(::chmod(source.c_str(), 0770) == 0);
    auto staged = glove::host::stage_runtime_harness({
        .runtime_id = "pi",
        .source_executable = bin / "pi",
        .protected_directory = temporary.root() / "protected" / "runtime",
        .dry_run = false,
    });
    if (!staged) {
        std::fprintf(stderr, "stage failed: %s\n", staged.error().c_str());
    }
    REQUIRE(staged);
    const pi_runtime_selection selection{
        .model = {.provider = pi_provider::openai, .model = "gpt-5"}, .runtime = *staged
    };
    const auto path = temporary.root() / "protected" / "pi-selection.json";
    auto absent = load_pi_runtime_selection(path);
    REQUIRE(absent && !*absent);
    REQUIRE(!store_pi_runtime_selection(path, selection, false));
    REQUIRE(!std::filesystem::exists(path));
    auto stored = store_pi_runtime_selection(path, selection, true);
    if (!stored) {
        std::fprintf(stderr, "store failed: %s\n", stored.error().c_str());
    }
    REQUIRE(stored && *stored);
    auto loaded = load_pi_runtime_selection(path);
    REQUIRE(loaded && *loaded);
    REQUIRE((*loaded)->model == selection.model);
    REQUIRE((*loaded)->runtime.snapshot_digest == staged->snapshot_digest);
    REQUIRE((*loaded)->runtime.launch_executable == staged->launch_executable);
    const auto original = contents(path);
    REQUIRE(!original.empty() && original.back() == '}');
    REQUIRE(original.find("api_key") == std::string::npos);
    REQUIRE(original.find("auth.json") == std::string::npos);
    auto repeated = store_pi_runtime_selection(path, selection, true);
    REQUIRE(repeated && !*repeated);
    auto changed = selection;
    changed.model.model = "gpt-6.1-sol";
    REQUIRE(!store_pi_runtime_selection(path, changed, true));
    REQUIRE(contents(path) == original);
    REQUIRE(!store_pi_runtime_selection(path, changed, false, true));
    auto refreshed = store_pi_runtime_selection(path, changed, true, true);
    REQUIRE(refreshed && *refreshed);
    auto refreshed_load = load_pi_runtime_selection(path);
    REQUIRE(refreshed_load && *refreshed_load);
    REQUIRE((*refreshed_load)->model == changed.model);
    REQUIRE(acl_cases(changed, path) == 0);
    REQUIRE(::chmod(path.c_str(), 0640) == 0);
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(::chmod(path.c_str(), 0600) == 0);
    std::filesystem::create_hard_link(path, path.parent_path() / "linked.json");
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(std::filesystem::remove(path.parent_path() / "linked.json"));
    const auto symlink = path.parent_path() / "alias.json";
    std::filesystem::create_symlink(path, symlink);
    REQUIRE(!load_pi_runtime_selection(symlink));
    REQUIRE(!store_pi_runtime_selection(symlink, selection, true, true));
    const auto fifo = path.parent_path() / "fifo.json";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    REQUIRE(!load_pi_runtime_selection(fifo));
    REQUIRE(!store_pi_runtime_selection(fifo, selection, true, true));
    const auto aliased_parent = temporary.root() / "aliased-parent";
    std::filesystem::create_symlink(path.parent_path(), aliased_parent);
    REQUIRE(!load_pi_runtime_selection(aliased_parent / "pi-selection.json"));
    REQUIRE(!store_pi_runtime_selection(aliased_parent / "new.json", selection, true));
    REQUIRE(::chmod(path.parent_path().c_str(), 0755) == 0);
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(::chmod(path.parent_path().c_str(), 0700) == 0);
    for (const auto& malformed : {
             std::string{"{}"},
             original + " ",
             std::string(524289, 'a'),
             original.substr(0, original.size() - 1) + ",\"api_key\":\"secret\"}",
             original.substr(0, original.size() - 1) + ",\"provider\":\"openai\"}",
         }) {
        REQUIRE(write_file(path, malformed, 0600));
        REQUIRE(!load_pi_runtime_selection(path));
        REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    }
    REQUIRE(write_file(path, original, 0600));
    REQUIRE(write_file(bin / "node", "#!/bin/sh\nexit 1\n"));
    REQUIRE(!load_pi_runtime_selection(path));
    REQUIRE(!store_pi_runtime_selection(path, selection, true, true));
    REQUIRE(write_file(bin / "node", "#!/bin/sh\nexit 0\n"));
    REQUIRE(load_pi_runtime_selection(path));
    REQUIRE(!load_pi_runtime_selection("relative.json"));
    REQUIRE(!load_pi_runtime_selection(path.parent_path() / ".." / "pi-selection.json"));
    auto missing_parent = load_pi_runtime_selection(temporary.root() / "absent" / "selection.json");
    REQUIRE(missing_parent && !*missing_parent);
    REQUIRE(!std::filesystem::exists(temporary.root() / "absent"));
    return library_case(temporary.root(), executable, library);
}

} // namespace

auto main(int argc, char** argv) -> int {
    REQUIRE(argc == 3);
    return run(argv[1], argv[2]);
}
