#include "glove/host/runtime_policy.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "../../src/host/runtime_snapshot.hpp"
#include "../support/descriptor_acl_fixture.hpp"

#if defined(__APPLE__)
#    include "../../src/container/macos/runtime_filesystem.hpp"
#endif

#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class fixture {
public:
    fixture() {
        std::string pattern = "/tmp/glove-pi-runtime-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root = std::filesystem::canonical(created);
        }
    }

    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;

    ~fixture() {
        std::error_code ignored;
        for (std::filesystem::recursive_directory_iterator iterator{root, ignored}, end;
             iterator != end && !ignored;
             iterator.increment(ignored)) {
            if (iterator->is_directory() && !iterator->is_symlink()) {
                (void)::chmod(iterator->path().c_str(), 0700);
            }
        }
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

auto write_file(const std::filesystem::path& path, std::string_view bytes, mode_t mode = 0700)
    -> bool {
    std::ofstream output{path, std::ios::binary};
    output << bytes;
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto acl_producer_cases(
    const glove::host::runtime_harness_stage_options& options,
    const glove::host::staged_runtime_harness& staged
) -> int {
#if defined(__APPLE__)
    const auto store = options.protected_directory;
    const auto refused_unchanged = [&]() {
        std::map<std::filesystem::path, struct stat> before;
        std::map<std::filesystem::path, std::string> bytes;
        const auto capture = [&](const std::filesystem::path& path) {
            struct stat info{};
            if (::lstat(path.c_str(), &info) != 0) {
                return false;
            }
            before.emplace(path, info);
            if (S_ISREG(info.st_mode)) {
                std::ifstream input{path};
                bytes.emplace(path, std::string{std::istreambuf_iterator<char>{input}, {}});
            }
            return true;
        };
        if (!capture(store)) {
            return false;
        }
        for (const auto& item : std::filesystem::recursive_directory_iterator(store)) {
            if (!capture(item.path())) {
                return false;
            }
        }
        if (glove::host::stage_runtime_harness(options)) {
            return false;
        }
        std::size_t after_count = 1;
        for (const auto& item : std::filesystem::recursive_directory_iterator(store)) {
            if (!before.contains(item.path())) {
                return false;
            }
            ++after_count;
        }
        if (after_count != before.size()) {
            return false;
        }
        for (const auto& [path, saved] : before) {
            struct stat after{};
            if (::lstat(path.c_str(), &after) != 0 || saved.st_dev != after.st_dev ||
                saved.st_ino != after.st_ino || saved.st_uid != after.st_uid ||
                saved.st_gid != after.st_gid || saved.st_mode != after.st_mode ||
                saved.st_nlink != after.st_nlink || saved.st_size != after.st_size ||
                saved.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
                saved.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
                saved.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
                saved.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) {
                return false;
            }
        }
        for (const auto& [path, content] : bytes) {
            std::ifstream input{path};
            if (std::string{std::istreambuf_iterator<char>{input}, {}} != content) {
                return false;
            }
        }
        return true;
    };
    REQUIRE(glove::test::set_fixture_acl(store, true, ACL_EXTENDED_ALLOW, true));
    struct stat mode{};
    REQUIRE(::lstat(store.c_str(), &mode) == 0 && (mode.st_mode & 07777U) == 0700U);
    REQUIRE(refused_unchanged());
    REQUIRE(glove::test::set_fixture_acl(store, true, ACL_EXTENDED_DENY));
    REQUIRE(glove::host::stage_runtime_harness(options));
    const auto snapshots = store / "snapshots";
    REQUIRE(glove::test::set_fixture_acl(snapshots, true));
    REQUIRE(refused_unchanged());
    REQUIRE(glove::test::set_fixture_acl(snapshots, true, ACL_EXTENDED_DENY));
    REQUIRE(glove::host::stage_runtime_harness(options));
    REQUIRE(glove::test::set_fixture_acl(staged.launch_executable, false));
    REQUIRE(refused_unchanged());
    REQUIRE(
        glove::test::set_fixture_acl(staged.launch_executable, false, ACL_EXTENDED_ALLOW, true)
    );
    REQUIRE(glove::host::stage_runtime_harness(options));
    std::filesystem::path copied_link;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(staged.read_only_paths.front())) {
        if (entry.is_symlink()) {
            copied_link = entry.path();
            break;
        }
    }
    REQUIRE(!copied_link.empty());
    REQUIRE(glove::test::set_fixture_acl(copied_link, false, ACL_EXTENDED_ALLOW, false, true));
    REQUIRE(refused_unchanged());
    REQUIRE(glove::test::set_fixture_acl(copied_link, false, ACL_EXTENDED_ALLOW, true, true));
    REQUIRE(glove::host::stage_runtime_harness(options));
    const auto alias = staged.protected_entry_point;
    REQUIRE(glove::test::set_fixture_acl(alias, false, ACL_EXTENDED_ALLOW, false, true));
    const bool validator_refused = !glove::host::validate_pi_runtime_harness(staged);
    const bool reuse_refused = refused_unchanged();
    std::ifstream source_input{options.source_executable};
    const std::string original_script{std::istreambuf_iterator<char>{source_input}, {}};
    REQUIRE(write_file(options.source_executable, "#!/usr/bin/env node\nfixture alias refresh\n"));
    const bool refresh_refused = refused_unchanged();
    REQUIRE(write_file(options.source_executable, original_script));
    if (!validator_refused || !reuse_refused || !refresh_refused) {
        std::fprintf(
            stderr,
            "alias ACL refusal: validator=%d reuse=%d refresh=%d\n",
            validator_refused,
            reuse_refused,
            refresh_refused
        );
    }
    REQUIRE(validator_refused && reuse_refused && refresh_refused);
    REQUIRE(glove::test::set_fixture_acl(alias, false, ACL_EXTENDED_ALLOW, true, true));
    REQUIRE(glove::host::validate_pi_runtime_harness(staged));
    REQUIRE(glove::host::stage_runtime_harness(options));
    REQUIRE(glove::test::set_fixture_acl(alias, false, ACL_EXTENDED_DENY, false, true));
    REQUIRE(glove::host::validate_pi_runtime_harness(staged));
    REQUIRE(glove::host::stage_runtime_harness(options));
    // Existing deny-only parents are compatible; fresh objects get empty ACLs.
    auto fresh_options = options;
    fresh_options.protected_directory = store / "fresh-runtime";
    auto fresh = glove::host::stage_runtime_harness(fresh_options);
    REQUIRE(fresh);
    for (const auto& directory :
         {fresh_options.protected_directory,
          fresh_options.protected_directory / "snapshots",
          fresh->read_only_paths.front().parent_path(),
          fresh->read_only_paths.front()}) {
        REQUIRE(glove::test::fixture_acl_empty(directory, true));
    }
    REQUIRE(glove::test::fixture_acl_empty(fresh->launch_executable, false));
    REQUIRE(glove::test::fixture_acl_empty(fresh->launch_arguments.front(), false));
    auto refused_fresh = options;
    refused_fresh.protected_directory = store.parent_path() / "refused-fresh-runtime";
    REQUIRE(!std::filesystem::exists(refused_fresh.protected_directory));
    REQUIRE(glove::test::set_fixture_acl(store.parent_path(), true));
    REQUIRE(!glove::host::stage_runtime_harness(refused_fresh));
    REQUIRE(!std::filesystem::exists(refused_fresh.protected_directory));
    REQUIRE(glove::test::set_fixture_acl(store.parent_path(), true, ACL_EXTENDED_DENY));
#else
    (void)options;
    (void)staged;
#endif
    return 0;
}

class agent_home_environment {
public:
    agent_home_environment(
        const std::filesystem::path& path,
        bool& restoration_failed,
        const char* variable = "PI_CODING_AGENT_DIR"
    )
        : variable_{variable}, restoration_failed_{restoration_failed} {
        if (const auto* previous = ::getenv(variable_); previous != nullptr) {
            previous_ = previous;
        }
        const auto value = path.string();
        changed_ = ::setenv(variable_, value.c_str(), 1) == 0;
    }

    agent_home_environment(const agent_home_environment&) = delete;
    auto operator=(const agent_home_environment&) -> agent_home_environment& = delete;

    ~agent_home_environment() {
        if (changed_) {
            const auto restored =
                previous_ ? ::setenv(variable_, previous_->c_str(), 1) : ::unsetenv(variable_);
            restoration_failed_ = restored != 0;
        }
    }

    [[nodiscard]] auto changed() const noexcept -> bool { return changed_; }

private:
    std::optional<std::string> previous_;
    const char* variable_;
    bool& restoration_failed_;
    bool changed_ = false;
};

auto co_located_operator_state_case() -> int {
    fixture temporary;
    REQUIRE(!temporary.root.empty());
    const auto state = temporary.root / "operator-home" / ".pi" / "agent";
    REQUIRE(std::filesystem::create_directories(state / "bin"));
    REQUIRE(std::filesystem::create_directories(state / "package" / "bin"));
    const auto node = state / "bin" / "node";
    const auto script = state / "package" / "bin" / "pi";
    const auto entry = state / "bin" / "pi";
    const auto auth = state / "auth.json";
    constexpr std::string_view credential = "fixture-only-co-located-credential\n";
    REQUIRE(write_file(node, "fixture node bytes\n"));
    REQUIRE(write_file(script, "#!/usr/bin/env node\nfixture pi bytes\n"));
    REQUIRE(write_file(state / "package" / "package.json", "{}\n", 0600));
    REQUIRE(write_file(auth, credential, 0600));
    REQUIRE(::symlink("../package/bin/pi", entry.c_str()) == 0);
    const auto account_home = temporary.root / "operator-home";
    const std::array roots{state};
    REQUIRE(!glove::host::snapshot::validate_pi_source_exclusions(roots, account_home));
    const auto alias_home = temporary.root / "alias-home";
    REQUIRE(std::filesystem::create_directory(alias_home));
    REQUIRE(::symlink(state.c_str(), (alias_home / ".pi").c_str()) == 0);
    REQUIRE(!glove::host::snapshot::validate_pi_source_exclusions(roots, alias_home));
    std::error_code case_error;
    const auto case_root = account_home / ".PI" / "agent";
    if (std::filesystem::equivalent(case_root, state, case_error) && !case_error) {
        REQUIRE(!glove::host::snapshot::validate_pi_source_exclusions(
            std::array{case_root}, account_home
        ));
    }
    glove::host::runtime_harness_stage_options options{
        .runtime_id = "pi",
        .source_executable = entry,
        .protected_directory = temporary.root / "initial-store",
    };
    // Ordinary resources named auth.json are not globally stripped. Only an
    // identified operator-state authority makes this otherwise bounded closure unsafe.
    auto staged = glove::host::stage_runtime_harness(options);
    REQUIRE(staged);
    REQUIRE(glove::host::validate_pi_runtime_harness(*staged));
    REQUIRE(staged->source_read_only_paths == std::vector<std::filesystem::path>{state});
    std::ifstream copied{staged->read_only_paths.front() / "root-0" / "auth.json"};
    const std::string copied_bytes{std::istreambuf_iterator<char>{copied}, {}};
    REQUIRE(copied_bytes == credential);
    struct stat before{};
    REQUIRE(::lstat(auth.c_str(), &before) == 0);
    options.protected_directory = temporary.root / "refused-store";
    for (const auto* variable : {"PI_CODING_AGENT_DIR", "HOME"}) {
        bool restoration_failed = false;
        bool changed = false;
        bool consumer_refused = false;
        bool producer_refused = false;
        bool output_absent = false;
        {
            agent_home_environment environment{
                std::string_view{variable} == "HOME" ? account_home : state,
                restoration_failed,
                variable
            };
            changed = environment.changed();
            if (changed) {
                consumer_refused = !glove::host::validate_pi_runtime_harness(*staged);
                producer_refused = !glove::host::stage_runtime_harness(options);
                output_absent = !std::filesystem::exists(options.protected_directory);
            }
        }
        struct stat after{};
        REQUIRE(::lstat(auth.c_str(), &after) == 0);
        std::ifstream original{auth};
        const std::string original_bytes{std::istreambuf_iterator<char>{original}, {}};
        REQUIRE(!restoration_failed && changed);
        REQUIRE(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
        REQUIRE(before.st_uid == after.st_uid && before.st_gid == after.st_gid);
        REQUIRE(before.st_mode == after.st_mode && before.st_nlink == after.st_nlink);
        REQUIRE(before.st_size == after.st_size && original_bytes == credential);
#if defined(__APPLE__)
        REQUIRE(
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
            before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
        );
        REQUIRE(
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
            before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
        );
#else
        REQUIRE(
            before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
            before.st_mtim.tv_nsec == after.st_mtim.tv_nsec
        );
        REQUIRE(
            before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
            before.st_ctim.tv_nsec == after.st_ctim.tv_nsec
        );
#endif
        if (!consumer_refused || !producer_refused || !output_absent) {
            std::fprintf(
                stderr,
                "co-located state (%s): consumer=%d producer=%d absent=%d\n",
                variable,
                consumer_refused,
                producer_refused,
                output_absent
            );
        }
        REQUIRE(consumer_refused && producer_refused && output_absent);
        REQUIRE(glove::host::validate_pi_runtime_harness(*staged));
    }
    return 0;
}

auto entry_budget_boundary_case() -> int {
    glove::host::snapshot::snapshot_tree_budget budget;
    for (std::size_t entry = 0; entry < 200'000U; ++entry) {
        REQUIRE(budget.admit(false));
    }
    REQUIRE(!budget.admit(false));
    for (std::size_t wrapper = 0; wrapper < 65U; ++wrapper) {
        REQUIRE(budget.admit(true));
    }
    REQUIRE(!budget.admit(true));
    REQUIRE(!budget.admit(false));
    return 0;
}

auto depth_boundary_case() -> int {
    fixture temporary;
    REQUIRE(!temporary.root.empty());
    const auto source = temporary.root / "source";
    REQUIRE(std::filesystem::create_directories(source / "bin"));
    REQUIRE(std::filesystem::create_directories(source / "package" / "bin"));
    REQUIRE(write_file(source / "bin" / "node", "fixture node bytes\n"));
    REQUIRE(write_file(source / "package" / "package.json", "{}\n", 0600));
    REQUIRE(write_file(source / "package" / "bin" / "pi", "#!/usr/bin/env node\nfixture\n"));
    REQUIRE(::symlink("../package/bin/pi", (source / "bin" / "pi").c_str()) == 0);
    auto directory = source;
    for (std::size_t depth = 0; depth < 128U; ++depth) {
        directory /= "d";
        REQUIRE(std::filesystem::create_directory(directory));
    }
    const glove::host::runtime_harness_stage_options options{
        .runtime_id = "pi",
        .source_executable = source / "bin" / "pi",
        .protected_directory = temporary.root / "runtime",
    };
    auto first = glove::host::stage_runtime_harness(options);
    if (!first) {
        std::fprintf(stderr, "depth boundary stage: %s\n", first.error().c_str());
    }
    REQUIRE(first);
    REQUIRE(glove::host::validate_pi_runtime_harness(*first));
#if defined(__APPLE__)
    const auto admitted = glove::container::macos_detail::validate_runtime_filesystem(
        {{.path = first->read_only_paths.front().string(), .writable = false}}
    );
    if (!admitted) {
        std::fprintf(stderr, "depth boundary native: %s\n", admitted.error().c_str());
    }
    REQUIRE(admitted);
#endif
    auto reused = glove::host::stage_runtime_harness(options);
    REQUIRE(reused && !reused->changed && reused->snapshot_digest == first->snapshot_digest);
    return 0;
}

auto run() -> int {
    using namespace glove::host;
    REQUIRE(entry_budget_boundary_case() == 0);
    REQUIRE(depth_boundary_case() == 0);
    REQUIRE(co_located_operator_state_case() == 0);
    fixture temporary;
    REQUIRE(!temporary.root.empty());
    const auto installation = temporary.root / "installation";
    const auto bin = installation / "bin";
    const auto package = installation / "package";
    REQUIRE(std::filesystem::create_directories(bin));
    REQUIRE(std::filesystem::create_directories(package / "bin"));
    REQUIRE(std::filesystem::create_directories(package / "build" / "Release"));
    REQUIRE(std::filesystem::create_directories(package / "resources"));
    REQUIRE(
        write_file(package / "build" / "Release" / "addon.node", "fixture addon bytes\n", 0600)
    );
    REQUIRE(write_file(package / "resources" / "prompt.md", "fixture package resource\n", 0600));
    const auto host_state = temporary.root / "operator-home" / ".pi" / "agent";
    REQUIRE(std::filesystem::create_directories(host_state));
    REQUIRE(write_file(host_state / "auth.json", "fixture-only-operator-credential\n", 0600));
    REQUIRE(write_file(host_state / "settings.json", "fixture-only-operator-settings\n", 0600));
    const auto node = bin / "node";
    const auto script = package / "bin" / "pi";
    const auto entry = bin / "pi";
    REQUIRE(write_file(node, "fixture node bytes\n"));
    REQUIRE(write_file(package / "package.json", "{}\n", 0600));
    REQUIRE(write_file(script, "#!/usr/bin/env node\nfixture pi bytes\n"));
    REQUIRE(::symlink("../package/bin/pi", entry.c_str()) == 0);
    // Unsafe discovery directories must be copied, not rejected as launch authority.
    REQUIRE(::chmod(installation.c_str(), 0770) == 0);
    const auto store = temporary.root / "protected" / "pi";
    runtime_harness_stage_options options{
        .runtime_id = "pi",
        .source_executable = entry,
        .protected_directory = store,
    };
    auto staged = stage_runtime_harness(options);
    if (!staged) {
        std::fprintf(stderr, "stage: %s\n", staged.error().c_str());
    }
    REQUIRE(staged);
    REQUIRE(staged->canonical_source_executable == script);
    REQUIRE(staged->source_launch_executable == node);
    REQUIRE(staged->source_read_only_paths == std::vector<std::filesystem::path>{installation});
    REQUIRE(validate_pi_runtime_harness(*staged));
    REQUIRE(acl_producer_cases(options, *staged) == 0);
    bool copied_addon = false;
    bool copied_resource = false;
    for (const auto& item :
         std::filesystem::recursive_directory_iterator(staged->read_only_paths.front())) {
        REQUIRE(item.path().filename() != "auth.json" && item.path().filename() != "settings.json");
        if (std::filesystem::is_regular_file(item.symlink_status())) {
            std::ifstream input{item.path(), std::ios::binary};
            const std::string bytes{
                std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}
            };
            REQUIRE(bytes.find("fixture-only-operator-") == std::string::npos);
            copied_addon = copied_addon || bytes == "fixture addon bytes\n";
            copied_resource = copied_resource || bytes == "fixture package resource\n";
        }
    }
    REQUIRE(copied_addon && copied_resource);

    const auto rejects = [&](auto mutate) {
        auto candidate = *staged;
        mutate(candidate);
        return !validate_pi_runtime_harness(candidate);
    };
    REQUIRE(rejects([](auto& value) { value.runtime_id = "codex"; }));
    REQUIRE(rejects([](auto& value) { value.executable_name = "node"; }));
    REQUIRE(rejects([](auto& value) { value.snapshot_digest.clear(); }));
    REQUIRE(rejects([](auto& value) { value.snapshot_digest.assign(64, 'A'); }));
    REQUIRE(rejects([](auto& value) { value.adoption_manifest_digest.assign(64, '0'); }));
    REQUIRE(rejects([](auto& value) { value.launch_arguments.push_back("--eval"); }));
    REQUIRE(rejects([&](auto& value) { value.launch_executable = node; }));
    REQUIRE(rejects([&](auto& value) { value.launch_arguments = {script.string()}; }));
    REQUIRE(rejects([](auto& value) { value.source_read_only_paths.clear(); }));
    REQUIRE(rejects([&](auto& value) { value.source_read_only_paths.assign(65U, installation); }));
    REQUIRE(rejects([&](auto& value) { value.source_read_only_paths = {installation, package}; }));
    REQUIRE(rejects([&](auto& value) { value.canonical_source_executable = entry; }));
    REQUIRE(rejects([](auto& value) { value.adoption_manifest_digest.clear(); }));
    REQUIRE(rejects([](auto& value) { ++value.snapshot_entries; }));
    REQUIRE(rejects([](auto& value) { ++value.snapshot_logical_bytes; }));
    REQUIRE(rejects([&](auto& value) { value.read_only_paths.push_back(installation); }));
    REQUIRE(rejects([](auto& value) { value.source_read_only_paths = {"/opt/homebrew"}; }));
    REQUIRE(rejects([](auto& value) { value.source_read_only_paths = {"/usr/local"}; }));
    REQUIRE(rejects([](auto& value) { value.source_read_only_paths = {"/"}; }));
    REQUIRE(rejects([](auto& value) { value.source_read_only_paths = {"/Users"}; }));
    REQUIRE(rejects([&](auto& value) {
        value.source_read_only_paths = {installation, installation};
    }));
    REQUIRE(rejects([](auto& value) { value.source_executable = std::string{"/tmp/a\0b", 8}; }));
    REQUIRE(rejects([](auto& value) { value.source_executable = "/" + std::string(4096, 'a'); }));
    REQUIRE(rejects([&](auto& value) { value.source_executable = bin / ".." / "bin" / "pi"; }));

    REQUIRE(write_file(script, "#!/usr/bin/env node\nchanged\n"));
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(write_file(script, "#!/usr/bin/env node\nfixture pi bytes\n"));
    REQUIRE(validate_pi_runtime_harness(*staged));
    REQUIRE(write_file(package / "bin" / "replacement", "#!/usr/bin/env node\n"));
    REQUIRE(::unlink(entry.c_str()) == 0);
    REQUIRE(::symlink("../package/bin/replacement", entry.c_str()) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::unlink(entry.c_str()) == 0);
    REQUIRE(::symlink("../package/bin/pi", entry.c_str()) == 0);
    REQUIRE(::unlink((package / "bin" / "replacement").c_str()) == 0);

    const auto alternate_node = temporary.root / "alternate-node";
    REQUIRE(write_file(alternate_node, "fixture node bytes\n"));
    REQUIRE(::unlink(node.c_str()) == 0);
    REQUIRE(::symlink(alternate_node.c_str(), node.c_str()) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::unlink(node.c_str()) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(write_file(node, "fixture node bytes\n"));
    REQUIRE(validate_pi_runtime_harness(*staged));

    const auto payload = staged->read_only_paths.front();
    const auto snapshot_root = payload.parent_path();
    REQUIRE(::chmod(snapshot_root.c_str(), 0700) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::chmod(snapshot_root.c_str(), 0500) == 0);
    REQUIRE(::chmod(staged->launch_executable.c_str(), 0570) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::chmod(staged->launch_executable.c_str(), 0500) == 0);
    REQUIRE(::chmod(staged->launch_executable.c_str(), 0700) == 0);
    REQUIRE(write_file(staged->launch_executable, "corrupt\n", 0500));
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::chmod(staged->launch_executable.c_str(), 0700) == 0);
    REQUIRE(write_file(staged->launch_executable, "fixture node bytes\n", 0500));
    REQUIRE(
        ::link(
            staged->launch_executable.c_str(), alternate_node.string().append("-link").c_str()
        ) == 0
    );
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::unlink(alternate_node.string().append("-link").c_str()) == 0);
    REQUIRE(::chmod(payload.c_str(), 0700) == 0);
    REQUIRE(std::filesystem::create_directory(payload / "root-99"));
    REQUIRE(::chmod((payload / "root-99").c_str(), 0500) == 0);
    REQUIRE(::chmod(payload.c_str(), 0500) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::chmod(payload.c_str(), 0700) == 0);
    REQUIRE(::rmdir((payload / "root-99").c_str()) == 0);
    REQUIRE(::chmod(payload.c_str(), 0500) == 0);
    const auto copied_bin = staged->launch_executable.parent_path();
    REQUIRE(::chmod(copied_bin.c_str(), 0700) == 0);
    REQUIRE(::symlink(node.c_str(), (copied_bin / "escape").c_str()) == 0);
    REQUIRE(::chmod(copied_bin.c_str(), 0500) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));
    REQUIRE(::chmod(copied_bin.c_str(), 0700) == 0);
    REQUIRE(::unlink((copied_bin / "escape").c_str()) == 0);
    REQUIRE(::chmod(copied_bin.c_str(), 0500) == 0);
    REQUIRE(validate_pi_runtime_harness(*staged));
    REQUIRE(::unlink(staged->protected_entry_point.c_str()) == 0);
    REQUIRE(::symlink(node.c_str(), staged->protected_entry_point.c_str()) == 0);
    REQUIRE(!validate_pi_runtime_harness(*staged));

    const auto refused_store = temporary.root / "refused-store";
    for (const auto* broad : {"/opt/homebrew", "/usr/local", "/", "/Users"}) {
        snapshot::runtime_dependency_closure broad_closure{
            .executable = node,
            .arguments = {script.string()},
            .read_only_paths = {broad},
        };
        REQUIRE(!snapshot::validate_pi_source_closure(entry, script, broad_closure, refused_store));
        REQUIRE(!std::filesystem::exists(refused_store));
    }
    auto overlap = options;
    overlap.protected_directory = installation / "protected";
    REQUIRE(!stage_runtime_harness(overlap));
    REQUIRE(!std::filesystem::exists(overlap.protected_directory));
    auto inverted_overlap = options;
    inverted_overlap.protected_directory = temporary.root;
    REQUIRE(!stage_runtime_harness(inverted_overlap));
    REQUIRE(!std::filesystem::exists(temporary.root / "snapshots"));
    auto missing = options;
    missing.protected_directory = temporary.root / "missing-interpreter-store";
    REQUIRE(::unlink(node.c_str()) == 0);
    REQUIRE(!stage_runtime_harness(missing));
    REQUIRE(!std::filesystem::exists(missing.protected_directory));
    REQUIRE(write_file(node, "fixture node bytes\n"));
    REQUIRE(write_file(script, "#!" + node.string() + "\nfixture pi bytes\n"));
    missing.protected_directory = temporary.root / "absolute-directive-store";
    auto absolute = stage_runtime_harness(missing);
    REQUIRE(absolute);
    REQUIRE(validate_pi_runtime_harness(*absolute));
    REQUIRE(write_file(script, "#!/usr/bin/env node " + std::string(8192, 'x') + "\n"));
    missing.protected_directory = temporary.root / "oversize-directive-store";
    REQUIRE(!stage_runtime_harness(missing));
    REQUIRE(!std::filesystem::exists(missing.protected_directory));
    REQUIRE(write_file(script, "#!/usr/bin/env sh\n"));
    REQUIRE(write_file(bin / "sh", "fixture sh\n"));
    REQUIRE(!stage_runtime_harness(missing));

    // Construct a fake Homebrew snapshot from explicit approved roots. Validation
    // must not re-derive dependencies or execute the deliberately absent brew.
    const auto keg = temporary.root / "fake-homebrew" / "Cellar" / "node" / "1";
    REQUIRE(std::filesystem::create_directories(keg / "bin"));
    REQUIRE(write_file(keg / "bin" / "node", "fixture keg node\n"));
    REQUIRE(write_file(script, "#!" + (keg / "bin" / "node").string() + "\n"));
    snapshot::runtime_dependency_closure closure{
        .executable = keg / "bin" / "node",
        .arguments = {script.string()},
        .read_only_paths = snapshot::minimise_roots({package, keg}),
    };
    const auto fake_store = temporary.root / "fake-keg-store";
    auto plan = snapshot::plan_runtime_snapshot(fake_store, script, closure);
    REQUIRE(plan);
    REQUIRE(snapshot::ensure_protected_directory(fake_store));
    REQUIRE(snapshot::materialize_runtime_snapshot(*plan));
    REQUIRE(::symlink(plan->mapped_source.c_str(), (fake_store / "pi").c_str()) == 0);
    auto fake = *absolute;
    fake.canonical_source_executable = script;
    fake.source_launch_executable = closure.executable;
    fake.source_read_only_paths = closure.read_only_paths;
    fake.protected_entry_point = fake_store / "pi";
    fake.launch_executable = plan->closure.executable;
    fake.launch_arguments = plan->closure.arguments;
    fake.read_only_paths = plan->closure.read_only_paths;
    fake.snapshot_digest = plan->digest;
    fake.snapshot_entries = plan->entries;
    fake.snapshot_logical_bytes = plan->logical_bytes;
    REQUIRE(validate_pi_runtime_harness(fake));
    REQUIRE(!std::filesystem::exists(temporary.root / "fake-homebrew" / "bin" / "brew"));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
