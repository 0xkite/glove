#include "glove/host/runtime_policy.hpp"

#include "../../src/host/dependency_command.hpp"
#include "../../src/host/runtime_snapshot.hpp"
#include "../../src/host/snapshot_copy.hpp"

#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
        std::string pattern = "/tmp/glove-snapshot-bounds-XXXXXX";
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
        for (std::filesystem::recursive_directory_iterator iterator{root, ignored}, end;
             iterator != end && !ignored;
             iterator.increment(ignored)) {
            if (std::filesystem::is_directory(iterator->symlink_status(ignored))) {
                (void)::chmod(iterator->path().c_str(), 0700);
            }
        }
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

auto write_file(const std::filesystem::path& path, std::string_view bytes) -> bool {
    std::ofstream output{path, std::ios::binary};
    output << bytes;
    output.close();
    return output.good() && ::chmod(path.c_str(), 0700) == 0;
}

auto fifo_case(const std::filesystem::path& root) -> int {
    const auto source = root / "source";
    const auto script = source / "package" / "bin" / "pi";
    REQUIRE(std::filesystem::create_directories(script.parent_path()));
    REQUIRE(std::filesystem::create_directory(source / "bin"));
    REQUIRE(write_file(source / "package" / "package.json", "{}\n"));
    REQUIRE(write_file(script, "#!/usr/bin/env node\n"));
    REQUIRE(write_file(source / "bin" / "node", "fixture node\n"));
    std::filesystem::create_symlink("../package/bin/pi", source / "bin" / "pi");
    auto runtime = glove::host::stage_runtime_harness({
        .runtime_id = "pi",
        .source_executable = source / "bin" / "pi",
        .protected_directory = root / "protected" / "pi",
    });
    REQUIRE(runtime);
    REQUIRE(::unlink(script.c_str()) == 0);
    REQUIRE(::mkfifo(script.c_str(), 0600) == 0);
    REQUIRE(!glove::host::validate_pi_runtime_harness(*runtime));
    std::fputs("snapshot-admission-ok\n", stdout);
    return 0;
}

auto growth_case(const std::filesystem::path& root) -> int {
    namespace snapshot = glove::host::snapshot;
    const auto source = root / "runtime";
    REQUIRE(write_file(source, "x"));
    const snapshot::runtime_dependency_closure closure{
        .executable = source,
        .arguments = {},
        .read_only_paths = {source},
    };
    auto plan = snapshot::plan_runtime_snapshot(root / "protected", source, closure);
    REQUIRE(plan && plan->logical_bytes == 1 && plan->entries == 1);
    REQUIRE(snapshot::ensure_protected_directory(root / "protected"));
    REQUIRE(write_file(source, std::string(65536, 'x')));
    // The old post-copy rejection writes beyond this limit first. The copier
    // must refuse source growth before writing more than the one-byte plan.
    struct rlimit limit{};
    REQUIRE(::getrlimit(RLIMIT_FSIZE, &limit) == 0);
    limit.rlim_cur = std::min<rlim_t>(1024, limit.rlim_max);
    REQUIRE(::setrlimit(RLIMIT_FSIZE, &limit) == 0);
    REQUIRE(std::signal(SIGXFSZ, SIG_DFL) != SIG_ERR);
    sigset_t unblocked{};
    REQUIRE(sigemptyset(&unblocked) == 0);
    REQUIRE(sigaddset(&unblocked, SIGXFSZ) == 0);
    REQUIRE(::sigprocmask(SIG_UNBLOCK, &unblocked, nullptr) == 0);
    auto refused = snapshot::materialize_runtime_snapshot(*plan);
    REQUIRE(!refused && refused.error().find("budget") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(plan->snapshot_root.parent_path()));
    std::fputs("snapshot-admission-ok\n", stdout);
    return 0;
}

auto copy_cases(const std::filesystem::path& root) -> int {
    namespace snapshot = glove::host::snapshot;
    const auto source = root / "copy-source";
    REQUIRE(std::filesystem::create_directories(source / "dir"));
    REQUIRE(write_file(source / "a", "abc"));
    REQUIRE(write_file(source / "dir" / "b", "de"));
    REQUIRE(::chmod((source / "dir" / "b").c_str(), 0600) == 0);
    const std::vector<std::filesystem::path> roots{source};
    for (const auto* name : {"exact", "bytes", "entries", "absolute", "links", "special"}) {
        REQUIRE(::mkdir((root / name).c_str(), 0700) == 0);
    }
    REQUIRE(snapshot::copy_runtime_closure(roots, root / "exact", 5, 3));
    const std::vector<std::filesystem::path> copied{root / "exact" / "root-0"};
    auto source_digest = snapshot::snapshot_closure_digest(roots);
    auto copied_digest = snapshot::snapshot_closure_digest(copied);
    REQUIRE(source_digest && copied_digest && *source_digest == *copied_digest);
    REQUIRE(!snapshot::copy_runtime_closure(roots, root / "exact", 5, 3));
    REQUIRE(!snapshot::copy_runtime_closure(roots, root / "bytes", 4, 3));
    REQUIRE(!snapshot::copy_runtime_closure(roots, root / "entries", 5, 2));
    const auto written = [](const std::filesystem::path& payload) {
        std::uint64_t bytes = 0;
        std::uint64_t entries = 0;
        const auto tree = payload / "root-0";
        for (const auto& item : std::filesystem::recursive_directory_iterator(tree)) {
            ++entries;
            if (std::filesystem::is_regular_file(item.symlink_status())) {
                bytes += item.file_size();
            }
        }
        return std::pair{bytes, entries};
    };
    REQUIRE(written(root / "bytes").first <= 4U);
    REQUIRE(written(root / "entries").second <= 2U);
    REQUIRE(
        !snapshot::copy_runtime_closure(roots, root / "absolute", (std::uint64_t{2} << 30) + 1, 3)
    );
    REQUIRE(!snapshot::copy_runtime_closure(roots, root / "absolute", 5, 200001));
    REQUIRE(std::filesystem::is_empty(root / "absolute"));
    std::filesystem::create_symlink("a", source / "direct");
    std::filesystem::create_symlink("direct", source / "chain");
    REQUIRE(snapshot::copy_runtime_closure(roots, root / "links", 5, 5));
    const std::vector<std::filesystem::path> linked{root / "links" / "root-0"};
    auto linked_digest = snapshot::snapshot_closure_digest(linked);
    auto original_link_digest = snapshot::snapshot_closure_digest(roots);
    REQUIRE(linked_digest && original_link_digest && *linked_digest == *original_link_digest);
    for (const auto& [name, target] : std::array{
             std::pair{"cycle", "bad"},
             std::pair{"escape", "../outside-auth.json"},
             std::pair{"absolute-link", "/etc/passwd"},
             std::pair{"dangling", "missing"}
         }) {
        const auto payload = root / name;
        REQUIRE(::mkdir(payload.c_str(), 0700) == 0);
        std::filesystem::create_symlink(target, source / "bad");
        REQUIRE(!snapshot::copy_runtime_closure(roots, payload, 5, 6));
        REQUIRE(::unlink((source / "bad").c_str()) == 0);
    }
    const auto linked_file = root / "copy-hardlink";
    REQUIRE(::mkdir(linked_file.c_str(), 0700) == 0);
    REQUIRE(::link((source / "a").c_str(), (source / "alias").c_str()) == 0);
    REQUIRE(!snapshot::copy_runtime_closure(roots, linked_file, 8, 6));
    REQUIRE(::unlink((source / "alias").c_str()) == 0);
    REQUIRE(::mkfifo((source / "fifo").c_str(), 0600) == 0);
    REQUIRE(!snapshot::copy_runtime_closure(roots, root / "special", 5, 6));
    return 0;
}

auto run(const std::filesystem::path& executable) -> int {
    fixture temporary;
    REQUIRE(!temporary.root.empty());
    bool failed = false;
    for (const auto* mode : {"--fifo", "--growth"}) {
        const auto root = temporary.root / (std::string{mode}.substr(2));
        REQUIRE(std::filesystem::create_directory(root));
        auto captured = glove::host::detail::capture_dependency_command(
            executable, {mode, root.string()}, std::chrono::seconds{2}
        );
        if (!captured || *captured != "snapshot-admission-ok\n") {
            std::fprintf(
                stderr,
                "%s failed: %s\n",
                mode,
                captured ? "unexpected fixture output" : captured.error().c_str()
            );
            failed = true;
        }
    }
    const auto source = temporary.root / "hardlink-source";
    REQUIRE(std::filesystem::create_directory(source));
    const auto secret = temporary.root / "outside-auth.json";
    REQUIRE(write_file(secret, "fixture-only-host-credential\n"));
    REQUIRE(::link(secret.c_str(), (source / "imported-auth.json").c_str()) == 0);
    const std::array roots{source};
    if (glove::host::snapshot::snapshot_closure_digest(roots)) {
        std::fprintf(stderr, "source hardlink was admitted\n");
        failed = true;
    }
    const auto directive = temporary.root / "directive";
    REQUIRE(write_file(directive, std::string(8192, 'x')));
    auto native = glove::host::snapshot::read_runtime_shebang(directive);
    REQUIRE(native && !*native);
    REQUIRE(write_file(directive, "#!/usr/bin/env node\nbody"));
    auto script = glove::host::snapshot::read_runtime_shebang(directive);
    REQUIRE(script && *script && (**script == std::vector<std::string>{"/usr/bin/env", "node"}));
    REQUIRE(write_file(directive, "#!" + std::string(4095, 'x') + "\n"));
    REQUIRE(!glove::host::snapshot::read_runtime_shebang(directive));
    REQUIRE(write_file(directive, std::string{"#!/usr/bin/env\0node\n", 20}));
    REQUIRE(!glove::host::snapshot::read_runtime_shebang(directive));
    const auto alias = temporary.root / "directive-alias";
    std::filesystem::create_symlink(directive, alias);
    REQUIRE(!glove::host::snapshot::read_runtime_shebang(alias));
    REQUIRE(copy_cases(temporary.root) == 0);
    return failed ? 1 : 0;
}
} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 3 && std::string_view{argv[1]} == "--fifo") {
        return fifo_case(argv[2]);
    }
    if (argc == 3 && std::string_view{argv[1]} == "--growth") {
        return growth_case(argv[2]);
    }
    REQUIRE(argc == 1);
    return run(std::filesystem::canonical(argv[0]));
}
