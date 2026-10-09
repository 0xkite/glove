#include "glove/host/runtime_policy.hpp"

#include "../../src/host/dependency_command.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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
        std::string pattern = "/tmp/glove-dependency-command-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = std::filesystem::canonical(created);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        if (root_.empty()) {
            return;
        }
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root_, ignored)) {
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

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_script(const std::filesystem::path& path, std::string_view contents) -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), 0700) == 0;
}

auto command_cases(const std::filesystem::path& root) -> int {
    using glove::host::detail::capture_dependency_command;
    using namespace std::chrono_literals;
    REQUIRE(!capture_dependency_command("/bin/sh", {"-c", "exit 0"}, 0ms));
    REQUIRE(!capture_dependency_command("/bin/sh", {"-c", "exit 0"}, -1ms));
    REQUIRE(!capture_dependency_command("/bin/sh", {"-c", "exit 0"}, 31s));
    REQUIRE(!capture_dependency_command(root / "absent", {}, 1s));
    REQUIRE(!capture_dependency_command("sh", {}, 1s));
    REQUIRE(!capture_dependency_command(std::string{"/bin/sh\0suffix", 14}, {}, 1s));
    REQUIRE(!capture_dependency_command("/bin/sh", std::vector<std::string>(17, ""), 1s));
    REQUIRE(!capture_dependency_command("/bin/sh", {std::string(4097, 'a')}, 1s));
    REQUIRE(!capture_dependency_command("/bin/sh", {std::string{"exit\0suffix", 11}}, 1s));
    auto success = capture_dependency_command("/bin/sh", {"-c", "printf 'libfixture\\n'"}, 1s);
    if (!success) {
        std::fprintf(stderr, "capture failed: %s\n", success.error().c_str());
    }
    REQUIRE(success);
    REQUIRE(*success == "libfixture\n");
    REQUIRE(!capture_dependency_command("/bin/sh", {"-c", "exit 7"}, 1s));
    REQUIRE(!capture_dependency_command("/bin/sh", {"-c", "kill -TERM $$"}, 1s));
    auto exact = capture_dependency_command(
        "/bin/sh", {"-c", "dd if=/dev/zero bs=1024 count=1024 2>/dev/null"}, 2s
    );
    REQUIRE(exact);
    REQUIRE(exact->size() == 1024U * 1024U);
    auto overflow = capture_dependency_command(
        "/bin/sh", {"-c", "dd if=/dev/zero bs=1024 count=1025 2>/dev/null"}, 2s
    );
    REQUIRE(!overflow);
    REQUIRE(overflow.error().find("output limit") != std::string::npos);
    for (const auto& script : {
             "exec /bin/sleep 10",
             "exec 1>&-; exec /bin/sleep 10",
             "while :; do printf a; /bin/sleep 0.05; done",
         }) {
        const auto started = std::chrono::steady_clock::now();
        auto hung = capture_dependency_command("/bin/sh", {"-c", script}, 500ms);
        REQUIRE(!hung);
        REQUIRE(hung.error().find("timed out") != std::string::npos);
        REQUIRE(std::chrono::steady_clock::now() - started < 3s);
    }
    const auto escaped = root / "escaped";
    auto held_pipe = capture_dependency_command(
        "/bin/sh",
        {"-c", "(/bin/sleep 1; printf escaped > \"$1\") & exit 0", "fixture", escaped.string()},
        250ms
    );
    REQUIRE(!held_pipe);
    REQUIRE(held_pipe.error().find("timed out") != std::string::npos);
    std::this_thread::sleep_for(1100ms);
    REQUIRE(!std::filesystem::exists(escaped));
    auto closed_pipe = capture_dependency_command(
        "/bin/sh",
        {"-c",
         "(exec 1>&-; /bin/sleep 1; printf escaped > \"$1\") & printf ok; exit 0",
         "fixture",
         escaped.string()},
        1s
    );
    REQUIRE(closed_pipe);
    REQUIRE(*closed_pipe == "ok");
    std::this_thread::sleep_for(1100ms);
    REQUIRE(!std::filesystem::exists(escaped));
    return 0;
}

auto closed_standard_cases() -> int {
    using namespace std::chrono_literals;
    for (unsigned int mask = 1; mask < 8; ++mask) {
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            for (const int descriptor : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
                if ((mask & (1U << static_cast<unsigned int>(descriptor))) != 0) {
                    (void)::close(descriptor);
                }
            }
            auto captured =
                glove::host::detail::capture_dependency_command("/bin/sh", {"-c", "printf ok"}, 1s);
            ::_exit(captured && *captured == "ok" ? 0 : 1);
        }
        int status = 0;
        pid_t waited = -1;
        do {
            waited = ::waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        REQUIRE(waited == child);
        REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}

auto group_drift_case(const std::filesystem::path& executable) -> int {
    using namespace std::chrono_literals;
    const auto started = std::chrono::steady_clock::now();
    auto drifted =
        glove::host::detail::capture_dependency_command(executable, {"--join-parent-group"}, 250ms);
    REQUIRE(!drifted);
    REQUIRE(drifted.error().find("timed out") != std::string::npos);
    REQUIRE(std::chrono::steady_clock::now() - started < 3s);
    return 0;
}

auto staging_cases(const std::filesystem::path& root) -> int {
    using namespace glove::host;
    const auto prefix = root / "brew-fixture";
    const auto bin = prefix / "bin";
    const auto node_keg = prefix / "Cellar" / "node" / "1";
    const auto dependency_keg = prefix / "Cellar" / "libfixture" / "1";
    const auto package = prefix / "lib" / "node_modules" / "@fixture" / "pi";
    REQUIRE(std::filesystem::create_directories(bin));
    REQUIRE(std::filesystem::create_directories(node_keg / "bin"));
    REQUIRE(std::filesystem::create_directories(dependency_keg / "lib"));
    REQUIRE(std::filesystem::create_directories(package / "bin"));
    REQUIRE(std::filesystem::create_directories(prefix / "opt"));
    REQUIRE(write_script(package / "package.json", "{}\n"));
    REQUIRE(write_script(package / "bin" / "pi", "#!/usr/bin/env node\n"));
    REQUIRE(write_script(node_keg / "bin" / "node", "#!/bin/sh\nexit 0\n"));
    REQUIRE(write_script(dependency_keg / "lib" / "fixture", "fixture\n"));
    std::filesystem::create_symlink(package / "bin" / "pi", bin / "pi");
    std::filesystem::create_symlink(node_keg / "bin" / "node", bin / "node");
    std::filesystem::create_symlink(dependency_keg, prefix / "opt" / "libfixture");
    const auto marker = root / "dependency-command-ran";
    REQUIRE(write_script(
        bin / "brew", "#!/bin/sh\nprintf ran > '" + marker.string() + "'\nprintf 'libfixture\\n'\n"
    ));
    runtime_harness_stage_options options{
        .runtime_id = "pi",
        .source_executable = bin / "pi",
        .protected_directory = root / "protected" / "pi",
        .dry_run = true,
    };
    auto preview = stage_runtime_harness(options);
    REQUIRE(!preview);
    REQUIRE(preview.error().find("dry-run") != std::string::npos);
    REQUIRE(!std::filesystem::exists(marker));
    REQUIRE(!std::filesystem::exists(options.protected_directory));
    options.dry_run = false;
    auto staged = stage_runtime_harness(options);
    if (!staged) {
        std::fprintf(stderr, "staging failed: %s\n", staged.error().c_str());
    }
    REQUIRE(staged);
    REQUIRE(staged->snapshot_digest.size() == 64U);
    REQUIRE(std::filesystem::exists(marker));
    REQUIRE(staged->launch_executable.string().find("snapshots/") != std::string::npos);
    REQUIRE(write_script(bin / "brew", "#!/bin/sh\nprintf 'missing-dependency\\n'\n"));
    auto missing = stage_runtime_harness(options);
    REQUIRE(!missing);
    REQUIRE(missing.error().find("missing-dependency") != std::string::npos);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 2 && std::string_view{argv[1]} == "--join-parent-group") {
        if (::setpgid(0, ::getpgid(::getppid())) != 0) {
            return 2;
        }
        std::this_thread::sleep_for(std::chrono::seconds{10});
        return 0;
    }
    const auto executable = std::filesystem::canonical(argv[0]);
    if (argc == 2 && std::string_view{argv[1]} == "--check-group-drift") {
        return group_drift_case(executable);
    }
    if (const int failed = group_drift_case(executable); failed != 0) {
        return failed;
    }
    if (const int failed = closed_standard_cases(); failed != 0) {
        return failed;
    }
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    if (const int failed = command_cases(temporary.root()); failed != 0) {
        return failed;
    }
    return staging_cases(temporary.root());
}
