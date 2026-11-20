// Opt-in host system services (macOS): the generated SBPL carries a
// mach-lookup or read grant only for the services a launch selected from the
// vetted catalog, and the grants are enough for real clients to initialize
// inside the sandbox.
//
// Live cases: /usr/bin/curl needs /private/etc/ssl (tls-config); a Rust
// client built on system-configuration panics while building its HTTP client
// unless configd is reachable (network-config). Neither needs a listener: the
// connect to a closed loopback port fails after initialization succeeds.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include "macos/launch_command.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::profile;
using glove::container::macos_detail::prepare_launch_command;

auto read_all(const std::filesystem::path& path) -> std::string {
    std::ifstream in{path};
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

auto sbpl_for(const std::vector<std::string>& services) -> std::string {
    profile prof;
    prof.system_services = services;
    auto command = prepare_launch_command(prof, {"/bin/sh", "-c", "true"});
    if (!command) {
        std::fprintf(stderr, "prepare_launch_command: %s\n", command.error().c_str());
        return {};
    }
    return command->arguments.at(2);
}

auto sbpl_follows_selection() -> int {
    const auto none = sbpl_for({});
    REQUIRE(!none.empty());
    REQUIRE(!none.contains("mach-lookup"));
    REQUIRE(!none.contains("/private/etc/ssl"));

    const auto network = sbpl_for({"network-config"});
    REQUIRE(network.contains(
        "(allow mach-lookup (global-name \"com.apple.SystemConfiguration.configd\")"
    ));
    REQUIRE(!network.contains("/private/etc/ssl"));

    const auto tls = sbpl_for({"tls-config"});
    REQUIRE(!tls.contains("mach-lookup"));
    REQUIRE(tls.contains("(allow file-read* (literal \"/private/etc/ssl\")"));

    const auto both = sbpl_for({"tls-config", "network-config", "tls-config"});
    REQUIRE(both.contains("com.apple.SystemConfiguration.configd"));
    REQUIRE(both.contains("/private/etc/ssl"));

    profile unknown;
    unknown.system_services = {"no-such-service"};
    REQUIRE(!prepare_launch_command(unknown, {"/bin/sh", "-c", "true"}).has_value());
    return 0;
}

struct workspace_tree {
    std::filesystem::path root;

    workspace_tree() {
        root = std::filesystem::temp_directory_path() /
               ("glove_sysvc_test_" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::create_directories(root / "ws", ec);
    }

    ~workspace_tree() {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    workspace_tree(const workspace_tree&) = delete;
    auto operator=(const workspace_tree&) -> workspace_tree& = delete;
};

// Runs script in a sandbox whose only writable path is the workspace; returns
// the script's marker file contents.
auto run_in_sandbox(
    const workspace_tree& tree,
    const std::vector<std::string>& services,
    const std::vector<std::string>& extra_reads,
    const std::string& script,
    const std::string& marker
) -> std::string {
    profile prof;
    prof.filesystem.push_back({.path = (tree.root / "ws").string(), .writable = true});
    for (const auto& path : extra_reads) {
        prof.filesystem.push_back({.path = path, .writable = false});
    }
    prof.home_dir = (tree.root / "ws").string();
    prof.system_services = services;
    auto code = glove::container::exec_contained(prof, {"/bin/sh", "-c", script});
    if (!code) {
        std::fprintf(stderr, "exec_contained: %s\n", code.error().c_str());
        return "<launch failed>";
    }
    return read_all(tree.root / "ws" / marker);
}

auto curl_initializes_only_with_tls_config(const workspace_tree& tree) -> int {
    const std::string script = "/usr/bin/curl -s -o /dev/null http://127.0.0.1:1/ 2>/dev/null; "
                               "echo $? > \"$HOME/curl_rc\"";
    const auto with = run_in_sandbox(tree, {"tls-config"}, {}, script, "curl_rc");
    REQUIRE(with == "7\n");
    const auto without = run_in_sandbox(tree, {}, {}, script, "curl_rc");
    REQUIRE(!without.empty());
    REQUIRE(without != "7\n");
    return 0;
}

auto cast_initializes_only_with_network_config(const workspace_tree& tree) -> int {
    const char* home = std::getenv("HOME");
    REQUIRE(home != nullptr && *home != '\0');
    const auto foundry = std::filesystem::path{home} / ".foundry";
    const auto cast = foundry / "bin" / "cast";
    if (!std::filesystem::exists(cast)) {
        std::printf("skip cast case: %s is absent\n", cast.c_str());
        return 0;
    }
    const std::string script = "'" + cast.string() +
                               "' block-number --rpc-url http://127.0.0.1:1 "
                               "> /dev/null 2> \"$HOME/cast_err\"; echo done > \"$HOME/cast_done\"";
    const auto reads = std::vector<std::string>{foundry.string()};
    run_in_sandbox(tree, {}, reads, script, "cast_done");
    const auto without = read_all(tree.root / "ws" / "cast_err");
    REQUIRE(without.contains("panicked"));
    std::filesystem::remove(tree.root / "ws" / "cast_err");
    run_in_sandbox(tree, {"network-config"}, reads, script, "cast_done");
    const auto with = read_all(tree.root / "ws" / "cast_err");
    REQUIRE(!with.contains("panicked"));
    return 0;
}

} // namespace

auto main() -> int {
    if (const int failed = sbpl_follows_selection(); failed != 0) {
        return failed;
    }
    const workspace_tree tree;
    REQUIRE(std::filesystem::is_directory(tree.root / "ws"));
    if (const int failed = curl_initializes_only_with_tls_config(tree); failed != 0) {
        return failed;
    }
    if (const int failed = cast_initializes_only_with_network_config(tree); failed != 0) {
        return failed;
    }
    std::printf("macos system services ok\n");
    return 0;
}
