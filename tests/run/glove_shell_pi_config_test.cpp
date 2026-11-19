// End-to-end: `glove shell --agent pi` stages host Pi configuration so Pi can
// start inside the sandbox without receiving host credentials.
// 1. A local package from host settings.json is readable in the sandbox and the
//    guest settings.json points at its absolute path.
// 2. A local package that cannot be exposed is dropped from the guest
//    settings.json instead of making Pi abort on an unreadable path.
// 3. The guest models.json keeps loopback dummy keys and drops remote secrets.
// 4. The guest auth.json stays empty.
// 5. A host settings.json that resolves into an agent-writable path does not
//    choose which host paths are exposed.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef GLOVE_BIN
#    error "GLOVE_BIN must point at the glove executable"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

namespace fs = std::filesystem;

auto run_glove(std::vector<std::string> argv_owned, std::vector<std::string> env_owned) -> int {
    std::vector<char*> argv;
    for (auto& value : argv_owned) {
        argv.push_back(value.data());
    }
    argv.push_back(nullptr);
    std::vector<char*> envp;
    for (auto& value : env_owned) {
        envp.push_back(value.data());
    }
    envp.push_back(nullptr);
    const ::pid_t child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        ::execve(GLOVE_BIN, argv.data(), envp.data());
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto slurp(const fs::path& path) -> std::string {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

auto run() -> int {
    std::error_code ec;
    const auto base = fs::canonical(fs::temp_directory_path()) /
                      ("glove_shell_pi_config_" + std::to_string(::getpid()));
    fs::remove_all(base, ec);
    const auto home = base / "home";
    const auto pi_agent = home / ".pi" / "agent";
    const auto package = home / "pkgs" / "local-pi";
    const auto out = base / "out";
    fs::create_directories(pi_agent, ec);
    fs::create_directories(package, ec);
    fs::create_directories(out, ec);
    fs::create_directories(base / "state", ec);
    fs::create_directories(base / "config", ec);
    REQUIRE(!ec);
    {
        std::ofstream(package / "package.json") << R"({"name":"local-pi-marker"})";
        std::ofstream(pi_agent / "settings.json")
            << R"({"defaultProvider":"deepseek","packages":["npm:pi-lens",)"
               R"("../../pkgs/local-pi","../../pkgs/missing"],)"
               R"("extensions":["!*.test.ts","./extensions/inpi.ts"]})";
        std::ofstream(pi_agent / "models.json")
            << R"({"providers":{"local":{"baseUrl":"http://127.0.0.1:8081/v1","apiKey":"dummy"},)"
               R"("remote":{"baseUrl":"https://api.example.com/v1","apiKey":"sk-remote-secret"}}})";
        std::ofstream(pi_agent / "auth.json")
            << R"({"deepseek":{"type":"api_key","key":"sk-host-auth-secret"}})";
    }
    fs::permissions(pi_agent / "auth.json", fs::perms::owner_read | fs::perms::owner_write);

    const std::string script =
        "cat \"$PI_CODING_AGENT_DIR/settings.json\" > '" + (out / "settings.json").string() +
        "'; cat \"$PI_CODING_AGENT_DIR/models.json\" > '" + (out / "models.json").string() +
        "'; cat \"$PI_CODING_AGENT_DIR/auth.json\" > '" + (out / "auth.json").string() +
        "'; cat '" + (package / "package.json").string() + "' > '" +
        (out / "package.txt").string() + "'; true";
    const int rc = run_glove(
        {GLOVE_BIN,
         "shell",
         "--agent",
         "pi",
         "--workspace",
         (base / "workspace").string(),
         "--write",
         out.string(),
         "--audit-log",
         (base / "audit.jsonl").string(),
         "--",
         "/bin/sh",
         "-c",
         script},
        {"HOME=" + home.string(),
         "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
         "XDG_STATE_HOME=" + (base / "state").string(),
         "XDG_CONFIG_HOME=" + (base / "config").string()}
    );
    REQUIRE(rc == 0);

    const auto settings = slurp(out / "settings.json");
    REQUIRE(settings.find(package.string()) != std::string::npos);
    REQUIRE(settings.find("npm:pi-lens") != std::string::npos);
    REQUIRE(settings.find("missing") == std::string::npos);
    REQUIRE(settings.find("\"!*.test.ts\"") != std::string::npos);
    REQUIRE(settings.find("\"./extensions/inpi.ts\"") != std::string::npos);
    REQUIRE(slurp(out / "package.txt").find("local-pi-marker") != std::string::npos);

    const auto models = slurp(out / "models.json");
    REQUIRE(models.find("\"dummy\"") != std::string::npos);
    REQUIRE(models.find("sk-remote-secret") == std::string::npos);
    REQUIRE(models.find("api.example.com") != std::string::npos);

    const auto auth = slurp(out / "auth.json");
    REQUIRE(auth.find("sk-host-auth-secret") == std::string::npos);

    // 5. settings.json symlinked into the writable workspace: the package it
    //    names must not become readable.
    const auto home2 = base / "home2";
    const auto pi_agent2 = home2 / ".pi" / "agent";
    const auto workspace2 = base / "workspace2";
    const auto planted = home2 / "pkgs" / "planted";
    fs::create_directories(pi_agent2, ec);
    fs::create_directories(planted, ec);
    fs::create_directories(workspace2, ec);
    REQUIRE(!ec);
    {
        std::ofstream(planted / "package.json") << R"({"name":"planted-marker"})";
        std::ofstream(workspace2 / "settings.json") << R"({"packages":["../../pkgs/planted"]})";
    }
    fs::create_symlink(workspace2 / "settings.json", pi_agent2 / "settings.json", ec);
    REQUIRE(!ec);
    const auto planted_out = out / "planted.txt";
    const int rc2 = run_glove(
        {GLOVE_BIN,
         "shell",
         "--agent",
         "pi",
         "--workspace",
         workspace2.string(),
         "--write",
         out.string(),
         "--audit-log",
         (base / "audit2.jsonl").string(),
         "--",
         "/bin/sh",
         "-c",
         "cat '" + (planted / "package.json").string() + "' > '" + planted_out.string() +
             "' 2>/dev/null; true"},
        {"HOME=" + home2.string(),
         "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
         "XDG_STATE_HOME=" + (base / "state").string(),
         "XDG_CONFIG_HOME=" + (base / "config").string()}
    );
    REQUIRE(rc2 == 0);
    REQUIRE(slurp(planted_out).find("planted-marker") == std::string::npos);

    fs::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
