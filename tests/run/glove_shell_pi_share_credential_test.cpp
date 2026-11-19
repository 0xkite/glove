// End-to-end: `glove shell --agent pi --share-credential deepseek` mediates the
// host DeepSeek key instead of copying it into the sandbox.
// 1. The guest models.json points the deepseek provider at the host loopback
//    endpoint and carries a session nonce, never the host key.
// 2. The host key appears nowhere in the guest Pi directory or environment.
// 3. A missing host key, raw egress, a forwarded DEEPSEEK_API_KEY, a driver
//    other than pi, and an unknown provider are refused before launch.

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

constexpr const char* host_key = "sk-deepseek-host-secret-fixture";

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

struct fixture {
    fs::path base;
    fs::path home;
    fs::path out;

    [[nodiscard]] auto env(bool with_key) const -> std::vector<std::string> {
        std::vector<std::string> env{
            "HOME=" + home.string(),
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "XDG_STATE_HOME=" + (base / "state").string(),
            "XDG_CONFIG_HOME=" + (base / "config").string(),
        };
        if (with_key) {
            env.push_back(std::string{"DEEPSEEK_API_KEY="} + host_key);
        }
        return env;
    }

    [[nodiscard]] auto argv(
        const std::string& tag,
        const std::vector<std::string>& extra,
        const std::string& agent = "pi"
    ) const -> std::vector<std::string> {
        std::vector<std::string> argv{
            GLOVE_BIN,
            "shell",
            "--agent",
            agent,
            "--workspace",
            (base / ("workspace-" + tag)).string(),
            "--write",
            out.string(),
            "--audit-log",
            (base / ("audit-" + tag + ".jsonl")).string(),
        };
        argv.insert(argv.end(), extra.begin(), extra.end());
        argv.emplace_back("--");
        argv.emplace_back("/bin/sh");
        argv.emplace_back("-c");
        argv.emplace_back(
            "cat \"$PI_CODING_AGENT_DIR/models.json\" > '" + (out / "models.json").string() +
            "'; cat \"$PI_CODING_AGENT_DIR\"/* > '" + (out / "agent-dir.txt").string() +
            "' 2>/dev/null; /usr/bin/env > '" + (out / "env.txt").string() + "'; true"
        );
        return argv;
    }
};

auto run() -> int {
    std::error_code ec;
    fixture fx;
    fx.base = fs::canonical(fs::temp_directory_path()) /
              ("glove_shell_pi_share_credential_" + std::to_string(::getpid()));
    fs::remove_all(fx.base, ec);
    fx.home = fx.base / "home";
    fx.out = fx.base / "out";
    const auto pi_agent = fx.home / ".pi" / "agent";
    fs::create_directories(pi_agent, ec);
    fs::create_directories(fx.out, ec);
    fs::create_directories(fx.base / "state", ec);
    fs::create_directories(fx.base / "config", ec);
    REQUIRE(!ec);
    {
        std::ofstream(pi_agent / "settings.json") << R"({"defaultProvider":"deepseek"})";
        std::ofstream(pi_agent / "models.json")
            << R"({"providers":{"local":{"baseUrl":"http://127.0.0.1:8081/v1","apiKey":"dummy"}}})";
    }

    // 1-2. Mediated: nonce and loopback base URL, no host key anywhere.
    const std::vector<std::string> share{"--share-credential", "deepseek"};
    REQUIRE(run_glove(fx.argv("ok", share), fx.env(true)) == 0);
    const auto models = slurp(fx.out / "models.json");
    REQUIRE(models.find("\"deepseek\"") != std::string::npos);
    REQUIRE(models.find("http://127.0.0.1:") != std::string::npos);
    REQUIRE(models.find("/deepseek\"") != std::string::npos);
    REQUIRE(models.find("glove-session-") != std::string::npos);
    REQUIRE(models.find("\"dummy\"") != std::string::npos);
    REQUIRE(models.find(host_key) == std::string::npos);
    REQUIRE(slurp(fx.out / "agent-dir.txt").find(host_key) == std::string::npos);
    const auto env = slurp(fx.out / "env.txt");
    REQUIRE(!env.empty());
    REQUIRE(env.find(host_key) == std::string::npos);
    REQUIRE(env.find("DEEPSEEK_API_KEY") == std::string::npos);
    const auto audit = slurp(fx.base / "audit-ok.jsonl");
    REQUIRE(audit.find(host_key) == std::string::npos);

    // 3. Refusals happen before launch: the probe script never runs.
    const auto refused = [&](const std::string& tag,
                             const std::vector<std::string>& extra,
                             bool with_key,
                             const std::string& agent = "pi") -> bool {
        fs::remove(fx.out / "env.txt", ec);
        const int rc = run_glove(fx.argv(tag, extra, agent), fx.env(with_key));
        return rc != 0 && !fs::exists(fx.out / "env.txt");
    };
    REQUIRE(refused("nokey", share, false));
    REQUIRE(refused(
        "egress", {"--share-credential", "deepseek", "--egress-allow", "api.deepseek.com"}, true
    ));
    REQUIRE(
        refused("envfwd", {"--share-credential", "deepseek", "--env", "DEEPSEEK_API_KEY"}, true)
    );
    REQUIRE(refused("codex", share, true, "codex"));
    REQUIRE(refused("unknown", {"--share-credential", "example"}, true));

    fs::remove_all(fx.base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
