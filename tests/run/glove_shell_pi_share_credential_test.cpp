// End-to-end: `glove shell --agent pi --share-credential <provider>` mediates a
// host Pi provider credential instead of copying it into the sandbox. One code
// path serves every provider; the data comes from Pi's own catalog and host
// auth.json. Three credential shapes are exercised (Bearer, x-api-key,
// x-goog-api-key), plus the refusals.
// 1. The guest models.json points the provider at the host loopback endpoint
//    (`/p/<provider>` plus the upstream base path) with a session nonce.
// 2. No host key appears in the guest Pi directory, environment, or audit log.
// 3. Subscription logins, unknown providers, raw egress, forwarded key
//    variables, and a driver other than pi are refused before launch.

#include <sys/wait.h>
#include <unistd.h>

#include <array>
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

struct provider_case {
    const char* name;
    const char* api;
    const char* base_url;
    const char* guest_suffix; // expected guest baseUrl after the loopback port
    const char* host_key;
};

constexpr std::array<provider_case, 3> providers{{
    {"deepseek", "openai-completions", "https://api.deepseek.com", "/p/deepseek\"",
     "sk-deepseek-host-fixture"},
    {"anthropic", "anthropic-messages", "https://api.anthropic.com", "/p/anthropic\"",
     "sk-ant-host-fixture"},
    {"google", "google-generative-ai", "https://generativelanguage.googleapis.com/v1beta",
     "/p/google/v1beta\"", "google-host-fixture"},
}};

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

auto catalog_json(const provider_case& p) -> std::string {
    return std::string{R"({")"} + p.api + R"(":{"chat:m1":{"id":"m1","provider":")" + p.name +
           R"(","api":")" + p.api + R"(","baseUrl":")" + p.base_url + R"("}}})";
}

struct fixture {
    fs::path base;
    fs::path home;
    fs::path out;

    [[nodiscard]] auto env() const -> std::vector<std::string> {
        return {
            "HOME=" + home.string(),
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "XDG_STATE_HOME=" + (base / "state").string(),
            "XDG_CONFIG_HOME=" + (base / "config").string(),
            "EXAMPLE_API_KEY=forward-me-not",
        };
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
    // Pi's managed install layout: install/current-version names the release.
    const auto catalog_dir = pi_agent / "install" / "releases" / "9.9.9" / "node_modules" /
                             "@earendil-works" / "pi-ai" / "dist" / "providers" / "data";
    fs::create_directories(catalog_dir, ec);
    fs::create_directories(fx.out, ec);
    fs::create_directories(fx.base / "state", ec);
    fs::create_directories(fx.base / "config", ec);
    REQUIRE(!ec);
    std::string auth = "{";
    for (const auto& p : providers) {
        std::ofstream(catalog_dir / (std::string{p.name} + ".json")) << catalog_json(p);
        auth += std::string{"\""} + p.name + R"(":{"type":"api_key","key":")" + p.host_key +
                "\"},";
    }
    auth += R"("openai-codex":{"type":"oauth","access":"codex-access-fixture","refresh":"r",)"
            R"("expires":1}})";
    {
        std::ofstream(catalog_dir / "openai-codex.json")
            << R"({"openai-codex-responses":{"chat:c":{"id":"c","provider":"openai-codex",)"
               R"("api":"openai-codex-responses","baseUrl":"https://chatgpt.com/backend-api"}}})";
        std::ofstream(pi_agent / "install" / "current-version") << "9.9.9\n";
        std::ofstream(pi_agent / "settings.json") << R"({"defaultProvider":"deepseek"})";
        std::ofstream(pi_agent / "models.json")
            << R"({"providers":{"local":{"baseUrl":"http://127.0.0.1:8081/v1","apiKey":"dummy"}}})";
        std::ofstream(pi_agent / "auth.json") << auth;
    }
    fs::permissions(pi_agent / "auth.json", fs::perms::owner_read | fs::perms::owner_write);

    // 1-2. Each credential shape goes through the same mediated path.
    for (const auto& p : providers) {
        fs::remove(fx.out / "models.json", ec);
        const std::string tag = std::string{"ok-"} + p.name;
        REQUIRE(run_glove(fx.argv(tag, {"--share-credential", p.name}), fx.env()) == 0);
        const auto models = slurp(fx.out / "models.json");
        REQUIRE(models.find(std::string{"\""} + p.name + "\"") != std::string::npos);
        REQUIRE(models.find("http://127.0.0.1:") != std::string::npos);
        REQUIRE(models.find(p.guest_suffix) != std::string::npos);
        REQUIRE(models.find("glove-session-") != std::string::npos);
        REQUIRE(models.find("\"dummy\"") != std::string::npos);
        const auto agent_dir = slurp(fx.out / "agent-dir.txt");
        const auto env = slurp(fx.out / "env.txt");
        const auto audit = slurp(fx.base / ("audit-" + tag + ".jsonl"));
        REQUIRE(!env.empty());
        for (const auto& other : providers) {
            REQUIRE(models.find(other.host_key) == std::string::npos);
            REQUIRE(agent_dir.find(other.host_key) == std::string::npos);
            REQUIRE(env.find(other.host_key) == std::string::npos);
            REQUIRE(audit.find(other.host_key) == std::string::npos);
        }
        REQUIRE(agent_dir.find("codex-access-fixture") == std::string::npos);
        REQUIRE(env.find("forward-me-not") == std::string::npos);
    }

    // 3. Refusals happen before launch: the probe script never runs.
    const auto refused = [&](const std::string& tag,
                             const std::vector<std::string>& extra,
                             const std::string& agent = "pi") -> bool {
        fs::remove(fx.out / "env.txt", ec);
        const int rc = run_glove(fx.argv(tag, extra, agent), fx.env());
        return rc != 0 && !fs::exists(fx.out / "env.txt");
    };
    REQUIRE(refused("oauth", {"--share-credential", "openai-codex"}));
    REQUIRE(refused("unknown", {"--share-credential", "nowhere"}));
    REQUIRE(refused("badname", {"--share-credential", "../deepseek"}));
    REQUIRE(refused(
        "egress", {"--share-credential", "deepseek", "--egress-allow", "api.deepseek.com"}
    ));
    REQUIRE(refused("envfwd", {"--share-credential", "deepseek", "--env", "EXAMPLE_API_KEY"}));
    REQUIRE(refused("codex", {"--share-credential", "deepseek"}, "codex"));

    fs::remove_all(fx.base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
