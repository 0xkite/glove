// Host Pi configuration staged into a sandbox: local package discovery and
// exposure, guest settings rewriting, and models.json credential scrubbing.

#include "glove/run/pi_host_config.hpp"

#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

namespace fs = std::filesystem;
using glove::run::pi_local_package;
using glove::run::pi_local_package_sources;
using glove::run::pi_package_exposure;
using glove::run::rewrite_pi_settings_packages;
using glove::run::scrub_pi_models_credentials;

auto contains(std::string_view haystack, std::string_view needle) -> bool {
    return haystack.find(needle) != std::string_view::npos;
}

auto local_sources() -> int {
    const fs::path home{"/home/u"};
    const fs::path dir = home / ".pi" / "agent";
    constexpr std::string_view settings = R"({
        "defaultProvider": "deepseek",
        "retry": {"enabled": true, "maxRetries": 3},
        "packages": [
            "npm:pi-lens",
            "../../work/sage-pi-adapter",
            "/opt/pi/abs-pkg",
            "~/pkgs/tilde",
            "./sibling",
            {"source": "../../objects/pkg", "extensions": ["+index.ts"]},
            {"source": "git:github.com/example/pi-tools@v1"},
            "https://github.com/example/pi-tools",
            "git:github.com/example/other"
        ]
    })";
    auto found = pi_local_package_sources(settings, dir, home);
    REQUIRE(found.has_value());
    const std::vector<pi_local_package> expected{
        {.declared = "../../work/sage-pi-adapter", .resolved = "/home/u/work/sage-pi-adapter"},
        {.declared = "/opt/pi/abs-pkg", .resolved = "/opt/pi/abs-pkg"},
        {.declared = "~/pkgs/tilde", .resolved = "/home/u/pkgs/tilde"},
        {.declared = "./sibling", .resolved = "/home/u/.pi/agent/sibling"},
        {.declared = "../../objects/pkg", .resolved = "/home/u/objects/pkg"},
    };
    REQUIRE(*found == expected);

    constexpr std::string_view pi_rules = R"({
        "packages": ["packages/bare-pkg", "  ./spaced  ", "file:///opt/pi/from-url",
                     "github:example/repo", "ssh://git@example.com/r.git",
                     "git@github.com:example/repo.git", "builtin:mcp"],
        "extensions": ["../../ext/one.ts", "-builtin:mcp", "!../../ext/skip.ts",
                       "+../../ext/glob/*.ts"],
        "skills": ["~/skills/local"],
        "prompts": ["npm:prompt-pack"],
        "themes": ["./themes/dark.json"]
    })";
    auto rules = pi_local_package_sources(pi_rules, dir, home);
    REQUIRE(rules.has_value());
    const std::vector<pi_local_package> expected_rules{
        {.declared = "packages/bare-pkg", .resolved = "/home/u/.pi/agent/packages/bare-pkg"},
        {.declared = "  ./spaced  ", .resolved = "/home/u/.pi/agent/spaced"},
        {.declared = "file:///opt/pi/from-url", .resolved = "/opt/pi/from-url"},
        {.declared = "../../ext/one.ts", .resolved = "/home/u/ext/one.ts"},
        {.declared = "!../../ext/skip.ts", .resolved = "/home/u/ext/skip.ts", .pattern = true},
        {.declared = "+../../ext/glob/*.ts", .resolved = "/home/u/ext/glob/*.ts", .pattern = true},
        {.declared = "~/skills/local", .resolved = "/home/u/skills/local"},
        {.declared = "./themes/dark.json", .resolved = "/home/u/.pi/agent/themes/dark.json"},
    };
    if (*rules != expected_rules) {
        for (const auto& rule : *rules) {
            std::fprintf(stderr, "got %s -> %s\n", rule.declared.c_str(), rule.resolved.c_str());
        }
    }
    REQUIRE(*rules == expected_rules);

    auto none = pi_local_package_sources(R"({"theme":"dark"})", dir, home);
    REQUIRE(none.has_value() && none->empty());
    REQUIRE(!pi_local_package_sources("{not json", dir, home).has_value());
    REQUIRE(!pi_local_package_sources(R"({"packages":"../../x"})", dir, home).has_value());
    return 0;
}

auto rewrite_packages() -> int {
    constexpr std::string_view settings = R"({
        "defaultModel": "deepseek-flash",
        "compaction": {"enabled": false},
        "packages": [
            "npm:pi-lens",
            "../../work/sage-pi-adapter",
            "../../missing/pkg",
            {"source": "../../objects/pkg", "extensions": ["+index.ts"]},
            {"source": "../../objects/unexposed"}
        ]
    })";
    const std::map<std::string, std::string> exposed{
        {"../../work/sage-pi-adapter", "/real/work/sage-pi-adapter"},
        {"../../objects/pkg", "/real/objects/pkg"},
    };
    auto rewritten = rewrite_pi_settings_packages(settings, exposed);
    REQUIRE(rewritten.has_value());

    glz::generic parsed{};
    REQUIRE(!glz::read_json(parsed, *rewritten));
    REQUIRE(parsed["defaultModel"].get<std::string>() == "deepseek-flash");
    REQUIRE(parsed["compaction"]["enabled"].get<bool>() == false);
    auto& packages = parsed["packages"].get<glz::generic::array_t>();
    REQUIRE(packages.size() == 3);
    REQUIRE(packages[0].get<std::string>() == "npm:pi-lens");
    REQUIRE(packages[1].get<std::string>() == "/real/work/sage-pi-adapter");
    REQUIRE(packages[2]["source"].get<std::string>() == "/real/objects/pkg");
    REQUIRE(packages[2]["extensions"].get<glz::generic::array_t>().size() == 1);
    REQUIRE(!contains(*rewritten, "missing/pkg"));
    REQUIRE(!contains(*rewritten, "unexposed"));

    constexpr std::string_view resources = R"({
        "extensions": ["../../ext/one.ts", "-builtin:mcp", "!../../ext/gone.ts",
                       "+../../ext/glob/*.ts"],
        "skills": ["~/skills/local"]
    })";
    auto resource_rewrite = rewrite_pi_settings_packages(
        resources,
        {{"../../ext/one.ts", "/real/ext/one.ts"},
         {"+../../ext/glob/*.ts", "/real/ext/glob/*.ts"},
         {"~/skills/local", "/real/skills/local"}}
    );
    REQUIRE(resource_rewrite.has_value());
    glz::generic resource_json{};
    REQUIRE(!glz::read_json(resource_json, *resource_rewrite));
    auto& extensions = resource_json["extensions"].get<glz::generic::array_t>();
    REQUIRE(extensions.size() == 4);
    REQUIRE(extensions[0].get<std::string>() == "/real/ext/one.ts");
    REQUIRE(extensions[1].get<std::string>() == "-builtin:mcp");
    REQUIRE(extensions[2].get<std::string>() == "!../../ext/gone.ts");
    REQUIRE(extensions[3].get<std::string>() == "+/real/ext/glob/*.ts");
    REQUIRE(
        resource_json["skills"].get<glz::generic::array_t>()[0].get<std::string>() ==
        "/real/skills/local"
    );

    auto untouched = rewrite_pi_settings_packages(R"({"theme":"dark"})", {});
    REQUIRE(untouched.has_value() && contains(*untouched, "dark"));
    REQUIRE(!rewrite_pi_settings_packages("[]", {}).has_value());
    return 0;
}

auto scrub_models() -> int {
    constexpr std::string_view models = R"({
        "providers": {
            "llamabarn": {"baseUrl": "http://127.0.0.1:8081/v1", "apiKey": "dummy",
                          "models": [{"id": "local-a", "contextWindow": 32768}]},
            "mlx": {"baseUrl": "http://localhost:8089/v1", "apiKey": "mlx-key"},
            "v6": {"baseUrl": "http://[::1]:9000/v1", "apiKey": "v6-dummy"},
            "remote": {"baseUrl": "https://api.example.com/v1", "apiKey": "sk-remote-secret",
                       "headers": {"Authorization": "Bearer sk-header-secret",
                                   "X-Env": "${EXAMPLE_TOKEN}"}},
            "envref": {"baseUrl": "https://api.example.org", "apiKey": "$EXAMPLE_API_KEY"},
            "cmd": {"baseUrl": "https://api.example.net", "apiKey": "!security find-generic-password -w"},
            "builtin-literal": {"apiKey": "sk-builtin-secret"},
            "spoof": {"baseUrl": "https://127.0.0.1.evil.example/v1", "apiKey": "sk-spoof-secret"}
        },
        "modelOverrides": {"deepseek": {"deepseek-flash": {"name": "Flash"}}}
    })";
    auto scrubbed = scrub_pi_models_credentials(models);
    REQUIRE(scrubbed.has_value());
    for (std::string_view secret : {
             "sk-remote-secret",
             "sk-header-secret",
             "security find-generic-password",
             "sk-builtin-secret",
             "sk-spoof-secret",
         }) {
        REQUIRE(!contains(*scrubbed, secret));
    }
    glz::generic parsed{};
    REQUIRE(!glz::read_json(parsed, *scrubbed));
    auto& providers = parsed["providers"];
    REQUIRE(providers["llamabarn"]["apiKey"].get<std::string>() == "dummy");
    REQUIRE(providers["llamabarn"]["models"].get<glz::generic::array_t>().size() == 1);
    REQUIRE(providers["mlx"]["apiKey"].get<std::string>() == "mlx-key");
    REQUIRE(providers["v6"]["apiKey"].get<std::string>() == "v6-dummy");
    REQUIRE(providers["envref"]["apiKey"].get<std::string>() == "$EXAMPLE_API_KEY");
    REQUIRE(providers["remote"]["headers"]["X-Env"].get<std::string>() == "${EXAMPLE_TOKEN}");
    REQUIRE(providers["remote"]["baseUrl"].get<std::string>() == "https://api.example.com/v1");
    REQUIRE(
        parsed["modelOverrides"]["deepseek"]["deepseek-flash"]["name"].get<std::string>() == "Flash"
    );

    constexpr std::string_view nested = R"({
        "providers": {
            "mixed": {"baseUrl": "http://127.0.0.1:8081/v1", "apiKey": "sk-mixed-provider-secret",
                      "models": [{"id": "far", "baseUrl": "https://api.example.com/v1"}]},
            "remote": {"baseUrl": "https://api.example.com/v1",
                       "models": [{"id": "m", "apiKey": "sk-model-key-secret",
                                   "headers": {"Authorization": "Bearer sk-model-header-secret",
                                               "X-Env": "$MODEL_TOKEN"}}],
                       "modelOverrides": {"m": {"headers": {"x-api-key": "sk-override-secret"}}}},
            "local": {"baseUrl": "http://localhost:8089/v1",
                      "models": [{"id": "l", "headers": {"X-Dummy": "local-dummy"}}]},
            "local-cmd": {"baseUrl": "http://127.0.0.1:8000/v1", "apiKey": "!cat sk-cmd-path"},
            "backslash": {"baseUrl": "https://evil.example\\@127.0.0.1/v1",
                          "apiKey": "sk-backslash-secret"},
            "userinfo": {"baseUrl": "http://user@127.0.0.1/v1", "apiKey": "sk-userinfo-secret"}
        },
        "modelOverrides": {"remote": {"m": {"headers": {"Authorization": "sk-top-override-secret"}}}}
    })";
    auto nested_scrubbed = scrub_pi_models_credentials(nested);
    REQUIRE(nested_scrubbed.has_value());
    for (std::string_view secret : {
             "sk-mixed-provider-secret",
             "sk-model-key-secret",
             "sk-model-header-secret",
             "sk-override-secret",
             "sk-cmd-path",
             "sk-backslash-secret",
             "sk-userinfo-secret",
             "sk-top-override-secret",
         }) {
        if (contains(*nested_scrubbed, secret)) {
            std::fprintf(stderr, "secret survived: %s\n", std::string{secret}.c_str());
        }
        REQUIRE(!contains(*nested_scrubbed, secret));
    }
    REQUIRE(contains(*nested_scrubbed, "$MODEL_TOKEN"));
    auto templated = scrub_pi_models_credentials(
        R"({"providers":{"r":{"baseUrl":"https://api.example.com","headers":{)"
        R"("Authorization":"Bearer ${EXAMPLE_TOKEN}","X-Mixed":"key-$EXAMPLE sk-mixed-literal"}}}})"
    );
    REQUIRE(templated.has_value());
    REQUIRE(contains(*templated, "Bearer ${EXAMPLE_TOKEN}"));
    REQUIRE(!contains(*templated, "sk-mixed-literal"));
    REQUIRE(contains(*nested_scrubbed, "local-dummy"));

    auto empty = scrub_pi_models_credentials(R"({})");
    REQUIRE(empty.has_value());
    REQUIRE(!scrub_pi_models_credentials("{\"providers\":").has_value());
    return 0;
}

auto exposure() -> int {
    std::error_code ec;
    const auto base = fs::canonical(fs::temp_directory_path()) /
                      ("glove_pi_host_config_" + std::to_string(::getpid()));
    fs::remove_all(base, ec);
    const auto home = base / "home";
    const auto pi_agent = home / ".pi" / "agent";
    const auto package = home / "work" / "sage-pi-adapter";
    fs::create_directories(pi_agent, ec);
    fs::create_directories(package, ec);
    fs::create_directories(home / ".ssh" / "pkg", ec);
    REQUIRE(!ec);
    { std::ofstream(package / "package.json") << "{}"; }
    const auto resource_only = home / "work" / "resource-only";
    const auto bare_dir = home / "work" / "no-manifest";
    fs::create_directories(resource_only / "extensions", ec);
    fs::create_directories(bare_dir, ec);
    fs::create_directories(home / ".config" / "gh", ec);
    fs::create_directories(home / ".local" / "share" / "pkg", ec);
    fs::create_directories(home / "Library" / "Keychains", ec);
    { std::ofstream(home / ".netrc") << "machine example"; }
    { std::ofstream(home / "notes.txt") << "notes"; }
    REQUIRE(!ec);
    { std::ofstream(home / "single-extension.ts") << "export default 1;"; }
    fs::create_directory_symlink(package, home / "linked-adapter", ec);
    fs::create_directory_symlink(home, home / "linked-home", ec);
    REQUIRE(!ec);

    auto ok = pi_package_exposure(package, home, pi_agent);
    REQUIRE(ok.has_value() && *ok == package);
    auto file = pi_package_exposure(home / "single-extension.ts", home, pi_agent);
    REQUIRE(file.has_value() && *file == home / "single-extension.ts");
    auto via_link = pi_package_exposure(home / "linked-adapter", home, pi_agent);
    REQUIRE(via_link.has_value() && *via_link == package);

    auto resources = pi_package_exposure(resource_only, home, pi_agent);
    REQUIRE(resources.has_value() && *resources == resource_only);
    REQUIRE(!pi_package_exposure(bare_dir, home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".config", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".config" / "gh", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".local", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".local" / "share" / "pkg", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / "Library", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".netrc", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / "notes.txt", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home, home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / "linked-home", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(base, home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".pi", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(pi_agent, home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / ".ssh" / "pkg", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(home / "missing", home, pi_agent).has_value());
    REQUIRE(!pi_package_exposure(fs::path{"/"}, home, pi_agent).has_value());

    fs::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    if (const int rc = local_sources(); rc != 0) {
        return rc;
    }
    if (const int rc = rewrite_packages(); rc != 0) {
        return rc;
    }
    if (const int rc = scrub_models(); rc != 0) {
        return rc;
    }
    return exposure();
}
