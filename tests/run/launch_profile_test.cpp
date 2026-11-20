// Launch profiles parse only the strict YAML subset, decode through the
// strict schema, round-trip through the canonical encoding, layer the
// command line on top, load only owner-only single-link regular files, and
// never let a launch expose glove's own configuration or state.

#include "glove/run/launch_profile.hpp"

#include "yaml_subset.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::run::launch_profile;
using glove::run::parse_launch_profile;

constexpr std::string_view full_profile = R"(# a full profile
version: 1
workspace: ~/src/project
agent: claude-code
read:
  - /usr/share       # trailing comment
  - "~/notes # not a comment"
write: [~/scratch, '/tmp/it''s']
env:
  LANG: { value: en_US.UTF-8 }
  PORT: { value: 8080 }
  CI: { from: host }
  NOTE:
    value: "say \"hi\" é"
egress:
  - { host: registry.npmjs.org }
  - host: example.com
    port: 8443
mcp:
  - { name: yams, argv: [/usr/local/bin/yams, serve, --quiet] }
allow: [yams.search]
allow_arg:
  - { tool: yams.search, field: path, prefix: /src }
bridge_port: 8080
secrets:
  provider: keychain://glove/anthropic
decoys:
  - "~/.private/glove_{nonce}"
  - /var/tmp/glove-canary
)";

auto parses_full_profile() -> int {
    const auto parsed = parse_launch_profile(full_profile);
    if (!parsed) {
        std::fprintf(stderr, "%s\n", parsed.error().c_str());
    }
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->workspace == "~/src/project");
    REQUIRE(parsed->agent == "claude-code");
    REQUIRE((parsed->read == std::vector<std::string>{"/usr/share", "~/notes # not a comment"}));
    REQUIRE((parsed->write == std::vector<std::string>{"~/scratch", "/tmp/it's"}));
    REQUIRE(parsed->env.size() == 4);
    // Sorted by name; integers become their decimal text.
    REQUIRE(parsed->env[0].name == "CI" && !parsed->env[0].value);
    REQUIRE(parsed->env[1].name == "LANG" && parsed->env[1].value == "en_US.UTF-8");
    REQUIRE(parsed->env[2].name == "NOTE" && parsed->env[2].value == "say \"hi\" \xc3\xa9");
    REQUIRE(parsed->env[3].name == "PORT" && parsed->env[3].value == "8080");
    REQUIRE(parsed->egress.size() == 2);
    REQUIRE(parsed->egress[0].host == "registry.npmjs.org" && parsed->egress[0].port == 443);
    REQUIRE(parsed->egress[1].host == "example.com" && parsed->egress[1].port == 8443);
    REQUIRE(!parsed->egress[0].allow_private && !parsed->egress[1].allow_private);
    REQUIRE(parsed->mcp.size() == 1 && parsed->mcp[0].name == "yams");
    REQUIRE(parsed->mcp[0].argv.size() == 3);
    REQUIRE(parsed->allow == std::vector<std::string>{"yams.search"});
    REQUIRE(parsed->allow_arg.size() == 1 && parsed->allow_arg[0].required_prefix == "/src");
    REQUIRE(parsed->bridge_port == 8080);
    REQUIRE(parsed->provider_secret.has_value());
    REQUIRE(parsed->provider_secret->source == glove::run::secret_source::keychain);
    REQUIRE(
        (parsed->decoys ==
         std::vector<std::string>{"~/.private/glove_{nonce}", "/var/tmp/glove-canary"})
    );

    const auto encoded = glove::run::encode_launch_profile(*parsed);
    const auto reparsed = parse_launch_profile(encoded);
    REQUIRE(reparsed.has_value());
    REQUIRE(*reparsed == *parsed);
    REQUIRE(glove::run::encode_launch_profile(*reparsed) == encoded);
    REQUIRE(encoded.contains("provider: \"keychain://glove/anthropic\""));
    // Equality is the fuzzer's oracle, so it must see every field.
    auto other_secret = *parsed;
    other_secret.provider_secret = *glove::run::parse_secret_reference("env://OTHER");
    REQUIRE(!(other_secret == *parsed));
    auto no_secret = *parsed;
    no_secret.provider_secret.reset();
    REQUIRE(!(no_secret == *parsed));
    using edit = void (*)(launch_profile&);
    for (const edit change : std::array<edit, 12>{
             [](launch_profile& p) { p.workspace = "/other"; },
             [](launch_profile& p) { p.agent = "pi"; },
             [](launch_profile& p) { p.read.pop_back(); },
             [](launch_profile& p) { p.write.pop_back(); },
             [](launch_profile& p) { p.env.front().value = "x"; },
             [](launch_profile& p) { p.egress.front().port = 1; },
             [](launch_profile& p) { p.egress.front().allow_private = true; },
             [](launch_profile& p) { p.mcp.front().argv.pop_back(); },
             [](launch_profile& p) { p.allow.clear(); },
             [](launch_profile& p) { p.allow_arg.front().required_prefix = "/x"; },
             [](launch_profile& p) { p.bridge_port = 1; },
             [](launch_profile& p) { p.decoys.pop_back(); },
         }) {
        auto changed = *parsed;
        change(changed);
        REQUIRE(!(changed == *parsed));
    }

    const auto starter = parse_launch_profile(glove::run::launch_profile_template());
    REQUIRE(starter.has_value());
    REQUIRE(*starter == launch_profile{});
    return 0;
}

struct refusal {
    std::string_view text;
    std::string_view reason; // a substring of the error
};

auto refuses_ambiguous_yaml() -> int {
    const std::string nul_text = std::string{"version: 1\nworkspace: /a"} + '\0' + "b\n";
    const std::array<refusal, 46> cases{{
        {"version: 1\nread: [/a]\nread: [/b]\n", "line 3: duplicate key 'read'"},
        {"version: 1\nenv:\n  A: { value: x }\n  A: { value: y }\n", "line 4: duplicate key 'A'"},
        {"version: 1\nenv:\n  A: { value: x, value: y }\n", "duplicate key 'value'"},
        {"version: 1\negress:\n  - host: a.b\n    host: c.d\n", "duplicate key 'host'"},
        {"version: 1\nread: &paths [/a]\n", "'&' cannot start a value"},
        {"version: 1\nwrite: *paths\n", "'*' cannot start a value"},
        {"version: 1\nworkspace: !!str /a\n", "'!' cannot start a value"},
        {"version: 1\nworkspace: |\n  /a\n", "'|' cannot start a value"},
        {"version: 1\nworkspace: >\n  /a\n", "'>' cannot start a value"},
        {"%YAML 1.2\nversion: 1\n", "line 1"},
        {"version: 1\n---\nversion: 2\n", "document markers"},
        {"version: 1\n...\n", "document markers"},
        {"version: 1\nread:\n\t- /a\n", "tabs are not allowed"},
        {"version: 1\r\n", "carriage returns"},
        {nul_text, "control or invisible"},
        {"version: 1\nworkspace: /\xff\n", "not valid UTF-8"},
        {"version: 1\nworkspace: /\xc0\xaf\n", "not valid UTF-8"},
        {"\xef\xbb\xbfversion: 1\n", "control or invisible"},
        {"version: 1\nworkspace: /a\xe2\x80\xa8\n", "control or invisible"},
        {"version: 1\nworkspace: \"/a\\u0000\"\n", "escaped control"},
        {"version: 1\nworkspace: \"/a\\x41\"\n", "unsupported escape"},
        {"version: 1\nworkspace: \"/a\n", "close on the same line"},
        {"version: 1\nworkspace: /a\n  /b\n", "unexpected indentation"},
        {"version: 1\nread: [/a, /b,]\n", "trailing commas"},
        {"version: 1\nread:\n  - - /a\n", "nested block sequences"},
        {"version: 1\nread:\n", "has no value"},
        {"version: 1\nworkspace: a: b\n", "cannot contain ': '"},
        {"version: 1\nworkspace: ~\n", "null is not allowed"},
        {"version: 1\nworkspace: null\n", "null is not allowed"},
        {"version: 1\n\"read\": [/a]\n", "plain key"},
        {"version: 1\nbogus: 1\n", "unknown_key"},
        {"read: [/a]\n", "missing_key"},
        {"version: 2\n", "unsupported profile version"},
        {"version: 1\nworkspace: src/project\n", "workspace"},
        {"version: 1\nread: [~user/x]\n", "read: paths must be absolute"},
        {"version: 1\nenv:\n  A: { value: x, from: host }\n", "exactly one of value or from"},
        {"version: 1\nenv:\n  A: { from: shell }\n", "from must be host"},
        {"version: 1\nenv:\n  1A: { value: x }\n", "not a variable name"},
        {"version: 1\nbridge_port: 70000\n", "schema"},
        {"version: 1\nsecrets:\n  provider: ANTHROPIC_API_KEY\n", "secrets.provider"},
        {"version: 1\nsecrets:\n  provider: op://vault/item\n", "unsupported secret reference"},
        {"version: 1\nsecrets:\n  token: env://A\n", "unknown_key"},
        {"version: 1\ndecoys: [relative/x]\n", "decoys: paths must be absolute"},
        {"version: 1\ndecoys: [\"~/\"]\n", "must name a file"},
        {"version: 1\ndecoys: [~/.private/glove_{nonce}]\n", "line 2"},
        {"version: 1\nmcp:\n  - { name: a, argv: [/x] }\n  - { name: a, argv: [/y] }\n",
         "unique server name"},
    }};
    for (const auto& item : cases) {
        const auto parsed = parse_launch_profile(item.text);
        if (parsed || !parsed.error().contains(item.reason)) {
            std::fprintf(
                stderr,
                "case %.*s: expected refusal containing '%.*s', got %s\n",
                static_cast<int>(item.text.size()),
                item.text.data(),
                static_cast<int>(item.reason.size()),
                item.reason.data(),
                parsed ? "acceptance" : parsed.error().c_str()
            );
            return 1;
        }
    }
    return 0;
}

auto accepts_plain_subtleties() -> int {
    // A quote inside a plain value does not open a quoted scalar; '#' needs a
    // space before it to start a comment; sequence items that are mappings
    // keep separate key sets.
    const auto parsed = parse_launch_profile(
        "version: 1\n"
        "workspace: /tmp/it's#here\n"
        "egress:\n"
        "  - host: a.example\n"
        "  - host: b.example\n"
        "    port: 444\n"
    );
    if (!parsed) {
        std::fprintf(stderr, "%s\n", parsed.error().c_str());
    }
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->workspace == "/tmp/it's#here");
    REQUIRE(parsed->egress.size() == 2 && parsed->egress[1].port == 444);

    const glove::run::detail::yaml_subset_limits limits{
        .max_bytes = 1024, .max_lines = 8, .max_entries = 2, .max_depth = 3
    };
    REQUIRE(glove::run::detail::yaml_subset_to_json("a: [1, 2]\n", limits) == "{\"a\":[1,2]}");
    REQUIRE(!glove::run::detail::yaml_subset_to_json("a: [1, 2, 3]\n", limits));
    REQUIRE(!glove::run::detail::yaml_subset_to_json("a: [[[[1]]]]\n", limits));
    REQUIRE(!glove::run::detail::yaml_subset_to_json(std::string(1025, 'a'), limits));
    REQUIRE(!glove::run::detail::yaml_subset_to_json("a: 1\n\n\n\n\n\n\n\nb: 2\n", limits));
    REQUIRE(glove::run::detail::yaml_subset_to_json("a: 007\n", limits) == "{\"a\":\"007\"}");
    REQUIRE(!glove::run::detail::yaml_subset_to_json("- a\n", limits));
    return 0;
}

// system_services names come from the vetted catalog: the profile accepts
// them, an unknown or raw name fails at load, and the CLI list is appended.
auto parses_system_services() -> int {
    auto parsed = parse_launch_profile(
        "version: 1\n"
        "system_services: [network-config, tls-config]\n"
    );
    REQUIRE(parsed.has_value());
    REQUIRE((parsed->system_services == std::vector<std::string>{"network-config", "tls-config"}));

    auto round_trip = parse_launch_profile(glove::run::encode_launch_profile(*parsed));
    REQUIRE(round_trip.has_value());
    REQUIRE(*round_trip == *parsed);

    auto unknown = parse_launch_profile("version: 1\nsystem_services: [no-such-service]\n");
    REQUIRE(!unknown.has_value());
    REQUIRE(unknown.error().contains("unknown system service 'no-such-service'"));

    auto raw = parse_launch_profile(
        "version: 1\nsystem_services: [com.apple.SystemConfiguration.configd]\n"
    );
    REQUIRE(!raw.has_value());
    REQUIRE(raw.error().contains("raw mach service names are not accepted"));

    auto absent = parse_launch_profile("version: 1\n");
    REQUIRE(absent.has_value() && absent->system_services.empty());

    glove::run::options cli;
    cli.system_services = {"tls-config"};
    cli.agent_argv = {"/bin/true"};
    auto applied = glove::run::apply_launch_profile(*parsed, cli, "/home/u");
    REQUIRE(applied.has_value());
    REQUIRE(
        (applied->system_services ==
         std::vector<std::string>{"network-config", "tls-config", "tls-config"})
    );
    return 0;
}

auto layers_command_line() -> int {
    auto parsed = parse_launch_profile(
        "version: 1\n"
        "workspace: ~/w\n"
        "agent: pi\n"
        "read: [~/r, /abs]\n"
        "write: [\"~\"]\n"
        "env:\n"
        "  A: { value: one }\n"
        "  B: { from: host }\n"
        "egress: [{ host: p.example }]\n"
        "bridge_port: 9000\n"
    );
    REQUIRE(parsed.has_value());
    glove::run::options cli;
    cli.readable = {"/cli-read"};
    cli.environment_names = {"C"};
    cli.egress.push_back({.host = "c.example"});
    cli.agent_argv = {"/bin/true"};
    parsed->provider_secret = *glove::run::parse_secret_reference("env://PROFILE_KEY");
    auto applied = glove::run::apply_launch_profile(*parsed, cli, "/home/u");
    REQUIRE(applied.has_value());
    REQUIRE(applied->workspace == std::filesystem::path{"/home/u/w"});
    REQUIRE(applied->agent_preset == "pi");
    REQUIRE(applied->bridge_port == 9000);
    REQUIRE((applied->readable == std::vector<std::string>{"/home/u/r", "/abs", "/cli-read"}));
    REQUIRE((applied->writable == std::vector<std::string>{"/home/u"}));
    REQUIRE((applied->environment_names == std::vector<std::string>{"B", "C"}));
    REQUIRE(applied->environment_values.size() == 1);
    REQUIRE(applied->environment_values[0].name == "A");
    REQUIRE(applied->environment_values[0].value == "one");
    REQUIRE(applied->egress.size() == 2 && applied->egress[1].host == "c.example");
    REQUIRE(applied->agent_argv == cli.agent_argv);
    REQUIRE(applied->provider_secret->locator == "PROFILE_KEY");

    cli.workspace = std::filesystem::path{"/cli-ws"};
    cli.agent_preset = "codex";
    cli.bridge_port = 1234;
    applied = glove::run::apply_launch_profile(*parsed, cli, "/home/u");
    REQUIRE(applied.has_value());
    REQUIRE(applied->workspace == std::filesystem::path{"/cli-ws"});
    REQUIRE(applied->agent_preset == "codex");
    REQUIRE(applied->bridge_port == 1234);

    REQUIRE(!glove::run::apply_launch_profile(*parsed, cli, "").has_value());
    REQUIRE(!glove::run::apply_launch_profile(*parsed, cli, "relative").has_value());
    return 0;
}

class temporary_tree {
public:
    temporary_tree() {
        std::error_code ec;
        const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
        std::string pattern = (base / "glove_profile_test_XXXXXX").string();
        if (!ec && ::mkdtemp(pattern.data()) != nullptr) {
            path_ = pattern;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

    ~temporary_tree() {
        if (!path_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto write_file(const std::filesystem::path& path, std::string_view text, mode_t mode) -> bool {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        return false;
    }
    const bool ok = ::fchmod(fd, mode) == 0 &&
                    ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ::close(fd);
    return ok;
}

auto loads_only_private_files(const temporary_tree& tree) -> int {
    const auto good = tree.path() / "good.yaml";
    REQUIRE(write_file(good, "version: 1\nread: [/a]\n", 0600));
    REQUIRE(glove::run::load_launch_profile_file(good).has_value());

    const auto shared = tree.path() / "shared.yaml";
    REQUIRE(write_file(shared, "version: 1\n", 0644));
    const auto shared_result = glove::run::load_launch_profile_file(shared);
    REQUIRE(!shared_result && shared_result.error().contains("mode 0600"));

    const auto link = tree.path() / "link.yaml";
    std::error_code ec;
    std::filesystem::create_symlink(good, link, ec);
    REQUIRE(!ec);
    const auto link_result = glove::run::load_launch_profile_file(link);
    REQUIRE(!link_result && link_result.error().contains("symbolic link"));

    const auto hard = tree.path() / "hard.yaml";
    std::filesystem::create_hard_link(good, hard, ec);
    REQUIRE(!ec);
    REQUIRE(!glove::run::load_launch_profile_file(hard).has_value());
    REQUIRE(!glove::run::load_launch_profile_file(good).has_value());

    const auto big = tree.path() / "big.yaml";
    REQUIRE(write_file(big, std::string(glove::run::max_launch_profile_bytes + 1, '#'), 0600));
    REQUIRE(!glove::run::load_launch_profile_file(big).has_value());

    const auto missing = glove::run::load_launch_profile_file(tree.path() / "missing.yaml");
    REQUIRE(!missing && missing.error().starts_with("no profile at "));
    return 0;
}

auto refuses_glove_roots(const temporary_tree& tree) -> int {
    const auto config = tree.path() / "config" / "glove";
    std::error_code ec;
    std::filesystem::create_directories(config, ec);
    REQUIRE(!ec);
    const std::vector<std::filesystem::path> roots{config};
    const auto check = [&roots](std::vector<std::string> exposed) {
        return glove::run::refuse_glove_root_exposure(exposed, roots).has_value();
    };
    REQUIRE(!check({(config / "profiles").string()}));
    REQUIRE(!check({config.string()}));
    REQUIRE(!check({(config.string() + "/")}));
    REQUIRE(!check({(tree.path() / "config").string()}));
    REQUIRE(!check({tree.path().string()}));
    REQUIRE(!check({"/"}));
    REQUIRE(check({(tree.path() / "config" / "glove-other").string()}));
    REQUIRE(check({(tree.path() / "workspace").string()}));
    REQUIRE(check({}));

    // A symlink that leads into the root is refused by its resolved form.
    const auto alias = tree.path() / "alias";
    std::filesystem::create_directory_symlink(config, alias, ec);
    REQUIRE(!ec);
    REQUIRE(!check({alias.string()}));
    REQUIRE(!check({(alias / "profiles").string()}));

    // The real roots come from XDG and the account's home.
    REQUIRE(!glove::run::protected_glove_roots().empty());
    return 0;
}

} // namespace

int main() {
    for (auto* step :
         {parses_full_profile,
          refuses_ambiguous_yaml,
          accepts_plain_subtleties,
          parses_system_services,
          layers_command_line}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    const temporary_tree tree;
    REQUIRE(!tree.path().empty());
    for (auto* step : {loads_only_private_files, refuses_glove_roots}) {
        if (const int failed = step(tree); failed != 0) {
            return failed;
        }
    }
    std::printf("launch profile ok\n");
    return 0;
}
