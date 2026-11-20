// Argument-level policy: tool-name allow/deny + per-tool argument prefix
// rules. Verifies the F1 fix — `read_file` allowed by name no longer means
// the agent can read /etc/passwd.

#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto test_default_deny() -> int {
    auto eng = glove::policy::make_jsonpath_engine({});
    auto out = eng->check("fs.read_file", R"({"path":"/etc/passwd"})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    return 0;
}

auto test_name_allow_no_rules() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":"/etc/passwd"})");
    REQUIRE(out.verdict == glove::policy::decision::allow);
    return 0;
}

auto test_prefix_rule_passes() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":"/workspace/src/main.cpp"})");
    REQUIRE(out.verdict == glove::policy::decision::allow);
    return 0;
}

auto test_prefix_rule_fails() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":"/etc/passwd"})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("must start with '/workspace/'") != std::string::npos);
    return 0;
}

auto test_prefix_rule_rejects_parent_traversal() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":"/workspace/../etc/passwd"})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    return 0;
}

auto test_missing_field_denies() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"other":"x"})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("missing") != std::string::npos);
    return 0;
}

auto test_wrong_type_denies() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":42})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("not a string") != std::string::npos);
    return 0;
}

auto test_unparseable_args_denies() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", "{not json");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    return 0;
}

auto test_unterminated_malformed_args_deny_without_overread() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));

    // A libFuzzer finding against the analogous codec path. This fixed-size
    // storage deliberately has no std::string sentinel beyond the view.
    constexpr std::string_view malformed_args =
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{},\"error\":{\"code\":-32603,"
        "\"message\":\"conflicting {\"json"
        "\x9A"
        "pc\"env"
        "\x9B\x93\x90\x98"
        "e\":\"2.0\",\"id\":{\"jsonr3,pc\"\"r\":\"2.0}\",\"sid}";
    std::array<char, malformed_args.size()> frame{};
    std::ranges::copy(malformed_args, frame.begin());

    auto out = eng->check("fs.read_file", std::string_view{frame.data(), frame.size()});
    REQUIRE(out.verdict == glove::policy::decision::deny);
    return 0;
}

auto test_deny_takes_precedence() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file"};
    opts.deny = {"fs.read_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto out = eng->check("fs.read_file", R"({"path":"/workspace/x"})");
    REQUIRE(out.verdict == glove::policy::decision::deny);
    REQUIRE(out.reason.find("deny list") != std::string::npos);
    return 0;
}

auto test_multiple_rules_all_must_pass() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.write_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.write_file", .field = "path", .required_prefix = "/workspace/"},
        {.tool_name = "fs.write_file", .field = "encoding", .required_prefix = "utf-"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    auto pass =
        eng->check("fs.write_file", R"({"path":"/workspace/a","encoding":"utf-8","content":"x"})");
    REQUIRE(pass.verdict == glove::policy::decision::allow);
    auto fail = eng->check(
        "fs.write_file", R"({"path":"/workspace/a","encoding":"latin-1","content":"x"})"
    );
    REQUIRE(fail.verdict == glove::policy::decision::deny);
    REQUIRE(fail.reason.find("encoding") != std::string::npos);
    return 0;
}

auto test_other_tool_unaffected() -> int {
    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.read_file", "fs.list_dir"};
    opts.prefix_rules = {
        {.tool_name = "fs.read_file", .field = "path", .required_prefix = "/workspace/"},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));
    // list_dir has no rules; allowed regardless of args.
    auto out = eng->check("fs.list_dir", R"({"path":"/anywhere"})");
    REQUIRE(out.verdict == glove::policy::decision::allow);
    return 0;
}

auto test_prefix_rule_rejects_symlink_escapes() -> int {
    // weakly_canonical() resolves only existing components, so an in-grant
    // dangling symlink used to compare as an in-grant name while the host-side
    // open() that the rule authorizes would follow it outside the grant.
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec) /
                ("glove-policy-symlink-" + std::to_string(::getpid()));
    const auto granted = root / "ws";
    const auto outside = root / "outside";
    std::filesystem::create_directories(granted, ec);
    REQUIRE(!ec);
    std::filesystem::create_directories(outside, ec);
    REQUIRE(!ec);
    {
        std::FILE* file = std::fopen((outside / "existing").c_str(), "w");
        REQUIRE(file != nullptr);
        std::fputs("outside\n", file);
        std::fclose(file);
    }
    std::filesystem::create_symlink(outside / "newfile", granted / "dangling", ec);
    REQUIRE(!ec);
    std::filesystem::create_symlink(outside / "existing", granted / "existing", ec);
    REQUIRE(!ec);
    std::filesystem::create_symlink(granted / "loop", granted / "loop", ec);
    REQUIRE(!ec);

    glove::policy::jsonpath_options opts;
    opts.allow = {"fs.write_file"};
    opts.prefix_rules = {
        {.tool_name = "fs.write_file", .field = "path", .required_prefix = granted.string()},
    };
    auto eng = glove::policy::make_jsonpath_engine(std::move(opts));

    const auto verdict = [&eng](const std::filesystem::path& path) {
        return eng->check("fs.write_file", R"({"path":")" + path.string() + R"("})").verdict;
    };
    const auto allow = glove::policy::decision::allow;
    const auto deny = glove::policy::decision::deny;

    // A new file directly under the grant stays allowed.
    REQUIRE(verdict(granted / "new-file") == allow);
    REQUIRE(verdict(granted / "nested" / "new-file") == allow);
    // A dangling link, a self-loop, and an existing link leaving the grant deny.
    REQUIRE(verdict(granted / "dangling") == deny);
    REQUIRE(verdict(granted / "loop") == deny);
    REQUIRE(verdict(granted / "existing") == deny);
    // The target itself is still outside the grant.
    REQUIRE(verdict(outside / "newfile") == deny);

    std::filesystem::remove_all(root, ec);
    return 0;
}

} // namespace

auto main() -> int {
    if (test_default_deny() != 0)
        return 1;
    if (test_name_allow_no_rules() != 0)
        return 1;
    if (test_prefix_rule_passes() != 0)
        return 1;
    if (test_prefix_rule_fails() != 0)
        return 1;
    if (test_prefix_rule_rejects_parent_traversal() != 0)
        return 1;
    if (test_prefix_rule_rejects_symlink_escapes() != 0)
        return 1;
    if (test_missing_field_denies() != 0)
        return 1;
    if (test_wrong_type_denies() != 0)
        return 1;
    if (test_unparseable_args_denies() != 0)
        return 1;
    if (test_unterminated_malformed_args_deny_without_overread() != 0)
        return 1;
    if (test_deny_takes_precedence() != 0)
        return 1;
    if (test_multiple_rules_all_must_pass() != 0)
        return 1;
    if (test_other_tool_unaffected() != 0)
        return 1;
    return 0;
}
