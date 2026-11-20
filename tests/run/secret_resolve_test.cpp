// Secret references parse strictly and round-trip; resolution reads env and
// owner-only single-link files, strips one trailing newline, refuses files
// the sandbox could reach, refuses values that are not one token, and never
// puts the value in an error.

#include "glove/run/secret_reference.hpp"

#include "secret_resolve.hpp"

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
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::run::parse_secret_reference;
using glove::run::secret_source;
using glove::run::detail::resolve_secret;

auto parses_references() -> int {
    for (const std::string_view text : {
             "env://ANTHROPIC_API_KEY",
             "file:///etc/glove/key",
             "file://~/.config/anthropic/key",
             "keychain://glove/anthropic",
             "keychain://com.example.svc/me+work@example.com",
         }) {
        const auto parsed = parse_secret_reference(text);
        REQUIRE(parsed.has_value());
        REQUIRE(glove::run::format_secret_reference(*parsed) == text);
    }
    const auto keychain = parse_secret_reference("keychain://glove/anthropic");
    REQUIRE(keychain->source == secret_source::keychain);
    REQUIRE(keychain->locator == "glove" && keychain->account == "anthropic");
    for (const std::string_view text : {
             "",
             "ANTHROPIC_API_KEY",
             "env://",
             "env://1BAD",
             "env://A-B",
             "file://relative/key",
             "file://~",
             "file:///dir/",
             "keychain://glove",
             "keychain:///anthropic",
             "keychain://glove/",
             "keychain://glove/a/b",
             "keychain://glo ve/a",
             "op://vault/item/field",
             "https://example.com/key",
             "env://A\nB",
         }) {
        REQUIRE(!parse_secret_reference(text).has_value());
    }
    REQUIRE(!parse_secret_reference("env://" + std::string(2000, 'A')).has_value());
    return 0;
}

class temporary_tree {
public:
    temporary_tree() {
        std::error_code ec;
        const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
        std::string pattern = (base / "glove_secret_test_XXXXXX").string();
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

auto resolves_env() -> int {
    const auto reference = *parse_secret_reference("env://GLOVE_SECRET_TEST_VALUE");
    ::unsetenv("GLOVE_SECRET_TEST_VALUE");
    REQUIRE(!resolve_secret(reference, "/", {}).has_value());
    ::setenv("GLOVE_SECRET_TEST_VALUE", "sk-test-123", 1);
    REQUIRE(resolve_secret(reference, "/", {}) == "sk-test-123");
    ::setenv("GLOVE_SECRET_TEST_VALUE", "two words", 1);
    const auto spaced = resolve_secret(reference, "/", {});
    REQUIRE(!spaced && !spaced.error().contains("two words"));
    ::unsetenv("GLOVE_SECRET_TEST_VALUE");
    return 0;
}

auto resolves_files(const temporary_tree& tree) -> int {
    const auto keys = tree.path() / "keys";
    std::error_code ec;
    std::filesystem::create_directories(keys, ec);
    REQUIRE(!ec);
    const auto key = keys / "provider";
    REQUIRE(write_file(key, "sk-file-secret\n", 0600));
    const auto reference = *parse_secret_reference("file://" + key.string());
    REQUIRE(resolve_secret(reference, "/", {}) == "sk-file-secret");

    // Home-relative references expand against the given home only.
    const auto relative = *parse_secret_reference("file://~/keys/provider");
    REQUIRE(resolve_secret(relative, tree.path(), {}) == "sk-file-secret");
    REQUIRE(!resolve_secret(relative, "", {}).has_value());

    // A file inside any grant is refused, also through a symlinked grant.
    const std::vector<std::string> exposing{keys.string()};
    const auto exposed = resolve_secret(reference, "/", exposing);
    REQUIRE(!exposed && exposed.error().contains("sandbox can reach"));
    const std::vector<std::string> parent{tree.path().string()};
    REQUIRE(!resolve_secret(reference, "/", parent).has_value());
    const auto alias = tree.path() / "alias";
    std::filesystem::create_directory_symlink(keys, alias, ec);
    REQUIRE(!ec);
    const std::vector<std::string> aliased{alias.string()};
    REQUIRE(!resolve_secret(reference, "/", aliased).has_value());
    const std::vector<std::string> sibling{(tree.path() / "keys-other").string()};
    REQUIRE(resolve_secret(reference, "/", sibling).has_value());

    const auto loose = keys / "loose";
    REQUIRE(write_file(loose, "sk-loose", 0640));
    const auto loose_result =
        resolve_secret(*parse_secret_reference("file://" + loose.string()), "/", {});
    REQUIRE(!loose_result && !loose_result.error().contains("sk-loose"));

    const auto link = keys / "link";
    std::filesystem::create_symlink(key, link, ec);
    REQUIRE(!ec);
    REQUIRE(!resolve_secret(*parse_secret_reference("file://" + link.string()), "/", {}));

    const auto hard = keys / "hard";
    std::filesystem::create_hard_link(key, hard, ec);
    REQUIRE(!ec);
    REQUIRE(!resolve_secret(reference, "/", {}).has_value());
    std::filesystem::remove(hard, ec);
    REQUIRE(resolve_secret(reference, "/", {}).has_value());

    const auto lines = keys / "lines";
    REQUIRE(write_file(lines, "sk-one\nsk-two\n", 0600));
    REQUIRE(!resolve_secret(*parse_secret_reference("file://" + lines.string()), "/", {}));
    const auto empty = keys / "empty";
    REQUIRE(write_file(empty, "", 0600));
    REQUIRE(!resolve_secret(*parse_secret_reference("file://" + empty.string()), "/", {}));
    return 0;
}

auto keychain_misses_cleanly() -> int {
    const auto missing = resolve_secret(
        *parse_secret_reference("keychain://glove-test-absent-service/absent-account"), "/", {}
    );
    REQUIRE(!missing.has_value());
#if defined(__APPLE__)
    REQUIRE(missing.error().contains("no such keychain item"));
#else
    REQUIRE(missing.error().contains("macOS only"));
#endif
    return 0;
}

} // namespace

int main() {
    for (auto* step : {parses_references, resolves_env, keychain_misses_cleanly}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    const temporary_tree tree;
    REQUIRE(!tree.path().empty());
    if (const int failed = resolves_files(tree); failed != 0) {
        return failed;
    }
    std::printf("secret resolve ok\n");
    return 0;
}
