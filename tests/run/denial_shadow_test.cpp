// The shadow decider's model file is loaded only when it is one regular
// file that this user or root owns, that no other user can write, that the
// sandbox cannot reach, and that is a valid model for this feature schema.

#include "denial_shadow.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
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

using glove::run::detail::load_shadow_decider;

// A logistic model over the current schema that scores only the decoy count.
auto model_text(std::string_view schema = {}) -> std::string {
    std::string features;
    std::string weights;
    for (const auto name : glove::container::denial_feature_names()) {
        features += (features.empty() ? "\"" : ",\"") + std::string{name} + "\"";
        weights += (weights.empty() ? "" : ",") + std::string{name == "target_decoy" ? "20" : "0"};
    }
    const std::string version =
        schema.empty() ? std::to_string(glove::container::denial_feature_schema_version)
                       : std::string{schema};
    return R"({"format":"glove-denial-model","version":1,"feature_schema":)" + version +
           R"(,"features":[)" + features + R"(],"type":"logistic","bias":-5,"weights":[)" +
           weights + R"(],"trees":[],"flag_threshold":0.5,"terminate_threshold":0.9})";
}

auto write(const std::filesystem::path& path, std::string_view text, mode_t mode = 0600) -> bool {
    {
        std::ofstream stream{path, std::ios::binary | std::ios::trunc};
        stream << text;
        if (!stream) {
            return false;
        }
    }
    return ::chmod(path.c_str(), mode) == 0;
}

auto refused(
    const std::filesystem::path& path, std::string_view why, std::vector<std::string> exposed = {}
) -> bool {
    const auto loaded = load_shadow_decider(path, exposed);
    if (loaded || !loaded.error().contains(why) || !loaded.error().starts_with("denial model: ")) {
        std::fprintf(
            stderr,
            "expected '%.*s', got '%s'\n",
            static_cast<int>(why.size()),
            why.data(),
            loaded ? "a decider" : loaded.error().c_str()
        );
        return false;
    }
    return true;
}

auto run(const std::filesystem::path& root) -> int {
    const auto model = root / "model.json";
    REQUIRE(write(model, model_text()));
    const auto loaded = load_shadow_decider(model, {});
    REQUIRE(loaded.has_value());
    REQUIRE((*loaded)->arm() == "model");
    glove::container::denial_features features{};
    REQUIRE((*loaded)->decide(features).verdict == glove::container::denial_verdict::proceed);
    // A relative path resolves against the working directory.
    REQUIRE(::chdir(root.c_str()) == 0);
    REQUIRE(load_shadow_decider("model.json", {}).has_value());

    REQUIRE(refused(root / "absent.json", "no such file"));
    REQUIRE(refused(root, "not one regular file"));
    const auto link = root / "link.json";
    REQUIRE(::symlink(model.c_str(), link.c_str()) == 0);
    REQUIRE(refused(link, "cannot open the file"));
    const auto twin = root / "twin.json";
    REQUIRE(::link(model.c_str(), twin.c_str()) == 0);
    REQUIRE(refused(model, "not one regular file"));
    REQUIRE(::unlink(twin.c_str()) == 0);
    REQUIRE(load_shadow_decider(model, {}).has_value());

    const auto shared = root / "shared.json";
    REQUIRE(write(shared, model_text(), 0620));
    REQUIRE(refused(shared, "another user could have written"));
    REQUIRE(::chmod(shared.c_str(), 0602) == 0);
    REQUIRE(refused(shared, "another user could have written"));
    REQUIRE(::chmod(shared.c_str(), 0644) == 0);
    REQUIRE(load_shadow_decider(shared, {}).has_value());

    const auto empty = root / "empty.json";
    REQUIRE(write(empty, ""));
    REQUIRE(refused(empty, "empty or too large"));
    const auto huge = root / "huge.json";
    REQUIRE(write(huge, std::string(glove::container::max_denial_model_bytes + 1, ' ')));
    REQUIRE(refused(huge, "empty or too large"));
    const auto garbage = root / "garbage.json";
    REQUIRE(write(garbage, "{not json"));
    REQUIRE(refused(garbage, "not a valid model"));
    const auto stale = root / "stale.json";
    REQUIRE(write(stale, model_text("1")));
    REQUIRE(refused(stale, "not a valid model"));

    // Anything the sandbox can reach is refused: the file's directory, the
    // file itself, and a grant that reaches it through a symlink.
    REQUIRE(refused(model, "sandbox can reach", {root.string()}));
    REQUIRE(refused(model, "sandbox can reach", {model.string()}));
    const auto alias = root.parent_path() / (root.filename().string() + "-alias");
    REQUIRE(::symlink(root.c_str(), alias.c_str()) == 0);
    const bool through_alias = refused(model, "sandbox can reach", {alias.string()});
    const bool named_by_alias = refused(alias / "model.json", "sandbox can reach", {root.string()});
    REQUIRE(::unlink(alias.c_str()) == 0);
    REQUIRE(through_alias && named_by_alias);
    const std::vector<std::string> elsewhere{(root / "other").string(), "/nonexistent"};
    REQUIRE(load_shadow_decider(model, elsewhere).has_value());
    return 0;
}

} // namespace

int main() {
    std::error_code ec;
    const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
    std::string pattern = (base / "glove_denial_shadow_test_XXXXXX").string();
    if (ec || ::mkdtemp(pattern.data()) == nullptr) {
        return 1;
    }
    const std::filesystem::path root{pattern};
    const int failed = run(root);
    std::filesystem::remove_all(root, ec);
    if (failed == 0) {
        std::printf("denial shadow ok\n");
    }
    return failed;
}
