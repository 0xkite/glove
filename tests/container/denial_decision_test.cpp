// Denial decision interface: the feature builder classifies and bounds what it
// counts, the heuristic arm escalates on its documented thresholds, and a
// model file loads only in the exact documented shape.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_telemetry.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <set>
#include <string>
#include <string_view>
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

using glove::container::denial_context;
using glove::container::denial_feature_builder;
using glove::container::denial_feature_count;
using glove::container::denial_feature_names;
using glove::container::denial_features;
using glove::container::denial_verdict;
using glove::container::load_denial_model;
using glove::container::make_denial_context;
using glove::container::make_heuristic_denial_decider;
using glove::container::sandbox_denial;
using std::chrono::milliseconds;

auto index_of(std::string_view name) -> std::size_t {
    const auto names = denial_feature_names();
    return static_cast<std::size_t>(std::ranges::find(names, name) - names.begin());
}

auto value(const denial_features& features, std::string_view name) -> float {
    return features.at(index_of(name));
}

auto counted(const denial_features& features, std::string_view name, double count) -> bool {
    return value(features, name) == static_cast<float>(std::log1p(count));
}

auto denial(std::string kind, std::string target) -> sandbox_denial {
    return {.kind = std::move(kind), .operation = "op", .target = std::move(target), .comm = "sh"};
}

auto context() -> denial_context {
    return {.workspace_roots = {"/Users/u/proj/"}, .home = "/Users/u"};
}

auto schema() -> int {
    const auto names = denial_feature_names();
    REQUIRE(names.size() == denial_feature_count);
    REQUIRE(std::set<std::string_view>(names.begin(), names.end()).size() == denial_feature_count);
    REQUIRE(index_of("idle_seconds") == denial_feature_count - 1);
    return 0;
}

auto target_classes() -> int {
    struct expectation {
        std::string_view kind;
        std::string_view target;
        std::string_view feature;
    };

    const std::vector<expectation> cases{
        {"file_read", "/Users/u/proj/src/a.c", "target_workspace"},
        {"file_read", "/Users/u/.gnupg/pubring.kbx", "target_home_secret"},
        {"file_read", "/Users/u/Library/Keychains/login.keychain-db", "target_home_secret"},
        {"file_read", "/Users/u/.gnupgx", "target_home_other"},
        {"file_read", "/Users/u/Documents/x", "target_home_other"},
        {"file_read", "/Users/uv/x", "target_other_path"},
        {"file_read", "/usr/lib/libz.dylib", "target_system"},
        {"file_read", "/private/tmp/x", "target_temp"},
        {"file_read", "/dev/null", "target_device"},
        {"file_read", "/Volumes/x", "target_other_path"},
        {"network", "", "target_none"},
        {"mach", "com.apple.x", "target_none"},
    };
    for (const auto& item : cases) {
        denial_feature_builder builder{context()};
        builder.observe(denial(std::string{item.kind}, std::string{item.target}), milliseconds{0});
        const auto features = builder.features(milliseconds{0});
        if (!counted(features, item.feature, 1)) {
            std::fprintf(stderr, "target %s\n", std::string{item.target}.c_str());
        }
        REQUIRE(counted(features, item.feature, 1));
        REQUIRE(counted(features, "denials", 1));
        REQUIRE(counted(features, "kind_" + std::string{item.kind}, 1));
    }

    denial_feature_builder builder{context()};
    sandbox_denial ambiguous;
    ambiguous.kind = "ambiguous";
    builder.observe(ambiguous, milliseconds{0});
    builder.observe(denial("not_a_kind", "/x"), milliseconds{0});
    const auto features = builder.features(milliseconds{0});
    REQUIRE(counted(features, "ambiguous", 1));
    REQUIRE(counted(features, "kind_other", 1));
    REQUIRE(counted(features, "target_none", 1));
    return 0;
}

auto encoded_context() -> int {
    const std::vector<std::string> roots{
        "/w/a%b/", "relative", "/", std::string(600, '/'), "/w/q\"x"
    };
    const auto made = make_denial_context(roots, "/h/\n");
    REQUIRE(made.home == "/h/%0A");
    REQUIRE(made.workspace_roots == std::vector<std::string>({"/w/a%25b", "/w/q%22x"}));
    // A target is matched in its encoded form, without encoding the roots twice.
    denial_feature_builder builder{made};
    builder.observe(denial("file_read", "/w/a%25b/f"), milliseconds{0});
    builder.observe(denial("file_read", "/h/%0A/.kube/config"), milliseconds{0});
    const auto features = builder.features(milliseconds{0});
    REQUIRE(counted(features, "target_workspace", 1));
    REQUIRE(counted(features, "target_home_secret", 1));
    // A context that is not encoded text is ignored, not re-encoded.
    denial_feature_builder raw{{.workspace_roots = {"/w/a b\"c"}, .home = "/h"}};
    raw.observe(denial("file_read", "/w/a b%22c/f"), milliseconds{0});
    REQUIRE(counted(raw.features(milliseconds{0}), "target_other_path", 1));
    return 0;
}

auto writes() -> int {
    denial_feature_builder builder{context()};
    builder.observe(denial("file_write", "/Users/u/proj/a"), milliseconds{0});
    builder.observe(denial("file_write", "/private/tmp/a"), milliseconds{0});
    builder.observe(denial("file_write", "/Users/u/.zshrc"), milliseconds{0});
    builder.observe(denial("file_write", "/Library/LaunchAgents/x.plist"), milliseconds{0});
    builder.observe(denial("file_read", "/Users/u/.zshrc"), milliseconds{0});
    REQUIRE(counted(builder.features(milliseconds{0}), "write_outside_workspace", 2));
    return 0;
}

auto rates_and_time() -> int {
    denial_feature_builder builder{context()};
    for (int at = 0; at != 40; ++at) {
        builder.observe(denial("file_read", "/x/" + std::to_string(at)), milliseconds{2000 + at});
    }
    // Time never runs backwards.
    builder.observe(denial("file_read", "/x/late"), milliseconds{10});
    auto now = builder.features(milliseconds{2039});
    REQUIRE(counted(now, "rate_1s", 41));
    REQUIRE(counted(now, "rate_10s", 41));
    REQUIRE(counted(now, "distinct_targets", 41));
    REQUIRE(counted(now, "distinct_comms", 1));
    REQUIRE(counted(now, "first_denial_seconds", 2.0));
    const auto later = builder.features(milliseconds{7039});
    REQUIRE(counted(later, "rate_1s", 0));
    REQUIRE(counted(later, "rate_10s", 41));
    REQUIRE(counted(later, "idle_seconds", 5.0));
    REQUIRE(counted(later, "elapsed_seconds", 7.039));
    REQUIRE(counted(builder.features(milliseconds{20000}), "rate_10s", 0));
    REQUIRE(builder.observed() == 41);
    return 0;
}

auto bounds() -> int {
    denial_feature_builder builder{context()};
    for (int index = 0; index != 5000; ++index) {
        auto item = denial("file_read", "/x/" + std::to_string(index));
        item.target_truncated = true;
        item.duplicate_reports = 2;
        builder.observe(item, milliseconds{0});
    }
    const auto features = builder.features(milliseconds{0});
    REQUIRE(counted(features, "distinct_targets", 1024));
    REQUIRE(counted(features, "rate_10s", 4096));
    REQUIRE(counted(features, "truncated_targets", 5000));
    REQUIRE(counted(features, "duplicate_reports", 10000));
    REQUIRE(std::ranges::all_of(features, [](float x) { return std::isfinite(x) && x >= 0.0F; }));
    return 0;
}

auto heuristic() -> int {
    const auto arm = make_heuristic_denial_decider();
    REQUIRE(arm->arm() == "heuristic");
    const auto verdict = [&](const std::vector<sandbox_denial>& items) {
        denial_feature_builder builder{context()};
        for (const auto& item : items) {
            builder.observe(item, milliseconds{0});
        }
        return arm->decide(builder.features(milliseconds{0})).verdict;
    };
    const auto secret = denial("file_read", "/Users/u/.kube/config");
    REQUIRE(verdict({}) == denial_verdict::proceed);
    REQUIRE(verdict({denial("file_read", "/Users/u/proj/x")}) == denial_verdict::proceed);
    REQUIRE(verdict({secret}) == denial_verdict::flag);
    REQUIRE(verdict({secret, secret, secret}) == denial_verdict::terminate);
    REQUIRE(verdict({secret, denial("network", "")}) == denial_verdict::terminate);
    REQUIRE(
        verdict({secret, denial("file_write", "/Users/u/.zshrc")}) == denial_verdict::terminate
    );
    REQUIRE(
        verdict(std::vector(40, denial("file_read", "/Users/u/proj/x"))) == denial_verdict::flag
    );
    REQUIRE(
        verdict(std::vector(200, denial("file_read", "/Users/u/proj/x"))) ==
        denial_verdict::terminate
    );
    return 0;
}

struct model_text {
    std::string format = R"("glove-denial-model")";
    std::string version = "1";
    std::string schema = "1";
    std::string features;
    std::string type = R"("logistic")";
    std::string bias = "-4";
    std::string weights;
    std::string trees = "[]";
    std::string flag = "0.5";
    std::string terminate = "0.9";
    std::string extra;

    model_text() {
        features = "[";
        for (const auto name : denial_feature_names()) {
            features += (features.size() > 1 ? ",\"" : "\"") + std::string{name} + "\"";
        }
        features += "]";
        weights = weight_list({});
    }

    // All zero except the named entries.
    static auto weight_list(const std::vector<std::pair<std::size_t, std::string>>& set)
        -> std::string {
        std::vector<std::string> items(denial_feature_count, "0");
        for (const auto& [index, weight] : set) {
            items.at(index) = weight;
        }
        std::string out = "[";
        for (const auto& item : items) {
            out += (out.size() > 1 ? "," : "") + item;
        }
        return out + "]";
    }

    [[nodiscard]] auto text() const -> std::string {
        return R"({"format":)" + format + R"(,"version":)" + version + R"(,"feature_schema":)" +
               schema + R"(,"features":)" + features + R"(,"type":)" + type + R"(,"bias":)" + bias +
               R"(,"weights":)" + weights + R"(,"trees":)" + trees + R"(,"flag_threshold":)" +
               flag + R"(,"terminate_threshold":)" + terminate + extra + "}";
    }
};

auto models() -> int {
    // Logistic: score = sigmoid(-4 + 4 * target_home_secret).
    model_text logistic;
    logistic.weights = model_text::weight_list({{index_of("target_home_secret"), "4"}});
    auto loaded = load_denial_model(logistic.text());
    REQUIRE(loaded.has_value());
    const auto& model = **loaded;
    REQUIRE(model.arm() == "model");
    denial_features features{};
    auto decision = model.decide(features);
    REQUIRE(decision.verdict == denial_verdict::proceed);
    REQUIRE(std::fabs(decision.score - (1.0F / (1.0F + std::exp(4.0F)))) < 1e-6F);
    features.at(index_of("target_home_secret")) = 1.0F;
    REQUIRE(model.decide(features).verdict == denial_verdict::flag);
    features.at(index_of("target_home_secret")) = 2.0F;
    REQUIRE(model.decide(features).verdict == denial_verdict::terminate);

    // One stump on rate_10s, plus a leaf-only tree.
    model_text trees;
    trees.type = R"("gbdt")";
    trees.weights = "[]";
    trees.bias = "0";
    trees.trees = R"([{"nodes":[{"feature":30,"threshold":3,"left":1,"right":2,"value":0},)"
                  R"({"feature":-1,"threshold":0,"left":0,"right":0,"value":-5},)"
                  R"({"feature":-1,"threshold":0,"left":0,"right":0,"value":4}]},)"
                  R"({"nodes":[{"feature":-1,"threshold":0,"left":0,"right":0,"value":1}]}])";
    auto tree_model = load_denial_model(trees.text());
    REQUIRE(tree_model.has_value());
    REQUIRE(index_of("rate_10s") == 30);
    denial_features calm{};
    denial_features burst{};
    burst.at(30) = 5.0F;
    REQUIRE((*tree_model)->decide(calm).verdict == denial_verdict::proceed);
    REQUIRE((*tree_model)->decide(burst).verdict == denial_verdict::terminate);
    return 0;
}

auto rejected(const model_text& model) -> bool {
    return !load_denial_model(model.text()).has_value();
}

template<typename Edit> auto rejected_after(Edit edit) -> bool {
    model_text model;
    edit(model);
    return rejected(model);
}

auto tree_model(const std::string& nodes) -> model_text {
    model_text model;
    model.type = R"("gbdt")";
    model.weights = "[]";
    model.trees = R"([{"nodes":)" + nodes + "}]";
    return model;
}

auto malformed_models() -> int {
    const model_text base;
    REQUIRE(load_denial_model(base.text()).has_value());
    REQUIRE(!load_denial_model("").has_value());
    REQUIRE(!load_denial_model(base.text() + "}").has_value());
    REQUIRE(!load_denial_model(base.text() + "x").has_value());
    REQUIRE(!load_denial_model(std::string((std::size_t{1} << 20U) + 1, ' ')).has_value());

    REQUIRE(rejected_after([](model_text& m) { m.format = R"("other")"; }));
    REQUIRE(rejected_after([](model_text& m) { m.version = "2"; }));
    REQUIRE(rejected_after([](model_text& m) { m.schema = "2"; }));
    REQUIRE(rejected_after([](model_text& m) { m.type = R"("forest")"; }));
    REQUIRE(rejected_after([](model_text& m) { m.extra = R"(,"note":1)"; }));
    REQUIRE(rejected_after([](model_text& m) { m.flag = "0"; }));
    REQUIRE(rejected_after([](model_text& m) { m.terminate = "0.4"; }));
    REQUIRE(rejected_after([](model_text& m) { m.bias = "1e39"; }));
    REQUIRE(rejected_after([](model_text& m) { m.weights = "[0]"; }));
    REQUIRE(rejected_after([](model_text& m) {
        m.features = m.features.substr(0, m.features.rfind(',')) + "]";
    }));
    REQUIRE(rejected_after([](model_text& m) {
        // Swap the first two names.
        const auto first = m.features.find(',');
        const auto second = m.features.find(',', first + 1);
        m.features = "[" + m.features.substr(first + 1, second - first - 1) + "," +
                     m.features.substr(1, first - 1) + m.features.substr(second);
    }));
    REQUIRE(rejected_after([](model_text& m) {
        m.trees = R"([{"nodes":[{"feature":-1,"threshold":0,"left":0,"right":0,"value":1}]}])";
    }));

    const std::string leaf = R"({"feature":-1,"threshold":0,"left":0,"right":0,"value":1})";
    REQUIRE(load_denial_model(tree_model("[" + leaf + "]").text()).has_value());
    REQUIRE(rejected(tree_model("[]")));
    // A child that points back to its parent would never end.
    REQUIRE(rejected(
        tree_model(R"([{"feature":0,"threshold":0,"left":0,"right":1,"value":0},)" + leaf + "]")
    ));
    REQUIRE(rejected(
        tree_model(R"([{"feature":0,"threshold":0,"left":1,"right":2,"value":0},)" + leaf + "]")
    ));
    REQUIRE(rejected(
        tree_model(R"([{"feature":34,"threshold":0,"left":1,"right":1,"value":0},)" + leaf + "]")
    ));
    REQUIRE(rejected(
        tree_model(R"([{"feature":-2,"threshold":0,"left":1,"right":1,"value":0},)" + leaf + "]")
    ));
    std::string many = "[";
    for (int index = 0; index != 256; ++index) {
        many += (index == 0 ? "" : ",") + leaf;
    }
    REQUIRE(rejected(tree_model(many + "]")));
    auto no_trees = tree_model("[" + leaf + "]");
    no_trees.trees = "[]";
    REQUIRE(rejected(no_trees));
    return 0;
}

} // namespace

int main() {
    for (auto* step :
         {schema,
          target_classes,
          encoded_context,
          writes,
          rates_and_time,
          bounds,
          heuristic,
          models,
          malformed_models}) {
        if (const int failed = step(); failed != 0) {
            return failed;
        }
    }
    std::printf("denial decision ok\n");
    return 0;
}
