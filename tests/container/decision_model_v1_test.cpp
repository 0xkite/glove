// Cross-language golden vector parity test for `sage.decision-model.v1`
// (Rust `sage-core` <-> C++20 `glove::container`).

#include "glove/container/decision_model_v1.hpp"

#include <glaze/glaze.hpp>

#include <cmath>
#include <cstdio>
#include <fstream>
#include <limits>
#include <sstream>
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

auto close_enough(double actual, double expected) -> bool {
    return std::abs(actual - expected) <= 1e-12;
}

auto parse_decision(std::string_view s) -> glove::container::decision_kind_v1 {
    if (s == "accept") {
        return glove::container::decision_kind_v1::accept;
    }
    if (s == "reject") {
        return glove::container::decision_kind_v1::reject;
    }
    return glove::container::decision_kind_v1::abstain;
}

auto test_golden_vectors(const std::string& path) -> int {
    std::ifstream ifs{path};
    REQUIRE(ifs.good());
    std::ostringstream ss;
    ss << ifs.rdbuf();
    const std::string raw = ss.str();

    glz::generic root;
    REQUIRE(!glz::read_json(root, raw));
    REQUIRE(root.is_object());
    const auto& suite = root.get<glz::generic::object_t>();
    const auto& cases = suite.at("cases").get<glz::generic::array_t>();
    REQUIRE(cases.size() >= 4U);

    for (const auto& cv : cases) {
        const auto& c = cv.get<glz::generic::object_t>();
        const std::string name = c.at("name").get<std::string>();
        const std::string pinned = c.at("expected_content_digest").get<std::string>();

        std::string artifact_json;
        REQUIRE(!glz::write_json(c.at("artifact"), artifact_json));

        auto loaded = glove::container::load_decision_model_v1(artifact_json, pinned);
        if (!loaded) {
            std::fprintf(stderr, "case %s failed load: %s\n", name.c_str(), loaded.error().c_str());
            return 1;
        }

        std::vector<double> features;
        for (const auto& fv : c.at("features").get<glz::generic::array_t>()) {
            features.push_back(fv.get<double>());
        }

        const auto& ev = c.at("evidence").get<glz::generic::object_t>();
        const glove::container::evidence_counts_v1 evidence{
            .successes = static_cast<std::uint64_t>(ev.at("successes").get<double>()),
            .failures = static_cast<std::uint64_t>(ev.at("failures").get<double>()),
            .exposures = static_cast<std::uint64_t>(ev.at("exposures").get<double>()),
            .skip_weight = ev.at("skip_weight").get<double>(),
        };
        const auto top_n = static_cast<std::size_t>(c.at("top_n").get<double>());

        auto out = glove::container::evaluate_decision_model_v1(*loaded, features, evidence, top_n);
        if (!out) {
            std::fprintf(stderr, "case %s failed eval: %s\n", name.c_str(), out.error().c_str());
            return 1;
        }

        REQUIRE(close_enough(out->raw_score, c.at("expected_raw_score").get<double>()));
        REQUIRE(close_enough(out->calibrated_prob, c.at("expected_calibrated_prob").get<double>()));
        REQUIRE(close_enough(out->blended_score, c.at("expected_blended_score").get<double>()));
        REQUIRE(close_enough(out->wilson_lower, c.at("expected_wilson_lower").get<double>()));
        REQUIRE(close_enough(out->wilson_upper, c.at("expected_wilson_upper").get<double>()));
        REQUIRE(close_enough(out->evidence_weight, c.at("expected_evidence_weight").get<double>()));
        REQUIRE(out->decision == parse_decision(c.at("expected_decision").get<std::string>()));
        REQUIRE(out->trigger_refinement == c.at("expected_trigger_refinement").get<bool>());

        const auto& exp_contribs = c.at("expected_top_contributions").get<glz::generic::array_t>();
        REQUIRE(out->top_contributions.size() == exp_contribs.size());
        for (std::size_t i = 0; i < exp_contribs.size(); ++i) {
            const auto& ec = exp_contribs[i].get<glz::generic::object_t>();
            REQUIRE(out->top_contributions[i].feature == ec.at("feature").get<std::string>());
            REQUIRE(close_enough(out->top_contributions[i].value, ec.at("value").get<double>()));
            REQUIRE(close_enough(
                out->top_contributions[i].contribution, ec.at("contribution").get<double>()
            ));
        }
    }
    // Tamper test: mutate one weight in golden vector #0 while leaving
    // content_digest untouched -> must fail SHA-256 verification.
    {
        auto tampered = cases[0].get<glz::generic::object_t>().at("artifact");
        auto& tobj = tampered.get<glz::generic::object_t>();
        auto& model = tobj.at("model").get<glz::generic::object_t>();
        model.at("bias") = 9.99;
        std::string tampered_json;
        REQUIRE(!glz::write_json(tampered, tampered_json));
        const std::string pinned =
            cases[0].get<glz::generic::object_t>().at("expected_content_digest").get<std::string>();
        REQUIRE(!glove::container::load_decision_model_v1(tampered_json, pinned).has_value());
    }

    return 0;
}

auto test_fail_closed(const std::string& fixture_path) -> int {
    // Oversized artifact
    const std::string huge(glove::container::max_decision_model_bytes + 1U, ' ');
    REQUIRE(!glove::container::load_decision_model_v1(huge).has_value());

    // Cyclic GBDT
    const std::string cyclic = R"({
        "schema": "sage.decision-model.v1",
        "artifact_version": 1,
        "model_id": "cyclic",
        "task_domain": "glove_denial",
        "feature_schema": {"version": "v1", "digest": "d", "numeric_features": ["f0"]},
        "model": {
            "kind": "gbdt",
            "base_score": 0.0,
            "learning_rate": 0.5,
            "trees": [{"nodes": [
                {"feature_index": 0, "threshold": 0.5, "left": 0, "right": 1, "value": 0.0},
                {"feature_index": -1, "threshold": 0.0, "left": 0, "right": 0, "value": 1.0}
            ]}]
        },
        "content_digest": "abc"
    })";
    REQUIRE(!glove::container::load_decision_model_v1(cyclic).has_value());

    // Load verified golden linear artifact, then fail closed on wrong pin, NaN input, and short
    // vector.
    std::ifstream ifs{fixture_path};
    REQUIRE(ifs.good());
    std::ostringstream ss;
    ss << ifs.rdbuf();
    glz::generic root;
    REQUIRE(!glz::read_json(root, ss.str()));
    const auto& c0 = root.get<glz::generic::object_t>()
                         .at("cases")
                         .get<glz::generic::array_t>()[0]
                         .get<glz::generic::object_t>();
    std::string valid;
    REQUIRE(!glz::write_json(c0.at("artifact"), valid));
    const std::string pinned = c0.at("expected_content_digest").get<std::string>();

    REQUIRE(!glove::container::load_decision_model_v1(valid, "wrong").has_value());
    auto loaded = glove::container::load_decision_model_v1(valid, pinned);
    REQUIRE(loaded.has_value());

    const std::vector<double> nan_feat{0.5, std::numeric_limits<double>::quiet_NaN(), 0.2, 0.1};
    REQUIRE(!glove::container::evaluate_decision_model_v1(*loaded, nan_feat, {}).has_value());
    const std::vector<double> short_feat{0.5};
    REQUIRE(!glove::container::evaluate_decision_model_v1(*loaded, short_feat, {}).has_value());
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <decision_model_v1_vectors.json>\n", argv[0]);
        return 2;
    }
    if (test_golden_vectors(argv[1]) != 0) {
        return 1;
    }
    if (test_fail_closed(argv[1]) != 0) {
        return 1;
    }
    return 0;
}
