#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace glove::container {

constexpr std::string_view decision_model_schema_v1 = "sage.decision-model.v1";
constexpr std::size_t max_decision_model_bytes = 512U * 1024U;
constexpr std::size_t max_decision_model_features = 256U;
constexpr std::size_t max_decision_model_trees = 256U;
constexpr std::size_t max_decision_model_nodes_per_tree = 127U;
constexpr std::size_t max_decision_model_tree_depth = 16U;
constexpr std::size_t max_decision_model_knots = 32U;

struct decision_feature_schema_v1 {
    std::string version;
    std::string digest;
    std::vector<std::string> numeric_features;
};

struct piecewise_linear_term_v1 {
    std::size_t feature_index = 0;
    std::vector<double> knots;
    std::vector<double> values;
};

struct gbdt_node_v1 {
    std::int32_t feature_index = -1;
    double threshold = 0.0;
    std::uint32_t left = 0;
    std::uint32_t right = 0;
    double value = 0.0;
    bool missing_left = true;

    [[nodiscard]] auto is_leaf() const noexcept -> bool { return feature_index < 0; }
};

struct gbdt_tree_v1 {
    std::vector<gbdt_node_v1> nodes;
};

struct linear_model_spec_v1 {
    std::vector<double> weights;
    double bias = 0.0;
};

struct piecewise_linear_model_spec_v1 {
    double bias = 0.0;
    std::vector<piecewise_linear_term_v1> terms;
};

struct gbdt_model_spec_v1 {
    double base_score = 0.0;
    double learning_rate = 1.0;
    std::vector<gbdt_tree_v1> trees;
};

struct lin_ucb_model_spec_v1 {
    std::vector<double> weights;
    double bias = 0.0;
    std::vector<double> a_inv_diag;
    double alpha = 0.0;
};

using decision_model_spec_v1 = std::variant<
    linear_model_spec_v1,
    piecewise_linear_model_spec_v1,
    gbdt_model_spec_v1,
    lin_ucb_model_spec_v1>;

enum class calibration_kind_v1 : std::uint8_t {
    identity,
    platt,
    raw_clamped,
};

struct decision_calibration_v1 {
    calibration_kind_v1 kind = calibration_kind_v1::identity;
    double a = 1.0;
    double b = 0.0;
};

struct decision_policy_v1 {
    double accept_threshold = 0.60;
    double reject_threshold = 0.35;
    double wilson_z = 1.96;
    double pseudo_count = 5.0;
    double refinement_wilson_upper_max = 0.45;
    std::uint64_t refinement_min_samples = 5;
    double refinement_score_ceiling = 0.45;
};

struct decision_model_artifact_v1 {
    std::string schema;
    std::uint32_t artifact_version = 1;
    std::string model_id;
    std::string task_domain;
    decision_feature_schema_v1 feature_schema;
    decision_model_spec_v1 model;
    decision_calibration_v1 calibration;
    decision_policy_v1 policy;
    std::string content_digest;
};

struct evidence_counts_v1 {
    std::uint64_t successes = 0;
    std::uint64_t failures = 0;
    std::uint64_t exposures = 0;
    double skip_weight = 0.15;

    [[nodiscard]] auto effective_samples() const noexcept -> double;
};

enum class decision_kind_v1 : std::uint8_t {
    accept,
    reject,
    abstain,
};

struct feature_contribution_v1 {
    std::string feature;
    double value = 0.0;
    double contribution = 0.0;
};

struct decision_output_v1 {
    std::string model_id;
    std::string content_digest;
    double raw_score = 0.0;
    double calibrated_prob = 0.0;
    double blended_score = 0.0;
    double wilson_lower = 0.0;
    double wilson_upper = 1.0;
    double evidence_weight = 0.0;
    double effective_samples = 0.0;
    decision_kind_v1 decision = decision_kind_v1::abstain;
    bool trigger_refinement = false;
    std::vector<feature_contribution_v1> top_contributions;
};

// Parse and validate a `sage.decision-model.v1` JSON artifact.
// When `pinned_digest` is non-empty, requires `artifact.content_digest == pinned_digest`.
[[nodiscard]] auto
load_decision_model_v1(std::string_view json_text, std::string_view pinned_digest = {})
    -> std::expected<decision_model_artifact_v1, std::string>;

// Evaluate a validated `sage.decision-model.v1` artifact on one feature vector
// and observed evidence counts. Fails closed on length mismatch or non-finite inputs.
[[nodiscard]] auto evaluate_decision_model_v1(
    const decision_model_artifact_v1& artifact,
    std::span<const double> features,
    const evidence_counts_v1& evidence,
    std::size_t top_n = 3
) -> std::expected<decision_output_v1, std::string>;

} // namespace glove::container
