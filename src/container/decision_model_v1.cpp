#include "glove/container/decision_model_v1.hpp"
#include "glove/container/digest.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <glaze/glaze.hpp>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace glove::container {
namespace {

using json_object = glz::generic::object_t;
using json_array = glz::generic::array_t;

auto get_field(const json_object& obj, std::string_view key) -> const glz::generic* {
    const auto it = obj.find(std::string{key});
    return it == obj.end() ? nullptr : &it->second;
}

auto read_string(const json_object& obj, std::string_view key)
    -> std::expected<std::string, std::string> {
    const auto* val = get_field(obj, key);
    if (val == nullptr || !val->is_string()) {
        return std::unexpected("missing or non-string field: " + std::string{key});
    }
    return val->get<std::string>();
}

auto read_double(const json_object& obj, std::string_view key)
    -> std::expected<double, std::string> {
    const auto* val = get_field(obj, key);
    if (val == nullptr || !val->is_number()) {
        return std::unexpected("missing or non-numeric field: " + std::string{key});
    }
    const double d = val->get<double>();
    if (!std::isfinite(d)) {
        return std::unexpected("non-finite number in field: " + std::string{key});
    }
    return d;
}

auto read_u64(const json_object& obj, std::string_view key)
    -> std::expected<std::uint64_t, std::string> {
    const auto d = read_double(obj, key);
    if (!d) {
        return std::unexpected(d.error());
    }
    if (*d < 0.0 || std::floor(*d) != *d ||
        *d >= static_cast<double>(std::numeric_limits<std::uint64_t>::max())) {
        return std::unexpected("invalid unsigned integer field: " + std::string{key});
    }
    return static_cast<std::uint64_t>(*d);
}

auto read_i32(const json_object& obj, std::string_view key)
    -> std::expected<std::int32_t, std::string> {
    const auto d = read_double(obj, key);
    if (!d) {
        return std::unexpected(d.error());
    }
    if (std::floor(*d) != *d ||
        *d < static_cast<double>(std::numeric_limits<std::int32_t>::min()) ||
        *d > static_cast<double>(std::numeric_limits<std::int32_t>::max())) {
        return std::unexpected("invalid int32 field: " + std::string{key});
    }
    return static_cast<std::int32_t>(*d);
}

auto read_double_vec(const json_object& obj, std::string_view key)
    -> std::expected<std::vector<double>, std::string> {
    const auto* val = get_field(obj, key);
    if (val == nullptr || !val->is_array()) {
        return std::unexpected("missing or non-array field: " + std::string{key});
    }
    const auto& arr = val->get<json_array>();
    std::vector<double> out;
    out.reserve(arr.size());
    for (const auto& elem : arr) {
        if (!elem.is_number()) {
            return std::unexpected("non-numeric array element in: " + std::string{key});
        }
        const double d = elem.get<double>();
        if (!std::isfinite(d)) {
            return std::unexpected("non-finite array element in: " + std::string{key});
        }
        out.push_back(d);
    }
    return out;
}

auto read_string_vec(const json_object& obj, std::string_view key)
    -> std::expected<std::vector<std::string>, std::string> {
    const auto* val = get_field(obj, key);
    if (val == nullptr || !val->is_array()) {
        return std::unexpected("missing or non-array field: " + std::string{key});
    }
    const auto& arr = val->get<json_array>();
    std::vector<std::string> out;
    out.reserve(arr.size());
    for (const auto& elem : arr) {
        if (!elem.is_string()) {
            return std::unexpected("non-string array element in: " + std::string{key});
        }
        out.push_back(elem.get<std::string>());
    }
    return out;
}

auto parse_gbdt_tree(const glz::generic& tree_val, std::size_t n_features)
    -> std::expected<gbdt_tree_v1, std::string> {
    if (!tree_val.is_object()) {
        return std::unexpected("gbdt tree is not an object");
    }
    const auto* nodes_val = get_field(tree_val.get<json_object>(), "nodes");
    if (nodes_val == nullptr || !nodes_val->is_array()) {
        return std::unexpected("gbdt tree missing nodes array");
    }
    const auto& nodes_arr = nodes_val->get<json_array>();
    const std::size_t n_nodes = nodes_arr.size();
    if (n_nodes == 0 || n_nodes > max_decision_model_nodes_per_tree) {
        return std::unexpected("gbdt tree node count out of bounds");
    }
    gbdt_tree_v1 tree;
    tree.nodes.reserve(n_nodes);
    for (const auto& nv : nodes_arr) {
        if (!nv.is_object()) {
            return std::unexpected("gbdt node is not an object");
        }
        const auto& nobj = nv.get<json_object>();
        const auto feat = read_i32(nobj, "feature_index");
        const auto thr = read_double(nobj, "threshold");
        const auto left = read_u64(nobj, "left");
        const auto right = read_u64(nobj, "right");
        const auto val = read_double(nobj, "value");
        if (!feat || !thr || !left || !right || !val) {
            return std::unexpected("malformed gbdt node");
        }
        bool missing_left = true;
        if (const auto* ml = get_field(nobj, "missing_left"); ml != nullptr) {
            if (!ml->is_boolean()) {
                return std::unexpected("gbdt node missing_left is not boolean");
            }
            missing_left = ml->get<bool>();
        }
        if (*left > std::numeric_limits<std::uint32_t>::max() ||
            *right > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected("gbdt node child index exceeds uint32 range");
        }
        tree.nodes.push_back(gbdt_node_v1{
            .feature_index = *feat,
            .threshold = *thr,
            .left = static_cast<std::uint32_t>(*left),
            .right = static_cast<std::uint32_t>(*right),
            .value = *val,
            .missing_left = missing_left,
        });
    }

    std::vector<std::size_t> depths(n_nodes, 0U);
    std::vector<bool> reachable(n_nodes, false);
    reachable[0] = true;
    for (std::size_t i = 0; i < n_nodes; ++i) {
        const auto& node = tree.nodes[i];
        if (node.is_leaf()) {
            if (node.feature_index != -1) {
                return std::unexpected("gbdt leaf node must have feature_index == -1");
            }
            continue;
        }
        if (static_cast<std::size_t>(node.feature_index) >= n_features) {
            return std::unexpected("gbdt node feature_index out of bounds");
        }
        if (node.left <= i || node.left >= n_nodes || node.right <= i || node.right >= n_nodes) {
            return std::unexpected("gbdt node child index violates acyclic DAG invariant");
        }
        if (reachable[i]) {
            const std::size_t next_depth = depths[i] + 1U;
            if (next_depth > max_decision_model_tree_depth) {
                return std::unexpected("gbdt tree exceeds max depth");
            }
            reachable[node.left] = true;
            reachable[node.right] = true;
            depths[node.left] = std::max(depths[node.left], next_depth);
            depths[node.right] = std::max(depths[node.right], next_depth);
        }
    }
    return tree;
}

auto parse_model_spec(const json_object& obj, std::size_t n_features)
    -> std::expected<decision_model_spec_v1, std::string> {
    const auto kind = read_string(obj, "kind");
    if (!kind) {
        return std::unexpected(kind.error());
    }
    if (*kind == "linear") {
        auto weights = read_double_vec(obj, "weights");
        const auto bias = read_double(obj, "bias");
        if (!weights || !bias) {
            return std::unexpected("malformed linear model");
        }
        if (weights->size() != n_features) {
            return std::unexpected("linear weights length mismatch");
        }
        return linear_model_spec_v1{.weights = std::move(*weights), .bias = *bias};
    }
    if (*kind == "piecewise_linear") {
        const auto bias = read_double(obj, "bias");
        const auto* terms_val = get_field(obj, "terms");
        if (!bias || terms_val == nullptr || !terms_val->is_array()) {
            return std::unexpected("malformed piecewise_linear model");
        }
        const auto& terms_arr = terms_val->get<json_array>();
        if (terms_arr.size() > max_decision_model_features) {
            return std::unexpected("piecewise_linear term count out of bounds");
        }
        piecewise_linear_model_spec_v1 spec{.bias = *bias, .terms = {}};
        spec.terms.reserve(terms_arr.size());
        for (const auto& tv : terms_arr) {
            if (!tv.is_object()) {
                return std::unexpected("piecewise_linear term is not an object");
            }
            const auto& tobj = tv.get<json_object>();
            const auto fi = read_u64(tobj, "feature_index");
            auto knots = read_double_vec(tobj, "knots");
            auto values = read_double_vec(tobj, "values");
            if (!fi || !knots || !values || *fi >= n_features || knots->size() < 2 ||
                knots->size() > max_decision_model_knots || knots->size() != values->size()) {
                return std::unexpected("invalid piecewise_linear term bounds");
            }
            for (std::size_t i = 1; i < knots->size(); ++i) {
                if ((*knots)[i] <= (*knots)[i - 1]) {
                    return std::unexpected("piecewise_linear knots must be strictly increasing");
                }
            }
            spec.terms.push_back(piecewise_linear_term_v1{
                .feature_index = static_cast<std::size_t>(*fi),
                .knots = std::move(*knots),
                .values = std::move(*values),
            });
        }
        return spec;
    }
    if (*kind == "gbdt") {
        const auto base_score = read_double(obj, "base_score");
        const auto lr = read_double(obj, "learning_rate");
        const auto* trees_val = get_field(obj, "trees");
        if (!base_score || !lr || trees_val == nullptr || !trees_val->is_array()) {
            return std::unexpected("malformed gbdt model");
        }
        const auto& trees_arr = trees_val->get<json_array>();
        if (trees_arr.empty() || trees_arr.size() > max_decision_model_trees) {
            return std::unexpected("gbdt tree count out of bounds");
        }
        gbdt_model_spec_v1 spec{.base_score = *base_score, .learning_rate = *lr, .trees = {}};
        spec.trees.reserve(trees_arr.size());
        for (const auto& tv : trees_arr) {
            auto parsed = parse_gbdt_tree(tv, n_features);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            spec.trees.push_back(std::move(*parsed));
        }
        return spec;
    }
    if (*kind == "lin_ucb") {
        auto weights = read_double_vec(obj, "weights");
        const auto bias = read_double(obj, "bias");
        auto a_inv_diag = read_double_vec(obj, "a_inv_diag");
        const auto alpha = read_double(obj, "alpha");
        if (!weights || !bias || !a_inv_diag || !alpha || weights->size() != n_features ||
            a_inv_diag->size() != n_features || *alpha < 0.0) {
            return std::unexpected("malformed lin_ucb model");
        }
        for (const double v : *a_inv_diag) {
            if (v < 0.0) {
                return std::unexpected("lin_ucb a_inv_diag entries must be >= 0");
            }
        }
        return lin_ucb_model_spec_v1{
            .weights = std::move(*weights),
            .bias = *bias,
            .a_inv_diag = std::move(*a_inv_diag),
            .alpha = *alpha,
        };
    }
    return std::unexpected("unsupported model kind: " + *kind);
}

auto parse_calibration(const json_object& obj)
    -> std::expected<decision_calibration_v1, std::string> {
    const auto kind = read_string(obj, "kind");
    if (!kind) {
        return std::unexpected(kind.error());
    }
    if (*kind == "identity") {
        return decision_calibration_v1{.kind = calibration_kind_v1::identity};
    }
    if (*kind == "raw_clamped") {
        return decision_calibration_v1{.kind = calibration_kind_v1::raw_clamped};
    }
    if (*kind == "platt") {
        const auto a = read_double(obj, "a");
        const auto b = read_double(obj, "b");
        if (!a || !b) {
            return std::unexpected("malformed platt calibration");
        }
        return decision_calibration_v1{.kind = calibration_kind_v1::platt, .a = *a, .b = *b};
    }
    return std::unexpected("unsupported calibration kind: " + *kind);
}

auto parse_policy(const json_object& obj) -> std::expected<decision_policy_v1, std::string> {
    const auto accept = read_double(obj, "accept_threshold");
    const auto reject = read_double(obj, "reject_threshold");
    const auto z = read_double(obj, "wilson_z");
    const auto k = read_double(obj, "pseudo_count");
    const auto ref_upper = read_double(obj, "refinement_wilson_upper_max");
    const auto ref_min = read_u64(obj, "refinement_min_samples");
    const auto ref_ceil = read_double(obj, "refinement_score_ceiling");
    if (!accept || !reject || !z || !k || !ref_upper || !ref_min || !ref_ceil) {
        return std::unexpected("malformed decision policy");
    }
    if (*reject < 0.0 || *accept > 1.0 || *reject > *accept || *z < 0.0 || *k < 0.0 ||
        *ref_upper < 0.0 || *ref_upper > 1.0 || *ref_ceil < 0.0 || *ref_ceil > 1.0) {
        return std::unexpected("decision policy thresholds out of bounds");
    }
    return decision_policy_v1{
        .accept_threshold = *accept,
        .reject_threshold = *reject,
        .wilson_z = *z,
        .pseudo_count = *k,
        .refinement_wilson_upper_max = *ref_upper,
        .refinement_min_samples = *ref_min,
        .refinement_score_ceiling = *ref_ceil,
    };
}

auto stable_sigmoid(double x) noexcept -> double {
    if (x >= 0.0) {
        return 1.0 / (1.0 + std::exp(-x));
    }
    const double ex = std::exp(x);
    return ex / (1.0 + ex);
}

auto eval_piecewise_term(const piecewise_linear_term_v1& term, double x) noexcept -> double {
    if (x <= term.knots.front()) {
        return term.values.front();
    }
    const std::size_t last = term.knots.size() - 1U;
    if (x >= term.knots[last]) {
        return term.values[last];
    }
    std::size_t lo = 0;
    std::size_t hi = last;
    while (hi - lo > 1U) {
        const std::size_t mid = lo + (hi - lo) / 2U;
        if (x < term.knots[mid]) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    const double t = (x - term.knots[lo]) / (term.knots[hi] - term.knots[lo]);
    return term.values[lo] + t * (term.values[hi] - term.values[lo]);
}

auto wilson_interval(double successes, double total, double z) noexcept
    -> std::pair<double, double> {
    if (!std::isfinite(total) || total <= 0.0) {
        return {0.0, 1.0};
    }
    const double z_clamped = std::isfinite(z) ? std::max(0.0, z) : 0.0;
    const double p_hat = std::clamp(successes / total, 0.0, 1.0);
    const double z2 = z_clamped * z_clamped;
    const double denom = 1.0 + z2 / total;
    const double centre = p_hat + z2 / (2.0 * total);
    const double margin =
        z_clamped * std::sqrt((p_hat * (1.0 - p_hat) + z2 / (4.0 * total)) / total);
    const double lo = (centre - margin) / denom;
    const double hi = (centre + margin) / denom;
    if (!std::isfinite(lo) || !std::isfinite(hi)) {
        return {0.0, 1.0};
    }
    return {
        std::clamp(lo, 0.0, 1.0),
        std::clamp(hi, 0.0, 1.0),
    };
}

auto format_rust_f64(double v) -> std::string {
    std::array<char, 64> buf{};
    const auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    if (ec != std::errc{}) {
        return "0.0";
    }
    std::string s(buf.data(), static_cast<std::size_t>(ptr - buf.data()));
    if (s.find('.') == std::string::npos && s.find('e') == std::string::npos &&
        s.find('E') == std::string::npos) {
        s += ".0";
    }
    return s;
}

auto quote_json_string(std::string_view s) -> std::string {
    std::string out;
    const auto err = glz::write_json(s, out);
    (void)err;
    return out;
}

void append_double_array(std::string& out, const std::vector<double>& vals) {
    out.push_back('[');
    for (std::size_t i = 0; i < vals.size(); ++i) {
        if (i > 0U) {
            out.push_back(',');
        }
        out += format_rust_f64(vals[i]);
    }
    out.push_back(']');
}

void append_string_array(std::string& out, const std::vector<std::string>& vals) {
    out.push_back('[');
    for (std::size_t i = 0; i < vals.size(); ++i) {
        if (i > 0U) {
            out.push_back(',');
        }
        out += quote_json_string(vals[i]);
    }
    out.push_back(']');
}

auto compute_canonical_content_digest(
    const decision_model_artifact_v1& art,
    const glz::generic* metadata
) -> std::expected<std::string, std::string> {
    std::string out;
    out.reserve(1024U);
    out += "{\"schema\":";
    out += quote_json_string(decision_model_schema_v1);
    out += ",\"artifact_version\":";
    out += std::to_string(art.artifact_version);
    out += ",\"model_id\":";
    out += quote_json_string(art.model_id);
    out += ",\"task_domain\":";
    out += quote_json_string(art.task_domain);
    out += ",\"feature_schema\":{\"version\":";
    out += quote_json_string(art.feature_schema.version);
    out += ",\"digest\":";
    out += quote_json_string(art.feature_schema.digest);
    out += ",\"numeric_features\":";
    append_string_array(out, art.feature_schema.numeric_features);
    out += "},\"model\":";

    if (const auto* lin = std::get_if<linear_model_spec_v1>(&art.model)) {
        out += "{\"kind\":\"linear\",\"weights\":";
        append_double_array(out, lin->weights);
        out += ",\"bias\":";
        out += format_rust_f64(lin->bias);
        out.push_back('}');
    } else if (const auto* pw = std::get_if<piecewise_linear_model_spec_v1>(&art.model)) {
        out += "{\"kind\":\"piecewise_linear\",\"bias\":";
        out += format_rust_f64(pw->bias);
        out += ",\"terms\":[";
        for (std::size_t i = 0; i < pw->terms.size(); ++i) {
            if (i > 0U) {
                out.push_back(',');
            }
            const auto& t = pw->terms[i];
            out += "{\"feature_index\":";
            out += std::to_string(t.feature_index);
            out += ",\"knots\":";
            append_double_array(out, t.knots);
            out += ",\"values\":";
            append_double_array(out, t.values);
            out.push_back('}');
        }
        out += "]}";
    } else if (const auto* gbdt = std::get_if<gbdt_model_spec_v1>(&art.model)) {
        out += "{\"kind\":\"gbdt\",\"base_score\":";
        out += format_rust_f64(gbdt->base_score);
        out += ",\"learning_rate\":";
        out += format_rust_f64(gbdt->learning_rate);
        out += ",\"trees\":[";
        for (std::size_t ti = 0; ti < gbdt->trees.size(); ++ti) {
            if (ti > 0U) {
                out.push_back(',');
            }
            out += "{\"nodes\":[";
            const auto& nodes = gbdt->trees[ti].nodes;
            for (std::size_t ni = 0; ni < nodes.size(); ++ni) {
                if (ni > 0U) {
                    out.push_back(',');
                }
                const auto& nd = nodes[ni];
                out += "{\"feature_index\":";
                out += std::to_string(nd.feature_index);
                out += ",\"threshold\":";
                out += format_rust_f64(nd.threshold);
                out += ",\"left\":";
                out += std::to_string(nd.left);
                out += ",\"right\":";
                out += std::to_string(nd.right);
                out += ",\"value\":";
                out += format_rust_f64(nd.value);
                out += ",\"missing_left\":";
                out += nd.missing_left ? "true" : "false";
                out.push_back('}');
            }
            out += "]}";
        }
        out += "]}";
    } else if (const auto* ucb = std::get_if<lin_ucb_model_spec_v1>(&art.model)) {
        out += "{\"kind\":\"lin_ucb\",\"weights\":";
        append_double_array(out, ucb->weights);
        out += ",\"bias\":";
        out += format_rust_f64(ucb->bias);
        out += ",\"a_inv_diag\":";
        append_double_array(out, ucb->a_inv_diag);
        out += ",\"alpha\":";
        out += format_rust_f64(ucb->alpha);
        out.push_back('}');
    }

    out += ",\"calibration\":";
    switch (art.calibration.kind) {
    case calibration_kind_v1::identity:
        out += "{\"kind\":\"identity\"}";
        break;
    case calibration_kind_v1::raw_clamped:
        out += "{\"kind\":\"raw_clamped\"}";
        break;
    case calibration_kind_v1::platt:
        out += "{\"kind\":\"platt\",\"a\":";
        out += format_rust_f64(art.calibration.a);
        out += ",\"b\":";
        out += format_rust_f64(art.calibration.b);
        out.push_back('}');
        break;
    }

    out += ",\"policy\":{\"accept_threshold\":";
    out += format_rust_f64(art.policy.accept_threshold);
    out += ",\"reject_threshold\":";
    out += format_rust_f64(art.policy.reject_threshold);
    out += ",\"wilson_z\":";
    out += format_rust_f64(art.policy.wilson_z);
    out += ",\"pseudo_count\":";
    out += format_rust_f64(art.policy.pseudo_count);
    out += ",\"refinement_wilson_upper_max\":";
    out += format_rust_f64(art.policy.refinement_wilson_upper_max);
    out += ",\"refinement_min_samples\":";
    out += std::to_string(art.policy.refinement_min_samples);
    out += ",\"refinement_score_ceiling\":";
    out += format_rust_f64(art.policy.refinement_score_ceiling);
    out.push_back('}');

    if (metadata != nullptr && metadata->is_object() &&
        !metadata->get<json_object>().empty()) {
        std::string meta_json;
        if (const auto err = glz::write_json(*metadata, meta_json); err) {
            return std::unexpected("failed to serialize metadata for digest");
        }
        out += ",\"metadata\":";
        out += meta_json;
    }
    out.push_back('}');

    const auto* raw = reinterpret_cast<const unsigned char*>(out.data());
    return sha256_hex(std::span<const unsigned char>{raw, out.size()});
}

} // namespace

auto evidence_counts_v1::effective_samples() const noexcept -> double {
    const std::uint64_t resolved = failures > (std::numeric_limits<std::uint64_t>::max() - successes)
                                       ? std::numeric_limits<std::uint64_t>::max()
                                       : (successes + failures);
    const std::uint64_t unobserved_skips = exposures > resolved ? (exposures - resolved) : 0U;
    const double w = std::isfinite(skip_weight) ? std::max(0.0, skip_weight) : 0.0;
    return static_cast<double>(resolved) + w * static_cast<double>(unobserved_skips);
}

auto load_decision_model_v1(std::string_view json_text, std::string_view pinned_digest)
    -> std::expected<decision_model_artifact_v1, std::string> {
    if (json_text.size() > max_decision_model_bytes) {
        return std::unexpected("decision model artifact exceeds 512 KiB limit");
    }
    glz::generic root;
    if (const auto err = glz::read_json(root, std::string{json_text}); err || !root.is_object()) {
        return std::unexpected("decision model artifact is not a valid JSON object");
    }
    const auto& obj = root.get<json_object>();
    const auto schema = read_string(obj, "schema");
    if (!schema || *schema != decision_model_schema_v1) {
        return std::unexpected("unsupported decision model schema");
    }
    const auto version = read_u64(obj, "artifact_version");
    const auto model_id = read_string(obj, "model_id");
    const auto task_domain = read_string(obj, "task_domain");
    const auto content_digest = read_string(obj, "content_digest");
    if (!version || *version != 1U || !model_id || model_id->empty() || !task_domain ||
        task_domain->empty() || !content_digest || content_digest->empty()) {
        return std::unexpected("missing or invalid decision model header fields");
    }

    const auto* fs_val = get_field(obj, "feature_schema");
    if (fs_val == nullptr || !fs_val->is_object()) {
        return std::unexpected("missing feature_schema");
    }
    const auto& fs_obj = fs_val->get<json_object>();
    const auto fs_ver = read_string(fs_obj, "version");
    const auto fs_dig = read_string(fs_obj, "digest");
    auto fs_names = read_string_vec(fs_obj, "numeric_features");
    if (!fs_ver || fs_ver->empty() || !fs_dig || fs_dig->empty() || !fs_names ||
        fs_names->empty() || fs_names->size() > max_decision_model_features) {
        return std::unexpected("invalid feature_schema");
    }

    const auto* model_val = get_field(obj, "model");
    if (model_val == nullptr || !model_val->is_object()) {
        return std::unexpected("missing model specification");
    }
    auto model_spec = parse_model_spec(model_val->get<json_object>(), fs_names->size());
    if (!model_spec) {
        return std::unexpected(model_spec.error());
    }

    decision_calibration_v1 calibration;
    if (const auto* cal_val = get_field(obj, "calibration"); cal_val != nullptr) {
        if (!cal_val->is_object()) {
            return std::unexpected("calibration is not an object");
        }
        auto parsed = parse_calibration(cal_val->get<json_object>());
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        calibration = *parsed;
    }

    decision_policy_v1 policy;
    if (const auto* pol_val = get_field(obj, "policy"); pol_val != nullptr) {
        if (!pol_val->is_object()) {
            return std::unexpected("policy is not an object");
        }
        auto parsed = parse_policy(pol_val->get<json_object>());
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        policy = *parsed;
    }

    decision_model_artifact_v1 artifact{
        .schema = *schema,
        .artifact_version = static_cast<std::uint32_t>(*version),
        .model_id = *model_id,
        .task_domain = *task_domain,
        .feature_schema =
            decision_feature_schema_v1{
                .version = *fs_ver,
                .digest = *fs_dig,
                .numeric_features = std::move(*fs_names),
            },
        .model = std::move(*model_spec),
        .calibration = calibration,
        .policy = policy,
        .content_digest = *content_digest,
    };

    const auto computed = compute_canonical_content_digest(artifact, get_field(obj, "metadata"));
    if (!computed) {
        return std::unexpected(computed.error());
    }
    if (*computed != artifact.content_digest) {
        return std::unexpected("decision model content_digest verification failed");
    }
    if (!pinned_digest.empty() && *computed != pinned_digest) {
        return std::unexpected("decision model pinned digest mismatch");
    }
    return artifact;
}

auto evaluate_decision_model_v1(
    const decision_model_artifact_v1& artifact,
    std::span<const double> features,
    const evidence_counts_v1& evidence,
    std::size_t top_n
) -> std::expected<decision_output_v1, std::string> {
    const std::size_t n = artifact.feature_schema.numeric_features.size();
    if (features.size() != n) {
        return std::unexpected("feature vector length mismatch");
    }
    for (const double x : features) {
        if (!std::isfinite(x)) {
            return std::unexpected("non-finite feature value");
        }
    }

    std::vector<double> per_feature(n, 0.0);
    double raw_score = 0.0;

    if (const auto* lin = std::get_if<linear_model_spec_v1>(&artifact.model)) {
        raw_score = lin->bias;
        for (std::size_t i = 0; i < n; ++i) {
            const double c = lin->weights[i] * features[i];
            per_feature[i] = c;
            raw_score += c;
        }
    } else if (const auto* pw = std::get_if<piecewise_linear_model_spec_v1>(&artifact.model)) {
        raw_score = pw->bias;
        for (const auto& term : pw->terms) {
            const double c = eval_piecewise_term(term, features[term.feature_index]);
            per_feature[term.feature_index] += c;
            raw_score += c;
        }
    } else if (const auto* gbdt = std::get_if<gbdt_model_spec_v1>(&artifact.model)) {
        raw_score = gbdt->base_score;
        std::vector<std::size_t> path_features;
        path_features.reserve(max_decision_model_tree_depth);
        for (const auto& tree : gbdt->trees) {
            path_features.clear();
            std::size_t idx = 0;
            for (std::size_t step = 0; step <= max_decision_model_tree_depth; ++step) {
                if (idx >= tree.nodes.size()) {
                    return std::unexpected("gbdt node index out of bounds");
                }
                const auto& node = tree.nodes[idx];
                if (node.is_leaf()) {
                    const double scaled = gbdt->learning_rate * node.value;
                    raw_score += scaled;
                    if (!path_features.empty()) {
                        const double share = scaled / static_cast<double>(path_features.size());
                        for (const std::size_t fi : path_features) {
                            per_feature[fi] += share;
                        }
                    }
                    break;
                }
                const auto fi = static_cast<std::size_t>(node.feature_index);
                path_features.push_back(fi);
                idx = features[fi] <= node.threshold ? node.left : node.right;
            }
        }
    } else if (const auto* ucb = std::get_if<lin_ucb_model_spec_v1>(&artifact.model)) {
        double mean = ucb->bias;
        double var = 0.0;
        for (std::size_t i = 0; i < n; ++i) {
            const double x = features[i];
            const double c = ucb->weights[i] * x;
            per_feature[i] = c;
            mean += c;
            var += ucb->a_inv_diag[i] * x * x;
        }
        raw_score = mean + ucb->alpha * std::sqrt(std::max(0.0, var));
    }

    if (!std::isfinite(raw_score)) {
        return std::unexpected("model evaluation produced non-finite raw score");
    }

    double calibrated_prob = 0.0;
    switch (artifact.calibration.kind) {
    case calibration_kind_v1::identity:
        calibrated_prob = stable_sigmoid(raw_score);
        break;
    case calibration_kind_v1::platt:
        calibrated_prob = stable_sigmoid(artifact.calibration.a * raw_score + artifact.calibration.b);
        break;
    case calibration_kind_v1::raw_clamped:
        calibrated_prob = std::clamp(raw_score, 0.0, 1.0);
        break;
    }
    calibrated_prob = std::clamp(calibrated_prob, 0.0, 1.0);

    const double eff_n = evidence.effective_samples();
    const auto [w_lo, w_hi] =
        wilson_interval(static_cast<double>(evidence.successes), eff_n, artifact.policy.wilson_z);
    const double k = std::max(0.0, artifact.policy.pseudo_count);
    const double evidence_weight = (eff_n > 0.0 && (eff_n + k) > 0.0) ? (eff_n / (eff_n + k)) : 0.0;
    const double blended_score =
        std::clamp(evidence_weight * w_lo + (1.0 - evidence_weight) * calibrated_prob, 0.0, 1.0);

    decision_kind_v1 decision = decision_kind_v1::abstain;
    if (blended_score >= artifact.policy.accept_threshold) {
        decision = decision_kind_v1::accept;
    } else if (blended_score <= artifact.policy.reject_threshold) {
        decision = decision_kind_v1::reject;
    }

    const bool has_min_samples = eff_n >= static_cast<double>(artifact.policy.refinement_min_samples);
    const bool trigger_refinement =
        has_min_samples && (w_hi < artifact.policy.refinement_wilson_upper_max ||
                            calibrated_prob < artifact.policy.refinement_score_ceiling);

    std::vector<feature_contribution_v1> contributions;
    for (std::size_t i = 0; i < n; ++i) {
        if (per_feature[i] != 0.0) {
            contributions.push_back(feature_contribution_v1{
                .feature = artifact.feature_schema.numeric_features[i],
                .value = features[i],
                .contribution = per_feature[i],
            });
        }
    }
    std::ranges::sort(contributions, [](const feature_contribution_v1& a,
                                        const feature_contribution_v1& b) {
        const double abs_a = std::abs(a.contribution);
        const double abs_b = std::abs(b.contribution);
        if (abs_a != abs_b) {
            return abs_a > abs_b;
        }
        return a.feature < b.feature;
    });
    if (contributions.size() > top_n) {
        contributions.resize(top_n);
    }

    return decision_output_v1{
        .model_id = artifact.model_id,
        .content_digest = artifact.content_digest,
        .raw_score = raw_score,
        .calibrated_prob = calibrated_prob,
        .blended_score = blended_score,
        .wilson_lower = w_lo,
        .wilson_upper = w_hi,
        .evidence_weight = evidence_weight,
        .effective_samples = eff_n,
        .decision = decision,
        .trigger_refinement = trigger_refinement,
        .top_contributions = std::move(contributions),
    };
}

} // namespace glove::container
