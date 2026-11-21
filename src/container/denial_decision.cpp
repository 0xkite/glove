#include "glove/container/denial_decision.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <numeric>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

// Schema version 2. Every value is log1p of a count or of seconds, so a
// linear model sees a usable scale and thresholds compare monotonically.
constexpr std::array<std::string_view, denial_feature_count> feature_names{
    "denials",
    "kind_file_read",
    "kind_file_write",
    "kind_file_other",
    "kind_network",
    "kind_mach",
    "kind_ipc",
    "kind_process_info",
    "kind_process",
    "kind_signal",
    "kind_sysctl",
    "kind_system_info",
    "kind_iokit",
    "kind_syscall",
    "kind_other",
    "ambiguous",
    "target_workspace",
    "target_home_secret",
    "target_home_other",
    "target_system",
    "target_temp",
    "target_device",
    "target_other_path",
    "target_none",
    "write_outside_workspace",
    "target_decoy",
    "distinct_targets",
    "distinct_comms",
    "truncated_targets",
    "duplicate_reports",
    "rate_1s",
    "rate_10s",
    "elapsed_seconds",
    "first_denial_seconds",
    "idle_seconds",
};

// Indices into the schema above.
constexpr std::size_t f_denials = 0;
constexpr std::size_t f_kind_first = 1;
constexpr std::size_t f_kind_network = 4;
constexpr std::size_t f_kind_other = 14;
constexpr std::size_t f_ambiguous = 15;
constexpr std::size_t f_target_workspace = 16;
constexpr std::size_t f_target_home_secret = 17;
constexpr std::size_t f_target_home_other = 18;
constexpr std::size_t f_target_system = 19;
constexpr std::size_t f_target_temp = 20;
constexpr std::size_t f_target_device = 21;
constexpr std::size_t f_target_other_path = 22;
constexpr std::size_t f_target_none = 23;
constexpr std::size_t f_write_outside_workspace = 24;
constexpr std::size_t f_target_decoy = 25;
constexpr std::size_t f_distinct_targets = 26;
constexpr std::size_t f_distinct_comms = 27;
constexpr std::size_t f_truncated_targets = 28;
constexpr std::size_t f_duplicate_reports = 29;
constexpr std::size_t f_rate_1s = 30;
constexpr std::size_t f_rate_10s = 31;
constexpr std::size_t f_elapsed_seconds = 32;
constexpr std::size_t f_first_denial_seconds = 33;
constexpr std::size_t f_idle_seconds = 34;

static_assert(f_idle_seconds + 1 == denial_feature_count);

// The order of denial_kind_name's vocabulary, from file_read to other.
constexpr std::array<std::string_view, f_kind_other - f_kind_first + 1> kind_names{
    "file_read",
    "file_write",
    "file_other",
    "network",
    "mach",
    "ipc",
    "process_info",
    "process",
    "signal",
    "sysctl",
    "system_info",
    "iokit",
    "syscall",
    "other",
};

// Credential and session stores under the home directory. A denied access to
// one is a feature, not a verdict; the decider weighs it.
constexpr std::array<std::string_view, 16> home_secret_suffixes{
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.netrc",
    "/.git-credentials",
    "/.config/gh",
    "/.config/gcloud",
    "/.azure",
    "/.kube",
    "/.docker",
    "/.npmrc",
    "/.pypirc",
    "/Library/Keychains",
    "/Library/Cookies",
    "/Library/Application Support/Google/Chrome",
    "/Library/Application Support/Firefox",
};

constexpr std::array<std::string_view, 9> system_prefixes{
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library",
    "/Applications",
    "/opt",
    "/private/etc",
    "/etc",
};

constexpr std::array<std::string_view, 4> temp_prefixes{
    "/private/tmp",
    "/tmp",
    "/private/var/folders",
    "/var/folders",
};

constexpr std::chrono::milliseconds one_second{1000};
constexpr std::chrono::milliseconds ten_seconds{10000};

// True when PATH is ROOT or lies under it on a component boundary.
auto within(std::string_view path, std::string_view root) -> bool {
    if (root.empty() || !path.starts_with(root)) {
        return false;
    }
    const auto rest = path.substr(root.size());
    return rest.empty() || rest.starts_with('/');
}

// An encoded absolute directory without trailing '/', or empty if unusable.
auto normalized_root(std::string_view encoded) -> std::string {
    if (!encoded.starts_with('/') || !is_encoded_text(encoded) ||
        encoded.size() > max_denial_target_text_bytes) {
        return {};
    }
    while (encoded.size() > 1 && encoded.ends_with('/')) {
        encoded.remove_suffix(1);
    }
    return encoded == "/" ? std::string{} : std::string{encoded};
}

auto encoded_root(std::string_view raw) -> std::string {
    const auto encoded = encode_untrusted(raw, max_denial_target_text_bytes);
    return encoded.truncated ? std::string{} : normalized_root(encoded.text);
}

auto log_scale(double value) noexcept -> float {
    return static_cast<float>(std::log1p(std::max(value, 0.0)));
}

auto seconds(std::chrono::milliseconds value) noexcept -> double {
    return static_cast<double>(value.count()) / 1000.0;
}

auto stable_hash(std::string_view text) noexcept -> std::uint64_t {
    // FNV-1a: deterministic across runs, so replayed traces reproduce features.
    std::uint64_t hash = 14695981039346656037ULL;
    for (const char byte : text) {
        hash ^= static_cast<unsigned char>(byte);
        hash *= 1099511628211ULL;
    }
    return hash;
}

void insert_bounded(std::unordered_set<std::uint64_t>& set, std::string_view text) {
    if (!text.empty() && set.size() < denial_distinct_capacity) {
        set.insert(stable_hash(text));
    }
}

} // namespace

auto denial_feature_names() noexcept -> std::span<const std::string_view, denial_feature_count> {
    return feature_names;
}

auto denial_verdict_name(denial_verdict verdict) noexcept -> std::string_view {
    switch (verdict) {
    case denial_verdict::proceed:
        return "proceed";
    case denial_verdict::flag:
        return "flag";
    case denial_verdict::terminate:
        return "terminate";
    }
    return "proceed";
}

auto make_denial_context(
    std::span<const std::string> raw_workspace_roots,
    std::string_view raw_home,
    std::span<const std::string> raw_decoys
) -> denial_context {
    denial_context out{.workspace_roots = {}, .home = encoded_root(raw_home), .decoys = {}};
    for (const auto& raw : raw_decoys) {
        if (out.decoys.size() == max_denial_context_decoys) {
            break;
        }
        if (auto decoy = encoded_root(raw); !decoy.empty()) {
            out.decoys.push_back(std::move(decoy));
        }
    }
    for (const auto& raw : raw_workspace_roots) {
        if (out.workspace_roots.size() == max_denial_context_roots) {
            break;
        }
        if (auto root = encoded_root(raw); !root.empty()) {
            out.workspace_roots.push_back(std::move(root));
        }
    }
    return out;
}

denial_feature_builder::denial_feature_builder(const denial_context& context)
    : home_{normalized_root(context.home)} {
    for (const auto& root : context.workspace_roots) {
        if (roots_.size() == max_denial_context_roots) {
            break;
        }
        if (auto normalized = normalized_root(root); !normalized.empty()) {
            roots_.push_back(std::move(normalized));
        }
    }
    for (const auto& decoy : context.decoys) {
        if (decoys_.size() == max_denial_context_decoys) {
            break;
        }
        if (auto normalized = normalized_root(decoy); !normalized.empty()) {
            decoys_.push_back(std::move(normalized));
        }
    }
}

void denial_feature_builder::expire(std::chrono::milliseconds elapsed) const {
    while (!window_.empty() && elapsed - window_.front() >= ten_seconds) {
        window_.pop_front();
    }
}

void denial_feature_builder::observe(
    const sandbox_denial& denial, std::chrono::milliseconds elapsed
) {
    elapsed = std::max({elapsed, last_, std::chrono::milliseconds{0}});
    ++total_;
    ++std::get<f_denials>(counts_);
    if (first_.count() < 0) {
        first_ = elapsed;
    }
    last_ = elapsed;
    expire(elapsed);
    if (window_.size() == denial_rate_window_capacity) {
        window_.pop_front();
    }
    window_.push_back(elapsed);

    if (denial.kind == "ambiguous") {
        ++std::get<f_ambiguous>(counts_);
        ++std::get<f_target_none>(counts_);
        return;
    }
    const auto* kind = std::ranges::find(kind_names, denial.kind);
    const auto kind_index =
        kind == kind_names.end()
            ? f_kind_other
            : f_kind_first + static_cast<std::size_t>(kind - kind_names.begin());
    ++counts_.at(kind_index);

    insert_bounded(targets_, denial.target);
    insert_bounded(comms_, denial.comm);
    if (denial.target_truncated) {
        ++std::get<f_truncated_targets>(counts_);
    }
    std::get<f_duplicate_reports>(counts_) += denial.duplicate_reports;

    const std::string_view target = denial.target;
    std::size_t target_class = f_target_other_path;
    if (!target.starts_with('/')) {
        target_class = f_target_none;
    } else if (std::ranges::any_of(roots_, [&](const std::string& root) {
                   return within(target, root);
               })) {
        target_class = f_target_workspace;
    } else if (!home_.empty() && within(target, home_)) {
        const auto rest = target.substr(home_.size());
        target_class =
            std::ranges::any_of(
                home_secret_suffixes, [&](std::string_view suffix) { return within(rest, suffix); }
            )
                ? f_target_home_secret
                : f_target_home_other;
    } else if (std::ranges::any_of(temp_prefixes, [&](std::string_view prefix) {
                   return within(target, prefix);
               })) {
        target_class = f_target_temp;
    } else if (within(target, "/dev")) {
        target_class = f_target_device;
    } else if (std::ranges::any_of(system_prefixes, [&](std::string_view prefix) {
                   return within(target, prefix);
               })) {
        target_class = f_target_system;
    }
    ++counts_.at(target_class);
    // A decoy is counted on top of its class: nothing legitimate names one.
    if (std::ranges::find(decoys_, target) != decoys_.end()) {
        ++std::get<f_target_decoy>(counts_);
    }
    if (denial.kind == "file_write" && target_class != f_target_workspace &&
        target_class != f_target_temp && target_class != f_target_none) {
        ++std::get<f_write_outside_workspace>(counts_);
    }
}

auto denial_feature_builder::features(std::chrono::milliseconds elapsed) const -> denial_features {
    elapsed = std::max({elapsed, last_, std::chrono::milliseconds{0}});
    expire(elapsed);
    denial_features out{};
    for (std::size_t index = 0; index != denial_feature_count; ++index) {
        out.at(index) = log_scale(static_cast<double>(counts_.at(index)));
    }
    std::get<f_distinct_targets>(out) = log_scale(static_cast<double>(targets_.size()));
    std::get<f_distinct_comms>(out) = log_scale(static_cast<double>(comms_.size()));
    const auto recent = std::ranges::count_if(window_, [&](std::chrono::milliseconds at) {
        return elapsed - at < one_second;
    });
    std::get<f_rate_1s>(out) = log_scale(static_cast<double>(recent));
    std::get<f_rate_10s>(out) = log_scale(static_cast<double>(window_.size()));
    std::get<f_elapsed_seconds>(out) = log_scale(seconds(elapsed));
    std::get<f_first_denial_seconds>(out) = first_.count() < 0 ? 0.0F : log_scale(seconds(first_));
    std::get<f_idle_seconds>(out) = last_.count() < 0 ? 0.0F : log_scale(seconds(elapsed - last_));
    return out;
}

// Glaze reflects these, so they need linkage.
namespace denial_model_detail {

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct model_node {
    std::int32_t feature = -1;
    float threshold = 0.0F;
    std::uint32_t left = 0;
    std::uint32_t right = 0;
    float value = 0.0F;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct model_tree {
    std::vector<model_node> nodes;
};

// The model file. Every member is required and no other is accepted.
// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct model_file {
    std::string format;
    std::uint32_t version = 0;
    std::uint32_t feature_schema = 0;
    std::vector<std::string> features;
    std::string type;
    float bias = 0.0F;
    std::vector<float> weights;
    std::vector<model_tree> trees;
    float flag_threshold = 0.0F;
    float terminate_threshold = 0.0F;
};

} // namespace denial_model_detail

namespace {

class heuristic_decider final : public denial_decider {
public:
    explicit heuristic_decider(denial_heuristic_thresholds limits)
        : flag_secret_{log_scale(limits.flag_secret)},
          terminate_secret_{log_scale(limits.terminate_secret)},
          flag_decoy_{log_scale(limits.flag_decoy)},
          terminate_decoy_{log_scale(limits.terminate_decoy)},
          flag_rate_{log_scale(limits.flag_rate_1s)},
          terminate_rate_{log_scale(limits.terminate_rate_10s)},
          flag_distinct_{log_scale(limits.flag_distinct_targets)} {}

    [[nodiscard]] auto arm() const noexcept -> std::string_view override { return "heuristic"; }

    [[nodiscard]] auto decide(const denial_features& in) const noexcept
        -> denial_decision override {
        const bool secret_and_egress =
            (std::get<f_target_home_secret>(in) > 0.0F || std::get<f_target_decoy>(in) > 0.0F) &&
            (std::get<f_kind_network>(in) > 0.0F || std::get<f_write_outside_workspace>(in) > 0.0F);
        if (std::get<f_target_home_secret>(in) >= terminate_secret_ ||
            std::get<f_target_decoy>(in) >= terminate_decoy_ || secret_and_egress ||
            std::get<f_rate_10s>(in) >= terminate_rate_) {
            return {.verdict = denial_verdict::terminate, .score = 1.0F};
        }
        if (std::get<f_target_home_secret>(in) >= flag_secret_ ||
            std::get<f_target_decoy>(in) >= flag_decoy_ || std::get<f_rate_1s>(in) >= flag_rate_ ||
            std::get<f_distinct_targets>(in) >= flag_distinct_) {
            return {.verdict = denial_verdict::flag, .score = 0.5F};
        }
        return {};
    }

private:
    float flag_secret_;
    float terminate_secret_;
    float flag_decoy_;
    float terminate_decoy_;
    float flag_rate_;
    float terminate_rate_;
    float flag_distinct_;
};

// Trailing bytes after the object are refused, not ignored.
struct model_opts : glz::opts {
    bool validate_trailing_whitespace = true;
};

using denial_model_detail::model_file;
using denial_model_detail::model_tree;

constexpr model_opts model_read_options{
    {.null_terminated = false, .error_on_unknown_keys = true, .error_on_missing_keys = true},
};

// Element INDEX of RANGE. Only for indices validate() already range-checked,
// so the hot path neither branches nor throws.
template<typename Range>
auto validated_at(const Range& range, std::size_t index) noexcept -> const auto& {
    return *(std::ranges::begin(range) + static_cast<std::ptrdiff_t>(index));
}

auto sigmoid(float value) noexcept -> float {
    return 1.0F / (1.0F + std::exp(-value));
}

class model_decider final : public denial_decider {
public:
    explicit model_decider(model_file model) : model_{std::move(model)} {}

    [[nodiscard]] auto arm() const noexcept -> std::string_view override { return "model"; }

    [[nodiscard]] auto decide(const denial_features& in) const noexcept
        -> denial_decision override {
        float margin = model_.bias;
        if (model_.trees.empty()) {
            margin = std::inner_product(in.begin(), in.end(), model_.weights.begin(), margin);
        } else {
            for (const auto& tree : model_.trees) {
                std::size_t at = 0;
                // Children follow their parent, so this ends within the tree.
                while (validated_at(tree.nodes, at).feature >= 0) {
                    const auto& node = validated_at(tree.nodes, at);
                    at = validated_at(in, static_cast<std::size_t>(node.feature)) <= node.threshold
                             ? node.left
                             : node.right;
                }
                margin += validated_at(tree.nodes, at).value;
            }
        }
        const float score = sigmoid(margin);
        if (!std::isfinite(score)) {
            return {};
        }
        if (score >= model_.terminate_threshold) {
            return {.verdict = denial_verdict::terminate, .score = score};
        }
        if (score >= model_.flag_threshold) {
            return {.verdict = denial_verdict::flag, .score = score};
        }
        return {.verdict = denial_verdict::proceed, .score = score};
    }

private:
    model_file model_;
};

auto valid_tree(const model_tree& tree) -> bool {
    const auto size = tree.nodes.size();
    if (size == 0 || size > max_denial_model_tree_nodes) {
        return false;
    }
    std::size_t index = 0;
    for (const auto& node : tree.nodes) {
        if (!std::isfinite(node.threshold) || !std::isfinite(node.value)) {
            return false;
        }
        if (node.feature != -1) {
            if (node.feature < 0 || std::cmp_greater_equal(node.feature, denial_feature_count)) {
                return false;
            }
            if (node.left <= index || node.right <= index || node.left >= size ||
                node.right >= size) {
                return false;
            }
        }
        ++index;
    }
    return true;
}

auto validate(const model_file& model) -> std::expected<void, std::string> {
    if (model.format != "glove-denial-model" || model.version != 1) {
        return std::unexpected(std::string{"not a version 1 glove denial model"});
    }
    if (model.feature_schema != denial_feature_schema_version) {
        return std::unexpected(std::string{"denial model was trained on another feature schema"});
    }
    if (!std::ranges::equal(model.features, feature_names)) {
        return std::unexpected(std::string{"denial model features do not match the schema"});
    }
    if (!std::isfinite(model.bias) || !std::isfinite(model.flag_threshold) ||
        !std::isfinite(model.terminate_threshold) || model.flag_threshold <= 0.0F ||
        model.terminate_threshold < model.flag_threshold) {
        return std::unexpected(std::string{"denial model thresholds are invalid"});
    }
    if (model.type == "logistic") {
        if (model.weights.size() != denial_feature_count || !model.trees.empty() ||
            !std::ranges::all_of(model.weights, [](float w) { return std::isfinite(w); })) {
            return std::unexpected(std::string{"logistic denial model is malformed"});
        }
        return {};
    }
    if (model.type == "gbdt") {
        if (!model.weights.empty() || model.trees.empty() ||
            model.trees.size() > max_denial_model_trees ||
            !std::ranges::all_of(model.trees, valid_tree)) {
            return std::unexpected(std::string{"tree denial model is malformed"});
        }
        return {};
    }
    return std::unexpected(std::string{"unknown denial model type"});
}

} // namespace

auto make_heuristic_denial_decider(denial_heuristic_thresholds thresholds)
    -> std::unique_ptr<denial_decider> {
    return std::make_unique<heuristic_decider>(thresholds);
}

auto load_denial_model(std::string_view text)
    -> std::expected<std::unique_ptr<denial_decider>, std::string> {
    if (text.size() > max_denial_model_bytes) {
        return std::unexpected(std::string{"denial model file is too large"});
    }
    model_file model;
    if (const auto error = glz::read<model_read_options>(model, text); error) {
        return std::unexpected(
            std::string{"denial model file is not valid JSON of the model shape"}
        );
    }
    if (auto valid = validate(model); !valid) {
        return std::unexpected(std::move(valid.error()));
    }
    return std::make_unique<model_decider>(std::move(model));
}

} // namespace glove::container
