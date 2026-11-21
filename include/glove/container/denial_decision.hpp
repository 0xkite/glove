#pragma once

// Decisions over one launch's sandbox denials: a fixed feature schema, a
// builder that turns the denial stream into features, and interchangeable
// deciders (a trained model, and a heuristic arm kept for ablation).
//
// A decider can only escalate. Its verdict is advice to a caller that may
// record it (shadow) or, when the operator enables enforcement, terminate the
// launch's group through the identity-checked teardown. The sandbox profile
// stays the control: a decider that is missing, fails to load, or returns
// proceed leaves the session sandboxed exactly as before, and nothing may wait
// on a decision.
//
// Inputs are agent-chosen. Every feature is a bounded count or duration
// computed from encoded fields, so an agent can steer its own verdict (evade
// a flag, or provoke its own termination) but cannot widen what the sandbox
// allows or reach another session.

#include "glove/container/denial_telemetry.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace glove::container {

// Bumped whenever a feature is added, removed, reordered or redefined. A model
// trained on another schema does not load.
constexpr std::uint32_t denial_feature_schema_version = 2;
constexpr std::size_t denial_feature_count = 35;

using denial_features = std::array<float, denial_feature_count>;

// Feature names in schema order; a model file lists exactly these.
[[nodiscard]] auto denial_feature_names() noexcept
    -> std::span<const std::string_view, denial_feature_count>;

// Where a launch's targets are classified from. Paths are in the form the
// kernel reports them (for example /private/var/..., not /var/...) and in the
// encoding of sandbox_denial::target, so a recorded trace replays exactly.
// Each root names a directory; a target inside it matches. Each decoy names
// one file this launch planted; only that exact target matches.
struct denial_context {
    std::vector<std::string> workspace_roots;
    std::string home;
    std::vector<std::string> decoys;
};

constexpr std::size_t max_denial_context_roots = 64;
constexpr std::size_t max_denial_context_decoys = 32;

// Encodes raw host paths with encode_untrusted. Drops a path that is not
// absolute, is "/", or does not fit max_denial_target_text_bytes, and keeps at
// most max_denial_context_roots roots and max_denial_context_decoys decoys.
[[nodiscard]] auto make_denial_context(
    std::span<const std::string> raw_workspace_roots,
    std::string_view raw_home,
    std::span<const std::string> raw_decoys = {}
) -> denial_context;
constexpr std::size_t denial_rate_window_capacity = 4096;
constexpr std::size_t denial_distinct_capacity = 1024;

// Turns one launch's denial stream into features. Not thread-safe: the caller
// feeds it from one thread (the telemetry thread). Memory is bounded; counts
// that pass a capacity saturate there.
class denial_feature_builder final {
public:
    explicit denial_feature_builder(const denial_context& context);

    // ELAPSED is the time since the launch began, non-decreasing across calls.
    void observe(const sandbox_denial& denial, std::chrono::milliseconds elapsed);

    [[nodiscard]] auto features(std::chrono::milliseconds elapsed) const -> denial_features;

    [[nodiscard]] auto observed() const noexcept -> std::uint64_t { return total_; }

private:
    void expire(std::chrono::milliseconds elapsed) const;

    std::vector<std::string> roots_;  // encoded, without a trailing '/'
    std::string home_;                // encoded, without a trailing '/'
    std::vector<std::string> decoys_; // encoded exact paths
    std::array<std::uint64_t, denial_feature_count> counts_{};
    std::uint64_t total_ = 0;
    std::chrono::milliseconds first_{-1};
    std::chrono::milliseconds last_{-1};
    mutable std::deque<std::chrono::milliseconds> window_;
    std::unordered_set<std::uint64_t> targets_;
    std::unordered_set<std::uint64_t> comms_;
};

enum class denial_verdict : std::uint8_t { proceed, flag, terminate };

[[nodiscard]] auto denial_verdict_name(denial_verdict verdict) noexcept -> std::string_view;

struct denial_decision {
    denial_verdict verdict = denial_verdict::proceed;
    float score = 0.0F; // in [0, 1]; what the verdict thresholds compare
};

class denial_decider {
public:
    denial_decider() = default;
    denial_decider(const denial_decider&) = delete;
    auto operator=(const denial_decider&) -> denial_decider& = delete;
    denial_decider(denial_decider&&) = delete;
    auto operator=(denial_decider&&) -> denial_decider& = delete;
    virtual ~denial_decider() = default;

    // Fixed ASCII: "model" or "heuristic".
    [[nodiscard]] virtual auto arm() const noexcept -> std::string_view = 0;
    // A pure function of FEATURES: no I/O, no blocking, no allocation.
    [[nodiscard]] virtual auto decide(const denial_features& features) const noexcept
        -> denial_decision = 0;
};

// Ablation arm only; it is never the product path.
struct denial_heuristic_thresholds {
    std::uint32_t flag_secret = 1;
    std::uint32_t terminate_secret = 3;
    std::uint32_t flag_decoy = 1;
    std::uint32_t terminate_decoy = 3;
    std::uint32_t flag_rate_1s = 32;
    std::uint32_t terminate_rate_10s = 200;
    std::uint32_t flag_distinct_targets = 64;
};

[[nodiscard]] auto make_heuristic_denial_decider(denial_heuristic_thresholds thresholds = {})
    -> std::unique_ptr<denial_decider>;

constexpr std::size_t max_denial_model_bytes = std::size_t{1} << 20U;
constexpr std::size_t max_denial_model_trees = 512;
constexpr std::size_t max_denial_model_tree_nodes = 255;

// Loads a trained model from its file text. The text is untrusted: it must be
// one JSON object of the documented shape, name this feature schema, list the
// features in order, hold only finite numbers, and describe trees whose
// children follow their parent (so evaluation always terminates).
[[nodiscard]] auto load_denial_model(std::string_view text)
    -> std::expected<std::unique_ptr<denial_decider>, std::string>;

} // namespace glove::container
