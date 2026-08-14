#pragma once

#include "glove/container/profile.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

inline constexpr std::string_view refinement_runtime_template_id = "refinement-eval-v1";
inline constexpr std::string_view refinement_fixture_schema = "glove.refinement-eval-fixture-v1";
inline constexpr std::string_view refinement_outcome_schema = "sage.refinement-eval-outcome-v1";
inline constexpr std::string_view refinement_outcome_encoding = "canonical-json-utf8";
inline constexpr std::string_view raw_pty_transcript_schema = "glove.raw-pty-transcript-v1";
inline constexpr std::string_view refinement_evaluator_schema =
    "glove.declarative-refinement-evaluator-v1";
inline constexpr std::uint8_t refinement_evaluation_receipt_schema_version = 1;
inline constexpr std::uint8_t refinement_evaluation_capability_schema_version = 1;

inline constexpr std::size_t max_refinement_fixture_bytes = 256U * 1024U;
inline constexpr std::size_t max_refinement_metrics = 256U;
inline constexpr std::size_t max_refinement_metric_name_bytes = 64U;
inline constexpr std::size_t max_refinement_transcript_literals = 128U;
inline constexpr std::size_t max_refinement_transcript_literal_bytes = 4U * 1024U;
inline constexpr std::size_t max_refinement_transcript_literal_total_bytes = 64U * 1024U;

enum class refinement_variant : std::uint8_t {
    base,
    candidate,
};

enum class refinement_evidence_status : std::uint8_t {
    valid_outcome,
    invalid_outcome,
};

struct refinement_projection_binding {
    std::string projection_id;
    std::string content_digest;
    std::string destination_alias;

    auto operator==(const refinement_projection_binding&) const -> bool = default;
};

struct refinement_plan_binding {
    std::uint8_t schema_version = 1;
    refinement_variant variant = refinement_variant::base;
    refinement_projection_binding fixture;
    refinement_projection_binding base;
    refinement_projection_binding candidate;
    std::string matched_context_digest;

    auto operator==(const refinement_plan_binding&) const -> bool = default;
};

// `plan_context_digest` is derived by Glove from the complete validated plan
// and is never accepted from the controller.
struct refinement_execution_binding : refinement_plan_binding {
    std::string plan_context_digest;

    auto operator==(const refinement_execution_binding&) const -> bool = default;
};

struct refinement_model_binding {
    std::optional<std::string> provider;
    std::string model_id;
    std::optional<std::string> model_family;
    std::optional<std::string> model_revision;
    std::string tier;
    std::uint32_t normalizer_version = 0;

    auto operator==(const refinement_model_binding&) const -> bool = default;
};

struct refinement_module_binding {
    std::string repository_id;
    std::string repository_tree;
    std::string module_id;
    std::string label;
    std::vector<std::string> include_paths;
    std::vector<std::string> exclude_paths;
    std::vector<std::string> languages;
    std::vector<std::string> frameworks;
    std::vector<std::string> package_managers;
    std::uint32_t detector_version = 0;

    auto operator==(const refinement_module_binding&) const -> bool = default;
};

struct refinement_fixture_assertions {
    resource_termination_cause expected_termination = resource_termination_cause::exited;
    std::optional<int> expected_exit_code;
    std::vector<std::string> required_transcript_literals;
    std::vector<std::string> forbidden_transcript_literals;
    std::optional<std::uint64_t> max_latency_ms;

    auto operator==(const refinement_fixture_assertions&) const -> bool = default;
};

struct refinement_fixture_manifest {
    std::string schema;
    std::string evaluation_run_id;
    std::string pair_id;
    std::string session_id;
    refinement_variant variant = refinement_variant::base;
    std::string proposal_digest;
    std::string base_projection_digest;
    std::string candidate_projection_digest;
    std::string fixture_id;
    std::string fixture_digest;
    std::string dataset_ref;
    std::string dataset_fingerprint;
    std::uint64_t seed = 0;
    refinement_model_binding model;
    std::string harness;
    std::optional<refinement_module_binding> module;
    std::string skill_projection_id;
    std::string skill_projection_digest;
    std::string matched_context_digest;
    refinement_fixture_assertions assertions;

    auto operator==(const refinement_fixture_manifest&) const -> bool = default;
};

struct refinement_outcome {
    std::string schema;
    std::string encoding;
    std::map<std::string, std::int64_t> metrics;

    auto operator==(const refinement_outcome&) const -> bool = default;
};

struct refinement_outcome_commitment {
    std::string schema;
    std::string encoding;
    std::string digest;
    std::uint64_t byte_length = 0;

    auto operator==(const refinement_outcome_commitment&) const -> bool = default;
};

struct raw_pty_transcript_commitment {
    std::string schema;
    std::string digest;
    std::uint64_t byte_count = 0;
    bool complete = false;

    auto operator==(const raw_pty_transcript_commitment&) const -> bool = default;
};

struct refinement_evaluator_commitment {
    std::string schema;
    bool fixture_complete = false;
    bool transcript_utf8 = false;
    std::uint32_t required_literals = 0;
    std::uint32_t forbidden_literals = 0;

    auto operator==(const refinement_evaluator_commitment&) const -> bool = default;
};

struct refinement_evaluation_receipt {
    std::uint8_t schema_version = 0;
    std::string runtime_template_id;
    resource_enforcement_receipt resource_receipt;
    refinement_evidence_status evidence_status = refinement_evidence_status::invalid_outcome;
    refinement_variant variant = refinement_variant::base;
    refinement_projection_binding fixture;
    refinement_projection_binding base;
    refinement_projection_binding candidate;
    std::string matched_context_digest;
    refinement_outcome_commitment outcome;
    std::optional<refinement_outcome> evaluated_outcome;
    raw_pty_transcript_commitment transcript;
    refinement_evaluator_commitment evaluator;

    auto operator==(const refinement_evaluation_receipt&) const -> bool = default;
};

[[nodiscard]] auto decode_refinement_fixture_manifest(std::span<const unsigned char> bytes)
    -> std::expected<refinement_fixture_manifest, std::string>;

[[nodiscard]] auto canonical_refinement_fixture_bytes(const refinement_fixture_manifest& fixture)
    -> std::expected<std::string, std::string>;

// The normalized fixture context excludes only the execution/session fields
// intentionally allowed to differ between matched base and candidate trials.
[[nodiscard]] auto refinement_fixture_context_digest(
    const refinement_fixture_manifest& fixture, std::string_view plan_context_digest
) -> std::expected<std::string, std::string>;

[[nodiscard]] auto canonical_refinement_outcome_bytes(const refinement_outcome& outcome)
    -> std::expected<std::string, std::string>;

class refinement_transcript_evaluator final {
public:
    struct implementation;

    class construction_token {
    private:
        construction_token() = default;
        friend class refinement_transcript_evaluator;
    };

    refinement_transcript_evaluator(
        construction_token token, std::unique_ptr<implementation> state
    );
    refinement_transcript_evaluator(const refinement_transcript_evaluator&) = delete;
    auto operator=(const refinement_transcript_evaluator&)
        -> refinement_transcript_evaluator& = delete;
    refinement_transcript_evaluator(refinement_transcript_evaluator&&) = delete;
    auto operator=(refinement_transcript_evaluator&&) -> refinement_transcript_evaluator& = delete;
    ~refinement_transcript_evaluator();

    [[nodiscard]] static auto create(
        std::span<const unsigned char> fixture_bytes,
        std::string_view expected_session_id,
        const refinement_execution_binding& binding
    ) -> std::expected<std::shared_ptr<refinement_transcript_evaluator>, std::string>;

    [[nodiscard]] auto consume(std::span<const unsigned char> bytes)
        -> std::expected<void, std::string>;

    [[nodiscard]] auto finish(
        const resource_enforcement_receipt& resource_receipt,
        const raw_pty_transcript_commitment& transcript
    ) -> std::expected<refinement_evaluation_receipt, std::string>;

    [[nodiscard]] auto binding() const -> refinement_execution_binding;

private:
    std::unique_ptr<implementation> state_;
};

[[nodiscard]] auto
refinement_evaluation_receipt_digest(const refinement_evaluation_receipt& receipt)
    -> std::expected<std::string, std::string>;

} // namespace glove::container
