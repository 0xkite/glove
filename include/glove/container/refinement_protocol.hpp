#pragma once

#include "glove/container/profile.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::container {

inline constexpr std::string_view refinement_runtime_template_id = "refinement-eval-v1";
inline constexpr std::string_view refinement_outcome_schema = "sage.refinement-eval-outcome-v1";
inline constexpr std::string_view refinement_outcome_encoding = "canonical-json-utf8";
inline constexpr std::string_view raw_pty_transcript_schema = "glove.raw-pty-transcript-v1";
inline constexpr std::string_view refinement_result_channel_schema =
    "glove.refinement-result-channel-v1";
inline constexpr std::uint8_t refinement_result_frame_schema_version = 1;
inline constexpr std::uint8_t refinement_evaluation_receipt_schema_version = 1;

// Zero is intentional until a Glove-owned runtime wrapper, non-inherited result
// descriptor, durable receipt journal, and registry projection are wired
// together. Capability discovery must not advertise protocol types alone.
inline constexpr std::uint8_t refinement_evaluation_capability_schema_version = 0;

inline constexpr std::size_t max_refinement_result_payload_bytes = 64U * 1024U;
inline constexpr std::size_t max_refinement_metrics = 256U;
inline constexpr std::size_t max_refinement_metric_name_bytes = 64U;

enum class refinement_evidence_status : std::uint8_t {
    valid_outcome,
    missing_outcome,
    invalid_outcome,
};

enum class refinement_result_channel_termination : std::uint8_t {
    clean_eof,
    truncated_frame,
    oversized_frame,
    malformed_frame,
    trailing_bytes,
    multiple_frames,
    read_error,
};

struct refinement_outcome {
    std::string schema;
    std::string encoding;
    std::map<std::string, std::int64_t> metrics;

    auto operator==(const refinement_outcome&) const -> bool = default;
};

struct refinement_result_frame {
    std::uint8_t schema_version = 0;
    std::string fixture_manifest_digest;
    refinement_outcome outcome;

    auto operator==(const refinement_result_frame&) const -> bool = default;
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

struct refinement_result_channel_commitment {
    std::string schema;
    std::uint32_t frame_count = 0;
    refinement_result_channel_termination termination =
        refinement_result_channel_termination::read_error;

    auto operator==(const refinement_result_channel_commitment&) const -> bool = default;
};

struct refinement_result_channel_observation {
    refinement_evidence_status evidence_status = refinement_evidence_status::invalid_outcome;
    std::string fixture_manifest_digest;
    refinement_outcome_commitment outcome_commitment;
    refinement_result_channel_commitment channel;
    std::optional<refinement_outcome> outcome;

    auto operator==(const refinement_result_channel_observation&) const -> bool = default;
};

// A distinct receipt type prevents callers from treating optional fields on the
// resource-enforcement V1 receipt as authenticated refinement evidence.
struct refinement_evaluation_receipt {
    std::uint8_t schema_version = 0;
    std::string runtime_template_id;
    resource_enforcement_receipt resource_receipt;
    refinement_evidence_status evidence_status = refinement_evidence_status::invalid_outcome;
    std::string fixture_manifest_digest;
    refinement_outcome_commitment outcome;
    raw_pty_transcript_commitment transcript;
    refinement_result_channel_commitment result_channel;

    auto operator==(const refinement_evaluation_receipt&) const -> bool = default;
};

// Encode one length-prefixed canonical frame. This is the writer-side primitive
// for a future trusted runtime wrapper; model output is never an input here.
[[nodiscard]] auto encode_refinement_result_frame(const refinement_result_frame& frame)
    -> std::expected<std::vector<unsigned char>, std::string>;

// Inspect the complete bounded result-channel byte stream after EOF. Untrusted
// frame failures become typed invalid evidence so a terminal receipt can bind
// the failure without treating it as a valid outcome.
[[nodiscard]] auto inspect_refinement_result_channel(
    std::span<const unsigned char> channel_bytes, std::string_view expected_fixture_manifest_digest
) -> std::expected<refinement_result_channel_observation, std::string>;

[[nodiscard]] auto canonical_refinement_outcome_bytes(const refinement_outcome& outcome)
    -> std::expected<std::string, std::string>;

[[nodiscard]] auto
refinement_evaluation_receipt_digest(const refinement_evaluation_receipt& receipt)
    -> std::expected<std::string, std::string>;

} // namespace glove::container
