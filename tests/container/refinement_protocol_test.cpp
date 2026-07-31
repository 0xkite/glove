#include "glove/container/digest.hpp"
#include "glove/container/receipt_chain.hpp"
#include "glove/container/refinement_protocol.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view profile_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr std::string_view fixture_manifest_digest =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

auto resource_receipt() -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::string{profile_digest},
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 60'000,
                .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                .pids = 128,
                .wall_time_ms = 120'000,
                .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 500,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = 8,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections = {},
        .retained_changes = {},
    };
}

auto result_frame() -> glove::container::refinement_result_frame {
    return {
        .schema_version = glove::container::refinement_result_frame_schema_version,
        .fixture_manifest_digest = std::string{fixture_manifest_digest},
        .outcome = {
            .schema = std::string{glove::container::refinement_outcome_schema},
            .encoding = std::string{glove::container::refinement_outcome_encoding},
            .metrics = {
                {"attempts", 3},
                {"score_microunits", 875'000},
                {"violations", 0},
            },
        },
    };
}

auto frame_bytes(std::string_view payload) -> std::vector<unsigned char> {
    std::vector<unsigned char> output;
    const auto size = static_cast<std::uint32_t>(payload.size());
    for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<unsigned char>(size >> shift));
    }
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

auto bytes(std::string_view value) -> std::span<const unsigned char> {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

auto run() -> int {
    using namespace glove::container;

    REQUIRE(refinement_evaluation_capability_schema_version == 0);
    REQUIRE(refinement_evaluation_receipt_schema_version == 1);

    const auto frame = result_frame();
    auto canonical_outcome = canonical_refinement_outcome_bytes(frame.outcome);
    REQUIRE(canonical_outcome.has_value());
    REQUIRE(
        *canonical_outcome ==
        R"({"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"attempts":3,"score_microunits":875000,"violations":0}})"
    );
    auto encoded = encode_refinement_result_frame(frame);
    REQUIRE(encoded.has_value());
    REQUIRE(encoded->size() > 4U);
    const std::string_view payload{
        reinterpret_cast<const char*>(encoded->data() + 4), encoded->size() - 4U
    };
    REQUIRE(
        payload ==
        R"({"schema_version":1,"fixture_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","outcome":{"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"attempts":3,"score_microunits":875000,"violations":0}}})"
    );

    auto observed = inspect_refinement_result_channel(*encoded, fixture_manifest_digest);
    REQUIRE(observed.has_value());
    REQUIRE(observed->evidence_status == refinement_evidence_status::valid_outcome);
    REQUIRE(observed->fixture_manifest_digest == fixture_manifest_digest);
    REQUIRE(observed->outcome.has_value());
    REQUIRE(observed->outcome == frame.outcome);
    REQUIRE(observed->channel.frame_count == 1);
    REQUIRE(observed->channel.termination == refinement_result_channel_termination::clean_eof);
    REQUIRE(observed->outcome_commitment.byte_length == canonical_outcome->size());
    REQUIRE(
        observed->outcome_commitment.digest ==
        "2aa9235533303ffeeec44254ce08e7b7c797160e0aa34251806be2eb65c8da6a"
    );

    auto missing = inspect_refinement_result_channel({}, fixture_manifest_digest);
    REQUIRE(missing.has_value());
    REQUIRE(missing->evidence_status == refinement_evidence_status::missing_outcome);
    REQUIRE(missing->channel.frame_count == 0);
    REQUIRE(missing->channel.termination == refinement_result_channel_termination::clean_eof);
    REQUIRE(missing->outcome_commitment.byte_length == 0);
    REQUIRE(
        missing->outcome_commitment.digest ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    auto truncated_prefix = inspect_refinement_result_channel(
        std::array<unsigned char, 3>{0, 0, 1}, fixture_manifest_digest
    );
    REQUIRE(truncated_prefix.has_value());
    REQUIRE(
        truncated_prefix->channel.termination ==
        refinement_result_channel_termination::truncated_frame
    );
    REQUIRE(truncated_prefix->channel.frame_count == 0);

    std::array<unsigned char, 4> oversized_prefix = {0, 1, 0, 1};
    auto oversized = inspect_refinement_result_channel(oversized_prefix, fixture_manifest_digest);
    REQUIRE(oversized.has_value());
    REQUIRE(
        oversized->channel.termination == refinement_result_channel_termination::oversized_frame
    );

    auto truncated = *encoded;
    truncated.pop_back();
    auto truncated_frame = inspect_refinement_result_channel(truncated, fixture_manifest_digest);
    REQUIRE(truncated_frame.has_value());
    REQUIRE(
        truncated_frame->channel.termination ==
        refinement_result_channel_termination::truncated_frame
    );

    auto trailing = *encoded;
    trailing.push_back(0);
    auto trailing_frame = inspect_refinement_result_channel(trailing, fixture_manifest_digest);
    REQUIRE(trailing_frame.has_value());
    REQUIRE(
        trailing_frame->channel.termination == refinement_result_channel_termination::trailing_bytes
    );

    auto multiple = *encoded;
    multiple.insert(multiple.end(), encoded->begin(), encoded->end());
    auto multiple_frames = inspect_refinement_result_channel(multiple, fixture_manifest_digest);
    REQUIRE(multiple_frames.has_value());
    REQUIRE(multiple_frames->channel.frame_count == 2);
    REQUIRE(
        multiple_frames->channel.termination ==
        refinement_result_channel_termination::multiple_frames
    );

    const auto unknown = frame_bytes(
        R"({"schema_version":1,"fixture_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","outcome":{"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"score":1}},"unknown":1})"
    );
    auto unknown_field = inspect_refinement_result_channel(unknown, fixture_manifest_digest);
    REQUIRE(unknown_field.has_value());
    REQUIRE(unknown_field->evidence_status == refinement_evidence_status::invalid_outcome);
    REQUIRE(
        unknown_field->channel.termination == refinement_result_channel_termination::malformed_frame
    );

    const auto duplicate = frame_bytes(
        R"({"schema_version":1,"schema_version":1,"fixture_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","outcome":{"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"score":1}}})"
    );
    auto duplicate_field = inspect_refinement_result_channel(duplicate, fixture_manifest_digest);
    REQUIRE(duplicate_field.has_value());
    REQUIRE(duplicate_field->evidence_status == refinement_evidence_status::invalid_outcome);

    const auto duplicate_metric = frame_bytes(
        R"({"schema_version":1,"fixture_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","outcome":{"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"score":1,"score":2}}})"
    );
    auto duplicate_metric_field =
        inspect_refinement_result_channel(duplicate_metric, fixture_manifest_digest);
    REQUIRE(duplicate_metric_field.has_value());
    REQUIRE(duplicate_metric_field->evidence_status == refinement_evidence_status::invalid_outcome);

    const auto fractional_metric = frame_bytes(
        R"({"schema_version":1,"fixture_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","outcome":{"schema":"sage.refinement-eval-outcome-v1","encoding":"canonical-json-utf8","metrics":{"score":1.5}}})"
    );
    auto fractional = inspect_refinement_result_channel(fractional_metric, fixture_manifest_digest);
    REQUIRE(fractional.has_value());
    REQUIRE(fractional->evidence_status == refinement_evidence_status::invalid_outcome);

    auto invalid_utf8 = *encoded;
    invalid_utf8[invalid_utf8.size() - 3U] = 0xffU;
    auto invalid_text = inspect_refinement_result_channel(invalid_utf8, fixture_manifest_digest);
    REQUIRE(invalid_text.has_value());
    REQUIRE(invalid_text->evidence_status == refinement_evidence_status::invalid_outcome);

    auto wrong_manifest = inspect_refinement_result_channel(
        *encoded, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
    REQUIRE(wrong_manifest.has_value());
    REQUIRE(wrong_manifest->evidence_status == refinement_evidence_status::invalid_outcome);

    auto too_many_metrics = frame;
    too_many_metrics.outcome.metrics.clear();
    for (std::size_t index = 0; index <= max_refinement_metrics; ++index) {
        too_many_metrics.outcome.metrics.emplace("m" + std::to_string(index), 1);
    }
    REQUIRE(!encode_refinement_result_frame(too_many_metrics).has_value());
    REQUIRE(!inspect_refinement_result_channel(*encoded, "not-a-digest").has_value());

    const auto transcript_digest = sha256_hex(bytes("raw pty\n"));
    REQUIRE(transcript_digest.has_value());
    REQUIRE(
        *transcript_digest == "c0d63d782c7ccf978b8e09fdec2e2689dcfa19c2544faba4d8b13998950bac8f"
    );
    refinement_evaluation_receipt receipt{
        .schema_version = refinement_evaluation_receipt_schema_version,
        .runtime_template_id = std::string{refinement_runtime_template_id},
        .resource_receipt = resource_receipt(),
        .evidence_status = observed->evidence_status,
        .fixture_manifest_digest = observed->fixture_manifest_digest,
        .outcome = observed->outcome_commitment,
        .transcript =
            {
                .schema = std::string{raw_pty_transcript_schema},
                .digest = *transcript_digest,
                .byte_count = 8,
                .complete = true,
            },
        .result_channel = observed->channel,
    };
    auto receipt_digest = refinement_evaluation_receipt_digest(receipt);
    REQUIRE(receipt_digest.has_value());
    REQUIRE(*receipt_digest == "252eaffe944c35bfa6c592e304ce18b460f3eeaa32924919698863107d97f397");

    auto envelope = make_authenticated_refinement_evaluation_receipt(
        audit_key, 1, std::string(64, '0'), "session-refinement-1", controller_plan_digest, receipt
    );
    REQUIRE(envelope.has_value());
    REQUIRE(envelope->receipt_digest == *receipt_digest);
    REQUIRE(
        envelope->this_hmac == "1c533f6a025f39c245b2dc2d642d72903772d7f092b5c5f24d3a316c499d2e0a"
    );
    auto anchor = receipt_audit_anchor::create(audit_key);
    REQUIRE(anchor.has_value());
    REQUIRE(verify_refinement_receipt_audit_envelope(
                *envelope, audit_key, "session-refinement-1", controller_plan_digest, **anchor
    )
                .has_value());
    REQUIRE((**anchor).sequence == 1);
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 *envelope, audit_key, "session-refinement-1", controller_plan_digest, **anchor
    )
                 .has_value());

    auto fresh_anchor = receipt_audit_anchor::create(audit_key);
    REQUIRE(fresh_anchor.has_value());
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 *envelope, audit_key, "session-other", controller_plan_digest, **fresh_anchor
    )
                 .has_value());
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 *envelope,
                 audit_key,
                 "session-refinement-1",
                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                 **fresh_anchor
    )
                 .has_value());

    auto mixed_manifest = *envelope;
    mixed_manifest.receipt.fixture_manifest_digest =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 mixed_manifest,
                 audit_key,
                 "session-refinement-1",
                 controller_plan_digest,
                 **fresh_anchor
    )
                 .has_value());
    auto mixed_outcome = *envelope;
    mixed_outcome.receipt.outcome.digest = std::string(64, 'f');
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 mixed_outcome,
                 audit_key,
                 "session-refinement-1",
                 controller_plan_digest,
                 **fresh_anchor
    )
                 .has_value());
    auto mixed_transcript = *envelope;
    mixed_transcript.receipt.transcript.digest = std::string(64, 'f');
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 mixed_transcript,
                 audit_key,
                 "session-refinement-1",
                 controller_plan_digest,
                 **fresh_anchor
    )
                 .has_value());
    auto mixed_channel = *envelope;
    mixed_channel.receipt.result_channel.frame_count = 2;
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 mixed_channel,
                 audit_key,
                 "session-refinement-1",
                 controller_plan_digest,
                 **fresh_anchor
    )
                 .has_value());

    auto invalid_receipt = receipt;
    invalid_receipt.transcript.byte_count = 7;
    REQUIRE(!refinement_evaluation_receipt_digest(invalid_receipt).has_value());
    invalid_receipt = receipt;
    invalid_receipt.runtime_template_id = "codex-safe";
    REQUIRE(!refinement_evaluation_receipt_digest(invalid_receipt).has_value());
    invalid_receipt = receipt;
    invalid_receipt.evidence_status = refinement_evidence_status::missing_outcome;
    REQUIRE(!refinement_evaluation_receipt_digest(invalid_receipt).has_value());

    auto missing_receipt = receipt;
    missing_receipt.evidence_status = missing->evidence_status;
    missing_receipt.outcome = missing->outcome_commitment;
    missing_receipt.result_channel = missing->channel;
    REQUIRE(refinement_evaluation_receipt_digest(missing_receipt).has_value());

    auto malformed_receipt = receipt;
    malformed_receipt.evidence_status = unknown_field->evidence_status;
    malformed_receipt.outcome = unknown_field->outcome_commitment;
    malformed_receipt.result_channel = unknown_field->channel;
    REQUIRE(refinement_evaluation_receipt_digest(malformed_receipt).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
