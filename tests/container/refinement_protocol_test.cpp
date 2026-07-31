#include "glove/container/digest.hpp"
#include "glove/container/receipt_chain.hpp"
#include "glove/container/refinement_protocol.hpp"

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

auto bytes(std::string_view value) -> std::span<const unsigned char> {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}

auto resource_receipt(
    std::uint64_t transcript_bytes,
    glove::container::resource_termination_cause cause =
        glove::container::resource_termination_cause::exited,
    std::optional<int> exit_code = 0
) -> glove::container::resource_enforcement_receipt {
    using namespace glove::container;
    return {
        .schema_version = 1,
        .profile_digest = std::string(64, 'c'),
        .backend = sandbox_backend::linux_production,
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
                .cpu_time = enforcement_mechanism::cgroup_v2,
                .memory = enforcement_mechanism::cgroup_v2,
                .pids = enforcement_mechanism::cgroup_v2,
                .wall_time = enforcement_mechanism::watchdog,
                .disk = enforcement_mechanism::filesystem_quota,
                .terminal_output = enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = 500,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = transcript_bytes,
            },
        .termination_cause = cause,
        .exit_code = std::move(exit_code),
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections = {},
        .retained_changes = {},
    };
}

struct fixture_case {
    glove::container::refinement_fixture_manifest fixture;
    glove::container::refinement_execution_binding binding;
    std::string encoded;
};

auto make_fixture() -> fixture_case {
    using namespace glove::container;
    refinement_execution_binding binding;
    binding.schema_version = 1;
    binding.variant = refinement_variant::candidate;
    binding.fixture = {
        .projection_id = "fixture",
        .content_digest = std::string(64, '0'),
        .destination_alias = "fixtures",
    };
    binding.base = {
        .projection_id = "base-skill",
        .content_digest = std::string(64, 'b'),
        .destination_alias = "skills",
    };
    binding.candidate = {
        .projection_id = "candidate-skill",
        .content_digest = std::string(64, 'c'),
        .destination_alias = "skills",
    };
    binding.matched_context_digest = std::string(64, '0');
    binding.plan_context_digest = std::string(64, 'e');

    refinement_fixture_manifest fixture{
        .schema = std::string{refinement_fixture_schema},
        .evaluation_run_id = "run-1",
        .pair_id = "pair-1",
        .session_id = "session-refinement-1",
        .variant = refinement_variant::candidate,
        .proposal_digest = std::string(64, 'a'),
        .base_projection_digest = binding.base.content_digest,
        .candidate_projection_digest = binding.candidate.content_digest,
        .fixture_id = "prompt-1",
        .fixture_digest = std::string(64, 'd'),
        .dataset_ref = "fixture:primary",
        .dataset_fingerprint = std::string(64, 'f'),
        .seed = 42,
        .model =
            {
                .provider = "openai",
                .model_id = "gpt-5.3-codex",
                .model_family = "gpt-5-codex",
                .model_revision = "2026-07-31",
                .tier = "reasoning",
                .normalizer_version = 1,
            },
        .harness = "codex",
        .module = std::nullopt,
        .skill_projection_id = binding.candidate.projection_id,
        .skill_projection_digest = binding.candidate.content_digest,
        .matched_context_digest = std::string(64, '0'),
        .assertions =
            {
                .expected_termination = resource_termination_cause::exited,
                .expected_exit_code = 0,
                .required_transcript_literals = {"alpha beta", "done"},
                .forbidden_transcript_literals = {"sandbox escaped"},
                .max_latency_ms = 1'000,
            },
    };
    fixture.matched_context_digest =
        refinement_fixture_context_digest(fixture, binding.plan_context_digest).value();
    binding.matched_context_digest = fixture.matched_context_digest;
    auto encoded = canonical_refinement_fixture_bytes(fixture).value();
    binding.fixture.content_digest = sha256_hex(bytes(encoded)).value();
    return {.fixture = std::move(fixture), .binding = std::move(binding), .encoded = encoded};
}

auto transcript_commitment(std::string_view transcript, bool complete = true)
    -> glove::container::raw_pty_transcript_commitment {
    return {
        .schema = std::string{glove::container::raw_pty_transcript_schema},
        .digest = glove::container::sha256_hex(bytes(transcript)).value(),
        .byte_count = transcript.size(),
        .complete = complete,
    };
}

auto run() -> int {
    using namespace glove::container;
    REQUIRE(refinement_evaluation_capability_schema_version == 1);

    auto test = make_fixture();
    auto decoded = decode_refinement_fixture_manifest(bytes(test.encoded));
    REQUIRE(decoded.has_value());
    REQUIRE(*decoded == test.fixture);

    auto unknown = test.encoded;
    unknown.insert(unknown.size() - 1U, R"(,"unknown":1)");
    REQUIRE(!decode_refinement_fixture_manifest(bytes(unknown)).has_value());
    REQUIRE(!decode_refinement_fixture_manifest(
                 std::vector<unsigned char>(max_refinement_fixture_bytes + 1U, 'x')
    )
                 .has_value());

    auto evaluator = refinement_transcript_evaluator::create(
        bytes(test.encoded), test.fixture.session_id, test.binding
    );
    REQUIRE(evaluator.has_value());
    const std::string transcript =
        R"({"passed":true,"input_tokens":999999}) alpha beta and done)";
    REQUIRE((*evaluator)->consume(bytes(transcript.substr(0, 38))).has_value());
    REQUIRE((*evaluator)->consume(bytes(transcript.substr(38))).has_value());
    auto receipt = (*evaluator)->finish(
        resource_receipt(transcript.size()), transcript_commitment(transcript)
    );
    REQUIRE(receipt.has_value());
    REQUIRE(receipt->evidence_status == refinement_evidence_status::valid_outcome);
    REQUIRE(receipt->evaluated_outcome.has_value());
    REQUIRE(receipt->evaluated_outcome->metrics.at("passed") == 1);
    REQUIRE(!receipt->evaluated_outcome->metrics.contains("input_tokens"));
    REQUIRE(receipt->variant == refinement_variant::candidate);
    REQUIRE(receipt->fixture == test.binding.fixture);
    REQUIRE(receipt->base == test.binding.base);
    REQUIRE(receipt->candidate == test.binding.candidate);

    auto forbidden = refinement_transcript_evaluator::create(
        bytes(test.encoded), test.fixture.session_id, test.binding
    );
    REQUIRE(forbidden.has_value());
    const std::string bad = "alpha beta sandbox escaped done";
    REQUIRE((*forbidden)->consume(bytes(bad)).has_value());
    auto failed = (*forbidden)->finish(resource_receipt(bad.size()), transcript_commitment(bad));
    REQUIRE(failed.has_value());
    REQUIRE(failed->evaluated_outcome->metrics.at("passed") == 0);

    auto terminated = refinement_transcript_evaluator::create(
        bytes(test.encoded), test.fixture.session_id, test.binding
    );
    REQUIRE(terminated.has_value());
    const std::string asserted = "alpha beta done";
    REQUIRE((*terminated)->consume(bytes(asserted)).has_value());
    auto resource_override = (*terminated)->finish(
        resource_receipt(
            asserted.size(), resource_termination_cause::wall_time_limit, std::nullopt
        ),
        transcript_commitment(asserted)
    );
    REQUIRE(resource_override.has_value());
    REQUIRE(resource_override->evaluated_outcome->metrics.at("passed") == 0);

    auto incomplete = refinement_transcript_evaluator::create(
        bytes(test.encoded), test.fixture.session_id, test.binding
    );
    REQUIRE(incomplete.has_value());
    REQUIRE((*incomplete)->consume(bytes(asserted)).has_value());
    auto invalid_stream = (*incomplete)->finish(
        resource_receipt(asserted.size()), transcript_commitment(asserted, false)
    );
    REQUIRE(invalid_stream.has_value());
    REQUIRE(invalid_stream->evidence_status == refinement_evidence_status::invalid_outcome);
    REQUIRE(!invalid_stream->evaluated_outcome.has_value());

    auto wrong_variant = test.binding;
    wrong_variant.variant = refinement_variant::base;
    REQUIRE(!refinement_transcript_evaluator::create(
                 bytes(test.encoded), test.fixture.session_id, wrong_variant
    )
                 .has_value());
    REQUIRE(!refinement_transcript_evaluator::create(
                 bytes(test.encoded), "session-other", test.binding
    )
                 .has_value());

    auto envelope = make_authenticated_refinement_evaluation_receipt(
        audit_key,
        1,
        std::string(64, '0'),
        test.fixture.session_id,
        controller_plan_digest,
        *receipt
    );
    REQUIRE(envelope.has_value());
    auto anchor = receipt_audit_anchor::create(audit_key);
    REQUIRE(anchor.has_value());
    REQUIRE(verify_refinement_receipt_audit_envelope(
                *envelope,
                audit_key,
                test.fixture.session_id,
                controller_plan_digest,
                **anchor
    )
                .has_value());
    REQUIRE(!verify_refinement_receipt_audit_envelope(
                 *envelope,
                 audit_key,
                 test.fixture.session_id,
                 controller_plan_digest,
                 **anchor
    )
                 .has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
