#include "glove/container/refinement_protocol.hpp"

#include "glove/container/receipt_chain.hpp"

#include "receipt_json.hpp"
#include "sha256.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t digest_hex_bytes = 64U;
constexpr std::size_t max_identifier_bytes = 512U;
constexpr std::size_t max_module_items = 256U;

class canonical_encoder {
public:
    void append_u8(std::uint8_t value) { bytes_.push_back(value); }

    void append_u32(std::uint32_t value) {
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_u64(std::uint64_t value) {
        for (const unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_bool(bool value) { append_u8(value ? 1U : 0U); }

    void append_string(std::string_view value) {
        append_u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    void append_optional_string(const std::optional<std::string>& value) {
        append_bool(value.has_value());
        if (value) {
            append_string(*value);
        }
    }

    void append_strings(const std::vector<std::string>& values) {
        append_u32(static_cast<std::uint32_t>(values.size()));
        for (const auto& value : values) {
            append_string(value);
        }
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

private:
    std::vector<unsigned char> bytes_;
};

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_token(std::string_view value, std::size_t max_bytes = max_identifier_bytes) noexcept
    -> bool {
    return !value.empty() && value.size() <= max_bytes &&
           std::ranges::none_of(value, [](unsigned char byte) {
               return byte < 0x20U || byte == 0x7fU;
           });
}

auto valid_metric_name(std::string_view value) noexcept -> bool {
    if (value.empty() || value.size() > max_refinement_metric_name_bytes || value.front() < 'a' ||
        value.front() > 'z') {
        return false;
    }
    return std::ranges::all_of(value, [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '_' ||
               byte == '-' || byte == '.';
    });
}

auto valid_utf8_literal(std::string_view value) noexcept -> bool {
    if (value.empty() || value.size() > max_refinement_transcript_literal_bytes) {
        return false;
    }
    std::size_t remaining = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (remaining == 0) {
            if (byte <= 0x7fU) {
                continue;
            }
            if (byte >= 0xc2U && byte <= 0xdfU) {
                remaining = 1;
                code_point = byte & 0x1fU;
                minimum = 0x80U;
            } else if (byte >= 0xe0U && byte <= 0xefU) {
                remaining = 2;
                code_point = byte & 0x0fU;
                minimum = 0x800U;
            } else if (byte >= 0xf0U && byte <= 0xf4U) {
                remaining = 3;
                code_point = byte & 0x07U;
                minimum = 0x10000U;
            } else {
                return false;
            }
            continue;
        }
        if ((byte & 0xc0U) != 0x80U) {
            return false;
        }
        code_point = (code_point << 6U) | (byte & 0x3fU);
        --remaining;
        if (remaining == 0 && (code_point < minimum || code_point > 0x10ffffU ||
                               (code_point >= 0xd800U && code_point <= 0xdfffU))) {
            return false;
        }
    }
    return remaining == 0;
}

auto valid_literal_set(const std::vector<std::string>& values, std::size_t& total) -> bool {
    if (values.size() > max_refinement_transcript_literals) {
        return false;
    }
    std::string_view previous;
    for (const auto& value : values) {
        if (!valid_utf8_literal(value) || (!previous.empty() && value <= previous) ||
            value.size() > max_refinement_transcript_literal_total_bytes - total) {
            return false;
        }
        total += value.size();
        previous = value;
    }
    return true;
}

auto valid_string_set(const std::vector<std::string>& values) -> bool {
    if (values.size() > max_module_items) {
        return false;
    }
    std::string_view previous;
    return std::ranges::all_of(values, [&](const auto& value) {
        const bool valid = valid_token(value) && (previous.empty() || value > previous);
        previous = value;
        return valid;
    });
}

auto valid_module(const refinement_module_binding& module) -> bool {
    return valid_token(module.repository_id) && valid_digest(module.repository_tree) &&
           valid_digest(module.module_id) && valid_token(module.label) &&
           module.detector_version != 0 && valid_string_set(module.include_paths) &&
           valid_string_set(module.exclude_paths) && valid_string_set(module.languages) &&
           valid_string_set(module.frameworks) && valid_string_set(module.package_managers);
}

auto valid_projection(const refinement_projection_binding& projection) -> bool {
    return valid_token(projection.projection_id, 128U) && valid_digest(projection.content_digest) &&
           valid_token(projection.destination_alias, 128U);
}

auto selected_projection(const refinement_execution_binding& binding)
    -> const refinement_projection_binding& {
    return binding.variant == refinement_variant::base ? binding.base : binding.candidate;
}

auto valid_binding(const refinement_execution_binding& binding) -> bool {
    return binding.schema_version == 1 && valid_projection(binding.fixture) &&
           valid_projection(binding.base) && valid_projection(binding.candidate) &&
           binding.fixture.projection_id != binding.base.projection_id &&
           binding.fixture.projection_id != binding.candidate.projection_id &&
           binding.base.projection_id != binding.candidate.projection_id &&
           valid_digest(binding.matched_context_digest) &&
           valid_digest(binding.plan_context_digest);
}

auto valid_fixture(const refinement_fixture_manifest& fixture) -> bool {
    std::size_t literal_bytes = 0;
    const bool expected_exit_valid =
        fixture.assertions.expected_termination == resource_termination_cause::exited
            ? fixture.assertions.expected_exit_code.has_value()
            : !fixture.assertions.expected_exit_code.has_value();
    return fixture.schema == refinement_fixture_schema && valid_token(fixture.evaluation_run_id) &&
           valid_token(fixture.pair_id) && valid_token(fixture.session_id, 128U) &&
           valid_digest(fixture.proposal_digest) && valid_digest(fixture.base_projection_digest) &&
           valid_digest(fixture.candidate_projection_digest) && valid_token(fixture.fixture_id) &&
           valid_digest(fixture.fixture_digest) && valid_token(fixture.dataset_ref) &&
           valid_digest(fixture.dataset_fingerprint) && valid_token(fixture.model.model_id) &&
           (!fixture.model.provider || valid_token(*fixture.model.provider)) &&
           (!fixture.model.model_family || valid_token(*fixture.model.model_family)) &&
           (!fixture.model.model_revision || valid_token(*fixture.model.model_revision)) &&
           valid_token(fixture.model.tier) && fixture.model.normalizer_version != 0 &&
           valid_token(fixture.harness) && (!fixture.module || valid_module(*fixture.module)) &&
           valid_token(fixture.skill_projection_id, 128U) &&
           valid_digest(fixture.skill_projection_digest) &&
           valid_digest(fixture.matched_context_digest) && expected_exit_valid &&
           fixture.assertions.expected_exit_code.value_or(0) >= 0 &&
           valid_literal_set(fixture.assertions.required_transcript_literals, literal_bytes) &&
           valid_literal_set(fixture.assertions.forbidden_transcript_literals, literal_bytes) &&
           (!fixture.assertions.max_latency_ms || *fixture.assertions.max_latency_ms != 0);
}

auto append_integer(std::string& output, std::int64_t value) -> bool {
    std::array<char, 32> encoded{};
    const auto [end, error] = std::to_chars(encoded.data(), encoded.data() + encoded.size(), value);
    if (error != std::errc{}) {
        return false;
    }
    output.append(encoded.data(), end);
    return true;
}

auto empty_outcome_commitment() -> std::expected<refinement_outcome_commitment, std::string> {
    auto digest = detail::sha256_hex({});
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return refinement_outcome_commitment{
        .schema = std::string{refinement_outcome_schema},
        .encoding = std::string{refinement_outcome_encoding},
        .digest = std::move(*digest),
        .byte_length = 0,
    };
}

auto outcome_commitment(const refinement_outcome& outcome)
    -> std::expected<refinement_outcome_commitment, std::string> {
    auto bytes = canonical_refinement_outcome_bytes(outcome);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto digest = detail::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(bytes->data()), bytes->size()
        }
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return refinement_outcome_commitment{
        .schema = outcome.schema,
        .encoding = outcome.encoding,
        .digest = std::move(*digest),
        .byte_length = bytes->size(),
    };
}

auto evidence_status_name(refinement_evidence_status status) noexcept -> std::string_view {
    switch (status) {
    case refinement_evidence_status::valid_outcome:
        return "valid_outcome";
    case refinement_evidence_status::invalid_outcome:
        return "invalid_outcome";
    }
    return {};
}

auto resource_termination_name(resource_termination_cause cause) noexcept -> std::string_view {
    switch (cause) {
    case resource_termination_cause::exited:
        return "exited";
    case resource_termination_cause::signaled:
        return "signaled";
    case resource_termination_cause::cpu_time_limit:
        return "cpu_time_limit";
    case resource_termination_cause::memory_limit:
        return "memory_limit";
    case resource_termination_cause::pid_limit:
        return "pid_limit";
    case resource_termination_cause::wall_time_limit:
        return "wall_time_limit";
    case resource_termination_cause::disk_limit:
        return "disk_limit";
    case resource_termination_cause::terminal_output_limit:
        return "terminal_output_limit";
    case resource_termination_cause::supervisor_error:
        return "supervisor_error";
    }
    return {};
}

auto variant_name(refinement_variant variant) noexcept -> std::string_view {
    switch (variant) {
    case refinement_variant::base:
        return "base";
    case refinement_variant::candidate:
        return "candidate";
    }
    return {};
}

auto append_projection(canonical_encoder& encoder, const refinement_projection_binding& value)
    -> void {
    encoder.append_string(value.projection_id);
    encoder.append_string(value.content_digest);
    encoder.append_string(value.destination_alias);
}

auto valid_receipt_evidence(const refinement_evaluation_receipt& receipt) -> bool {
    if (receipt.schema_version != refinement_evaluation_receipt_schema_version ||
        receipt.runtime_template_id != refinement_runtime_template_id ||
        !valid_projection(receipt.fixture) || !valid_projection(receipt.base) ||
        !valid_projection(receipt.candidate) || !valid_digest(receipt.matched_context_digest) ||
        receipt.outcome.schema != refinement_outcome_schema ||
        receipt.outcome.encoding != refinement_outcome_encoding ||
        !valid_digest(receipt.outcome.digest) ||
        receipt.outcome.byte_length > max_refinement_fixture_bytes ||
        receipt.transcript.schema != raw_pty_transcript_schema ||
        !valid_digest(receipt.transcript.digest) ||
        receipt.transcript.byte_count != receipt.resource_receipt.observed.terminal_output_bytes ||
        receipt.evaluator.schema != refinement_evaluator_schema ||
        evidence_status_name(receipt.evidence_status).empty() ||
        variant_name(receipt.variant).empty()) {
        return false;
    }
    if (receipt.evidence_status == refinement_evidence_status::valid_outcome) {
        if (!receipt.evaluated_outcome || !receipt.transcript.complete ||
            !receipt.evaluator.fixture_complete || !receipt.evaluator.transcript_utf8 ||
            receipt.outcome.byte_length == 0) {
            return false;
        }
        auto expected = outcome_commitment(*receipt.evaluated_outcome);
        return expected && *expected == receipt.outcome;
    }
    auto empty = empty_outcome_commitment();
    return !receipt.evaluated_outcome && empty && *empty == receipt.outcome &&
           (!receipt.transcript.complete || !receipt.evaluator.transcript_utf8);
}

struct literal_matcher {
    std::string literal;
    std::vector<std::size_t> prefix;
    std::size_t matched = 0;
    bool found = false;

    explicit literal_matcher(std::string value)
        : literal{std::move(value)}, prefix(literal.size()) {
        for (std::size_t index = 1, length = 0; index < literal.size();) {
            if (literal[index] == literal[length]) {
                prefix[index++] = ++length;
            } else if (length != 0) {
                length = prefix[length - 1U];
            } else {
                prefix[index++] = 0;
            }
        }
    }

    void consume(unsigned char byte) noexcept {
        const char value = static_cast<char>(byte);
        while (matched != 0 && literal[matched] != value) {
            matched = prefix[matched - 1U];
        }
        if (literal[matched] == value) {
            ++matched;
        }
        if (matched == literal.size()) {
            found = true;
            matched = prefix[matched - 1U];
        }
    }
};

} // namespace

struct refinement_transcript_evaluator::implementation {
    refinement_execution_binding binding;
    refinement_fixture_manifest fixture;
    std::vector<literal_matcher> required;
    std::vector<literal_matcher> forbidden;
    std::size_t utf8_remaining = 0;
    std::uint32_t utf8_code_point = 0;
    std::uint32_t utf8_minimum = 0;
    bool utf8_valid = true;
    bool finished = false;
    std::optional<refinement_evaluation_receipt> receipt;
    mutable std::mutex mutex;
};

auto canonical_refinement_fixture_bytes(const refinement_fixture_manifest& fixture)
    -> std::expected<std::string, std::string> {
    if (!valid_fixture(fixture)) {
        return std::unexpected(std::string{"invalid refinement fixture manifest"});
    }
    auto encoded = glz::write_json(fixture);
    if (!encoded || encoded->size() > max_refinement_fixture_bytes) {
        return std::unexpected(std::string{"refinement fixture encoding exceeds its bound"});
    }
    return std::move(*encoded);
}

auto decode_refinement_fixture_manifest(std::span<const unsigned char> bytes)
    -> std::expected<refinement_fixture_manifest, std::string> {
    if (bytes.empty() || bytes.size() > max_refinement_fixture_bytes) {
        return std::unexpected(std::string{"refinement fixture bytes exceed their bound"});
    }
    std::string input{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    refinement_fixture_manifest fixture;
    if (const auto error = glz::read<strict_read_options>(fixture, input); error) {
        return std::unexpected(
            std::string{"refinement fixture decode: "} + glz::format_error(error, input)
        );
    }
    auto canonical = canonical_refinement_fixture_bytes(fixture);
    if (!canonical || *canonical != input) {
        return std::unexpected(std::string{"refinement fixture is not canonical"});
    }
    return fixture;
}

auto refinement_fixture_context_digest(
    const refinement_fixture_manifest& fixture, std::string_view plan_context_digest
) -> std::expected<std::string, std::string> {
    if (!valid_fixture(fixture) || !valid_digest(plan_context_digest)) {
        return std::unexpected(std::string{"invalid refinement matched context"});
    }
    canonical_encoder encoder;
    encoder.append_string("glove.refinement-matched-context");
    encoder.append_u8(1);
    encoder.append_string(plan_context_digest);
    encoder.append_string(fixture.schema);
    encoder.append_string(fixture.evaluation_run_id);
    encoder.append_string(fixture.pair_id);
    encoder.append_string(fixture.proposal_digest);
    encoder.append_string(fixture.base_projection_digest);
    encoder.append_string(fixture.candidate_projection_digest);
    encoder.append_string(fixture.fixture_id);
    encoder.append_string(fixture.fixture_digest);
    encoder.append_string(fixture.dataset_ref);
    encoder.append_string(fixture.dataset_fingerprint);
    encoder.append_u64(fixture.seed);
    encoder.append_optional_string(fixture.model.provider);
    encoder.append_string(fixture.model.model_id);
    encoder.append_optional_string(fixture.model.model_family);
    encoder.append_optional_string(fixture.model.model_revision);
    encoder.append_string(fixture.model.tier);
    encoder.append_u32(fixture.model.normalizer_version);
    encoder.append_string(fixture.harness);
    encoder.append_bool(fixture.module.has_value());
    if (fixture.module) {
        encoder.append_string(fixture.module->repository_id);
        encoder.append_string(fixture.module->repository_tree);
        encoder.append_string(fixture.module->module_id);
        encoder.append_string(fixture.module->label);
        encoder.append_strings(fixture.module->include_paths);
        encoder.append_strings(fixture.module->exclude_paths);
        encoder.append_strings(fixture.module->languages);
        encoder.append_strings(fixture.module->frameworks);
        encoder.append_strings(fixture.module->package_managers);
        encoder.append_u32(fixture.module->detector_version);
    }
    encoder.append_string(resource_termination_name(fixture.assertions.expected_termination));
    encoder.append_bool(fixture.assertions.expected_exit_code.has_value());
    if (fixture.assertions.expected_exit_code) {
        encoder.append_u32(static_cast<std::uint32_t>(*fixture.assertions.expected_exit_code));
    }
    encoder.append_strings(fixture.assertions.required_transcript_literals);
    encoder.append_strings(fixture.assertions.forbidden_transcript_literals);
    encoder.append_bool(fixture.assertions.max_latency_ms.has_value());
    if (fixture.assertions.max_latency_ms) {
        encoder.append_u64(*fixture.assertions.max_latency_ms);
    }
    return detail::sha256_hex(encoder.bytes());
}

auto canonical_refinement_outcome_bytes(const refinement_outcome& outcome)
    -> std::expected<std::string, std::string> {
    if (outcome.schema != refinement_outcome_schema ||
        outcome.encoding != refinement_outcome_encoding || outcome.metrics.empty() ||
        outcome.metrics.size() > max_refinement_metrics ||
        std::ranges::any_of(outcome.metrics, [](const auto& metric) {
            return !valid_metric_name(metric.first);
        })) {
        return std::unexpected(std::string{"invalid refinement outcome"});
    }
    std::string canonical;
    canonical.reserve(128U + outcome.metrics.size() * 32U);
    canonical.append(R"({"schema":"sage.refinement-eval-outcome-v1","encoding":)");
    canonical.append(R"("canonical-json-utf8","metrics":{)");
    bool first = true;
    for (const auto& [name, value] : outcome.metrics) {
        if (!first) {
            canonical.push_back(',');
        }
        canonical.push_back('"');
        canonical.append(name);
        canonical.append("\":");
        if (!append_integer(canonical, value)) {
            return std::unexpected(std::string{"encode refinement metric integer"});
        }
        first = false;
    }
    canonical.append("}}");
    if (canonical.size() > max_refinement_fixture_bytes) {
        return std::unexpected(std::string{"canonical refinement outcome exceeds its bound"});
    }
    return canonical;
}

refinement_transcript_evaluator::refinement_transcript_evaluator(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

refinement_transcript_evaluator::~refinement_transcript_evaluator() = default;

auto refinement_transcript_evaluator::create(
    std::span<const unsigned char> fixture_bytes,
    std::string_view expected_session_id,
    const refinement_execution_binding& binding
) -> std::expected<std::shared_ptr<refinement_transcript_evaluator>, std::string> {
    if (!valid_binding(binding) || !valid_token(expected_session_id, 128U)) {
        return std::unexpected(std::string{"invalid refinement execution binding"});
    }
    auto fixture = decode_refinement_fixture_manifest(fixture_bytes);
    if (!fixture) {
        return std::unexpected(fixture.error());
    }
    const auto& selected = selected_projection(binding);
    if (fixture->session_id != expected_session_id || fixture->variant != binding.variant ||
        fixture->base_projection_digest != binding.base.content_digest ||
        fixture->candidate_projection_digest != binding.candidate.content_digest ||
        fixture->skill_projection_id != selected.projection_id ||
        fixture->skill_projection_digest != selected.content_digest ||
        fixture->matched_context_digest != binding.matched_context_digest) {
        return std::unexpected(std::string{"refinement fixture execution binding mismatch"});
    }
    auto context = refinement_fixture_context_digest(*fixture, binding.plan_context_digest);
    if (!context || *context != binding.matched_context_digest) {
        return std::unexpected(std::string{"refinement fixture matched context mismatch"});
    }
    auto fixture_digest = detail::sha256_hex(fixture_bytes);
    if (!fixture_digest || *fixture_digest != binding.fixture.content_digest) {
        return std::unexpected(std::string{"refinement fixture projection digest mismatch"});
    }
    try {
        auto state = std::make_unique<implementation>();
        state->binding = binding;
        state->fixture = std::move(*fixture);
        state->required.reserve(state->fixture.assertions.required_transcript_literals.size());
        for (const auto& literal : state->fixture.assertions.required_transcript_literals) {
            state->required.emplace_back(literal);
        }
        state->forbidden.reserve(state->fixture.assertions.forbidden_transcript_literals.size());
        for (const auto& literal : state->fixture.assertions.forbidden_transcript_literals) {
            state->forbidden.emplace_back(literal);
        }
        return std::make_shared<refinement_transcript_evaluator>(
            construction_token{}, std::move(state)
        );
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate refinement transcript evaluator"});
    }
}

auto refinement_transcript_evaluator::consume(std::span<const unsigned char> bytes)
    -> std::expected<void, std::string> {
    const std::lock_guard lock{state_->mutex};
    if (state_->finished) {
        return std::unexpected(std::string{"refinement evaluator is already finished"});
    }
    for (const unsigned char byte : bytes) {
        for (auto& matcher : state_->required) {
            matcher.consume(byte);
        }
        for (auto& matcher : state_->forbidden) {
            matcher.consume(byte);
        }
        if (!state_->utf8_valid) {
            continue;
        }
        if (state_->utf8_remaining == 0) {
            if (byte <= 0x7fU) {
                continue;
            }
            if (byte >= 0xc2U && byte <= 0xdfU) {
                state_->utf8_remaining = 1;
                state_->utf8_code_point = byte & 0x1fU;
                state_->utf8_minimum = 0x80U;
            } else if (byte >= 0xe0U && byte <= 0xefU) {
                state_->utf8_remaining = 2;
                state_->utf8_code_point = byte & 0x0fU;
                state_->utf8_minimum = 0x800U;
            } else if (byte >= 0xf0U && byte <= 0xf4U) {
                state_->utf8_remaining = 3;
                state_->utf8_code_point = byte & 0x07U;
                state_->utf8_minimum = 0x10000U;
            } else {
                state_->utf8_valid = false;
            }
            continue;
        }
        if ((byte & 0xc0U) != 0x80U) {
            state_->utf8_valid = false;
            continue;
        }
        state_->utf8_code_point = (state_->utf8_code_point << 6U) | (byte & 0x3fU);
        --state_->utf8_remaining;
        if (state_->utf8_remaining == 0 &&
            (state_->utf8_code_point < state_->utf8_minimum ||
             state_->utf8_code_point > 0x10ffffU ||
             (state_->utf8_code_point >= 0xd800U && state_->utf8_code_point <= 0xdfffU))) {
            state_->utf8_valid = false;
        }
    }
    return {};
}

auto refinement_transcript_evaluator::finish(
    const resource_enforcement_receipt& resource_receipt,
    const raw_pty_transcript_commitment& transcript
) -> std::expected<refinement_evaluation_receipt, std::string> {
    const std::lock_guard lock{state_->mutex};
    if (state_->receipt) {
        return *state_->receipt;
    }
    if (state_->finished || resource_receipt.schema_version != 1 ||
        transcript.schema != raw_pty_transcript_schema ||
        transcript.byte_count != resource_receipt.observed.terminal_output_bytes) {
        return std::unexpected(std::string{"invalid refinement evaluator terminal input"});
    }
    state_->finished = true;
    const bool utf8_complete = state_->utf8_valid && state_->utf8_remaining == 0;
    const bool stream_complete = transcript.complete && utf8_complete;
    auto empty = empty_outcome_commitment();
    if (!empty) {
        return std::unexpected(empty.error());
    }
    refinement_evaluation_receipt receipt{
        .schema_version = refinement_evaluation_receipt_schema_version,
        .runtime_template_id = std::string{refinement_runtime_template_id},
        .resource_receipt = resource_receipt,
        .evidence_status = refinement_evidence_status::invalid_outcome,
        .variant = state_->binding.variant,
        .fixture = state_->binding.fixture,
        .base = state_->binding.base,
        .candidate = state_->binding.candidate,
        .matched_context_digest = state_->binding.matched_context_digest,
        .outcome = std::move(*empty),
        .evaluated_outcome = std::nullopt,
        .transcript = transcript,
        .evaluator = {
            .schema = std::string{refinement_evaluator_schema},
            .fixture_complete = true,
            .transcript_utf8 = utf8_complete,
            .required_literals = static_cast<std::uint32_t>(state_->required.size()),
            .forbidden_literals = static_cast<std::uint32_t>(state_->forbidden.size()),
        },
    };
    if (stream_complete) {
        std::uint64_t failed_assertions = 0;
        failed_assertions += static_cast<std::uint64_t>(std::ranges::count_if(
            state_->required, [](const auto& matcher) { return !matcher.found; }
        ));
        failed_assertions += static_cast<std::uint64_t>(std::ranges::count_if(
            state_->forbidden, [](const auto& matcher) { return matcher.found; }
        ));
        const bool termination_matches =
            resource_receipt.termination_cause == state_->fixture.assertions.expected_termination;
        const bool exit_matches =
            !state_->fixture.assertions.expected_exit_code ||
            resource_receipt.exit_code == state_->fixture.assertions.expected_exit_code;
        const bool latency_matches =
            !state_->fixture.assertions.max_latency_ms ||
            resource_receipt.observed.wall_time_ms <= *state_->fixture.assertions.max_latency_ms;
        failed_assertions += termination_matches ? 0U : 1U;
        failed_assertions += exit_matches ? 0U : 1U;
        failed_assertions += latency_matches ? 0U : 1U;
        const auto latency_us =
            resource_receipt.observed.wall_time_ms >
                    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 1'000U
                ? std::numeric_limits<std::int64_t>::max()
                : static_cast<std::int64_t>(resource_receipt.observed.wall_time_ms * 1'000U);
        refinement_outcome outcome{
            .schema = std::string{refinement_outcome_schema},
            .encoding = std::string{refinement_outcome_encoding},
            .metrics = {
                {"failed_assertions", static_cast<std::int64_t>(failed_assertions)},
                {"forbidden_literals", static_cast<std::int64_t>(state_->forbidden.size())},
                {"latency_us", latency_us},
                {"passed", failed_assertions == 0 ? 1 : 0},
                {"required_literals", static_cast<std::int64_t>(state_->required.size())},
            },
        };
        auto commitment = outcome_commitment(outcome);
        if (!commitment) {
            return std::unexpected(commitment.error());
        }
        receipt.evidence_status = refinement_evidence_status::valid_outcome;
        receipt.outcome = std::move(*commitment);
        receipt.evaluated_outcome = std::move(outcome);
    }
    state_->receipt = receipt;
    return receipt;
}

auto refinement_transcript_evaluator::binding() const -> refinement_execution_binding {
    const std::lock_guard lock{state_->mutex};
    return state_->binding;
}

auto refinement_evaluation_receipt_digest(const refinement_evaluation_receipt& receipt)
    -> std::expected<std::string, std::string> {
    auto resource_digest = resource_enforcement_receipt_digest(receipt.resource_receipt);
    if (!resource_digest || !valid_receipt_evidence(receipt)) {
        return std::unexpected(std::string{"invalid refinement evaluation receipt"});
    }
    canonical_encoder encoder;
    encoder.append_string("glove.refinement-evaluation-receipt");
    encoder.append_u8(2);
    encoder.append_u8(receipt.schema_version);
    encoder.append_string(receipt.runtime_template_id);
    encoder.append_string(*resource_digest);
    encoder.append_string(evidence_status_name(receipt.evidence_status));
    encoder.append_string(variant_name(receipt.variant));
    append_projection(encoder, receipt.fixture);
    append_projection(encoder, receipt.base);
    append_projection(encoder, receipt.candidate);
    encoder.append_string(receipt.matched_context_digest);
    encoder.append_string(receipt.outcome.schema);
    encoder.append_string(receipt.outcome.encoding);
    encoder.append_string(receipt.outcome.digest);
    encoder.append_u64(receipt.outcome.byte_length);
    encoder.append_bool(receipt.evaluated_outcome.has_value());
    if (receipt.evaluated_outcome) {
        auto outcome_bytes = canonical_refinement_outcome_bytes(*receipt.evaluated_outcome);
        if (!outcome_bytes) {
            return std::unexpected(outcome_bytes.error());
        }
        encoder.append_string(*outcome_bytes);
    }
    encoder.append_string(receipt.transcript.schema);
    encoder.append_string(receipt.transcript.digest);
    encoder.append_u64(receipt.transcript.byte_count);
    encoder.append_bool(receipt.transcript.complete);
    encoder.append_string(receipt.evaluator.schema);
    encoder.append_bool(receipt.evaluator.fixture_complete);
    encoder.append_bool(receipt.evaluator.transcript_utf8);
    encoder.append_u32(receipt.evaluator.required_literals);
    encoder.append_u32(receipt.evaluator.forbidden_literals);
    return detail::sha256_hex(encoder.bytes());
}

} // namespace glove::container
