#include "glove/container/refinement_protocol.hpp"

#include "glove/container/receipt_chain.hpp"

#include "sha256.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
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
constexpr std::size_t frame_prefix_bytes = 4U;
constexpr std::size_t max_result_channel_bytes =
    frame_prefix_bytes + max_refinement_result_payload_bytes + frame_prefix_bytes;

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

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

private:
    std::vector<unsigned char> bytes_;
};

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
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

auto valid_utf8(std::span<const unsigned char> bytes) noexcept -> bool {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto lead = bytes[offset++];
        if (lead <= 0x7fU) {
            continue;
        }
        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (lead >= 0xc2U && lead <= 0xdfU) {
            continuation_count = 1;
            code_point = lead & 0x1fU;
            minimum = 0x80U;
        } else if (lead >= 0xe0U && lead <= 0xefU) {
            continuation_count = 2;
            code_point = lead & 0x0fU;
            minimum = 0x800U;
        } else if (lead >= 0xf0U && lead <= 0xf4U) {
            continuation_count = 3;
            code_point = lead & 0x07U;
            minimum = 0x10000U;
        } else {
            return false;
        }
        if (continuation_count > bytes.size() - offset) {
            return false;
        }
        for (std::size_t index = 0; index < continuation_count; ++index) {
            const auto continuation = bytes[offset++];
            if ((continuation & 0xc0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | (continuation & 0x3fU);
        }
        if (code_point < minimum || code_point > 0x10ffffU ||
            (code_point >= 0xd800U && code_point <= 0xdfffU)) {
            return false;
        }
    }
    return true;
}

auto valid_outcome(const refinement_outcome& outcome) -> bool {
    return outcome.schema == refinement_outcome_schema &&
           outcome.encoding == refinement_outcome_encoding && !outcome.metrics.empty() &&
           outcome.metrics.size() <= max_refinement_metrics &&
           std::ranges::all_of(outcome.metrics, [](const auto& metric) {
               return valid_metric_name(metric.first);
           });
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

auto canonical_frame_payload(const refinement_result_frame& frame)
    -> std::expected<std::string, std::string> {
    if (frame.schema_version != refinement_result_frame_schema_version ||
        !valid_digest(frame.fixture_manifest_digest) || !valid_outcome(frame.outcome)) {
        return std::unexpected(std::string{"invalid refinement result frame"});
    }
    auto outcome = canonical_refinement_outcome_bytes(frame.outcome);
    if (!outcome) {
        return std::unexpected(outcome.error());
    }
    std::string payload;
    payload.reserve(128U + frame.fixture_manifest_digest.size() + outcome->size());
    payload.append(R"({"schema_version":1,"fixture_manifest_digest":")");
    payload.append(frame.fixture_manifest_digest);
    payload.append(R"(","outcome":)");
    payload.append(*outcome);
    payload.push_back('}');
    if (payload.size() > max_refinement_result_payload_bytes) {
        return std::unexpected(std::string{"refinement result payload exceeds its bound"});
    }
    return payload;
}

auto append_frame_prefix(std::vector<unsigned char>& output, std::uint32_t value) -> void {
    for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<unsigned char>(value >> shift));
    }
}

auto decode_frame_size(std::span<const unsigned char> bytes) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
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

auto failure_observation(
    std::string_view fixture_manifest_digest,
    refinement_evidence_status status,
    refinement_result_channel_termination termination,
    std::uint32_t frame_count
) -> std::expected<refinement_result_channel_observation, std::string> {
    auto outcome = empty_outcome_commitment();
    if (!outcome) {
        return std::unexpected(outcome.error());
    }
    return refinement_result_channel_observation{
        .evidence_status = status,
        .fixture_manifest_digest = std::string{fixture_manifest_digest},
        .outcome_commitment = std::move(*outcome),
        .channel =
            {
                .schema = std::string{refinement_result_channel_schema},
                .frame_count = frame_count,
                .termination = termination,
            },
        .outcome = std::nullopt,
    };
}

auto evidence_status_name(refinement_evidence_status status) noexcept -> std::string_view {
    switch (status) {
    case refinement_evidence_status::valid_outcome:
        return "valid_outcome";
    case refinement_evidence_status::missing_outcome:
        return "missing_outcome";
    case refinement_evidence_status::invalid_outcome:
        return "invalid_outcome";
    }
    return {};
}

auto termination_name(refinement_result_channel_termination termination) noexcept
    -> std::string_view {
    switch (termination) {
    case refinement_result_channel_termination::clean_eof:
        return "clean_eof";
    case refinement_result_channel_termination::truncated_frame:
        return "truncated_frame";
    case refinement_result_channel_termination::oversized_frame:
        return "oversized_frame";
    case refinement_result_channel_termination::malformed_frame:
        return "malformed_frame";
    case refinement_result_channel_termination::trailing_bytes:
        return "trailing_bytes";
    case refinement_result_channel_termination::multiple_frames:
        return "multiple_frames";
    case refinement_result_channel_termination::read_error:
        return "read_error";
    }
    return {};
}

auto valid_receipt_evidence(const refinement_evaluation_receipt& receipt) -> bool {
    if (receipt.schema_version != refinement_evaluation_receipt_schema_version ||
        receipt.runtime_template_id != refinement_runtime_template_id ||
        !valid_digest(receipt.fixture_manifest_digest) ||
        receipt.outcome.schema != refinement_outcome_schema ||
        receipt.outcome.encoding != refinement_outcome_encoding ||
        !valid_digest(receipt.outcome.digest) ||
        receipt.outcome.byte_length > max_refinement_result_payload_bytes ||
        receipt.transcript.schema != raw_pty_transcript_schema ||
        !valid_digest(receipt.transcript.digest) ||
        receipt.transcript.byte_count != receipt.resource_receipt.observed.terminal_output_bytes ||
        receipt.result_channel.schema != refinement_result_channel_schema ||
        receipt.result_channel.frame_count > 2U ||
        evidence_status_name(receipt.evidence_status).empty() ||
        termination_name(receipt.result_channel.termination).empty()) {
        return false;
    }
    const auto empty_digest = detail::sha256_hex({});
    if (!empty_digest) {
        return false;
    }
    switch (receipt.evidence_status) {
    case refinement_evidence_status::valid_outcome:
        return receipt.outcome.byte_length > 0 && receipt.result_channel.frame_count == 1U &&
               receipt.result_channel.termination ==
                   refinement_result_channel_termination::clean_eof;
    case refinement_evidence_status::missing_outcome:
        return receipt.outcome.byte_length == 0 && receipt.outcome.digest == *empty_digest &&
               receipt.result_channel.frame_count == 0U &&
               receipt.result_channel.termination ==
                   refinement_result_channel_termination::clean_eof;
    case refinement_evidence_status::invalid_outcome:
        return receipt.outcome.byte_length == 0 && receipt.outcome.digest == *empty_digest &&
               receipt.result_channel.termination !=
                   refinement_result_channel_termination::clean_eof;
    }
    return false;
}

} // namespace

auto canonical_refinement_outcome_bytes(const refinement_outcome& outcome)
    -> std::expected<std::string, std::string> {
    if (!valid_outcome(outcome)) {
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
    if (canonical.size() > max_refinement_result_payload_bytes) {
        return std::unexpected(std::string{"canonical refinement outcome exceeds its bound"});
    }
    return canonical;
}

auto encode_refinement_result_frame(const refinement_result_frame& frame)
    -> std::expected<std::vector<unsigned char>, std::string> {
    auto payload = canonical_frame_payload(frame);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    std::vector<unsigned char> encoded;
    encoded.reserve(frame_prefix_bytes + payload->size());
    append_frame_prefix(encoded, static_cast<std::uint32_t>(payload->size()));
    encoded.insert(encoded.end(), payload->begin(), payload->end());
    return encoded;
}

auto inspect_refinement_result_channel(
    std::span<const unsigned char> channel_bytes, std::string_view expected_fixture_manifest_digest
) -> std::expected<refinement_result_channel_observation, std::string> {
    if (!valid_digest(expected_fixture_manifest_digest)) {
        return std::unexpected(std::string{"invalid expected fixture manifest digest"});
    }
    if (channel_bytes.empty()) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::missing_outcome,
            refinement_result_channel_termination::clean_eof,
            0
        );
    }
    if (channel_bytes.size() < frame_prefix_bytes) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::truncated_frame,
            0
        );
    }
    const auto payload_size = decode_frame_size(channel_bytes.first(frame_prefix_bytes));
    if (payload_size == 0) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::malformed_frame,
            1
        );
    }
    if (payload_size > max_refinement_result_payload_bytes ||
        channel_bytes.size() > max_result_channel_bytes) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::oversized_frame,
            1
        );
    }
    const auto first_frame_bytes = frame_prefix_bytes + static_cast<std::size_t>(payload_size);
    if (channel_bytes.size() < first_frame_bytes) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::truncated_frame,
            1
        );
    }
    if (channel_bytes.size() > first_frame_bytes) {
        const auto trailing = channel_bytes.subspan(first_frame_bytes);
        const bool has_second_prefix = trailing.size() >= frame_prefix_bytes;
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            has_second_prefix ? refinement_result_channel_termination::multiple_frames
                              : refinement_result_channel_termination::trailing_bytes,
            has_second_prefix ? 2U : 1U
        );
    }

    const auto payload = channel_bytes.subspan(frame_prefix_bytes, payload_size);
    if (!valid_utf8(payload)) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::malformed_frame,
            1
        );
    }
    std::string parse_buffer{reinterpret_cast<const char*>(payload.data()), payload.size()};
    refinement_result_frame frame;
    if (const auto error = glz::read<strict_read_options>(frame, parse_buffer); error) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::malformed_frame,
            1
        );
    }
    auto canonical_payload = canonical_frame_payload(frame);
    if (!canonical_payload ||
        std::string_view{reinterpret_cast<const char*>(payload.data()), payload.size()} !=
            *canonical_payload ||
        frame.fixture_manifest_digest != expected_fixture_manifest_digest) {
        return failure_observation(
            expected_fixture_manifest_digest,
            refinement_evidence_status::invalid_outcome,
            refinement_result_channel_termination::malformed_frame,
            1
        );
    }
    auto outcome_bytes = canonical_refinement_outcome_bytes(frame.outcome);
    if (!outcome_bytes) {
        return std::unexpected(outcome_bytes.error());
    }
    auto outcome_digest = detail::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(outcome_bytes->data()), outcome_bytes->size()
        }
    );
    if (!outcome_digest) {
        return std::unexpected(outcome_digest.error());
    }
    return refinement_result_channel_observation{
        .evidence_status = refinement_evidence_status::valid_outcome,
        .fixture_manifest_digest = frame.fixture_manifest_digest,
        .outcome_commitment =
            {
                .schema = frame.outcome.schema,
                .encoding = frame.outcome.encoding,
                .digest = std::move(*outcome_digest),
                .byte_length = outcome_bytes->size(),
            },
        .channel =
            {
                .schema = std::string{refinement_result_channel_schema},
                .frame_count = 1,
                .termination = refinement_result_channel_termination::clean_eof,
            },
        .outcome = std::move(frame.outcome),
    };
}

auto refinement_evaluation_receipt_digest(const refinement_evaluation_receipt& receipt)
    -> std::expected<std::string, std::string> {
    auto resource_digest = resource_enforcement_receipt_digest(receipt.resource_receipt);
    if (!resource_digest || !valid_receipt_evidence(receipt)) {
        return std::unexpected(std::string{"invalid refinement evaluation receipt"});
    }
    const auto status = evidence_status_name(receipt.evidence_status);
    const auto termination = termination_name(receipt.result_channel.termination);
    canonical_encoder encoder;
    encoder.append_string("glove.refinement-evaluation-receipt");
    encoder.append_u8(1);
    encoder.append_u8(receipt.schema_version);
    encoder.append_string(receipt.runtime_template_id);
    encoder.append_string(*resource_digest);
    encoder.append_string(status);
    encoder.append_string(receipt.fixture_manifest_digest);
    encoder.append_string(receipt.outcome.schema);
    encoder.append_string(receipt.outcome.encoding);
    encoder.append_string(receipt.outcome.digest);
    encoder.append_u64(receipt.outcome.byte_length);
    encoder.append_string(receipt.transcript.schema);
    encoder.append_string(receipt.transcript.digest);
    encoder.append_u64(receipt.transcript.byte_count);
    encoder.append_bool(receipt.transcript.complete);
    encoder.append_string(receipt.result_channel.schema);
    encoder.append_u32(receipt.result_channel.frame_count);
    encoder.append_string(termination);
    return detail::sha256_hex(encoder.bytes());
}

} // namespace glove::container
