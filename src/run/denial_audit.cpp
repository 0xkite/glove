#include "denial_audit.hpp"

#include "glove/audit/event.hpp"
#include "glove/mcp/messages.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <utility>

namespace glove::run::detail {

namespace {

constexpr std::size_t max_kind_bytes = 32;
constexpr auto window = std::chrono::milliseconds{1000};

auto boolean(bool value) -> std::string_view {
    return value ? "true" : "false";
}

auto state_name(glove::container::denial_telemetry_state state) -> std::string_view {
    switch (state) {
    case glove::container::denial_telemetry_state::unavailable:
        return "unavailable";
    case glove::container::denial_telemetry_state::live:
        return "live";
    case glove::container::denial_telemetry_state::degraded:
        return "degraded";
    }
    return "unavailable";
}

// A score in [0, 1] as fixed text; anything else (a NaN from a broken
// decider, for one) is written as 0.
auto score_text(float score) -> std::string {
    const double bounded = score >= 0.0F && score <= 1.0F ? static_cast<double>(score) : 0.0;
    std::array<char, 16> buffer{};
    const int written = std::snprintf(buffer.data(), buffer.size(), "%.3f", bounded);
    return written > 0 ? std::string{buffer.data(), static_cast<std::size_t>(written)}
                       : std::string{"0.000"};
}

} // namespace

denial_audit_writer::denial_audit_writer(std::shared_ptr<glove::audit::sink> sink, clock now)
    : sink_{std::move(sink)}, now_{std::move(now)} {
    if (!now_) {
        now_ = [] { return std::chrono::steady_clock::now(); };
    }
}

auto denial_audit_writer::checked(std::string_view text, std::size_t max_bytes) -> std::string {
    if (text.size() > max_bytes || !glove::container::is_encoded_text(text)) {
        ++unsafe_fields_;
        return {};
    }
    return std::string{text};
}

void denial_audit_writer::append(
    std::string tool, std::string arguments, bool ok, std::string error
) {
    if (!sink_) {
        return;
    }
    const glove::audit::event event{
        .what = glove::audit::action::sandbox_denial,
        .tool_name = std::move(tool),
        .arguments_json = std::move(arguments),
        .status =
            ok ? glove::mcp::tool_call_status::ok : glove::mcp::tool_call_status::transport_error,
        .error_message = std::move(error),
    };
    if (auto recorded = sink_->record(event); !recorded && !first_error_) {
        first_error_ = recorded.error();
    }
}

void denial_audit_writer::record_start(
    glove::container::denial_telemetry_state state, std::string_view reason
) {
    const std::lock_guard lock{mutex_};
    if (finished_ || started_) {
        return;
    }
    started_ = true;
    if (state == glove::container::denial_telemetry_state::unavailable) {
        started_unavailable_ = true;
        pending_degraded_.reset();
        append(
            "telemetry",
            R"({"state":"unavailable"})",
            false,
            checked(reason, glove::container::max_denial_reason_text_bytes)
        );
        return;
    }
    append("telemetry", R"({"state":"live"})", true, {});
    if (state == glove::container::denial_telemetry_state::degraded && !pending_degraded_) {
        pending_degraded_ = std::string{reason};
    }
    if (pending_degraded_) {
        const std::string pending = std::move(*pending_degraded_);
        pending_degraded_.reset();
        append_degraded(pending);
    }
}

void denial_audit_writer::watch_decoys(std::span<const std::filesystem::path> decoys) {
    const std::lock_guard lock{mutex_};
    for (const auto& decoy : decoys) {
        auto encoded = glove::container::encode_untrusted(
            decoy.native(), glove::container::max_denial_target_text_bytes
        );
        if (!encoded.truncated) {
            decoy_targets_.push_back(std::move(encoded.text));
        }
    }
}

void denial_audit_writer::attach_decider(
    std::shared_ptr<const glove::container::denial_decider> decider,
    const glove::container::denial_context& context
) {
    const std::lock_guard lock{mutex_};
    if (!decider || started_ || finished_) {
        return;
    }
    decider_ = std::move(decider);
    features_.emplace(context);
    decider_started_ = now_();
}

void denial_audit_writer::record_decider_unavailable(std::string_view reason) {
    const std::lock_guard lock{mutex_};
    if (finished_ || decider_unavailable_written_) {
        return;
    }
    decider_unavailable_written_ = true;
    append(
        "decider",
        R"({"state":"unavailable"})",
        false,
        checked(reason, glove::container::max_denial_reason_text_bytes)
    );
}

void denial_audit_writer::on_denial(const glove::container::sandbox_denial& denial) {
    const std::lock_guard lock{mutex_};
    if (finished_) {
        return;
    }
    duplicates_ += denial.duplicate_reports;
    if (decider_ && features_ && decider_started_) {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(now_() - *decider_started_);
        features_->observe(denial, elapsed);
        const auto decision = decider_->decide(features_->features(elapsed));
        if (decision.verdict > highest_.verdict) {
            highest_ = decision;
            std::string verdict = R"({"mode":"shadow","arm":")";
            verdict += checked(decider_->arm(), max_kind_bytes);
            verdict += R"(","verdict":")";
            verdict += glove::container::denial_verdict_name(decision.verdict);
            verdict += R"(","score":)";
            verdict += score_text(decision.score);
            verdict += R"(,"denials":)";
            verdict += std::to_string(features_->observed());
            verdict += R"(,"t_ms":)";
            verdict += std::to_string(elapsed.count());
            verdict += "}";
            append("verdict", std::move(verdict), false, "shadow verdict; no action was taken");
        } else if (decision.verdict == highest_.verdict && decision.score > highest_.score) {
            highest_.score = decision.score;
        }
    }
    if (first_error_) {
        ++suppressed_error_;
        return;
    }
    if (!denial.target_truncated &&
        std::ranges::find(decoy_targets_, denial.target) != decoy_targets_.end()) {
        if (decoy_recorded_ == decoy_audit_per_session) {
            ++decoy_suppressed_;
        } else {
            std::string decoy = R"({"operation":")";
            decoy += checked(denial.operation, glove::container::max_denial_operation_text_bytes);
            decoy += R"(","target":")";
            decoy += checked(denial.target, glove::container::max_denial_target_text_bytes);
            decoy += R"(","comm":")";
            decoy += checked(denial.comm, glove::container::max_denial_comm_text_bytes);
            decoy += R"(","pid":)";
            decoy += std::to_string(denial.pid);
            decoy += "}";
            append("decoy", std::move(decoy), false, "a sandboxed process reached for a decoy");
            ++decoy_recorded_;
        }
    }
    if (recorded_ == denial_audit_per_session) {
        ++suppressed_cap_;
        return;
    }
    const auto now = now_();
    if (!window_start_ || now - *window_start_ >= window) {
        window_start_ = now;
        window_count_ = 0;
    }
    if (window_count_ == denial_audit_per_second) {
        ++suppressed_rate_;
        return;
    }
    std::string arguments = R"({"operation":")";
    arguments += checked(denial.operation, glove::container::max_denial_operation_text_bytes);
    arguments += R"(","target":")";
    arguments += checked(denial.target, glove::container::max_denial_target_text_bytes);
    arguments += R"(","target_truncated":)";
    arguments += boolean(denial.target_truncated);
    arguments += R"(,"comm":")";
    arguments += checked(denial.comm, glove::container::max_denial_comm_text_bytes);
    arguments += R"(","pid":)";
    arguments += std::to_string(denial.pid);
    arguments += R"(,"duplicates":)";
    arguments += std::to_string(denial.duplicate_reports);
    arguments += R"(,"readings":)";
    arguments += std::to_string(denial.readings);
    arguments += "}";
    append(checked(denial.kind, max_kind_bytes), std::move(arguments), true, {});
    ++recorded_;
    ++window_count_;
}

void denial_audit_writer::on_degraded(std::string_view reason) {
    const std::lock_guard lock{mutex_};
    if (finished_) {
        return;
    }
    if (!started_) {
        if (!pending_degraded_) {
            pending_degraded_ = std::string{reason};
        }
        return;
    }
    append_degraded(reason);
}

// Caller holds mutex_; at most one degraded record per writer.
void denial_audit_writer::append_degraded(std::string_view reason) {
    if (degraded_written_ || started_unavailable_) {
        return;
    }
    degraded_written_ = true;
    append(
        "telemetry",
        R"({"state":"degraded"})",
        false,
        checked(reason, glove::container::max_denial_reason_text_bytes)
    );
}

auto denial_audit_writer::finish(const glove::container::denial_monitor_report& report)
    -> std::expected<void, std::string> {
    const std::lock_guard lock{mutex_};
    if (!finished_ && !started_unavailable_) {
        const bool clean =
            report.state == glove::container::denial_telemetry_state::live && report.end_proof;
        std::string arguments = R"({"state":")";
        arguments += state_name(report.state);
        arguments += R"(","recorded":)";
        arguments += std::to_string(recorded_);
        arguments += R"(,"suppressed_rate":)";
        arguments += std::to_string(suppressed_rate_);
        arguments += R"(,"suppressed_cap":)";
        arguments += std::to_string(suppressed_cap_);
        arguments += R"(,"suppressed_error":)";
        arguments += std::to_string(suppressed_error_);
        // The reason is checked first so its own rejection is counted below.
        std::string error =
            clean ? std::string{}
                  : checked(report.reason, glove::container::max_denial_reason_text_bytes);
        arguments += R"(,"unsafe_fields":)";
        arguments += std::to_string(unsafe_fields_);
        arguments += R"(,"duplicates":)";
        arguments += std::to_string(duplicates_);
        arguments += R"(,"stream_events":)";
        arguments += std::to_string(report.stream_events);
        arguments += R"(,"stream_rejected":)";
        arguments += std::to_string(report.stream_rejected);
        arguments += R"(,"end_proof":)";
        arguments += boolean(report.end_proof);
        if (decider_) {
            arguments += R"(,"decider":")";
            arguments += checked(decider_->arm(), max_kind_bytes);
            arguments += R"(","verdict":")";
            arguments += glove::container::denial_verdict_name(highest_.verdict);
            arguments += R"(","score":)";
            arguments += score_text(highest_.score);
        }
        if (!decoy_targets_.empty()) {
            arguments += R"(,"decoys":)";
            arguments += std::to_string(decoy_targets_.size());
            arguments += R"(,"decoy_hits":)";
            arguments += std::to_string(decoy_recorded_ + decoy_suppressed_);
        }
        arguments += "}";
        append("summary", std::move(arguments), clean, std::move(error));
    }
    finished_ = true;
    if (first_error_) {
        return std::unexpected("audit denial telemetry: " + *first_error_);
    }
    return {};
}

auto denial_notice_line(denial_notice what, std::string_view reason) -> std::string {
    const std::string shown = reason.size() <= glove::container::max_denial_reason_text_bytes &&
                                      glove::container::is_encoded_text(reason)
                                  ? std::string{reason}
                                  : std::string{"unknown"};
    switch (what) {
    case denial_notice::starting:
        return "glove: starting sandbox denial telemetry (up to 2 s)\n";
    case denial_notice::live:
        return "glove: sandbox denial telemetry is live\n";
    case denial_notice::unavailable:
        return "glove: sandbox denial telemetry unavailable (" + shown +
               "); the agent still runs sandboxed\n";
    case denial_notice::stopping:
        return "glove: stopping sandbox denial telemetry (up to 1 s)\n";
    case denial_notice::degraded:
        return "glove: sandbox denial telemetry was incomplete this session (" + shown +
               "); the agent ran sandboxed\n";
    }
    return "glove: sandbox denial telemetry unavailable (unknown); the agent still runs "
           "sandboxed\n";
}

} // namespace glove::run::detail
