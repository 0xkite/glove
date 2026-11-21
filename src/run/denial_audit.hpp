#pragma once

// Bounded audit records for one launch's sandbox denial telemetry, and the
// stderr notices that tell a person when the CLI waits for it or runs
// without it. Telemetry only: nothing here can stop, delay or fail a launch.

#include "glove/audit/sink.hpp"
#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_telemetry.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

constexpr std::size_t denial_audit_per_second = 16;
constexpr std::size_t denial_audit_per_session = 256;

class denial_audit_writer final {
public:
    using clock = std::function<std::chrono::steady_clock::time_point()>;

    // An empty clock means steady_clock::now; a null sink records nothing.
    explicit denial_audit_writer(std::shared_ptr<glove::audit::sink> sink, clock now = {});

    denial_audit_writer(const denial_audit_writer&) = delete;
    auto operator=(const denial_audit_writer&) -> denial_audit_writer& = delete;
    denial_audit_writer(denial_audit_writer&&) = delete;
    auto operator=(denial_audit_writer&&) -> denial_audit_writer& = delete;
    ~denial_audit_writer() = default;

    // A degraded state writes the live start record, then the degraded one.
    void record_start(glove::container::denial_telemetry_state state, std::string_view reason);
    // Raw host paths of this launch's decoys. A denial whose target is one
    // of them is also written as a "decoy" record with its own cap, so
    // ordinary denial volume can never crowd it out. Call before start.
    void watch_decoys(std::span<const std::filesystem::path> decoys);
    // Shadow decisions: DECIDER's verdict over this launch's denials is
    // recorded and never acted on. A "verdict" record is written each time
    // the verdict escalates (so at most two), and the summary carries the
    // highest one. Call before start.
    void attach_decider(
        std::shared_ptr<const glove::container::denial_decider> decider,
        const glove::container::denial_context& context
    );
    // Records once that the operator asked for a decider that could not be
    // used; the launch runs sandboxed without one.
    void record_decider_unavailable(std::string_view reason);
    // Safe from any thread.
    void on_denial(const glove::container::sandbox_denial& denial);
    // Safe from any thread; at most one degraded record per writer.
    void on_degraded(std::string_view reason);
    // Writes the summary unless the start was unavailable. Nothing is written
    // afterwards. Returns the first audit append failure of any record.
    [[nodiscard]] auto finish(const glove::container::denial_monitor_report& report)
        -> std::expected<void, std::string>;

private:
    // Caller holds mutex_.
    void append(std::string tool, std::string arguments, bool ok, std::string error);
    auto checked(std::string_view text, std::size_t max_bytes) -> std::string;

    std::mutex mutex_;
    std::shared_ptr<glove::audit::sink> sink_;
    clock now_;
    void append_degraded(std::string_view reason);

    bool started_ = false;
    bool started_unavailable_ = false;
    bool degraded_written_ = false;
    // A degradation reported before record_start is written after the start
    // record, so the trail never shows degraded before live.
    std::optional<std::string> pending_degraded_;
    bool finished_ = false;
    std::optional<std::chrono::steady_clock::time_point> window_start_;
    std::size_t window_count_ = 0;
    std::uint64_t recorded_ = 0;
    std::uint64_t suppressed_rate_ = 0;
    std::uint64_t suppressed_cap_ = 0;
    std::uint64_t suppressed_error_ = 0;
    std::uint64_t unsafe_fields_ = 0;
    std::uint64_t duplicates_ = 0;
    std::optional<std::string> first_error_;
    std::vector<std::string> decoy_targets_; // encoded like denial targets
    std::uint64_t decoy_recorded_ = 0;
    std::uint64_t decoy_suppressed_ = 0;
    std::shared_ptr<const glove::container::denial_decider> decider_;
    std::optional<glove::container::denial_feature_builder> features_;
    std::optional<std::chrono::steady_clock::time_point> decider_started_;
    glove::container::denial_decision highest_;
    bool decider_unavailable_written_ = false;
};

constexpr std::size_t decoy_audit_per_session = 32;

enum class denial_notice : std::uint8_t { starting, live, unavailable, stopping, degraded };

// One line ending in '\n'. reason is used only by unavailable and degraded;
// a reason that is not encoded text or exceeds 256 bytes becomes "unknown".
[[nodiscard]] auto denial_notice_line(denial_notice what, std::string_view reason) -> std::string;

} // namespace glove::run::detail
