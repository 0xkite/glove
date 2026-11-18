#pragma once

// Attributes a parsed sandbox denial to one agent process group, or refuses.
//
// The caller guarantees the leader is its own unreaped child leading group
// `leader` from start() until retire() returns, so the group number cannot be
// reused while the ledger samples it. A member result is evidence, not proof:
// a PID can be reused inside the time window. A process that has left the
// group is never attributed. A process that exits between two snapshots and
// before its event arrives is not attributed, so attributed counts are a
// lower bound. Nothing here may be used to choose a signal target.

#include "sandbox_denial_log.hpp"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

namespace glove::container::macos_detail {

constexpr int ledger_snapshot_interval_ms = 20;
constexpr std::size_t ledger_max_members = 4096;
constexpr std::size_t ledger_max_listing = 1024;
constexpr int ledger_event_slack_ms = 100;

enum class attribution : std::uint8_t { leader, member, unattributed, ambiguous, after_retirement };

struct attribution_result {
    attribution how = attribution::unattributed;
    std::int32_t pid = 0; // non-zero only for leader and member
};

struct ledger_counters {
    std::uint64_t snapshots = 0;
    std::uint64_t snapshot_failures = 0;
    std::uint64_t members_recorded = 0;
    std::uint64_t members_evicted = 0;
    std::uint64_t table_size = 0;
};

struct ledger_options {
    // 0 or more than ledger_max_members is an error.
    std::size_t max_members = ledger_max_members;
};

class identity_ledger final {
public:
    identity_ledger(const identity_ledger&) = delete;
    auto operator=(const identity_ledger&) -> identity_ledger& = delete;
    identity_ledger(identity_ledger&&) = delete;
    auto operator=(identity_ledger&&) -> identity_ledger& = delete;
    // Retires, stops and joins the snapshot thread.
    ~identity_ledger();

    static auto start(::pid_t leader, ledger_options options = {})
        -> std::expected<std::unique_ptr<identity_ledger>, std::string>;

    // Safe from any thread.
    [[nodiscard]] auto attribute(const detail::denial_event& event) -> attribution_result;

    // The owner calls this immediately before it reaps the leader. When it
    // returns no group listing or PID lookup is in flight or will start.
    // Idempotent.
    void retire() noexcept;

    [[nodiscard]] auto counters() const noexcept -> ledger_counters;

private:
    struct implementation;

    explicit identity_ledger(std::unique_ptr<implementation> impl) noexcept;

    std::unique_ptr<implementation> impl_;
};

} // namespace glove::container::macos_detail
