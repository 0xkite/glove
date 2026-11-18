#include "identity_ledger.hpp"

#include <sys/proc.h>
#include <sys/sysctl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace glove::container::macos_detail {

namespace {

constexpr std::int64_t micros_per_ms = 1000;

auto now_micros() noexcept -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch()
    )
        .count();
}

auto start_micros(const struct kinfo_proc& process) noexcept -> std::int64_t {
    const auto& started = process.kp_proc.p_starttime;
    return (static_cast<std::int64_t>(started.tv_sec) * 1'000'000) +
           static_cast<std::int64_t>(started.tv_usec);
}

struct member_entry {
    ::pid_t pid = 0;
    std::int64_t start = 0;
    std::int64_t last_seen = 0;
};

} // namespace

struct identity_ledger::implementation {
    ::pid_t leader = 0;
    std::size_t max_members = ledger_max_members;
    std::int64_t started = 0;

    // Guards table, retired_at, and every sysctl naming the group or one of
    // its PIDs: retire() taking it proves no lookup is in flight.
    std::mutex mutex;
    std::condition_variable_any wake;
    std::vector<member_entry> table;
    std::optional<std::int64_t> retired_at;
    std::atomic<bool> retired{false};
    // Written only by the snapshot thread; allocated once.
    std::vector<struct kinfo_proc> listing;

    std::atomic<std::uint64_t> snapshots{0};
    std::atomic<std::uint64_t> snapshot_failures{0};
    std::atomic<std::uint64_t> members_recorded{0};
    std::atomic<std::uint64_t> members_evicted{0};
    std::atomic<std::uint64_t> table_size{0};

    std::jthread sampler;

    // Caller holds mutex.
    void record(::pid_t pid, std::int64_t start, std::int64_t seen) {
        for (auto& entry : table) {
            if (entry.pid == pid && entry.start == start) {
                entry.last_seen = seen;
                return;
            }
        }
        if (table.size() >= max_members) {
            const auto oldest = std::ranges::min_element(table, {}, &member_entry::last_seen);
            table.erase(oldest);
            members_evicted.fetch_add(1, std::memory_order_relaxed);
        }
        table.push_back(member_entry{.pid = pid, .start = start, .last_seen = seen});
        members_recorded.fetch_add(1, std::memory_order_relaxed);
        table_size.store(table.size(), std::memory_order_relaxed);
    }

    // Caller holds mutex and has checked the ledger is not retired.
    void snapshot() {
        std::array<int, 4> mib{CTL_KERN, KERN_PROC, KERN_PROC_PGRP, leader};
        std::size_t bytes = listing.size() * sizeof(struct kinfo_proc);
        if (::sysctl(mib.data(), mib.size(), listing.data(), &bytes, nullptr, 0) != 0 ||
            bytes % sizeof(struct kinfo_proc) != 0) {
            snapshot_failures.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const auto seen = now_micros();
        const auto count = bytes / sizeof(struct kinfo_proc);
        for (std::size_t index = 0; index != count; ++index) {
            const auto& process = listing.at(index);
            record(process.kp_proc.p_pid, start_micros(process), seen);
        }
        snapshots.fetch_add(1, std::memory_order_relaxed);
    }

    void sample(const std::stop_token& stop) {
        std::unique_lock lock{mutex};
        while (!stop.stop_requested() && !retired_at && !retired.load()) {
            snapshot();
            (void)wake.wait_for(
                lock, stop, std::chrono::milliseconds{ledger_snapshot_interval_ms}, [this] {
                    return retired_at.has_value();
                }
            );
        }
    }

    // Caller holds mutex and has checked the ledger is not retired.
    auto lookup_member(std::int32_t pid, std::int64_t event_micros) -> bool {
        struct kinfo_proc process{};
        std::size_t bytes = sizeof(process);
        std::array<int, 4> mib{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        if (::sysctl(mib.data(), mib.size(), &process, &bytes, nullptr, 0) != 0 ||
            bytes != sizeof(process)) {
            return false;
        }
        const auto start = start_micros(process);
        if (process.kp_eproc.e_pgid != leader ||
            start > event_micros + (ledger_event_slack_ms * micros_per_ms)) {
            return false;
        }
        record(pid, start, now_micros());
        return true;
    }
};

identity_ledger::identity_ledger(std::unique_ptr<implementation> impl) noexcept
    : impl_{std::move(impl)} {}

identity_ledger::~identity_ledger() {
    retire();
    try {
        impl_->sampler.request_stop();
        if (impl_->sampler.joinable()) {
            impl_->sampler.join();
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): a destructor cannot report.
    }
}

auto identity_ledger::start(::pid_t leader, ledger_options options)
    -> std::expected<std::unique_ptr<identity_ledger>, std::string> {
    if (leader < 1) {
        return std::unexpected(std::string{"identity ledger: leader must be a positive pid"});
    }
    if (options.max_members == 0 || options.max_members > ledger_max_members) {
        return std::unexpected(std::string{"identity ledger: max_members out of range"});
    }
    auto impl = std::make_unique<implementation>();
    impl->leader = leader;
    impl->max_members = options.max_members;
    impl->started = now_micros();
    impl->table.reserve(options.max_members);
    impl->listing.resize(ledger_max_listing);
    auto ledger = std::unique_ptr<identity_ledger>(new identity_ledger(std::move(impl)));
    implementation* const state = ledger->impl_.get();
    ledger->impl_->sampler = std::jthread{[state](const std::stop_token& stop) {
        try {
            state->sample(stop);
        } catch (...) { // NOLINT(bugprone-empty-catch): sampling stops; attribution still answers.
        }
    }};
    return ledger;
}

auto identity_ledger::attribute(const detail::denial_event& event) -> attribution_result {
    if (event.readings.size() != 1) {
        return {.how = attribution::ambiguous, .pid = 0};
    }
    auto& self = *impl_;
    const std::lock_guard lock{self.mutex};
    if (self.retired_at && event.unix_micros > *self.retired_at) {
        return {.how = attribution::after_retirement, .pid = 0};
    }
    const std::int64_t slack = ledger_event_slack_ms * micros_per_ms;
    if (event.unix_micros < self.started - slack) {
        return {.how = attribution::unattributed, .pid = 0};
    }
    const std::int32_t pid = event.readings.front().pid;
    if (pid == self.leader) {
        return {.how = attribution::leader, .pid = pid};
    }
    const std::int64_t freshness = (ledger_snapshot_interval_ms * micros_per_ms) + slack;
    for (const auto& entry : self.table) {
        if (entry.pid == pid && entry.start <= event.unix_micros + slack &&
            entry.last_seen >= event.unix_micros - freshness) {
            return {.how = attribution::member, .pid = pid};
        }
    }
    if (!self.retired_at && !self.retired.load() && self.lookup_member(pid, event.unix_micros)) {
        return {.how = attribution::member, .pid = pid};
    }
    return {.how = attribution::unattributed, .pid = 0};
}

void identity_ledger::retire() noexcept {
    auto& self = *impl_;
    self.retired.store(true);
    try {
        {
            const std::lock_guard lock{self.mutex};
            if (!self.retired_at) {
                self.retired_at = now_micros();
            }
        }
        self.wake.notify_all();
    } catch (...) { // NOLINT(bugprone-empty-catch): the atomic flag still records retirement.
    }
}

auto identity_ledger::counters() const noexcept -> ledger_counters {
    return {
        .snapshots = impl_->snapshots.load(),
        .snapshot_failures = impl_->snapshot_failures.load(),
        .members_recorded = impl_->members_recorded.load(),
        .members_evicted = impl_->members_evicted.load(),
        .table_size = impl_->table_size.load(),
    };
}

} // namespace glove::container::macos_detail
