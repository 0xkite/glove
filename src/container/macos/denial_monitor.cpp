#include "glove/container/denial_telemetry.hpp"

#include "denial_stream.hpp"
#include "denial_tag.hpp"
#include "denial_telemetry_detail.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

auto encoded_reason(std::string_view reason) -> std::string {
    return encode_untrusted(reason, max_denial_reason_text_bytes).text;
}

} // namespace

struct denial_monitor::implementation {
    denial_observer observer;
    std::string tag;
    std::unique_ptr<macos_detail::denial_stream> stream;
    // Callbacks reach the observer only while armed: from a proven-live start
    // until finish() or destruction begins.
    std::atomic<bool> armed{false};
    std::atomic<bool> degraded_notified{false};
    std::atomic<denial_telemetry_state> current{denial_telemetry_state::unavailable};

    mutable std::mutex mutex;
    std::string reason; // guarded by mutex
    std::optional<denial_monitor_report> report;

    // Telemetry thread. An observer exception degrades the monitor and never
    // reaches the stream.
    void forward(const detail::denial_event& event) {
        if (!armed.load()) {
            return;
        }
        try {
            if (observer.on_denial) {
                observer.on_denial(detail::to_sandbox_denial(event));
            }
        } catch (...) {
            degrade("denial observer failed", true);
        }
    }

    // live -> degraded once; notify only for degradation observed while armed.
    void degrade(std::string_view why, bool notify) {
        std::string stored;
        {
            const std::lock_guard lock{mutex};
            auto expected = denial_telemetry_state::live;
            if (!current.compare_exchange_strong(expected, denial_telemetry_state::degraded)) {
                return;
            }
            reason = encoded_reason(why);
            stored = reason;
        }
        if (notify && armed.load() && observer.on_degraded && !degraded_notified.exchange(true)) {
            try {
                observer.on_degraded(stored);
            } catch (...) { // NOLINT(bugprone-empty-catch): already degraded.
            }
        }
    }

    void set_unavailable(std::string_view why) {
        const std::lock_guard lock{mutex};
        reason = encoded_reason(why);
        current.store(denial_telemetry_state::unavailable);
    }

    void stop_stream() noexcept {
        armed.store(false);
        // Destroying the stream joins its reader, so no callback is running
        // or can start once this returns.
        stream.reset();
    }
};

denial_monitor::denial_monitor(std::unique_ptr<implementation> impl) noexcept
    : impl_{std::move(impl)} {}

denial_monitor::~denial_monitor() {
    impl_->stop_stream();
}

auto denial_monitor::start(denial_observer observer) -> std::unique_ptr<denial_monitor> {
    return start_for_test(std::move(observer), {});
}

auto denial_monitor::start_for_test(denial_observer observer, std::vector<std::string> stream_argv)
    -> std::unique_ptr<denial_monitor> {
    auto impl = std::make_unique<implementation>();
    impl->observer = std::move(observer);
    implementation* const self = impl.get();
    auto monitor = std::unique_ptr<denial_monitor>(new denial_monitor(std::move(impl)));

    std::string tag = macos_detail::make_denial_tag();
    auto started = macos_detail::denial_stream::start({
        .tag = tag,
        .argv = std::move(stream_argv),
        .on_event = [self](const detail::denial_event& event) { self->forward(event); },
        .on_degraded = [self](std::string_view why) { self->degrade(why, true); },
    });
    if (!started) {
        self->set_unavailable(started.error());
        return monitor;
    }
    auto proven =
        (*started)->prove_live(std::chrono::milliseconds{denial_monitor_start_timeout_ms});
    if (!proven) {
        started->reset();
        self->set_unavailable(proven.error());
        return monitor;
    }
    self->stream = std::move(*started);
    self->tag = std::move(tag);
    {
        const std::lock_guard lock{self->mutex};
        self->reason.clear();
        self->current.store(denial_telemetry_state::live);
    }
    self->armed.store(true);
    // A stream that degraded between the proof and arming is still live to
    // its reader only if its own state says so.
    if (self->stream->state() != macos_detail::denial_stream_state::live) {
        self->degrade("denial stream degraded", true);
    }
    return monitor;
}

auto denial_monitor::state() const noexcept -> denial_telemetry_state {
    return impl_->current.load();
}

auto denial_monitor::reason() const -> std::string {
    const std::lock_guard lock{impl_->mutex};
    return impl_->reason;
}

auto denial_monitor::tag() const noexcept -> const std::string& {
    return impl_->tag;
}

auto denial_monitor::finish() -> denial_monitor_report {
    auto& self = *impl_;
    if (self.report) {
        return *self.report;
    }
    denial_monitor_report out;
    if (self.current.load() == denial_telemetry_state::live && self.stream) {
        // The log is ordered: once the closing canary's denial is observed,
        // every session denial logged before it has been delivered.
        const auto proven =
            self.stream->prove_live(std::chrono::milliseconds{denial_monitor_finish_timeout_ms});
        out.end_proof = proven.has_value();
        if (!out.end_proof) {
            self.degrade("denial stream stalled", false);
        }
    }
    self.armed.store(false);
    if (self.stream) {
        const auto counted = self.stream->counters();
        out.stream_events = counted.events;
        out.stream_rejected = counted.oversized_lines + counted.rejected_not_json +
                              counted.rejected_provenance + counted.rejected_not_a_denial +
                              counted.rejected_timestamp + counted.rejected_untagged;
    }
    self.stop_stream();
    out.state = self.current.load();
    out.reason = reason();
    self.report = out;
    return out;
}

auto denial_monitor::stream_pid_for_test() const noexcept -> int {
    return impl_->stream ? impl_->stream->child_pid_for_test() : -1;
}

} // namespace glove::container
