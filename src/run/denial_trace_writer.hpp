#pragma once

// Writes one launch's denial trace (see glove/container/denial_trace.hpp) to
// a new file the operator named. Opt-in data collection for training and
// evaluating denial deciders. Like the audit writer it is telemetry only: a
// trace that cannot be written never stops, delays or fails a launch, and the
// failure is reported after the agent exits.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_telemetry.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace glove::run::detail {

class denial_trace_writer final {
public:
    using clock = std::function<std::chrono::steady_clock::time_point()>;

    // Creates PATH (never an existing file, never through a final symlink)
    // with mode 0600 and writes the header. An empty clock means
    // steady_clock::now; elapsed times are measured from this call.
    static auto create(
        const std::filesystem::path& path,
        const glove::container::denial_context& context,
        clock now = {}
    ) -> std::expected<std::unique_ptr<denial_trace_writer>, std::string>;

    denial_trace_writer(const denial_trace_writer&) = delete;
    auto operator=(const denial_trace_writer&) -> denial_trace_writer& = delete;
    denial_trace_writer(denial_trace_writer&&) = delete;
    auto operator=(denial_trace_writer&&) -> denial_trace_writer& = delete;
    ~denial_trace_writer();

    // Safe from any thread; never throws. Past max_denial_trace_events, or
    // for a denial out of the format's bounds, the denial is counted as
    // dropped instead.
    void on_denial(const glove::container::sandbox_denial& denial) noexcept;
    // Writes the end line and closes the file. Nothing is written afterwards.
    // Returns the first write failure of any line.
    [[nodiscard]] auto finish(const glove::container::denial_monitor_report& report)
        -> std::expected<void, std::string>;

private:
    denial_trace_writer(int fd, clock now);

    // Caller holds mutex_.
    void write_line(std::string_view line) noexcept;
    [[nodiscard]] auto elapsed() const -> std::chrono::milliseconds;

    std::mutex mutex_;
    int fd_ = -1;
    clock now_;
    std::chrono::steady_clock::time_point started_;
    std::uint64_t recorded_ = 0;
    std::uint64_t dropped_ = 0;
    // The errno of the first failed write; read on the caller's thread only.
    int write_error_ = 0;
    bool failed_ = false;
    bool finished_ = false;
};

} // namespace glove::run::detail
