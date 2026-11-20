#include "denial_trace_writer.hpp"

#include "glove/container/denial_trace.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::run::detail {

namespace {

auto errno_text(int code) -> std::string {
    return std::error_code{code, std::generic_category()}.message();
}

} // namespace

denial_trace_writer::denial_trace_writer(int fd, clock now) : fd_{fd}, now_{std::move(now)} {
    if (!now_) {
        now_ = [] { return std::chrono::steady_clock::now(); };
    }
    started_ = now_();
}

denial_trace_writer::~denial_trace_writer() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

auto denial_trace_writer::create(
    const std::filesystem::path& path, const glove::container::denial_context& context, clock now
) -> std::expected<std::unique_ptr<denial_trace_writer>, std::string> {
    auto header = glove::container::denial_trace_header_line(context);
    if (!header) {
        return std::unexpected(header.error());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg): POSIX open.
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return std::unexpected("denial trace " + path.string() + ": " + errno_text(errno));
    }
    std::unique_ptr<denial_trace_writer> writer{new denial_trace_writer(fd, std::move(now))};
    const std::scoped_lock lock{writer->mutex_};
    writer->write_line(*header);
    if (writer->failed_) {
        return std::unexpected(
            "denial trace " + path.string() + ": " + errno_text(writer->write_error_)
        );
    }
    return writer;
}

auto denial_trace_writer::elapsed() const -> std::chrono::milliseconds {
    return std::chrono::duration_cast<std::chrono::milliseconds>(now_() - started_);
}

void denial_trace_writer::write_line(std::string_view line) noexcept {
    while (!failed_ && !line.empty()) {
        const auto wrote = ::write(fd_, line.data(), line.size());
        if (wrote < 0 && errno == EINTR) {
            continue;
        }
        if (wrote <= 0) {
            failed_ = true;
            write_error_ = wrote < 0 ? errno : EIO;
            return;
        }
        line.remove_prefix(static_cast<std::size_t>(wrote));
    }
}

void denial_trace_writer::on_denial(const glove::container::sandbox_denial& denial) noexcept {
    try {
        const std::scoped_lock lock{mutex_};
        if (finished_ || failed_) {
            return;
        }
        if (recorded_ == glove::container::max_denial_trace_events) {
            ++dropped_;
            return;
        }
        auto line = glove::container::denial_trace_event_line({.at = elapsed(), .denial = denial});
        if (!line) {
            ++dropped_;
            return;
        }
        write_line(*line);
        if (!failed_) {
            ++recorded_;
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): a lost trace line is counted, never thrown.
        // An allocation failure or a throwing clock loses this line only.
    }
}

auto denial_trace_writer::finish(const glove::container::denial_monitor_report& report)
    -> std::expected<void, std::string> {
    const std::scoped_lock lock{mutex_};
    if (finished_) {
        return {};
    }
    finished_ = true;
    auto line = glove::container::denial_trace_end_line({
        .at = elapsed(),
        .state = report.state,
        .reason = report.reason,
        .end_proof = report.end_proof,
        .stream_events = report.stream_events,
        .stream_rejected = report.stream_rejected,
        .dropped = dropped_,
    });
    if (line) {
        write_line(*line);
    }
    const int closed = ::close(fd_);
    const int close_error = closed != 0 ? errno : 0;
    fd_ = -1;
    if (failed_) {
        return std::unexpected("denial trace: " + errno_text(write_error_));
    }
    if (!line) {
        return std::unexpected(line.error());
    }
    if (closed != 0) {
        return std::unexpected("denial trace: " + errno_text(close_error));
    }
    return {};
}

} // namespace glove::run::detail
