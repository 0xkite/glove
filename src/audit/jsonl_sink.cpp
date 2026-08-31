#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::audit {

// Wire-shape struct: glaze serializes this aggregate into one JSON object per
// event. Field names are deliberately stable so downstream tooling (e.g. log
// shippers) doesn't break on internal renames. At namespace scope (not
// anonymous) so glaze's reflection can take its address.
struct wire_event {
    std::string action;
    std::string tool;
    std::string arguments;
    std::string status;
    std::string error;
    std::int64_t timestamp_ns;
    std::int64_t latency_ns;
};

namespace {

auto system_error(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto write_all(int descriptor, std::string_view bytes) -> std::expected<void, std::string> {
    while (!bytes.empty()) {
        const auto written = ::write(descriptor, bytes.data(), bytes.size());
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return std::unexpected(system_error("write audit event"));
        }
        bytes.remove_prefix(static_cast<std::size_t>(written));
    }
    return {};
}

auto status_name(glove::mcp::tool_call_status s) -> std::string_view {
    using glove::mcp::tool_call_status;
    switch (s) {
    case tool_call_status::ok:
        return "ok";
    case tool_call_status::tool_not_found:
        return "tool_not_found";
    case tool_call_status::invalid_arguments:
        return "invalid_arguments";
    case tool_call_status::execution_error:
        return "execution_error";
    case tool_call_status::transport_error:
        return "transport_error";
    }
    return "unknown";
}

auto action_name(action a) -> std::string_view {
    switch (a) {
    case action::list_tools:
        return "list_tools";
    case action::call_tool:
        return "call_tool";
    case action::initialize:
        return "initialize";
    case action::agent_launch:
        return "agent_launch";
    case action::agent_exit:
        return "agent_exit";
    case action::egress:
        return "egress";
    case action::observation:
        return "observation";
    case action::local_service:
        return "local_service";
    case action::control:
        return "control";
    }
    return "unknown";
}

class jsonl_sink final : public sink {
public:
    explicit jsonl_sink(int descriptor, jsonl_sink_limits limits, std::uint64_t current_bytes)
        : descriptor_{descriptor}, limits_{limits}, current_bytes_{current_bytes} {}

    ~jsonl_sink() override {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    auto record(const event& e) -> std::expected<void, std::string> override {
        wire_event w{
            .action = std::string{action_name(e.what)},
            .tool = e.tool_name,
            .arguments = e.arguments_json,
            .status = std::string{status_name(e.status)},
            .error = e.error_message,
            .timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(e.at.time_since_epoch())
                    .count(),
            .latency_ns = e.latency.count(),
        };
        auto encoded = glz::write_json(w);
        if (!encoded) {
            return std::unexpected(
                std::string{"glaze write_json: "} +
                glz::format_error(encoded.error(), std::string{})
            );
        }

        std::scoped_lock lock{mu_};
        encoded->push_back('\n');
        if (limits_.max_file_bytes != 0 &&
            current_bytes_ + encoded->size() > limits_.max_file_bytes) {
            if (auto truncated = truncate_oldest(encoded->size()); !truncated) {
                return truncated;
            }
        }
        if (auto written = write_all(descriptor_, *encoded); !written) {
            return written;
        }
        current_bytes_ += encoded->size();
        if (::fsync(descriptor_) != 0) {
            return std::unexpected(system_error("sync audit event"));
        }
        return {};
    }

private:
    // Drop the oldest complete records until `incoming` bytes fit under the
    // configured cap. Reads are bounded by the cap itself, so this cannot
    // scan an unbounded file. The file descriptor stays O_APPEND: after
    // ftruncate(0) the next write lands at offset 0.
    auto truncate_oldest(std::uint64_t incoming) -> std::expected<void, std::string> {
        const auto keep_budget =
            limits_.max_file_bytes > incoming ? limits_.max_file_bytes - incoming : 0U;
        std::string contents(static_cast<std::size_t>(current_bytes_), '\0');
        std::size_t consumed = 0;
        while (consumed < contents.size()) {
            const auto result = ::pread(
                descriptor_,
                contents.data() + consumed,
                contents.size() - consumed,
                static_cast<off_t>(consumed)
            );
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                return std::unexpected(system_error("read audit journal for truncation"));
            }
            consumed += static_cast<std::size_t>(result);
        }
        // Keep the newest complete lines that fit in the retained budget.
        std::size_t keep_from = contents.size();
        std::uint64_t kept_bytes = 0;
        while (keep_from > 0) {
            const auto line_start = contents.rfind('\n', keep_from - 1);
            if (line_start == std::string::npos) {
                // `keep_from` sits at the first (possibly unterminated) line;
                // it is never retained.
                break;
            }
            const std::size_t begin = line_start + 1U;
            if (begin == keep_from) {
                // Degenerate double-newline input: skip the empty line.
                keep_from = begin - 1U;
                continue;
            }
            const std::size_t line_bytes = keep_from - begin;
            if (kept_bytes + line_bytes > keep_budget) {
                break;
            }
            kept_bytes += line_bytes;
            keep_from = begin;
        }
        if (::ftruncate(descriptor_, 0) != 0) {
            return std::unexpected(system_error("truncate audit journal"));
        }
        current_bytes_ = 0;
        if (keep_from < contents.size() && kept_bytes != 0) {
            const std::string_view retained{
                contents.data() + keep_from, contents.size() - keep_from
            };
            if (auto written = write_all(descriptor_, retained); !written) {
                return written;
            }
            current_bytes_ = kept_bytes;
        }
        return {};
    }

    std::mutex mu_;
    int descriptor_ = -1;
    jsonl_sink_limits limits_;
    std::uint64_t current_bytes_ = 0;
};

} // namespace

auto make_jsonl_sink(const std::filesystem::path& path, jsonl_sink_limits limits)
    -> std::expected<std::shared_ptr<sink>, std::string> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"jsonl_sink: path must be dedicated and absolute"});
    }
    // O_RDWR (not O_WRONLY): the bounded policy must read the journal back to
    // truncate its oldest records.
    const int descriptor = ::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        path.c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600
    );
    if (descriptor < 0) {
        return std::unexpected(system_error("open audit journal"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U) {
        ::close(descriptor);
        return std::unexpected(
            std::string{"audit journal must be an owner-only single-link regular file"}
        );
    }
    while (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EINTR) {
            continue;
        }
        const auto error = system_error("lock audit journal");
        ::close(descriptor);
        return std::unexpected(error);
    }
    return std::make_shared<jsonl_sink>(
        descriptor, limits, static_cast<std::uint64_t>(metadata.st_size)
    );
}

} // namespace glove::audit
