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
    }
    return "unknown";
}

class jsonl_sink final : public sink {
public:
    explicit jsonl_sink(int descriptor) : descriptor_{descriptor} {}

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
        if (auto written = write_all(descriptor_, *encoded); !written) {
            return written;
        }
        if (::fsync(descriptor_) != 0) {
            return std::unexpected(system_error("sync audit event"));
        }
        return {};
    }

private:
    std::mutex mu_;
    int descriptor_ = -1;
};

} // namespace

auto make_jsonl_sink(const std::filesystem::path& path)
    -> std::expected<std::shared_ptr<sink>, std::string> {
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"jsonl_sink: path must be dedicated and absolute"});
    }
    const int descriptor = ::open( // NOLINT(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600
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
    return std::make_shared<jsonl_sink>(descriptor);
}

} // namespace glove::audit
