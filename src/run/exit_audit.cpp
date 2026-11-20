#include "exit_audit.hpp"

#include "glove/audit/event.hpp"
#include "glove/mcp/messages.hpp"

#include <string>
#include <utility>

namespace glove::run::detail {

namespace {

auto record_event(
    const std::shared_ptr<glove::audit::sink>& sink,
    glove::audit::action what,
    std::string subject,
    glove::mcp::tool_call_status status,
    std::string error = {}
) -> std::expected<void, std::string> {
    if (!sink) {
        return {};
    }
    const glove::audit::event event{
        .what = what,
        .tool_name = std::move(subject),
        .arguments_json = {},
        .status = status,
        .error_message = std::move(error),
    };
    return sink->record(event);
}

auto record_exit_code(const std::shared_ptr<glove::audit::sink>& sink, int code)
    -> std::expected<void, std::string> {
    return record_event(
        sink,
        glove::audit::action::agent_exit,
        std::to_string(code),
        code == 0 ? glove::mcp::tool_call_status::ok : glove::mcp::tool_call_status::execution_error
    );
}

} // namespace

auto record_agent_exit(
    const std::shared_ptr<glove::audit::sink>& sink,
    const std::expected<int, std::string>& waited,
    std::optional<int> reaped_code
) -> std::expected<int, std::string> {
    if (waited) {
        if (auto audited = record_exit_code(sink, *waited); !audited) {
            return std::unexpected("audit exit: " + audited.error());
        }
        return *waited;
    }
    std::string error = "wait: " + waited.error();
    if (!reaped_code) {
        return std::unexpected(std::move(error));
    }
    // Both records are attempted; the first audit failure is reported.
    auto exited = record_exit_code(sink, *reaped_code);
    auto cleanup = record_event(
        sink,
        glove::audit::action::control,
        "agent_cleanup_failed",
        glove::mcp::tool_call_status::execution_error,
        waited.error()
    );
    if (!exited) {
        error += "; audit exit: " + exited.error();
    } else if (!cleanup) {
        error += "; audit exit: " + cleanup.error();
    }
    return std::unexpected(std::move(error));
}

} // namespace glove::run::detail
