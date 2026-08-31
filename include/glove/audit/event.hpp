#pragma once

#include "glove/mcp/messages.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace glove::audit {

enum class action : std::uint8_t {
    list_tools,
    call_tool,
    initialize,
    agent_launch,
    agent_exit,
    egress,
    observation,
    local_service,
};

// One observed agent interaction. Recorded after the inner call returns so
// `latency` is the inner call's wall time.
struct event {
    action what = action::list_tools;
    std::string tool_name;      // empty for list_tools / initialize
    std::string arguments_json; // empty for list_tools / initialize
    glove::mcp::tool_call_status status = glove::mcp::tool_call_status::ok;
    std::string error_message;
    std::chrono::system_clock::time_point at = std::chrono::system_clock::now();
    std::chrono::nanoseconds latency{0};
};

} // namespace glove::audit
