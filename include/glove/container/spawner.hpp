#pragma once

#include "glove/container/profile.hpp"
#include "glove/mcp/transport.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace glove::container {

// Handle to a running contained agent. Owns the agent's pid + the parent end
// of the pipe pair the kernel speaks MCP over. Destroying the handle signals
// the agent (closing stdin), waits for it to exit, and reaps it.
class agent_handle {
public:
    agent_handle() = default;
    agent_handle(const agent_handle&) = delete;
    agent_handle& operator=(const agent_handle&) = delete;
    agent_handle(agent_handle&&) = delete;
    agent_handle& operator=(agent_handle&&) = delete;
    virtual ~agent_handle() = default;

    // Transport carrying MCP frames between the kernel (this side) and the
    // contained agent. send() writes a request to the agent's stdin; recv()
    // reads a response from the agent's stdout.
    virtual auto transport() -> glove::mcp::transport& = 0;

    // Block until the agent exits, returning its exit code (or a negative
    // value for abnormal termination). The first result, value or error, is
    // cached and returned by later calls. wait() can return an error after the
    // agent has exited, when its group cannot be proven empty or the leader
    // was reaped elsewhere. The destructor invokes this if it has not already
    // been called and does not retry a failed wait(), so an explicit wait() is
    // optional unless the caller wants the code.
    virtual auto wait() -> std::expected<int, std::string> = 0;

    // The leader's exit code once this handle has reaped it, including when
    // wait() then returned an error because the group could not be proven
    // empty. Empty before the reap, when another waiter reaped the leader,
    // and on backends that do not report it.
    [[nodiscard]] virtual auto reaped_exit_code() const noexcept -> std::optional<int> {
        return std::nullopt;
    }

    // Return the terminal resource-enforcement receipt. This is unavailable
    // before wait() completes, for profiles without mandatory limits, and for
    // backends that fail the all-or-nothing capability gate.
    [[nodiscard]] virtual auto resource_receipt() const
        -> std::expected<resource_enforcement_receipt, std::string> = 0;
};

// Abstract spawner. Concrete impls install platform isolation primitives
// (sandbox-exec on macOS, namespaces+seccomp on Linux) before exec'ing the
// supplied agent.
class spawner {
public:
    spawner() = default;
    spawner(const spawner&) = delete;
    spawner& operator=(const spawner&) = delete;
    spawner(spawner&&) = delete;
    spawner& operator=(spawner&&) = delete;
    virtual ~spawner() = default;

    // Report mechanisms this backend installs and records for each child.
    // Callers must not infer support from the operating system alone.
    [[nodiscard]] virtual auto resource_capabilities() const noexcept
        -> resource_enforcement_capabilities = 0;

    // Launch the agent program described by `argv` under `prof`. argv[0] is
    // the program path; later elements are CLI args. Returns a handle whose
    // transport is wired to the agent's stdin/stdout.
    virtual auto spawn(const profile& prof, const std::vector<std::string>& argv)
        -> std::expected<std::unique_ptr<agent_handle>, std::string> = 0;
};

// Build the spawner appropriate for the current platform. Returns nullptr if
// no platform impl is compiled in (e.g. Linux build before Phase 4 lands).
auto make_default_spawner() -> std::unique_ptr<spawner>;

// Synchronously run `argv` contained under `prof` with the parent's stdio
// (fd 0/1/2) inherited — no MCP pipe and no kernel. Blocks until the agent
// exits and returns its exit code. This is the `glove exec` path: a real,
// self-driving agent (its terminal + LLM are its own) gets glove's OS perimeter
// and egress, but is not driven as an MCP client. Returns an error on platforms
// without a passthrough implementation yet.
struct containment_escape_event {
    std::string mechanism;
    std::string detail;
    std::int32_t pid = -1;
};

using escape_event_observer = std::function<void(const containment_escape_event&)>;

auto exec_contained(const profile& prof, const std::vector<std::string>& argv)
    -> std::expected<int, std::string>;

auto exec_contained(
    const profile& prof, const std::vector<std::string>& argv, escape_event_observer on_escape
) -> std::expected<int, std::string>;

} // namespace glove::container
