#pragma once

#include "glove/net/credentialed_endpoint.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::test_support {

// Test-only deterministic Anthropic Messages responder. It is an
// upstream_forwarder for the real credentialed endpoint and NEVER dials: every
// request is answered from fixtures or refused. Only POST /v1/messages is
// implemented; any other route is refused with 404 (no upstream fallback).
struct fixture_request {
    std::string method;
    std::string target;
    std::string model;
    std::string anthropic_version;
    bool stream = false;
    std::size_t messages = 0;
    std::string body;
    std::string secret_seen;
};

class anthropic_fixture_responder {
public:
    anthropic_fixture_responder() = default;
    anthropic_fixture_responder(const anthropic_fixture_responder&) = delete;
    auto operator=(const anthropic_fixture_responder&) -> anthropic_fixture_responder& = delete;

    // Scripted assistant texts, consumed in order; the last repeats.
    void script(std::vector<std::string> replies);

    // A scripted tool call: the reply is one tool_use block (stop_reason
    // tool_use) for `name` with the exact JSON `input`.
    struct tool_reply {
        std::string name;
        std::string input_json;
    };

    void script_tool_then(std::vector<tool_reply> tools, std::vector<std::string> texts);
    // Hold the next /v1/messages reply until release() or cancellation.
    void hold_next();
    // Hold the reply to the N-th /v1/messages request (1-based), armed ahead
    // of time so a fast client cannot race the barrier.
    void hold_request(std::size_t index);
    void release();
    [[nodiscard]] auto wait_held(std::chrono::milliseconds limit) -> bool;

    [[nodiscard]] auto forwarder() -> net::upstream_forwarder;
    [[nodiscard]] auto requests() const -> std::vector<fixture_request>;
    [[nodiscard]] auto refusals() const -> std::uint64_t;
    [[nodiscard]] auto cancelled_holds() const -> std::uint64_t;

private:
    auto respond(
        const net::upstream_request& request,
        std::stop_token stop,
        std::chrono::steady_clock::time_point deadline
    ) -> std::expected<net::upstream_response, std::string>;

    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::vector<std::string> replies_{"pong"};
    std::vector<tool_reply> tools_;
    std::size_t next_reply_ = 0;
    std::vector<fixture_request> requests_;
    std::uint64_t refusals_ = 0;
    std::uint64_t cancelled_holds_ = 0;
    bool hold_ = false;
    std::size_t hold_at_ = 0;
    bool held_ = false;
    bool released_ = false;
};

} // namespace glove::run::test_support
