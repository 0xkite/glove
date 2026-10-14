#include "anthropic_fixture_responder.hpp"

#include <algorithm>
#include <utility>

namespace glove::run::test_support {
namespace {

auto json_escape(std::string_view text) -> std::string {
    std::string out;
    for (const char ch : text) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        default:
            if (const auto byte = static_cast<unsigned char>(ch); byte < 0x20U) {
                out += "\\u00";
                out += "0123456789abcdef"[(byte >> 4U) & 0xfU];
                out += "0123456789abcdef"[byte & 0xfU];
            } else {
                out.push_back(ch);
            }
        }
    }
    return out;
}

// Narrow string-field extraction for diagnostics; the responder never
// interprets the body beyond these fields.
auto string_field(std::string_view body, std::string_view key) -> std::string {
    const std::string needle = "\"" + std::string{key} + "\":\"";
    const auto at = body.find(needle);
    if (at == std::string_view::npos) {
        return {};
    }
    const auto start = at + needle.size();
    const auto end = body.find('"', start);
    return end == std::string_view::npos ? std::string{}
                                         : std::string{body.substr(start, end - start)};
}

auto count_occurrences(std::string_view body, std::string_view needle) -> std::size_t {
    std::size_t count = 0;
    std::size_t at = 0;
    while ((at = body.find(needle, at)) != std::string_view::npos) {
        ++count;
        at += needle.size();
    }
    return count;
}

auto header_value(const net::upstream_request& request, std::string_view name) -> std::string {
    for (const auto& [key, value] : request.headers) {
        if (key == name) {
            return value;
        }
    }
    return {};
}

auto sse_event(std::string_view event, std::string_view data) -> std::string {
    return "event: " + std::string{event} + "\ndata: " + std::string{data} + "\n\n";
}

} // namespace

void anthropic_fixture_responder::script(std::vector<std::string> replies) {
    std::scoped_lock lock{mutex_};
    if (!replies.empty()) {
        replies_ = std::move(replies);
        next_reply_ = 0;
    }
}

void anthropic_fixture_responder::hold_next() {
    std::scoped_lock lock{mutex_};
    hold_ = true;
    held_ = false;
    released_ = false;
}

void anthropic_fixture_responder::release() {
    std::scoped_lock lock{mutex_};
    released_ = true;
    changed_.notify_all();
}

auto anthropic_fixture_responder::wait_held(std::chrono::milliseconds limit) -> bool {
    std::unique_lock lock{mutex_};
    return changed_.wait_for(lock, limit, [&] { return held_; });
}

auto anthropic_fixture_responder::requests() const -> std::vector<fixture_request> {
    std::scoped_lock lock{mutex_};
    return requests_;
}

auto anthropic_fixture_responder::refusals() const -> std::uint64_t {
    std::scoped_lock lock{mutex_};
    return refusals_;
}

auto anthropic_fixture_responder::cancelled_holds() const -> std::uint64_t {
    std::scoped_lock lock{mutex_};
    return cancelled_holds_;
}

auto anthropic_fixture_responder::forwarder() -> net::upstream_forwarder {
    return [this](
               const net::upstream_request& request,
               std::stop_token stop,
               std::chrono::steady_clock::time_point deadline
           ) { return respond(request, std::move(stop), deadline); };
}

auto anthropic_fixture_responder::respond(
    const net::upstream_request& request,
    std::stop_token stop,
    std::chrono::steady_clock::time_point deadline
) -> std::expected<net::upstream_response, std::string> {
    const bool stream = request.body.find("\"stream\":true") != std::string::npos;
    // Route on the path only; the query (e.g. ?beta=true) is recorded, not matched.
    const auto query = request.target.find('?');
    const std::string path =
        query == std::string::npos ? request.target : request.target.substr(0, query);
    fixture_request record{
        .method = request.method,
        .target = request.target,
        .model = string_field(request.body, "model"),
        .anthropic_version = header_value(request, "anthropic-version"),
        .stream = stream,
        .messages = count_occurrences(request.body, "\"role\":"),
        .body = request.body.substr(0, 65536),
        .secret_seen = request.secret_token
    };
    std::string reply;
    bool hold = false;
    {
        std::scoped_lock lock{mutex_};
        requests_.push_back(record);
        if (request.method != "POST" || path != "/v1/messages") {
            ++refusals_;
            return net::upstream_response{
                .status_code = 404,
                .body = "{\"type\":\"error\",\"error\":{\"type\":\"not_found_error\",\"message\":"
                        "\"fixture route not implemented\"}}",
                .headers = {
                    {"Content-Type", "application/json"}, {"request-id", "req_fixture_refused"}
                }
            };
        }
        reply = replies_[std::min(next_reply_, replies_.size() - 1)];
        ++next_reply_;
        hold = std::exchange(hold_, false);
    }
    if (hold) {
        std::unique_lock lock{mutex_};
        held_ = true;
        changed_.notify_all();
        // Notify only: locking mutex_ here could deadlock with this thread
        // holding the lock while the callback object is destroyed.
        const std::stop_callback wake{stop, [&] { changed_.notify_all(); }};
        const bool released =
            changed_.wait_until(lock, deadline, [&] { return released_ || stop.stop_requested(); });
        held_ = false;
        if (!released || !released_) {
            ++cancelled_holds_;
            return std::unexpected("fixture hold cancelled or timed out");
        }
    }
    const std::string model = record.model.empty() ? "fixture-model" : record.model;
    const std::string id = "msg_fixture_" + std::to_string(requests_.size());
    if (!stream) {
        return net::upstream_response{
            .status_code = 200,
            .body = "{\"id\":\"" + id +
                    "\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"" +
                    json_escape(model) + "\",\"content\":[{\"type\":\"text\",\"text\":\"" +
                    json_escape(reply) +
                    "\"}],\"stop_reason\":\"end_turn\",\"stop_sequence\":null,\"usage\":{"
                    "\"input_tokens\":12,\"output_tokens\":3}}",
            .headers = {{"Content-Type", "application/json"}, {"request-id", "req_fixture"}}
        };
    }
    std::string body;
    body += sse_event(
        "message_start",
        "{\"type\":\"message_start\",\"message\":{\"id\":\"" + id +
            "\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"" + json_escape(model) +
            "\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{"
            "\"input_tokens\":12,\"output_tokens\":1}}}"
    );
    body += sse_event(
        "content_block_start",
        "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\","
        "\"text\":\"\"}}"
    );
    body += sse_event(
        "content_block_delta",
        "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\","
        "\"text\":\"" +
            json_escape(reply) + "\"}}"
    );
    body += sse_event("content_block_stop", "{\"type\":\"content_block_stop\",\"index\":0}");
    body += sse_event(
        "message_delta",
        "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":"
        "null},\"usage\":{\"output_tokens\":3}}"
    );
    body += sse_event("message_stop", "{\"type\":\"message_stop\"}");
    return net::upstream_response{
        .status_code = 200,
        .body = std::move(body),
        .headers = {
            {"Content-Type", "text/event-stream; charset=utf-8"}, {"request-id", "req_fixture"}
        }
    };
}

} // namespace glove::run::test_support
