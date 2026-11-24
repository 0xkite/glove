#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <stop_token>
#include <string>
#include <vector>

namespace glove::net {

enum class endpoint_provider : std::uint8_t {
    anthropic,
    openai,
    github,
    custom,
    // The credential is injected into the field where the client presented
    // the session nonce (`Authorization: Bearer`, `x-api-key`, or
    // `x-goog-api-key`), so one rule serves any provider whose client formats
    // its own authentication header.
    client_placed,
};

struct credentialed_endpoint_rule {
    endpoint_provider provider = endpoint_provider::anthropic;
    std::string path_prefix;   // e.g. "/anthropic"
    std::string upstream_host; // e.g. "api.anthropic.com"
    std::uint16_t upstream_port = 443;
    std::string secret_token;  // Maintained in host memory only
    std::string session_nonce; // Ephemeral token required from sandbox
    std::vector<std::string> allowed_methods = {"POST"};
    // Empty means allow all under prefix. An entry is an exact path, a subtree
    // ("/v1/*"), or one segment ending in a suffix ("/v1/models/*:generate").
    std::vector<std::string> allowed_paths;
};

struct endpoint_event {
    endpoint_provider provider = endpoint_provider::anthropic;
    std::string method;
    std::string path;
    bool allowed = false;
    std::string detail;
    std::size_t request_bytes = 0;
    std::size_t response_bytes = 0;
    // Set only on the event that follows the exchange with the provider
    // (detail "completed" or "upstream_error"): how long the exchange took
    // and, when it produced a response, its status code. The decision event
    // (detail "allowed") is emitted before the exchange and has neither.
    std::chrono::nanoseconds upstream_duration{0};
    int upstream_status = 0;
    // Token counts the provider reported in the response (outcome event
    // only); tokens_reported is false when the body carried none.
    std::uint64_t input_tokens = 0;
    std::uint64_t output_tokens = 0;
    bool tokens_reported = false;
};

// Per-endpoint budgets; 0 means unlimited. Checked after authentication and
// before anything is forwarded. A request over a budget is refused with 429
// and recorded with its reason: "request_limit", "rate_limit" or
// "token_limit". Tokens count what providers reported, so a provider that
// reports none never reaches the token limit.
struct endpoint_limits {
    std::uint64_t max_requests = 0;
    std::uint32_t max_requests_per_minute = 0;
    std::uint64_t max_tokens = 0;
};

// One request that has already been authenticated, matched to a rule, and had
// its target validated; only the exchange with the provider remains. The
// endpoint never reaches the network itself, so the transport can be a real TLS
// client in production and a stub under test without the production path
// carrying any test-only behaviour.
struct upstream_request {
    endpoint_provider provider = endpoint_provider::anthropic;
    std::string upstream_host;
    std::uint16_t upstream_port = 443;
    std::string method;
    // Request target after the endpoint prefix is stripped, including any query.
    std::string target;
    // Sanitised end-to-end headers. Hop-by-hop, routing, and credential fields
    // are already removed: the transport sets Host and the credential itself.
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    // Lowercase name of the header that carried the session nonce. Used to
    // place the secret for `endpoint_provider::client_placed`.
    std::string credential_field;
    // The provider credential to present. Host memory only; never leaves it as
    // plain agent-visible state.
    std::string secret_token;
};

struct upstream_response {
    int status_code = 502;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

// Optional provider transport. It receives the stop token and an absolute
// deadline and must honour both: a stalled exchange must not pin the endpoint's
// single worker or block shutdown. When unset, the endpoint refuses with 501 Not
// Implemented rather than pretending it forwarded anything.
using upstream_forwarder = std::function<std::expected<upstream_response, std::string>(
    const upstream_request&, std::stop_token, std::chrono::steady_clock::time_point
)>;

struct credentialed_endpoint_options {
    std::vector<credentialed_endpoint_rule> endpoints;
    std::function<std::expected<void, std::string>(const endpoint_event&)> on_event;
    upstream_forwarder forward;
    endpoint_limits limits;
    // Planted canary / decoy tokens that must never leave the sandbox in an
    // outbound request target, header, or body. Each token must be 8..256 bytes
    // (at most 64 tokens). Matches are refused fail-closed with 403 Forbidden
    // and audited as "canary_exfiltration" without echoing the token.
    std::vector<std::string> canary_tokens;
    // When true, each rule's secret_token (if >= 8 bytes) is also added to the
    // outbound canary scanner so a leaked host credential cannot be exfiltrated
    // back out through the proxy.
    bool scan_rule_secrets = true;
    // Absolute deadlines for the body and response phases. Both are bounded so a
    // client that declares a body it never sends, or stops reading the response,
    // cannot pin the endpoint's single worker or block shutdown. Configurable so
    // a test can exercise the timeout path without waiting out the default.
    int body_deadline_ms = 30000;
    int response_deadline_ms = 30000;
    // Absolute deadline for the provider exchange. The transport receives it and
    // must not outlive it, so a stalled upstream cannot hold the worker.
    int upstream_deadline_ms = 120000;
};

// Host-side local reverse proxy for mediating agent API requests.
// Listens on an ephemeral loopback port, terminates agent HTTP/1.1 requests,
// validates the ephemeral session nonce, strips it, injects the real provider
// secret, and relays over TLS to the fixed upstream.
class credentialed_endpoint {
public:
    credentialed_endpoint() = default;
    credentialed_endpoint(const credentialed_endpoint&) = delete;
    credentialed_endpoint& operator=(const credentialed_endpoint&) = delete;
    credentialed_endpoint(credentialed_endpoint&&) = delete;
    credentialed_endpoint& operator=(credentialed_endpoint&&) = delete;
    virtual ~credentialed_endpoint() = default;

    [[nodiscard]] virtual auto port() const -> std::uint16_t = 0;
    [[nodiscard]] virtual auto base_url(endpoint_provider provider) const
        -> std::expected<std::string, std::string> = 0;
    [[nodiscard]] virtual auto session_nonce(endpoint_provider provider) const
        -> std::expected<std::string, std::string> = 0;
};

auto start_credentialed_endpoint(credentialed_endpoint_options opts)
    -> std::expected<std::unique_ptr<credentialed_endpoint>, std::string>;

} // namespace glove::net
