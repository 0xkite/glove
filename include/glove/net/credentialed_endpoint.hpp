#pragma once

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace glove::net {

enum class endpoint_provider : std::uint8_t {
    anthropic,
    openai,
    github,
    custom,
};

struct credentialed_endpoint_rule {
    endpoint_provider provider = endpoint_provider::anthropic;
    std::string path_prefix;   // e.g. "/anthropic"
    std::string upstream_host; // e.g. "api.anthropic.com"
    std::uint16_t upstream_port = 443;
    std::string secret_token;  // Maintained in host memory only
    std::string session_nonce; // Ephemeral token required from sandbox
    std::vector<std::string> allowed_methods = {"POST"};
    std::vector<std::string> allowed_paths; // Empty means allow all under prefix
};

struct endpoint_event {
    endpoint_provider provider = endpoint_provider::anthropic;
    std::string method;
    std::string path;
    bool allowed = false;
    std::string detail;
    std::size_t request_bytes = 0;
    std::size_t response_bytes = 0;
};

struct credentialed_endpoint_options {
    std::vector<credentialed_endpoint_rule> endpoints;
    std::function<std::expected<void, std::string>(const endpoint_event&)> on_event;
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
