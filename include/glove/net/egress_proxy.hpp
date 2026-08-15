#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace glove::net {

struct egress_event {
    std::string host;
    std::uint16_t port = 0;
    bool allowed = false;
    std::string detail;
};

struct egress_rule {
    std::string host;
    std::uint16_t port = 443;
    // Private, loopback, link-local, and other non-public destinations are
    // denied after DNS resolution unless the operator explicitly opts in.
    bool allow_private = false;
};

struct egress_options {
    std::vector<egress_rule> allow;
    // Returning an error for an allowed event prevents the tunnel from being
    // released. This lets the runner make durable audit recording mandatory.
    std::function<std::expected<void, std::string>(const egress_event&)> on_event;
};

// Authenticated loopback HTTP CONNECT proxy. Every request must carry the
// per-run Basic credential embedded in proxy_url(), then match an exact
// host+port rule. DNS resolution and address classification occur once; the
// validated address is the one connected, preventing DNS-rebinding gaps.
class egress_proxy {
public:
    egress_proxy() = default;
    egress_proxy(const egress_proxy&) = delete;
    egress_proxy& operator=(const egress_proxy&) = delete;
    egress_proxy(egress_proxy&&) = delete;
    egress_proxy& operator=(egress_proxy&&) = delete;
    virtual ~egress_proxy() = default;

    virtual auto port() const -> std::uint16_t = 0;
    virtual auto proxy_url() const -> std::string = 0;
    virtual auto proxy_authorization() const -> std::string = 0;
    virtual auto host_allowed(const std::string& host, std::uint16_t port) const -> bool = 0;
};

auto start_egress_proxy(egress_options opts)
    -> std::expected<std::unique_ptr<egress_proxy>, std::string>;

// The same authenticated CONNECT broker over an owner-only Unix socket. This
// is the VM boundary used by Apple Container: the guest receives only a
// forwarded socket and a loopback relay, never a general network interface.
auto start_egress_proxy_on_unix_socket(
    egress_options opts,
    const std::filesystem::path& socket_path,
    std::uint16_t advertised_guest_port
) -> std::expected<std::unique_ptr<egress_proxy>, std::string>;

} // namespace glove::net
