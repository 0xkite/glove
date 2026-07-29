#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <string>

namespace glove::container::linux_detail {

struct egress_channel_pair {
    int host_fd = -1;
    int sandbox_fd = -1;
};

// Creates the inherited authenticated transport used to move accepted
// private-netns loopback sockets to the host. The channel is never exposed to
// the agent process.
auto create_egress_channel() -> std::expected<egress_channel_pair, std::string>;

class host_egress_bridge {
public:
    host_egress_bridge() = default;
    host_egress_bridge(const host_egress_bridge&) = delete;
    auto operator=(const host_egress_bridge&) -> host_egress_bridge& = delete;
    host_egress_bridge(host_egress_bridge&&) = delete;
    auto operator=(host_egress_bridge&&) -> host_egress_bridge& = delete;
    virtual ~host_egress_bridge() = default;
};

// Owns host_channel_fd on success and forwards every received descriptor only
// to the authenticated host-loopback proxy at proxy_port.
auto start_host_egress_bridge(int host_channel_fd, std::uint16_t proxy_port)
    -> std::expected<std::unique_ptr<host_egress_bridge>, std::string>;

// Runs after CLONE_NEWNET and the user-namespace mapping are active. It brings
// up private loopback, binds the advertised proxy port, and forks a tiny
// namespace-local descriptor forwarder. The function consumes
// sandbox_channel_fd whether it succeeds or fails.
auto install_sandbox_egress_bridge(int sandbox_channel_fd, std::uint16_t proxy_port)
    -> std::expected<void, std::string>;

} // namespace glove::container::linux_detail
