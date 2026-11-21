// Plain host-loopback service ports on macOS: the generated SBPL carries one
// bridge-shaped rule per port, and a live sandbox reaches exactly the listed
// ports and no others.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include "macos/launch_command.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::profile;
using glove::container::macos_detail::prepare_launch_command;

struct listener {
    int fd = -1;
    std::uint16_t port = 0;

    listener() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        ::sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::socklen_t length = sizeof(address);
        if (fd < 0 || ::bind(fd, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(fd, 8) != 0 ||
            ::getsockname(fd, reinterpret_cast<::sockaddr*>(&address), &length) != 0) {
            return;
        }
        port = ntohs(address.sin_port);
    }

    listener(const listener&) = delete;
    auto operator=(const listener&) -> listener& = delete;

    ~listener() {
        if (fd >= 0) {
            ::close(fd);
        }
    }
};

auto count_of(std::string_view text, std::string_view needle) -> std::size_t {
    std::size_t count = 0;
    for (auto pos = text.find(needle); pos != std::string_view::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

auto rule_for(std::uint16_t port) -> std::string {
    return "(allow network-outbound (require-all (remote tcp \"localhost:" + std::to_string(port) +
           "\") (socket-domain AF_INET)))\n";
}

// Exit status of `nc -z` against 127.0.0.1:<port> inside the sandbox.
auto probe(const profile& prof, std::uint16_t port) -> std::optional<int> {
    auto code = glove::container::exec_contained(
        prof, {"/usr/bin/nc", "-z", "-w", "3", "127.0.0.1", std::to_string(port)}
    );
    if (!code) {
        std::fprintf(stderr, "exec nc: %s\n", code.error().c_str());
        return std::nullopt;
    }
    return *code;
}

auto run() -> int {
    // SBPL generation: one rule per port, in the bridge rule's form.
    {
        profile none;
        const auto base = prepare_launch_command(none, {"/usr/bin/true"});
        REQUIRE(base.has_value());
        profile two;
        two.service_ports = {18001, 18000};
        const auto with_two = prepare_launch_command(two, {"/usr/bin/true"});
        REQUIRE(with_two.has_value());
        const std::string_view text = with_two->arguments.at(2);
        REQUIRE(text.contains(rule_for(18000)));
        REQUIRE(text.contains(rule_for(18001)));
        REQUIRE(count_of(text, "(remote tcp \"localhost:") == 2);
        REQUIRE(count_of(base->arguments.at(2), "(remote tcp \"localhost:") == 0);

        // The bridge's own rule is the same shape.
        profile bridged;
        bridged.bridge_endpoint = glove::container::bridge_endpoint_settings{.port = 18000};
        const auto bridge_cmd = prepare_launch_command(bridged, {"/usr/bin/true"});
        REQUIRE(bridge_cmd.has_value());
        REQUIRE(std::string_view{bridge_cmd->arguments.at(2)}.contains(rule_for(18000)));
    }

    // Live: the sandbox reaches a listed port and no other.
    listener first;
    listener second;
    listener unlisted;
    REQUIRE(first.port != 0 && second.port != 0 && unlisted.port != 0);

    profile one;
    one.service_ports = {first.port};
    REQUIRE(probe(one, first.port) == 0);
    REQUIRE(probe(one, second.port).value_or(0) != 0);
    REQUIRE(probe(one, unlisted.port).value_or(0) != 0);

    profile both;
    both.service_ports = {first.port, second.port};
    REQUIRE(probe(both, first.port) == 0);
    REQUIRE(probe(both, second.port) == 0);
    REQUIRE(probe(both, unlisted.port).value_or(0) != 0);

    profile unlisted_everything;
    REQUIRE(probe(unlisted_everything, first.port).value_or(0) != 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
