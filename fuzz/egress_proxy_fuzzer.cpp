#include "net/egress_connect_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

constexpr std::size_t kMaxRequestBytes = 16U * 1024U;

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > kMaxRequestBytes) {
        return 0;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view raw{reinterpret_cast<const char*>(data), size};
    std::string host;
    std::uint16_t port = 0;
    if (glove::net::detail::parse_connect(raw, host, port)) {
        // Invariants on admitted CONNECT targets: non-empty lowercase host without path/auth bytes,
        // non-zero port.
        if (host.empty() || port == 0 || host.find_first_of("/@?#[]\\") != std::string::npos) {
            __builtin_trap();
        }
        static_cast<void>(glove::net::detail::host_matches(".example.com", host));
        static_cast<void>(glove::net::detail::host_matches("localhost", host));
    }

    const std::size_t nl = raw.find('\n');
    const std::string_view expected_token = nl == std::string_view::npos ? raw : raw.substr(0, nl);
    static_cast<void>(glove::net::detail::authenticated(raw, expected_token));
    static_cast<void>(glove::net::detail::normalise_host(std::string{expected_token}));
    return 0;
}
