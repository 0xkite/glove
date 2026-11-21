#include "glove/container/system_services.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <string_view>

namespace glove::container {

namespace {

using std::string_view_literals::operator""sv;

constexpr std::array<std::string_view, 1> configd_mach{"com.apple.SystemConfiguration.configd"sv};
constexpr std::array<std::string_view, 1> ssl_paths{"/private/etc/ssl"sv};

constexpr std::array<system_service_entry, 2> catalog{{
    {
        .name = "network-config",
        .macos_mach_services = configd_mach,
        .macos_read_paths = {},
        .description = "System network and proxy configuration (configd). Reveals the host's "
                       "network and proxy settings to the guest.",
    },
    {
        .name = "tls-config",
        .macos_mach_services = {},
        .macos_read_paths = ssl_paths,
        .description = "System TLS trust configuration for LibreSSL/OpenSSL clients such as "
                       "/usr/bin/curl.",
    },
}};

} // namespace

auto system_service_catalog() noexcept -> std::span<const system_service_entry> {
    return catalog;
}

auto find_system_service(std::string_view name) noexcept -> const system_service_entry* {
    const auto it = std::ranges::find(catalog, name, &system_service_entry::name);
    return it == catalog.end() ? nullptr : &*it;
}

} // namespace glove::container
