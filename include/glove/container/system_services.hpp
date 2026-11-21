#pragma once

// Vetted catalog of opt-in host system services. A launch selects services by
// catalog name; the name is data that maps to the host facilities a class of
// client needs (macOS mach-lookup global names and read-only paths). The
// default selection is empty, so a launch exposes none of them.
//
// This table is the only place a service name is spelled. Unknown names and
// raw platform names (for example a mach service) are refused by lookup, never
// guessed. Linux entries carry no rules: Linux accepts the names and enforces
// nothing for them.

#include <span>
#include <string_view>

namespace glove::container {

struct system_service_entry {
    std::string_view name;
    // macOS global names the sandbox may mach-lookup.
    std::span<const std::string_view> macos_mach_services;
    // macOS absolute paths the sandbox may read (never write).
    std::span<const std::string_view> macos_read_paths;
    std::string_view description;
};

// Entries in catalog order.
[[nodiscard]] auto system_service_catalog() noexcept -> std::span<const system_service_entry>;

// The entry for NAME, or nullptr when NAME is not in the catalog.
[[nodiscard]] auto find_system_service(std::string_view name) noexcept
    -> const system_service_entry*;

} // namespace glove::container
