#include "glove/container/image_identity.hpp"

#include <algorithm>
#include <cstdint>

namespace glove::container {
namespace {

[[nodiscard]] auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto ascii_alphanumeric(char byte) noexcept -> bool {
    return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
}

[[nodiscard]] auto valid_name_component(std::string_view component) noexcept -> bool {
    if (component.empty() || !ascii_alphanumeric(component.front()) ||
        !ascii_alphanumeric(component.back())) {
        return false;
    }
    return std::ranges::all_of(component, [](char byte) {
        return ascii_alphanumeric(byte) || byte == '.' || byte == '_' || byte == '-';
    });
}

[[nodiscard]] auto valid_registry_component(std::string_view component) noexcept -> bool {
    const auto colon = component.find(':');
    if (colon == std::string_view::npos) {
        return valid_name_component(component);
    }
    if (colon == 0U || colon + 1U >= component.size() ||
        component.find(':', colon + 1U) != std::string_view::npos) {
        return false;
    }
    const auto host = component.substr(0, colon);
    const auto port = component.substr(colon + 1U);
    if (!valid_name_component(host) || port.size() > 5U ||
        !std::ranges::all_of(port, [](char byte) { return byte >= '0' && byte <= '9'; })) {
        return false;
    }
    std::uint32_t parsed_port = 0;
    for (const char digit : port) {
        parsed_port = (parsed_port * 10U) + static_cast<std::uint32_t>(digit - '0');
    }
    return parsed_port > 0U && parsed_port <= 65'535U;
}

[[nodiscard]] auto valid_image_name(std::string_view name) noexcept -> bool {
    if (name.empty() || name.front() == '/' || name.back() == '/' || name.contains('@')) {
        return false;
    }
    std::size_t component_index = 0;
    while (!name.empty()) {
        const auto separator = name.find('/');
        const auto component = name.substr(0, separator);
        const bool valid = component_index == 0U && separator != std::string_view::npos
                               ? valid_registry_component(component)
                               : valid_name_component(component);
        if (!valid || (component.contains(':') && separator == std::string_view::npos)) {
            return false;
        }
        if (separator == std::string_view::npos) {
            return true;
        }
        name.remove_prefix(separator + 1U);
        ++component_index;
    }
    return false;
}

} // namespace

auto valid_immutable_container_image(std::string_view reference, std::string_view digest) noexcept
    -> bool {
    if (reference.empty() || reference.size() > 256U || !valid_digest(digest)) {
        return false;
    }
    if (reference.size() <= digest.size() ||
        reference[reference.size() - digest.size() - 1U] != '@' ||
        reference.substr(reference.size() - digest.size()) != digest) {
        return false;
    }
    return valid_image_name(reference.substr(0, reference.size() - digest.size() - 1U));
}

} // namespace glove::container
