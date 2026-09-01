#pragma once

#include "glove/control/guest_channel.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace glove::adapters::sage {

[[nodiscard]] auto guest_channel_host()
    -> std::expected<std::shared_ptr<const control::channel_host>, std::string>;

// Resolves only Sage's exact opaque adapter/schema pair. Unsupported operator
// bindings fail startup rather than degrading to a generic capability.
[[nodiscard]] auto resolve_guest_channel_adapter(
    std::string_view adapter_id,
    std::string_view channel_schema_id,
    std::string_view transport_id = {}
) -> std::expected<std::shared_ptr<const control::guest_channel_adapter_binding>, std::string>;

} // namespace glove::adapters::sage
