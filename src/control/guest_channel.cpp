#include "glove/control/guest_channel.hpp"

#include "channel_identifier_grammar.hpp"

namespace glove::control {

auto channel_host::register_channel(channel_descriptor descriptor)
    -> std::expected<void, std::string> {
    if (!detail::valid_identifier(descriptor.channel_id) ||
        !detail::valid_identifier(descriptor.schema_id) || !descriptor.body_validator) {
        return std::unexpected(std::string{"channel descriptor identity is invalid"});
    }
    const auto& bounds = descriptor.bounds;
    if (bounds.max_items == 0 || bounds.max_items > max_observation_items ||
        bounds.max_body_bytes == 0 || bounds.max_body_bytes > max_observation_body_bytes ||
        bounds.max_ttl_ms == 0 || bounds.max_ttl_ms > max_observation_intent_ttl_ms ||
        bounds.max_skew_ms > max_observation_intent_clock_skew_ms) {
        return std::unexpected(std::string{"channel descriptor bounds are invalid"});
    }
    if (descriptors_.contains(descriptor.schema_id)) {
        return std::unexpected(std::string{"channel schema is already registered"});
    }
    auto [position, inserted] =
        descriptors_.emplace(std::move(descriptor.schema_id), std::move(descriptor));
    if (!inserted) {
        return std::unexpected(std::string{"channel schema is already registered"});
    }
    (void)position;
    return {};
}

auto channel_host::admits(std::string_view schema_id) const -> const channel_descriptor* {
    const auto found = descriptors_.find(std::string{schema_id});
    return found == descriptors_.end() ? nullptr : &found->second;
}

} // namespace glove::control
