#include "glove/control/guest_channel.hpp"

#include <algorithm>

namespace glove::control {

namespace {

// Same bounded identifier grammar the session registry enforces for durable
// channel and schema identifiers.
auto valid_channel_identifier(std::string_view value) noexcept -> bool {
    constexpr std::size_t max_identifier_bytes = 128U;
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

} // namespace

auto channel_host::register_channel(channel_descriptor descriptor)
    -> std::expected<void, std::string> {
    if (!valid_channel_identifier(descriptor.channel_id) ||
        !valid_channel_identifier(descriptor.schema_id) || !descriptor.body_validator) {
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

auto channel_host::catalog() const -> std::vector<channel_catalog_entry> {
    std::vector<channel_catalog_entry> entries;
    entries.reserve(descriptors_.size());
    for (const auto& [schema_id, descriptor] : descriptors_) {
        entries.push_back({
            .channel_id = descriptor.channel_id,
            .schema_id = schema_id,
            .bounds = descriptor.bounds,
        });
    }
    std::ranges::sort(entries, {}, [](const channel_catalog_entry& entry) -> std::string_view {
        return entry.schema_id;
    });
    return entries;
}

} // namespace glove::control
