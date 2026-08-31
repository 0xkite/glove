#include "adapters/sage/guest_channel.hpp"

#include <memory>
#include <string>

namespace glove::adapters::sage {
namespace {

constexpr std::string_view adapter_id = "sage-observation";
constexpr std::string_view observation_schema = "sage.glove-observation.v1";

auto accepts_observation(const control::glove_observation_body&) noexcept -> bool {
    return true;
}

} // namespace

auto guest_channel_host()
    -> std::expected<std::shared_ptr<const control::channel_host>, std::string> {
    auto host = std::make_shared<control::channel_host>();
    if (auto registered = host->register_channel({
            .schema_id = std::string{observation_schema},
            .body_validator = &accepts_observation,
            .bounds =
                {
                    .max_items = control::max_observation_items,
                    .max_body_bytes = 8'192U,
                    .max_ttl_ms = 600'000U,
                    .max_skew_ms = 30'000U,
                },
        });
        !registered) {
        return std::unexpected(
            std::string{"register Sage observation channel: "} + registered.error()
        );
    }
    if (auto frozen = host->freeze(); !frozen) {
        return std::unexpected(std::string{"freeze Sage channel catalog: "} + frozen.error());
    }
    return std::shared_ptr<const control::channel_host>{std::move(host)};
}

auto resolve_guest_channel_adapter(
    std::string_view configured_adapter_id, std::string_view configured_channel_schema_id
) -> std::expected<std::shared_ptr<const control::guest_channel_adapter_binding>, std::string> {
    if (configured_adapter_id != adapter_id || configured_channel_schema_id != observation_schema) {
        return std::unexpected(std::string{"unsupported guest channel adapter binding"});
    }
    auto channels = guest_channel_host();
    if (!channels) {
        return std::unexpected(channels.error());
    }
    return std::make_shared<const control::guest_channel_adapter_binding>(
        control::guest_channel_adapter_binding{
            .adapter_id = std::string{adapter_id},
            .channel_schema_id = std::string{observation_schema},
            .runtime_ids = {"pi"},
            .channels = std::move(*channels),
        }
    );
}

} // namespace glove::adapters::sage
