#pragma once

#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace glove::control {

// Per-channel resource bounds supplied by the host at registration. Glove
// core enforces these as structural invariants; it never supplies defaults
// for harness-specific payload semantics.
struct channel_bounds {
    std::size_t max_items = 0;
    std::size_t max_body_bytes = 0;
    std::uint64_t max_ttl_ms = 0;
    std::uint64_t max_skew_ms = 0;

    auto operator==(const channel_bounds&) const -> bool = default;
};

// Harness-owned admission for one guest payload schema. Registered by the
// host from harness configuration — never compiled into Glove core.
// `schema_id` is opaque to core; `body_validator` carries all payload
// semantics (kind, digest constants, item contracts); `bounds` replace the
// former per-schema limits; `on_exchange` (optional) is invoked once after
// an intent bound to this channel is durably enqueued. The callback must be
// non-blocking and must not re-enter the session registry.
struct channel_descriptor {
    std::string channel_id;
    std::string schema_id;
    std::function<bool(const glove_observation_body&)> body_validator;
    channel_bounds bounds{};
    std::function<void(const observation_intent_item&)> on_exchange = {};
};

// Read-only capability-discovery entry surfaced by channel_host::catalog().
// Hosts authorize catalog reads like every other host-control operation.
struct channel_catalog_entry {
    std::string channel_id;
    std::string schema_id;
    channel_bounds bounds{};

    auto operator==(const channel_catalog_entry&) const -> bool = default;
};

// Host-registered schema admission table, one per managed session. The
// session registry holds it and delegates body semantics to the registered
// validators while keeping structural invariants (identifier charset,
// digest hex, TTL/skew arithmetic, capacity, idempotency) in core.
// register_channel must complete before the host is shared with a registry;
// concurrent admits() afterwards are safe. Replay of a durable intent whose
// schema is no longer registered fails closed at recovery.
class channel_host {
public:
    channel_host() = default;
    channel_host(const channel_host&) = delete;
    auto operator=(const channel_host&) -> channel_host& = delete;

    [[nodiscard]] auto register_channel(channel_descriptor descriptor)
        -> std::expected<void, std::string>;
    // Returns nullptr when the schema is not registered (fail closed).
    [[nodiscard]] auto admits(std::string_view schema_id) const -> const channel_descriptor*;
    [[nodiscard]] auto catalog() const -> std::vector<channel_catalog_entry>;

private:
    std::unordered_map<std::string, channel_descriptor> descriptors_;
};

} // namespace glove::control
