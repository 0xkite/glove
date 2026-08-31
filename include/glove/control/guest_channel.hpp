#pragma once

#include "glove/control/session_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
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
// former per-schema limits.
struct channel_descriptor {
    using body_validator_type = bool (*)(const glove_observation_body&) noexcept;

    std::string schema_id;
    body_validator_type body_validator = nullptr;
    channel_bounds bounds{};
};

// Host-registered schema admission table, one per managed session. The
// session registry holds it and delegates body semantics to the registered
// validators while keeping structural invariants (identifier charset,
// digest hex, TTL/skew arithmetic, capacity, idempotency) in core.
// Registration and validation complete before freeze() and before the host is
// shared with a registry. Concurrent read-only admits() calls are then safe.
// Authentic durable intents whose schema is no longer registered recover as
// non-actionable quarantine metadata.
class channel_host {
public:
    channel_host() = default;
    channel_host(const channel_host&) = delete;
    auto operator=(const channel_host&) -> channel_host& = delete;

    [[nodiscard]] auto register_channel(channel_descriptor descriptor)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto freeze() -> std::expected<void, std::string>;

    [[nodiscard]] auto empty() const noexcept -> bool { return descriptors_.empty(); }

    [[nodiscard]] auto frozen() const noexcept -> bool { return frozen_; }

    [[nodiscard]] auto size() const noexcept -> std::size_t { return descriptors_.size(); }

    // Returns nullptr unless the frozen catalog contains the schema.
    [[nodiscard]] auto admits(std::string_view schema_id) const -> const channel_descriptor*;

private:
    std::unordered_map<std::string, channel_descriptor> descriptors_;
    bool frozen_ = false;
};

// Opaque adapter identity resolved by an explicit adapter composition layer.
// Core compares these bounded values and runtime sets but assigns no semantics
// to them.
struct guest_channel_adapter_binding {
    std::string adapter_id;
    std::string channel_schema_id;
    std::vector<std::string> runtime_ids;
    std::shared_ptr<const channel_host> channels;
};

} // namespace glove::control
