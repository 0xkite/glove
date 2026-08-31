#pragma once

#include "glove/control/session_registry.hpp"
#include "glove/control/session_registry_wire.hpp"

#include "session_registry_impl.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace glove::control {

// Binding-identity comparison for frozen observation intent/disposition
// snapshots against the session record they were bound to. Neutralizes the
// append-journal bookkeeping fields plus the three lifecycle-mutable fields
// (`state`, `running_at_ms`, `policy_revision`); any other difference is a
// genuine session-binding crossing. Exposed for regression tests.
auto same_session_snapshot(wire::persisted_session left, wire::persisted_session right) -> bool;

// A single decoded persisted record plus the byte offset of the next record.
struct decoded_persisted_record {
    wire::persisted_session record;
    std::uint64_t next_offset = 0;
};

// Replay lookups reconstruct the exact historical idempotent response for a
// repeated operation. `found = false` means "no prior record; proceed fresh".
struct replay_lookup {
    bool found = false;
    session_record record;
};

struct start_replay_lookup {
    bool found = false;
    session_start_reservation reservation;
};

struct starting_replay_lookup {
    bool found = false;
    session_starting_record record;
};

struct running_replay_lookup {
    bool found = false;
    session_running_record record;
};

struct stopping_replay_lookup {
    bool found = false;
    session_stopping_record record;
};

struct exited_replay_lookup {
    bool found = false;
    session_exited_record record;
};

struct failure_replay_lookup {
    bool found = false;
    session_failed_record record;
};

// Recovery state machine: reads, validates, and re-admits persisted records
// when the daemon reopens a registry.
auto initialize_empty(session_registry::implementation& state) -> std::expected<void, std::string>;
auto read_persisted_record(int descriptor, std::uint64_t file_size, std::uint64_t offset)
    -> std::expected<decoded_persisted_record, std::string>;
auto accept_recovered_record(
    session_registry::implementation& state,
    wire::persisted_session record,
    std::string_view previous_hash
) -> std::expected<void, std::string>;
auto recover(session_registry::implementation& state) -> std::expected<void, std::string>;
auto verify_identity(session_registry::implementation& state) -> bool;
auto rollback_append(session_registry::implementation& state, std::uint64_t original_size) -> bool;

} // namespace glove::control
