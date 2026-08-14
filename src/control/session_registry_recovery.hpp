#pragma once

#include "glove/control/session_registry.hpp"
#include "glove/control/session_registry_wire.hpp"

#include <cstdint>

namespace glove::control {

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

} // namespace glove::control
