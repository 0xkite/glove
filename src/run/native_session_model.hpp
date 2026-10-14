#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

// Pure logical-session lifecycle. No I/O, no process, no clock. The owning
// supervisor journals request intent before applying an operation and drives
// execution events into this model; the model only decides what is admitted.
//
// Preparation cancellation is modelled as an explicit asynchronous edge:
// preparing --stop--> stopping. The launch thread later reports either
// prepare_cancelled (no launch effect existed; stopping -> stopped with absent
// history), prepare_failed (admission refused; -> stopped), or launched (the
// owned process exists; stopping remains until a process outcome arrives).
enum class session_phase : std::uint8_t {
    fresh,
    preparing,
    running,
    interrupting,
    stopping,
    finalizing,
    stopped,
    recovery_required
};

enum class history_status : std::uint8_t { absent, available, published, invalid, failed };
enum class effects_status : std::uint8_t { unassessed, incomplete, reconciled };

enum class session_operation : std::uint8_t { status, start, stop, interrupt, resume, shutdown };

enum class result_code : std::uint8_t {
    ok,
    accepted,
    unauthorized,
    unsupported_version,
    unsupported_operation,
    malformed,
    stale_epoch,
    stale_generation,
    invalid_state,
    request_conflict,
    capacity,
    admission_failed,
    checkpoint_failed,
    outcome_uncertain
};

[[nodiscard]] auto to_string(session_phase value) -> std::string_view;
[[nodiscard]] auto to_string(history_status value) -> std::string_view;
[[nodiscard]] auto to_string(effects_status value) -> std::string_view;
[[nodiscard]] auto to_string(session_operation value) -> std::string_view;
[[nodiscard]] auto to_string(result_code value) -> std::string_view;
[[nodiscard]] auto parse_session_operation(std::string_view value)
    -> std::optional<session_operation>;

// Exact lowercase-hex identity grammar. Durable IDs carry no authority.
[[nodiscard]] auto valid_session_id(std::string_view value) -> bool;    // ns- + 32 hex
[[nodiscard]] auto valid_epoch(std::string_view value) -> bool;         // 32 hex
[[nodiscard]] auto valid_generation(std::string_view value) -> bool;    // 16 hex
[[nodiscard]] auto valid_request_id(std::string_view value) -> bool;    // 32 hex
[[nodiscard]] auto valid_checkpoint_id(std::string_view value) -> bool; // 64 hex
[[nodiscard]] auto format_generation(std::uint64_t counter) -> std::string;
[[nodiscard]] auto parse_generation(std::string_view value) -> std::optional<std::uint64_t>;

struct session_projection {
    session_phase phase = session_phase::fresh;
    std::uint64_t generation = 0;
    history_status history = history_status::absent;
    effects_status effects = effects_status::unassessed;
    std::optional<std::string> checkpoint;

    auto operator==(const session_projection&) const -> bool = default;
};

// One authenticated, schema-valid v1 request. body_digest is the SHA-256 of
// the exact validated UTF-8 request bytes; the model compares it for replay.
struct operation_request {
    std::string epoch;
    std::uint64_t generation = 0;
    std::string request;
    session_operation op = session_operation::status;
    std::optional<std::string> checkpoint;
    std::string body_digest;
};

struct operation_result {
    session_operation op = session_operation::status;
    result_code code = result_code::ok;
    bool final = true;
    session_projection snapshot;

    auto operator==(const operation_result&) const -> bool = default;
};

inline constexpr std::size_t max_operation_records = 64;
// Stop and shutdown stay admissible past the record cap so a running
// generation can always be cancelled; this is their own hard bound.
inline constexpr std::size_t max_operation_records_with_stops = max_operation_records + 8;

class native_session_model {
public:
    explicit native_session_model(std::string epoch);

    [[nodiscard]] auto epoch() const -> const std::string&;
    [[nodiscard]] auto projection() const -> const session_projection&;
    [[nodiscard]] auto operation_records() const -> std::size_t;

    // Reconstruct a durable projection under a fresh epoch. Any unsettled prior
    // operation is the caller's recovery_required evidence, never a replay.
    [[nodiscard]] auto restore(session_projection durable) -> std::expected<void, std::string>;

    // Admission order: epoch, replay evidence, expected generation, phase.
    // Mutations that start a new generation return accepted (final=false) and
    // reserve the next generation counter; the owner reports completion.
    [[nodiscard]] auto submit(const operation_request& request) -> operation_result;

    // Execution events reported by the owning supervisor. Each returns the
    // settled result for the mutation it completes, if any.
    struct settled {
        std::string request;
        operation_result result;
    };

    [[nodiscard]] auto launched() -> std::expected<void, std::string>;
    [[nodiscard]] auto prepare_cancelled() -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto prepare_failed() -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto interrupt_acknowledged()
        -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto interrupt_timed_out() -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto process_outcome_known() -> std::expected<void, std::string>;
    [[nodiscard]] auto process_outcome_uncertain()
        -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto history_classified(history_status status, effects_status effects)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto checkpoint_published(std::string checkpoint)
        -> std::expected<std::optional<settled>, std::string>;
    [[nodiscard]] auto checkpoint_failed() -> std::expected<std::optional<settled>, std::string>;
    // Finalization with no publishable history (absent/invalid) settles the
    // generation as stopped; uncertain history blocks automatic resume.
    [[nodiscard]] auto finalized_without_checkpoint()
        -> std::expected<std::optional<settled>, std::string>;

private:
    struct record {
        std::string request;
        std::string body_digest;
        std::uint64_t generation = 0;
        session_operation op = session_operation::status;
        std::optional<operation_result> settled;
    };

    [[nodiscard]] auto reply(const operation_request& request, result_code code, bool final) const
        -> operation_result;
    [[nodiscard]] auto settle(result_code code) -> std::optional<settled>;
    [[nodiscard]] auto find(std::string_view request) -> record*;

    std::string epoch_;
    session_projection projection_;
    std::vector<record> records_;
    // The one mutation (start/resume/stop/interrupt) still in flight, if any.
    std::optional<std::string> pending_;
    // True once the owned generation exists; preparation reports are then invalid.
    bool launched_ = false;
};

} // namespace glove::run::detail
