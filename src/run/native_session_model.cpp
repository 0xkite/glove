#include "native_session_model.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace glove::run::detail {
namespace {

auto lowercase_hex(std::string_view value, std::size_t size) -> bool {
    return value.size() == size && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto starts_new_generation(session_operation op) -> bool {
    return op == session_operation::start || op == session_operation::resume;
}

} // namespace

auto to_string(session_phase value) -> std::string_view {
    switch (value) {
    case session_phase::fresh:
        return "new";
    case session_phase::preparing:
        return "preparing";
    case session_phase::running:
        return "running";
    case session_phase::interrupting:
        return "interrupting";
    case session_phase::stopping:
        return "stopping";
    case session_phase::finalizing:
        return "finalizing";
    case session_phase::stopped:
        return "stopped";
    case session_phase::recovery_required:
        return "recovery_required";
    }
    return "invalid";
}

auto to_string(history_status value) -> std::string_view {
    switch (value) {
    case history_status::absent:
        return "absent";
    case history_status::available:
        return "available";
    case history_status::published:
        return "published";
    case history_status::invalid:
        return "invalid";
    case history_status::failed:
        return "failed";
    }
    return "invalid";
}

auto to_string(effects_status value) -> std::string_view {
    switch (value) {
    case effects_status::unassessed:
        return "unassessed";
    case effects_status::incomplete:
        return "incomplete";
    case effects_status::reconciled:
        return "reconciled";
    }
    return "incomplete";
}

auto to_string(session_operation value) -> std::string_view {
    switch (value) {
    case session_operation::status:
        return "status";
    case session_operation::start:
        return "start";
    case session_operation::stop:
        return "stop";
    case session_operation::interrupt:
        return "interrupt";
    case session_operation::resume:
        return "resume";
    case session_operation::shutdown:
        return "shutdown";
    }
    return "status";
}

auto to_string(result_code value) -> std::string_view {
    switch (value) {
    case result_code::ok:
        return "ok";
    case result_code::accepted:
        return "accepted";
    case result_code::unauthorized:
        return "unauthorized";
    case result_code::unsupported_version:
        return "unsupported_version";
    case result_code::unsupported_operation:
        return "unsupported_operation";
    case result_code::malformed:
        return "malformed";
    case result_code::stale_epoch:
        return "stale_epoch";
    case result_code::stale_generation:
        return "stale_generation";
    case result_code::invalid_state:
        return "invalid_state";
    case result_code::request_conflict:
        return "request_conflict";
    case result_code::capacity:
        return "capacity";
    case result_code::admission_failed:
        return "admission_failed";
    case result_code::checkpoint_failed:
        return "checkpoint_failed";
    case result_code::outcome_uncertain:
        return "outcome_uncertain";
    }
    return "malformed";
}

auto parse_session_operation(std::string_view value) -> std::optional<session_operation> {
    constexpr std::array operations{
        session_operation::status,
        session_operation::start,
        session_operation::stop,
        session_operation::interrupt,
        session_operation::resume,
        session_operation::shutdown
    };
    for (const auto op : operations) {
        if (to_string(op) == value) {
            return op;
        }
    }
    return std::nullopt;
}

auto valid_session_id(std::string_view value) -> bool {
    return value.starts_with("ns-") && lowercase_hex(value.substr(3), 32);
}

auto valid_epoch(std::string_view value) -> bool {
    return lowercase_hex(value, 32);
}

auto valid_generation(std::string_view value) -> bool {
    return lowercase_hex(value, 16);
}

auto valid_request_id(std::string_view value) -> bool {
    return lowercase_hex(value, 32);
}

auto valid_checkpoint_id(std::string_view value) -> bool {
    return lowercase_hex(value, 64);
}

auto format_generation(std::uint64_t counter) -> std::string {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string text(16, '0');
    for (std::size_t index = 0; index < 16; ++index) {
        text[15 - index] = digits[(counter >> (4U * index)) & 15U];
    }
    return text;
}

auto parse_generation(std::string_view value) -> std::optional<std::uint64_t> {
    if (!valid_generation(value)) {
        return std::nullopt;
    }
    std::uint64_t counter = 0;
    for (const auto byte : value) {
        counter = (counter << 4U) |
                  static_cast<std::uint64_t>(byte <= '9' ? byte - '0' : byte - 'a' + 10);
    }
    return counter;
}

native_session_model::native_session_model(std::string epoch) : epoch_{std::move(epoch)} {}

auto native_session_model::epoch() const -> const std::string& {
    return epoch_;
}

auto native_session_model::projection() const -> const session_projection& {
    return projection_;
}

auto native_session_model::operation_records() const -> std::size_t {
    return records_.size();
}

auto native_session_model::restore(session_projection durable) -> std::expected<void, std::string> {
    if (projection_.phase != session_phase::fresh || !records_.empty()) {
        return std::unexpected("native session projection can be restored only once");
    }
    if (durable.checkpoint && !valid_checkpoint_id(*durable.checkpoint)) {
        return std::unexpected("durable native checkpoint identity is malformed");
    }
    switch (durable.phase) {
    case session_phase::fresh:
    case session_phase::stopped:
    case session_phase::recovery_required:
        break;
    case session_phase::preparing:
    case session_phase::running:
    case session_phase::interrupting:
    case session_phase::stopping:
    case session_phase::finalizing:
        // An interrupted generation cannot be adopted or relaunched; its
        // ownership and effects are unresolved until explicitly reconciled.
        durable.phase = session_phase::recovery_required;
        durable.effects = effects_status::incomplete;
        if (durable.history == history_status::available) {
            durable.history = history_status::failed;
        }
        break;
    }
    projection_ = std::move(durable);
    return {};
}

auto native_session_model::reply(
    const operation_request& request, result_code code, bool final
) const -> operation_result {
    return {.op = request.op, .code = code, .final = final, .snapshot = projection_};
}

auto native_session_model::find(std::string_view request) -> record* {
    const auto found = std::ranges::find(records_, request, &record::request);
    return found == records_.end() ? nullptr : &*found;
}

auto native_session_model::submit(const operation_request& request) -> operation_result {
    if (request.epoch != epoch_) {
        return reply(request, result_code::stale_epoch, true);
    }
    if (!valid_request_id(request.request) || !valid_checkpoint_id(request.body_digest) ||
        (request.checkpoint && !valid_checkpoint_id(*request.checkpoint))) {
        return reply(request, result_code::malformed, true);
    }
    if (request.op == session_operation::status) {
        // Read-only: the current projection, never a historical mutation lookup.
        return reply(request, result_code::ok, true);
    }
    if ((request.op == session_operation::resume) != request.checkpoint.has_value()) {
        return reply(request, result_code::malformed, true);
    }
    if (auto* known = find(request.request); known != nullptr) {
        if (known->body_digest != request.body_digest || known->op != request.op) {
            return reply(request, result_code::request_conflict, true);
        }
        if (known->settled) {
            return *known->settled;
        }
        return reply(request, result_code::accepted, false);
    }
    if (request.generation != projection_.generation) {
        return reply(request, result_code::stale_generation, true);
    }
    const bool cancelling =
        request.op == session_operation::stop || request.op == session_operation::shutdown;
    if (records_.size() >=
        (cancelling ? max_operation_records_with_stops : max_operation_records)) {
        return reply(request, result_code::capacity, true);
    }
    const auto phase = projection_.phase;
    auto admit = [&](result_code code, bool final) {
        records_.push_back(
            {.request = request.request,
             .body_digest = request.body_digest,
             .generation = projection_.generation,
             .op = request.op,
             .settled = std::nullopt}
        );
        auto result = reply(request, code, final);
        if (final) {
            records_.back().settled = result;
        } else {
            pending_ = request.request;
        }
        return result;
    };
    switch (request.op) {
    case session_operation::start:
    case session_operation::resume:
        if (phase != session_phase::fresh && phase != session_phase::stopped) {
            return reply(request, result_code::invalid_state, true);
        }
        if (pending_) {
            return reply(request, result_code::invalid_state, true);
        }
        if (request.op == session_operation::resume &&
            (!projection_.checkpoint || *request.checkpoint != *projection_.checkpoint ||
             projection_.history != history_status::published)) {
            return reply(request, result_code::admission_failed, true);
        }
        if (projection_.generation == std::numeric_limits<std::uint64_t>::max()) {
            return reply(request, result_code::capacity, true);
        }
        ++projection_.generation;
        launched_ = false;
        projection_.phase = session_phase::preparing;
        projection_.history = history_status::absent;
        projection_.effects = effects_status::unassessed;
        return admit(result_code::accepted, false);
    case session_operation::stop:
        if (phase == session_phase::preparing || phase == session_phase::running ||
            phase == session_phase::interrupting) {
            // A stop during preparation is the explicit preparing -> stopping
            // edge. Any in-flight start/resume settles when the launch thread
            // reports how far preparation got; a stop never launches anything.
            projection_.phase = session_phase::stopping;
            auto result = admit(result_code::accepted, false);
            return result;
        }
        if (phase == session_phase::stopping) {
            return admit(result_code::accepted, false);
        }
        return reply(request, result_code::invalid_state, true);
    case session_operation::interrupt:
        if (phase != session_phase::running || pending_) {
            return reply(request, result_code::invalid_state, true);
        }
        projection_.phase = session_phase::interrupting;
        return admit(result_code::accepted, false);
    case session_operation::shutdown:
        if (phase != session_phase::fresh && phase != session_phase::stopped &&
            phase != session_phase::recovery_required) {
            return reply(request, result_code::invalid_state, true);
        }
        return admit(result_code::ok, true);
    case session_operation::status:
        break;
    }
    return reply(request, result_code::unsupported_operation, true);
}

auto native_session_model::settle(result_code code) -> std::optional<settled> {
    std::optional<settled> first;
    for (auto& item : records_) {
        if (item.settled) {
            continue;
        }
        item.settled =
            operation_result{.op = item.op, .code = code, .final = true, .snapshot = projection_};
        if (!first) {
            first = settled{.request = item.request, .result = *item.settled};
        }
    }
    pending_.reset();
    return first;
}

auto native_session_model::launched() -> std::expected<void, std::string> {
    if (projection_.phase == session_phase::preparing) {
        projection_.phase = session_phase::running;
    } else if (projection_.phase != session_phase::stopping || launched_) {
        return std::unexpected("launch reported outside preparation");
    }
    launched_ = true;
    // Start/resume settle once the owned generation exists; an accepted stop
    // during preparation stays pending until the process outcome is known.
    for (auto& item : records_) {
        if (!item.settled && starts_new_generation(item.op)) {
            item.settled = operation_result{
                .op = item.op, .code = result_code::ok, .final = true, .snapshot = projection_
            };
        }
    }
    const bool stop_pending = std::ranges::any_of(records_, [](const record& item) {
        return !item.settled && item.op == session_operation::stop;
    });
    if (!stop_pending) {
        pending_.reset();
    }
    return {};
}

auto native_session_model::prepare_cancelled()
    -> std::expected<std::optional<settled>, std::string> {
    if (launched_ || (projection_.phase != session_phase::preparing &&
                      projection_.phase != session_phase::stopping)) {
        return std::unexpected("preparation cancellation reported outside preparation");
    }
    projection_.phase = session_phase::stopped;
    projection_.history = history_status::absent;
    projection_.effects = effects_status::unassessed;
    return settle(result_code::ok);
}

auto native_session_model::prepare_failed() -> std::expected<std::optional<settled>, std::string> {
    if (launched_ || (projection_.phase != session_phase::preparing &&
                      projection_.phase != session_phase::stopping)) {
        return std::unexpected("preparation failure reported outside preparation");
    }
    projection_.phase = session_phase::stopped;
    projection_.history = history_status::absent;
    projection_.effects = effects_status::unassessed;
    std::optional<settled> first;
    for (auto& item : records_) {
        if (item.settled) {
            continue;
        }
        const auto code =
            starts_new_generation(item.op) ? result_code::admission_failed : result_code::ok;
        item.settled =
            operation_result{.op = item.op, .code = code, .final = true, .snapshot = projection_};
        if (!first) {
            first = settled{.request = item.request, .result = *item.settled};
        }
    }
    pending_.reset();
    return first;
}

auto native_session_model::interrupt_acknowledged()
    -> std::expected<std::optional<settled>, std::string> {
    if (projection_.phase != session_phase::interrupting) {
        return std::unexpected("interrupt acknowledgement outside interrupting");
    }
    projection_.phase = session_phase::running;
    return settle(result_code::ok);
}

auto native_session_model::interrupt_timed_out()
    -> std::expected<std::optional<settled>, std::string> {
    if (projection_.phase != session_phase::interrupting) {
        return std::unexpected("interrupt timeout outside interrupting");
    }
    // The owned process is still owned; only the interrupt observation failed.
    projection_.phase = session_phase::running;
    return settle(result_code::outcome_uncertain);
}

auto native_session_model::process_outcome_known() -> std::expected<void, std::string> {
    if (!launched_ || (projection_.phase != session_phase::running &&
                       projection_.phase != session_phase::interrupting &&
                       projection_.phase != session_phase::stopping)) {
        return std::unexpected("process outcome reported without an owned generation");
    }
    projection_.phase = session_phase::finalizing;
    return {};
}

auto native_session_model::process_outcome_uncertain()
    -> std::expected<std::optional<settled>, std::string> {
    if (!launched_ || (projection_.phase != session_phase::running &&
                       projection_.phase != session_phase::interrupting &&
                       projection_.phase != session_phase::stopping)) {
        return std::unexpected("uncertain outcome reported without an owned generation");
    }
    projection_.phase = session_phase::recovery_required;
    projection_.effects = effects_status::incomplete;
    if (projection_.history == history_status::available) {
        projection_.history = history_status::failed;
    }
    return settle(result_code::outcome_uncertain);
}

auto native_session_model::history_classified(history_status status, effects_status effects)
    -> std::expected<void, std::string> {
    if (projection_.phase != session_phase::finalizing) {
        return std::unexpected("history classification outside finalization");
    }
    if (status == history_status::published) {
        return std::unexpected("publication is reported by checkpoint_published");
    }
    projection_.history = status;
    projection_.effects = effects;
    return {};
}

auto native_session_model::checkpoint_published(std::string checkpoint)
    -> std::expected<std::optional<settled>, std::string> {
    if (projection_.phase != session_phase::finalizing ||
        projection_.history != history_status::available) {
        return std::unexpected("checkpoint published without available finalizing history");
    }
    if (!valid_checkpoint_id(checkpoint)) {
        return std::unexpected("published checkpoint identity is malformed");
    }
    projection_.phase = session_phase::stopped;
    projection_.history = history_status::published;
    projection_.checkpoint = std::move(checkpoint);
    return settle(result_code::ok);
}

auto native_session_model::checkpoint_failed()
    -> std::expected<std::optional<settled>, std::string> {
    if (projection_.phase != session_phase::finalizing) {
        return std::unexpected("checkpoint failure outside finalization");
    }
    // The previous checkpoint identity is retained; the generation's history
    // and effects are unresolved, so automatic resume is blocked.
    projection_.phase = session_phase::recovery_required;
    projection_.history = history_status::failed;
    projection_.effects = effects_status::incomplete;
    return settle(result_code::checkpoint_failed);
}

auto native_session_model::finalized_without_checkpoint()
    -> std::expected<std::optional<settled>, std::string> {
    if (projection_.phase != session_phase::finalizing) {
        return std::unexpected("finalization reported outside finalizing");
    }
    if (projection_.history == history_status::available ||
        projection_.history == history_status::published) {
        return std::unexpected("available history must be published, not discarded");
    }
    if (projection_.history == history_status::failed) {
        projection_.phase = session_phase::recovery_required;
        projection_.effects = effects_status::incomplete;
        return settle(result_code::checkpoint_failed);
    }
    projection_.phase = session_phase::stopped;
    return settle(result_code::ok);
}

} // namespace glove::run::detail
