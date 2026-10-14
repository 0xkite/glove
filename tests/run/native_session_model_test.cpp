#include "native_session_model.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using namespace glove::run::detail;

const std::string epoch_a(32, 'a');
const std::string epoch_b(32, 'b');
const std::string digest_1(64, '1');
const std::string digest_2(64, '2');
const std::string checkpoint_x(64, 'c');

auto request_id(char fill) -> std::string {
    return std::string(32, fill);
}

auto make(
    session_operation op,
    char id,
    std::uint64_t generation,
    std::string digest = digest_1,
    std::optional<std::string> checkpoint = std::nullopt
) -> operation_request {
    return {
        .epoch = epoch_a,
        .generation = generation,
        .request = request_id(id),
        .op = op,
        .checkpoint = std::move(checkpoint),
        .body_digest = std::move(digest)
    };
}

auto identity_grammar() -> int {
    REQUIRE(valid_session_id("ns-" + std::string(32, '0')));
    REQUIRE(!valid_session_id("ns-" + std::string(32, 'A')));
    REQUIRE(!valid_session_id("ns-" + std::string(31, '0')));
    REQUIRE(!valid_session_id(std::string(35, '0')));
    REQUIRE(valid_epoch(epoch_a) && !valid_epoch(epoch_a + "\n") && !valid_epoch("00"));
    REQUIRE(valid_generation(format_generation(1)) && format_generation(1).ends_with("01"));
    REQUIRE(format_generation(0xffffffffffffffffULL) == std::string(16, 'f'));
    REQUIRE(parse_generation("0000000000000010") == 16U);
    REQUIRE(!parse_generation("000000000000001"));
    REQUIRE(!parse_generation("000000000000001G"));
    REQUIRE(valid_checkpoint_id(checkpoint_x) && !valid_checkpoint_id(digest_1 + "0"));
    REQUIRE(parse_session_operation("status") == session_operation::status);
    REQUIRE(parse_session_operation("resume") == session_operation::resume);
    REQUIRE(!parse_session_operation("Status") && !parse_session_operation("signal"));
    REQUIRE(to_string(session_phase::fresh) == "new");
    REQUIRE(to_string(result_code::outcome_uncertain) == "outcome_uncertain");
    return 0;
}

auto full_generation_cycle() -> int {
    native_session_model model{epoch_a};
    REQUIRE(model.projection().phase == session_phase::fresh);
    // Status is read-only and records nothing in any phase.
    auto status = model.submit(make(session_operation::status, 'e', 999));
    REQUIRE(status.code == result_code::ok && status.final);
    REQUIRE(model.operation_records() == 0);

    auto started = model.submit(make(session_operation::start, '1', 0));
    REQUIRE(started.code == result_code::accepted && !started.final);
    REQUIRE(started.snapshot.phase == session_phase::preparing);
    REQUIRE(started.snapshot.generation == 1);
    REQUIRE(started.snapshot.history == history_status::absent);
    // Exact retry while preparing: accepted progress, not a second generation.
    auto retry = model.submit(make(session_operation::start, '1', 0));
    REQUIRE(retry.code == result_code::accepted && !retry.final);
    REQUIRE(model.projection().generation == 1);
    // Changed body with the same mutation ID conflicts without effects.
    auto conflict = model.submit(make(session_operation::start, '1', 0, digest_2));
    REQUIRE(conflict.code == result_code::request_conflict && conflict.final);
    // A second start while preparing is invalid even with the current generation.
    auto second = model.submit(make(session_operation::start, '2', 1));
    REQUIRE(second.code == result_code::invalid_state && second.final);
    REQUIRE(model.projection().generation == 1);

    REQUIRE(model.launched());
    REQUIRE(model.projection().phase == session_phase::running);
    auto settled_start = model.submit(make(session_operation::start, '1', 0));
    REQUIRE(settled_start.code == result_code::ok && settled_start.final);
    REQUIRE(settled_start.snapshot.phase == session_phase::running);

    // Stale observed generation for an unknown mutation refuses without effects.
    auto stale = model.submit(make(session_operation::stop, '3', 0));
    REQUIRE(stale.code == result_code::stale_generation && stale.final);
    REQUIRE(model.projection().phase == session_phase::running);
    // Status accepts a stale observation and resyncs.
    status = model.submit(make(session_operation::status, 'e', 0));
    REQUIRE(status.code == result_code::ok && status.snapshot.generation == 1);

    auto stopping = model.submit(make(session_operation::stop, '4', 1));
    REQUIRE(stopping.code == result_code::accepted && !stopping.final);
    REQUIRE(stopping.snapshot.phase == session_phase::stopping);
    auto repeated = model.submit(make(session_operation::stop, '4', 1));
    REQUIRE(repeated.code == result_code::accepted && !repeated.final);
    REQUIRE(model.operation_records() == 2);
    // A different stop request while stopping is accepted and settles together.
    auto another = model.submit(make(session_operation::stop, '5', 1));
    REQUIRE(another.code == result_code::accepted);
    // Resume while stopping is invalid.
    auto early_resume =
        model.submit(make(session_operation::resume, '6', 1, digest_1, checkpoint_x));
    REQUIRE(early_resume.code == result_code::invalid_state);

    REQUIRE(model.process_outcome_known());
    REQUIRE(model.projection().phase == session_phase::finalizing);
    status = model.submit(make(session_operation::status, 'e', 1));
    REQUIRE(status.final && status.snapshot.phase == session_phase::finalizing);
    REQUIRE(!model.checkpoint_published(checkpoint_x));
    REQUIRE(model.history_classified(history_status::available, effects_status::unassessed));
    REQUIRE(!model.finalized_without_checkpoint());
    auto published = model.checkpoint_published(checkpoint_x);
    REQUIRE(published && *published);
    REQUIRE((*published)->request == request_id('4'));
    REQUIRE((*published)->result.code == result_code::ok && (*published)->result.final);
    REQUIRE((*published)->result.snapshot.phase == session_phase::stopped);
    REQUIRE(model.projection().history == history_status::published);
    REQUIRE(model.projection().checkpoint == checkpoint_x);
    auto settled_stop = model.submit(make(session_operation::stop, '5', 1));
    REQUIRE(settled_stop.code == result_code::ok && settled_stop.final);
    REQUIRE(settled_stop.snapshot.phase == session_phase::stopped);
    // Stop in stopped is invalid; a replay of the old stop is the recorded snapshot.
    auto late_stop = model.submit(make(session_operation::stop, '7', 1));
    REQUIRE(late_stop.code == result_code::invalid_state);

    // Resume requires the exact published checkpoint.
    auto missing = model.submit(make(session_operation::resume, '8', 1));
    REQUIRE(missing.code == result_code::malformed);
    auto wrong = model.submit(make(session_operation::resume, '8', 1, digest_1, digest_2));
    REQUIRE(wrong.code == result_code::admission_failed);
    REQUIRE(model.projection().generation == 1);
    auto start_with_checkpoint =
        model.submit(make(session_operation::start, '9', 1, digest_1, checkpoint_x));
    REQUIRE(start_with_checkpoint.code == result_code::malformed);
    auto resumed = model.submit(make(session_operation::resume, 'a', 1, digest_1, checkpoint_x));
    REQUIRE(resumed.code == result_code::accepted && !resumed.final);
    REQUIRE(resumed.snapshot.generation == 2 && resumed.snapshot.phase == session_phase::preparing);
    REQUIRE(resumed.snapshot.history == history_status::absent);
    REQUIRE(resumed.snapshot.checkpoint == checkpoint_x);
    REQUIRE(model.launched());
    // Exact retry of the resume after generation increment within the same epoch
    // retrieves the settled result; it never launches again.
    auto resume_retry =
        model.submit(make(session_operation::resume, 'a', 1, digest_1, checkpoint_x));
    REQUIRE(resume_retry.code == result_code::ok && resume_retry.final);
    REQUIRE(resume_retry.snapshot.generation == 2);
    REQUIRE(model.projection().generation == 2);
    // An unknown mutation carrying the old generation is stale.
    auto stale_resume =
        model.submit(make(session_operation::resume, 'b', 1, digest_1, checkpoint_x));
    REQUIRE(stale_resume.code == result_code::stale_generation);
    return 0;
}

auto preparation_cancellation_edges() -> int {
    {
        // Stop during preparing: explicit preparing -> stopping edge; cancellation
        // before any launch effect settles both operations as stopped/absent.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        auto stop = model.submit(make(session_operation::stop, '2', 1));
        REQUIRE(
            stop.code == result_code::accepted && stop.snapshot.phase == session_phase::stopping
        );
        auto cancelled = model.prepare_cancelled();
        REQUIRE(cancelled && *cancelled);
        REQUIRE(model.projection().phase == session_phase::stopped);
        REQUIRE(model.projection().history == history_status::absent);
        REQUIRE(!model.projection().checkpoint);
        auto start_result = model.submit(make(session_operation::start, '1', 0));
        REQUIRE(start_result.final && start_result.code == result_code::ok);
        REQUIRE(start_result.snapshot.phase == session_phase::stopped);
        auto stop_result = model.submit(make(session_operation::stop, '2', 1));
        REQUIRE(stop_result.final && stop_result.code == result_code::ok);
        // Nothing was launched, so there is no checkpoint and resume is refused.
        auto resume = model.submit(make(session_operation::resume, '3', 1, digest_1, checkpoint_x));
        REQUIRE(resume.code == result_code::admission_failed);
        REQUIRE(model.submit(make(session_operation::start, '4', 1)).code == result_code::accepted);
        REQUIRE(model.projection().generation == 2);
    }
    {
        // Race: the stop lands after the launch thread passed its last check.
        // The process exists, stays owned, and finalizes through the stop path.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.submit(make(session_operation::stop, '2', 1)).code == result_code::accepted);
        REQUIRE(model.launched());
        REQUIRE(model.projection().phase == session_phase::stopping);
        auto start_result = model.submit(make(session_operation::start, '1', 0));
        REQUIRE(start_result.final && start_result.code == result_code::ok);
        REQUIRE(start_result.snapshot.phase == session_phase::stopping);
        REQUIRE(model.submit(make(session_operation::stop, '2', 1)).code == result_code::accepted);
        REQUIRE(!model.prepare_cancelled());
        REQUIRE(model.process_outcome_known());
        REQUIRE(model.history_classified(history_status::absent, effects_status::unassessed));
        auto finalized = model.finalized_without_checkpoint();
        REQUIRE(finalized && *finalized && (*finalized)->request == request_id('2'));
        REQUIRE(model.projection().phase == session_phase::stopped);
    }
    {
        // Preparation admission failure settles start as admission_failed.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        auto failed = model.prepare_failed();
        REQUIRE(failed && *failed);
        REQUIRE((*failed)->result.code == result_code::admission_failed);
        REQUIRE(model.projection().phase == session_phase::stopped);
        REQUIRE(model.projection().generation == 1);
        // The reserved counter is consumed, never reused.
        REQUIRE(model.submit(make(session_operation::start, '2', 1)).snapshot.generation == 2);
    }
    {
        // Cancellation without a stop request (owner-side cancel) is also terminal.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.prepare_cancelled());
        REQUIRE(model.projection().phase == session_phase::stopped);
    }
    return 0;
}

auto uncertainty_paths() -> int {
    {
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.launched());
        REQUIRE(model.submit(make(session_operation::stop, '2', 1)).code == result_code::accepted);
        auto uncertain = model.process_outcome_uncertain();
        REQUIRE(uncertain && *uncertain);
        REQUIRE((*uncertain)->result.code == result_code::outcome_uncertain);
        REQUIRE(model.projection().phase == session_phase::recovery_required);
        REQUIRE(model.projection().effects == effects_status::incomplete);
        // No automatic resume or start from recovery_required; shutdown is allowed.
        REQUIRE(
            model.submit(make(session_operation::start, '3', 1)).code == result_code::invalid_state
        );
        REQUIRE(
            model.submit(make(session_operation::resume, '4', 1, digest_1, checkpoint_x)).code ==
            result_code::invalid_state
        );
        REQUIRE(
            model.submit(make(session_operation::stop, '5', 1)).code == result_code::invalid_state
        );
        auto shutdown = model.submit(make(session_operation::shutdown, '6', 1));
        REQUIRE(shutdown.code == result_code::ok && shutdown.final);
    }
    {
        // Publication failure retains the prior checkpoint and blocks resume.
        native_session_model model{epoch_a};
        REQUIRE(model.restore(
            {.phase = session_phase::stopped,
             .generation = 3,
             .history = history_status::published,
             .effects = effects_status::unassessed,
             .checkpoint = checkpoint_x}
        ));
        REQUIRE(
            model.submit(make(session_operation::resume, '1', 3, digest_1, checkpoint_x)).code ==
            result_code::accepted
        );
        REQUIRE(model.launched());
        REQUIRE(model.submit(make(session_operation::stop, '2', 4)).code == result_code::accepted);
        REQUIRE(model.process_outcome_known());
        REQUIRE(model.history_classified(history_status::available, effects_status::unassessed));
        auto failed = model.checkpoint_failed();
        REQUIRE(failed && *failed && (*failed)->result.code == result_code::checkpoint_failed);
        REQUIRE(model.projection().phase == session_phase::recovery_required);
        REQUIRE(model.projection().history == history_status::failed);
        REQUIRE(model.projection().checkpoint == checkpoint_x);
        REQUIRE(
            model.submit(make(session_operation::resume, '3', 4, digest_1, checkpoint_x)).code ==
            result_code::invalid_state
        );
    }
    {
        // Invalid history finalizes as stopped without a new checkpoint; the
        // previous checkpoint identity is retained but not re-published.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.launched());
        REQUIRE(model.process_outcome_known());
        REQUIRE(!model.history_classified(history_status::published, effects_status::unassessed));
        REQUIRE(model.history_classified(history_status::invalid, effects_status::incomplete));
        auto finalized = model.finalized_without_checkpoint();
        REQUIRE(finalized && !*finalized);
        REQUIRE(model.projection().phase == session_phase::stopped);
        REQUIRE(model.projection().history == history_status::invalid);
        REQUIRE(!model.projection().checkpoint);
        REQUIRE(
            model.submit(make(session_operation::resume, '2', 1, digest_1, checkpoint_x)).code ==
            result_code::admission_failed
        );
    }
    {
        // Failed history copy during finalization is recovery_required.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.launched());
        REQUIRE(model.process_outcome_known());
        REQUIRE(model.history_classified(history_status::failed, effects_status::incomplete));
        auto finalized = model.finalized_without_checkpoint();
        REQUIRE(finalized);
        REQUIRE(model.projection().phase == session_phase::recovery_required);
    }
    return 0;
}

auto interrupt_paths() -> int {
    native_session_model model{epoch_a};
    REQUIRE(
        model.submit(make(session_operation::interrupt, '0', 0)).code == result_code::invalid_state
    );
    REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
    REQUIRE(
        model.submit(make(session_operation::interrupt, '2', 1)).code == result_code::invalid_state
    );
    REQUIRE(model.launched());
    auto interrupting = model.submit(make(session_operation::interrupt, '3', 1));
    REQUIRE(interrupting.code == result_code::accepted);
    REQUIRE(model.projection().phase == session_phase::interrupting);
    auto timed_out = model.interrupt_timed_out();
    REQUIRE(timed_out && *timed_out && (*timed_out)->result.code == result_code::outcome_uncertain);
    REQUIRE(model.projection().phase == session_phase::running);
    auto again = model.submit(make(session_operation::interrupt, '4', 1));
    REQUIRE(again.code == result_code::accepted);
    auto acknowledged = model.interrupt_acknowledged();
    REQUIRE(acknowledged && *acknowledged && (*acknowledged)->result.code == result_code::ok);
    REQUIRE(model.projection().phase == session_phase::running);
    // Stop while interrupting is allowed.
    REQUIRE(model.submit(make(session_operation::interrupt, '5', 1)).code == result_code::accepted);
    REQUIRE(model.submit(make(session_operation::stop, '6', 1)).code == result_code::accepted);
    REQUIRE(model.projection().phase == session_phase::stopping);
    return 0;
}

auto epoch_and_capacity() -> int {
    {
        native_session_model model{epoch_a};
        auto stale = model.submit(
            {.epoch = epoch_b,
             .generation = 0,
             .request = request_id('1'),
             .op = session_operation::start,
             .checkpoint = std::nullopt,
             .body_digest = digest_1}
        );
        REQUIRE(stale.code == result_code::stale_epoch && stale.final);
        REQUIRE(model.operation_records() == 0 && model.projection().generation == 0);
        auto malformed = model.submit(make(session_operation::start, '1', 0, "short"));
        REQUIRE(malformed.code == result_code::malformed && model.operation_records() == 0);
        REQUIRE(model.restore(
            {.phase = session_phase::stopped,
             .generation = 0,
             .history = history_status::absent,
             .effects = effects_status::unassessed,
             .checkpoint = std::nullopt}
        ));
    }
    {
        // 64 settled records are retained as replay evidence; the 65th mutation
        // refuses with capacity instead of evicting dedup evidence.
        native_session_model model{epoch_a};
        REQUIRE(model.submit(make(session_operation::start, '1', 0)).code == result_code::accepted);
        REQUIRE(model.launched());
        for (std::size_t index = 1; index < max_operation_records; ++index) {
            auto request = make(session_operation::interrupt, '0', 1);
            request.request = std::string(24, '0') + std::to_string(10000000 + index).substr(0, 8);
            REQUIRE(model.submit(request).code == result_code::accepted);
            REQUIRE(model.interrupt_acknowledged());
        }
        REQUIRE(model.operation_records() == max_operation_records);
        auto overflow = model.submit(make(session_operation::interrupt, '9', 1));
        REQUIRE(overflow.code == result_code::capacity && overflow.final);
        REQUIRE(model.projection().phase == session_phase::running);
        // Stop stays admissible past the cap, within its own hard bound.
        auto stop = model.submit(make(session_operation::stop, '8', 1));
        REQUIRE(stop.code == result_code::accepted);
        REQUIRE(model.projection().phase == session_phase::stopping);
        for (std::size_t extra = 1;
             extra < max_operation_records_with_stops - max_operation_records;
             ++extra) {
            auto request = make(session_operation::stop, '0', 1);
            request.request = std::string(24, '1') + std::to_string(20000000 + extra).substr(0, 8);
            REQUIRE(model.submit(request).code == result_code::accepted);
        }
        auto exhausted = make(session_operation::stop, '0', 1);
        exhausted.request = std::string(24, '2') + "00000001";
        REQUIRE(model.submit(exhausted).code == result_code::capacity);
        auto replay = model.submit(make(session_operation::start, '1', 0));
        REQUIRE(replay.code == result_code::ok && replay.final);
    }
    {
        // Restoring an interrupted durable record never relaunches.
        native_session_model model{epoch_b};
        REQUIRE(model.restore(
            {.phase = session_phase::running,
             .generation = 7,
             .history = history_status::available,
             .effects = effects_status::unassessed,
             .checkpoint = std::nullopt}
        ));
        REQUIRE(model.projection().phase == session_phase::recovery_required);
        REQUIRE(model.projection().history == history_status::failed);
        REQUIRE(model.projection().effects == effects_status::incomplete);
        REQUIRE(model.projection().generation == 7);
        REQUIRE(!model.restore(
            {.phase = session_phase::stopped,
             .generation = 0,
             .history = history_status::absent,
             .effects = effects_status::unassessed,
             .checkpoint = std::nullopt}
        ));
        REQUIRE(!model.launched() && !model.process_outcome_known());
        REQUIRE(!model.prepare_cancelled() && !model.checkpoint_failed());
    }
    {
        native_session_model model{epoch_b};
        REQUIRE(!model.restore(
            {.phase = session_phase::stopped,
             .generation = 0,
             .history = history_status::absent,
             .effects = effects_status::unassessed,
             .checkpoint = "bad"}
        ));
    }
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(identity_grammar() == 0);
    REQUIRE(full_generation_cycle() == 0);
    REQUIRE(preparation_cancellation_edges() == 0);
    REQUIRE(uncertainty_paths() == 0);
    REQUIRE(interrupt_paths() == 0);
    REQUIRE(epoch_and_capacity() == 0);
    return 0;
}
