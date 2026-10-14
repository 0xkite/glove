#include "native_session_fixture.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <thread>

namespace {

#define REQUIRE_CREATED(created)                                                                   \
    do {                                                                                           \
        if (!(created)) {                                                                          \
            std::fprintf(stderr, "create failed: %s @ %d\n", (created).error().c_str(), __LINE__); \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using namespace glove::run::detail;
using namespace glove::run::test_support;
using namespace std::chrono_literals;

struct temporary_directory {
    fs::path path;

    temporary_directory() {
        char pattern[] = "/tmp/gsv-XXXXXX";
        if (const auto* created = ::mkdtemp(pattern)) {
            std::error_code error;
            path = fs::canonical(created, error);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        if (!path.empty()) {
            std::error_code error;
            for (const auto& entry : fs::recursive_directory_iterator(path, error)) {
                if (fs::is_directory(entry.symlink_status(error))) {
                    fs::permissions(
                        entry.path(), fs::perms::owner_write, fs::perm_options::add, error
                    );
                }
            }
            fs::remove_all(path, error);
        }
    }
};

unsigned request_counter = 0;

auto next_request() -> std::string {
    char buffer[40];
    std::snprintf(buffer, sizeof(buffer), "%032x", ++request_counter);
    return buffer;
}

// Host-local control through the real management transport, one request each.
auto control(
    const native_session_supervisor& supervisor,
    session_operation op,
    std::uint64_t observed,
    std::optional<std::string> checkpoint = std::nullopt,
    std::string request = {}
) -> std::expected<management_result, management_client_failure> {
    if (request.empty()) {
        request = next_request();
    }
    return management_request_once(
        supervisor.control_directory(),
        supervisor.snapshot().session,
        {.observed_generation = observed,
         .request = request,
         .op = op,
         .checkpoint = std::move(checkpoint),
         .body_digest = {}}
    );
}

// Terminal phases are observed only once the synchronous generation call has
// fully returned (publication, quiescent marker and cleanup included).
auto phase_is(session_phase phase) {
    return [phase](const supervisor_snapshot& snapshot) {
        const bool terminal =
            phase == session_phase::stopped || phase == session_phase::recovery_required;
        return snapshot.projection.phase == phase && (!terminal || !snapshot.generation_active);
    };
}

// A missed phase reports the supervisor's own last error alongside the
// settled snapshot, so a remote failure carries more than the timeout.
template<typename Supervisor>
auto reached(Supervisor& supervisor, session_phase phase, std::chrono::seconds wait) -> bool {
    if (supervisor.wait_for(phase_is(phase), wait)) {
        return true;
    }
    const auto snapshot = supervisor.snapshot();
    std::fprintf(
        stderr,
        "phase %d not reached: phase=%d generation_active=%d last_error=%s\n",
        static_cast<int>(phase),
        static_cast<int>(snapshot.projection.phase),
        snapshot.generation_active ? 1 : 0,
        snapshot.last_error ? snapshot.last_error->c_str() : "(none)"
    );
    return false;
}

auto kinds(const std::vector<journal_event>& events) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& event : events) {
        out.push_back(event.kind + (event.op.empty() ? "" : ":" + event.op));
    }
    return out;
}

auto index_of(const std::vector<std::string>& items, std::string_view value, std::size_t from = 0)
    -> std::size_t {
    for (std::size_t index = from; index < items.size(); ++index) {
        if (items[index] == value) {
            return index;
        }
    }
    return items.size();
}

class running_supervisor {
public:
    explicit running_supervisor(native_session_supervisor& supervisor) : supervisor_{supervisor} {
        thread_ = std::thread([this] { result_ = supervisor_.run(); });
    }

    running_supervisor(const running_supervisor&) = delete;
    auto operator=(const running_supervisor&) -> running_supervisor& = delete;

    ~running_supervisor() {
        if (thread_.joinable()) {
            // A failed assertion must not hang the test: cancel any owned
            // generation, wait for it to settle, then request shutdown
            // through the same admission path and join.
            const auto submit = [&](session_operation op) {
                const auto snapshot = supervisor_.snapshot();
                return supervisor_.submit(
                    {.observed_generation = snapshot.projection.generation,
                     .request = next_request(),
                     .op = op,
                     .checkpoint = std::nullopt,
                     .body_digest = std::string(64, '0')}
                );
            };
            if (submit(session_operation::shutdown).code != result_code::ok) {
                (void)submit(session_operation::stop);
                (void)supervisor_.wait_for(
                    [](const supervisor_snapshot& snapshot) { return !snapshot.generation_active; },
                    std::chrono::seconds{60}
                );
                (void)submit(session_operation::shutdown);
            }
            thread_.join();
        }
    }

    auto join() -> std::expected<std::uint64_t, std::string> {
        if (thread_.joinable()) {
            thread_.join();
        }
        return result_;
    }

private:
    native_session_supervisor& supervisor_;
    std::thread thread_;
    std::expected<std::uint64_t, std::string> result_;
};

auto full_sleep_wake_cycle(const fs::path& root) -> int {
    supervisor_fixture f{root / "cycle"};
    REQUIRE(f.prepare());
    auto created = native_session_supervisor::create(f.options(), f.harness);
    REQUIRE_CREATED(created);
    auto& supervisor = **created;
    const auto session = supervisor.snapshot().session;
    const auto epoch = supervisor.snapshot().epoch;
    REQUIRE(valid_session_id(session) && valid_epoch(epoch));
    REQUIRE(supervisor.snapshot().projection.phase == session_phase::fresh);
    running_supervisor runner{supervisor};

    // Status before any generation: read-only, final, no effects.
    auto idle = control(supervisor, session_operation::status, 0);
    REQUIRE(
        idle && idle->code == result_code::ok && idle->final && idle->state == session_phase::fresh
    );
    REQUIRE(idle->epoch == epoch && idle->generation == 0 && !idle->checkpoint);
    // Resume with no checkpoint, stop with nothing running: refused without effects.
    REQUIRE(
        control(supervisor, session_operation::resume, 0, std::string(64, 'c'))->code ==
        result_code::admission_failed
    );
    REQUIRE(control(supervisor, session_operation::stop, 0)->code == result_code::invalid_state);
    REQUIRE(
        control(supervisor, session_operation::interrupt, 0)->code ==
        result_code::unsupported_operation
    );
    REQUIRE(f.harness.observed.births == 0);

    // Start: accepted, then running with one owned worker birth.
    const auto start_id = next_request();
    auto started = control(supervisor, session_operation::start, 0, std::nullopt, start_id);
    REQUIRE(started && started->code == result_code::accepted && !started->final);
    REQUIRE(started->state == session_phase::preparing && started->generation == 1);
    REQUIRE(reached(supervisor, session_phase::running, 60s));
    REQUIRE(f.harness.wait_running(10s));
    REQUIRE(f.harness.observed.births == 1);
    REQUIRE(f.harness.observed.argv.size() > 3 && f.harness.observed.argv[1] == "--bare");
    REQUIRE(!f.harness.observed.resumed);
    REQUIRE(f.harness.observed.nonce.starts_with("glove-session-"));
    REQUIRE(f.harness.observed.base_url == "http://127.0.0.1:40000/anthropic");
    const auto first_nonce = f.harness.observed.nonce;
    const auto first_config = f.harness.observed.config_dir;
    REQUIRE(f.run_count() == 1);
    REQUIRE(
        read_file(f.runs() / fs::path{first_config}.parent_path().filename() / ".glove-pi-lease")
            .ends_with("\nlaunching\n")
    );
    // The settled start is retrievable by exact replay.
    auto replay = control(supervisor, session_operation::start, 0, std::nullopt, start_id);
    REQUIRE(
        replay && replay->code == result_code::ok && replay->final &&
        replay->state == session_phase::running
    );

    // Detach/wake analogue: repeated frontend reconnection (fresh authenticated
    // status) preserves the same epoch/generation and never launches again.
    for (int attempt = 0; attempt < 5; ++attempt) {
        auto status = control(supervisor, session_operation::status, 0);
        REQUIRE(status && status->state == session_phase::running && status->generation == 1);
        REQUIRE(status->epoch == epoch && status->history == history_status::absent);
    }
    REQUIRE(f.harness.observed.births == 1 && f.run_count() == 1);
    REQUIRE(control(supervisor, session_operation::start, 1)->code == result_code::invalid_state);
    REQUIRE(
        control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
        result_code::invalid_state
    );

    // Lost control reply: the stop body is sent twice; one cancellation only.
    const auto stop_id = next_request();
    auto body = render_management_request(
        session, epoch, 1, stop_id, session_operation::stop, std::nullopt
    );
    REQUIRE(body);
    auto stopping = management_request_raw(supervisor.control_directory(), session, *body);
    REQUIRE(stopping && stopping->code == result_code::accepted && !stopping->final);
    REQUIRE(
        stopping->state == session_phase::stopping ||
        stopping->state == session_phase::finalizing || stopping->state == session_phase::stopped
    );
    REQUIRE(reached(supervisor, session_phase::stopped, 60s));
    auto again = management_request_raw(supervisor.control_directory(), session, *body);
    REQUIRE(
        again && again->code == result_code::ok && again->final &&
        again->state == session_phase::stopped
    );
    REQUIRE(f.harness.observed.births == 1 && f.harness.observed.stop_seen);
    const auto snapshot = supervisor.snapshot();
    REQUIRE(snapshot.projection.history == history_status::published);
    REQUIRE(snapshot.projection.checkpoint && valid_checkpoint_id(*snapshot.projection.checkpoint));
    REQUIRE(snapshot.projection.generation == 1 && snapshot.launches == 1);
    const auto first_checkpoint = *snapshot.projection.checkpoint;
    // Publication happened BEFORE disposable cleanup: endpoint revoked first,
    // then outcome_known, checkpoint_published, finalized; run dir removed last.
    const auto order = kinds(supervisor.journal());
    const auto launched = index_of(order, "launched");
    const auto stop_intent = index_of(order, "intent:stop");
    const auto known = index_of(order, "outcome_known");
    const auto published = index_of(order, "checkpoint_published");
    REQUIRE(launched < stop_intent && stop_intent < known && known < published);
    REQUIRE(f.harness.revocations.size() == 1 && f.harness.revocations.front() == first_nonce);
    REQUIRE(f.run_count() == 0);
    const auto checkpoint_history =
        read_file(supervisor.session_root() / "checkpoints" / first_checkpoint / "history.jsonl");
    REQUIRE(checkpoint_history.find("\"type\":\"assistant\"") != std::string::npos);
    REQUIRE(std::count(checkpoint_history.begin(), checkpoint_history.end(), '\n') == 2);

    // Wake: explicit resume of the exact checkpoint in a fresh generation.
    f.harness.reset_barriers();
    REQUIRE(
        control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
        result_code::admission_failed
    );
    REQUIRE(control(supervisor, session_operation::resume, 1)->code == result_code::malformed);
    REQUIRE(
        control(supervisor, session_operation::resume, 0, first_checkpoint)->code ==
        result_code::stale_generation
    );
    const auto resume_id = next_request();
    auto resumed = control(supervisor, session_operation::resume, 1, first_checkpoint, resume_id);
    REQUIRE(resumed && resumed->code == result_code::accepted && resumed->generation == 2);
    REQUIRE(reached(supervisor, session_phase::running, 60s));
    REQUIRE(f.harness.wait_running(10s));
    REQUIRE(f.harness.observed.births == 2 && f.harness.observed.resumed);
    REQUIRE(
        f.harness.observed.nonce != first_nonce && f.harness.observed.config_dir != first_config
    );
    REQUIRE(f.harness.observed.materialized == checkpoint_history);
    REQUIRE(
        std::ranges::find(f.harness.observed.argv, std::string{fixture_conversation}) !=
        f.harness.observed.argv.end()
    );
    REQUIRE(
        std::ranges::find(f.harness.observed.argv, "--session-id") == f.harness.observed.argv.end()
    );
    // Exact resume retry after the generation moved: settled snapshot, no relaunch.
    auto resume_replay =
        control(supervisor, session_operation::resume, 1, first_checkpoint, resume_id);
    REQUIRE(resume_replay && resume_replay->code == result_code::ok && resume_replay->final);
    REQUIRE(resume_replay->generation == 2 && f.harness.observed.births == 2);
    auto stale_mutation = control(supervisor, session_operation::stop, 1);
    REQUIRE(stale_mutation && stale_mutation->code == result_code::stale_generation);
    REQUIRE(control(supervisor, session_operation::stop, 2)->code == result_code::accepted);
    REQUIRE(reached(supervisor, session_phase::stopped, 60s));
    const auto second = supervisor.snapshot();
    REQUIRE(second.projection.checkpoint && *second.projection.checkpoint != first_checkpoint);
    const auto second_history = read_file(
        supervisor.session_root() / "checkpoints" / *second.projection.checkpoint / "history.jsonl"
    );
    REQUIRE(second_history.starts_with(checkpoint_history));
    REQUIRE(std::count(second_history.begin(), second_history.end(), '\n') == 4);
    REQUIRE(f.harness.revocations.size() == 2 && f.run_count() == 0);

    // Shutdown ends the loop; the listener and capability are removed.
    auto shutdown = control(supervisor, session_operation::shutdown, 2);
    if (!shutdown || shutdown->code != result_code::ok) {
        std::fprintf(
            stderr,
            "shutdown: %s state=%s gen=%llu\n",
            shutdown ? std::string{to_string(shutdown->code)}.c_str()
                     : shutdown.error().message.c_str(),
            shutdown ? std::string{to_string(shutdown->state)}.c_str() : "-",
            shutdown ? static_cast<unsigned long long>(shutdown->generation) : 0ULL
        );
        for (const auto& line : f.log) {
            std::fprintf(stderr, "log: %s\n", line.c_str());
        }
    }
    REQUIRE(shutdown && shutdown->code == result_code::ok);
    auto generations = runner.join();
    REQUIRE(generations && *generations == 2);
    const auto control_path = supervisor.control_directory();
    REQUIRE(control(supervisor, session_operation::status, 2)->state == session_phase::stopped);
    // After shutdown nothing can be reserved that no loop would run.
    REQUIRE(control(supervisor, session_operation::start, 2)->code == result_code::invalid_state);
    REQUIRE(
        control(supervisor, session_operation::resume, 2, *second.projection.checkpoint)->code ==
        result_code::invalid_state
    );
    REQUIRE(supervisor.snapshot().projection.generation == 2);
    // A later supervisor epoch reopens the same session, reconstructs the
    // durable projection, and the old epoch's capability no longer authenticates.
    created->reset();
    REQUIRE(!fs::exists(control_path / "s") && !fs::exists(control_path / "cap"));
    auto reopened = native_session_supervisor::create(f.options(session), f.harness);
    REQUIRE(reopened);
    const auto restored = (*reopened)->snapshot();
    REQUIRE(restored.epoch != epoch && restored.projection.phase == session_phase::stopped);
    REQUIRE(
        restored.projection.generation == 2 &&
        restored.projection.checkpoint == second.projection.checkpoint
    );
    auto new_status = control(**reopened, session_operation::status, 0);
    REQUIRE(new_status && new_status->epoch == restored.epoch);
    // Replaying an old-epoch mutation body is not a lookup under the new epoch.
    auto old_body = management_request_raw((*reopened)->control_directory(), session, *body);
    REQUIRE(!old_body);
    running_supervisor second_runner{**reopened};
    REQUIRE(control(**reopened, session_operation::shutdown, 2)->code == result_code::ok);
    REQUIRE(second_runner.join());
    return 0;
}

auto preparation_cancellation(const fs::path& root) -> int {
    supervisor_fixture f{root / "prepare-cancel"};
    REQUIRE(f.prepare());
    f.harness.script.block_admission = true;
    auto created = native_session_supervisor::create(f.options(), f.harness);
    REQUIRE_CREATED(created);
    auto& supervisor = **created;
    running_supervisor runner{supervisor};
    REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
    REQUIRE(f.harness.wait_admission_blocked(10s));
    // Stop during preparation: explicit preparing -> stopping edge.
    auto stop = control(supervisor, session_operation::stop, 1);
    REQUIRE(stop && stop->code == result_code::accepted && stop->state == session_phase::stopping);
    f.harness.release();
    REQUIRE(reached(supervisor, session_phase::stopped, 60s));
    REQUIRE(f.harness.observed.births == 0 && f.run_count() == 0);
    REQUIRE(f.harness.revocations.empty());
    const auto order = kinds(supervisor.journal());
    REQUIRE(index_of(order, "prepare_cancelled") < order.size());
    REQUIRE(index_of(order, "launched") == order.size());
    REQUIRE(supervisor.snapshot().projection.history == history_status::absent);
    REQUIRE(!supervisor.snapshot().projection.checkpoint);
    // A fresh start afterwards reserves generation 2.
    f.harness.script.block_admission = false;
    f.harness.reset_barriers();
    auto restart = control(supervisor, session_operation::start, 1);
    REQUIRE(restart && restart->code == result_code::accepted && restart->generation == 2);
    REQUIRE(reached(supervisor, session_phase::running, 60s));
    REQUIRE(control(supervisor, session_operation::stop, 2)->code == result_code::accepted);
    REQUIRE(reached(supervisor, session_phase::stopped, 60s));
    REQUIRE(control(supervisor, session_operation::shutdown, 2)->code == result_code::ok);
    REQUIRE(runner.join());
    return 0;
}

auto persistence_and_uncertainty(const fs::path& root) -> int {
    {
        // Injected publication faults retain the prior checkpoint, mark the
        // generation uncertain, and keep the private run.
        supervisor_fixture f{root / "publish-fault"};
        REQUIRE(f.prepare());
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        running_supervisor runner{supervisor};
        REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        REQUIRE(control(supervisor, session_operation::stop, 1)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::stopped, 60s));
        const auto prior = supervisor.snapshot().projection.checkpoint;
        REQUIRE(prior);
        f.harness.reset_barriers();
        REQUIRE(
            control(supervisor, session_operation::resume, 1, *prior)->code == result_code::accepted
        );
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        supervisor.inject_store_fault(store_fault::history_fsync);
        auto stop = control(supervisor, session_operation::stop, 2);
        REQUIRE(stop && stop->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::recovery_required, 60s));
        const auto snapshot = supervisor.snapshot();
        REQUIRE(snapshot.projection.history == history_status::failed);
        REQUIRE(snapshot.projection.effects == effects_status::incomplete);
        REQUIRE(snapshot.projection.checkpoint == prior);
        REQUIRE(f.run_count() == 1);
        auto settled = control(supervisor, session_operation::stop, 2, std::nullopt, stop->request);
        REQUIRE(settled && settled->code == result_code::checkpoint_failed && settled->final);
        REQUIRE(
            control(supervisor, session_operation::resume, 2, *prior)->code ==
            result_code::invalid_state
        );
        REQUIRE(
            control(supervisor, session_operation::start, 2)->code == result_code::invalid_state
        );
        const auto order = kinds(supervisor.journal());
        REQUIRE(index_of(order, "checkpoint_failed") < order.size());
        REQUIRE(control(supervisor, session_operation::shutdown, 2)->code == result_code::ok);
        REQUIRE(runner.join());
        // Reopening keeps recovery_required and refuses automatic resume; the
        // retained run directory is not swept.
        const auto session = snapshot.session;
        created->reset();
        auto reopened = native_session_supervisor::create(f.options(session), f.harness);
        REQUIRE(reopened);
        REQUIRE((*reopened)->snapshot().projection.phase == session_phase::recovery_required);
        REQUIRE((*reopened)->snapshot().projection.checkpoint == prior);
        REQUIRE(f.run_count() == 1);
        running_supervisor second{**reopened};
        REQUIRE(
            control(**reopened, session_operation::resume, 2, *prior)->code ==
            result_code::invalid_state
        );
        REQUIRE(control(**reopened, session_operation::shutdown, 2)->code == result_code::ok);
        REQUIRE(second.join());
    }
    {
        // Journal append fault on the checkpoint record also retains uncertainty.
        supervisor_fixture f{root / "journal-fault"};
        REQUIRE(f.prepare());
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        running_supervisor runner{supervisor};
        REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        supervisor.inject_store_fault(store_fault::journal_append);
        REQUIRE(control(supervisor, session_operation::stop, 1)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::recovery_required, 60s));
        REQUIRE(!supervisor.snapshot().projection.checkpoint);
        REQUIRE(f.run_count() == 1);
        REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
        REQUIRE(runner.join());
    }
    {
        // Uncertain process outcome: no PID guess, generation retained.
        supervisor_fixture f{root / "uncertain"};
        REQUIRE(f.prepare());
        f.harness.script.fail_outcome = true;
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        running_supervisor runner{supervisor};
        REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        auto stop = control(supervisor, session_operation::stop, 1);
        REQUIRE(stop && stop->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::recovery_required, 60s));
        auto settled = control(supervisor, session_operation::stop, 1, std::nullopt, stop->request);
        REQUIRE(settled && settled->code == result_code::outcome_uncertain);
        REQUIRE(supervisor.snapshot().projection.effects == effects_status::incomplete);
        REQUIRE(!supervisor.snapshot().projection.checkpoint);
        REQUIRE(f.run_count() == 1);
        REQUIRE(read_file(
                    f.runs() / fs::path{f.harness.observed.config_dir}.parent_path().filename() /
                    ".glove-pi-lease"
        )
                    .ends_with("\nlaunching\n"));
        REQUIRE(f.harness.revocations.size() == 1);
        REQUIRE(
            control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
            result_code::invalid_state
        );
        REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
        REQUIRE(runner.join());
    }
    return 0;
}

auto history_classification(const fs::path& root) -> int {
    const struct {
        const char* name;
        history_mode mode;
        history_status expected;
    } cases[]{
        {"missing", history_mode::none, history_status::absent},
        {"invalid", history_mode::invalid, history_status::invalid},
        {"foreign", history_mode::foreign_session, history_status::invalid},
        {"partial", history_mode::user_only, history_status::invalid},
    };

    for (const auto& item : cases) {
        supervisor_fixture f{root / item.name};
        REQUIRE(f.prepare());
        f.harness.script.history = item.mode;
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        running_supervisor runner{supervisor};
        REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        REQUIRE(control(supervisor, session_operation::stop, 1)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::stopped, 60s));
        const auto snapshot = supervisor.snapshot();
        REQUIRE(snapshot.projection.history == item.expected);
        REQUIRE(!snapshot.projection.checkpoint);
        // No usable checkpoint: resume is refused and no new conversation is
        // silently substituted. Disposable state is cleaned (outcome was known).
        REQUIRE(
            control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
            result_code::admission_failed
        );
        REQUIRE(f.run_count() == 0);
        REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
        REQUIRE(runner.join());
    }
    return 0;
}

auto corrupted_checkpoint_and_unknown_ownership(const fs::path& root) -> int {
    {
        supervisor_fixture f{root / "corrupt"};
        REQUIRE(f.prepare());
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        running_supervisor runner{supervisor};
        REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::running, 60s));
        REQUIRE(control(supervisor, session_operation::stop, 1)->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::stopped, 60s));
        const auto checkpoint = *supervisor.snapshot().projection.checkpoint;
        const auto directory = supervisor.session_root() / "checkpoints" / checkpoint;
        // Corrupt the stored history bytes; resume must refuse before any effect.
        REQUIRE(::chmod(directory.c_str(), 0700) == 0);
        REQUIRE(::chmod((directory / "history.jsonl").c_str(), 0600) == 0);
        REQUIRE(write_file(directory / "history.jsonl", "{\"type\":\"user\"}\n", 0400));
        REQUIRE(::chmod(directory.c_str(), 0500) == 0);
        f.harness.reset_barriers();
        auto resume = control(supervisor, session_operation::resume, 1, checkpoint);
        REQUIRE(resume && resume->code == result_code::accepted);
        REQUIRE(reached(supervisor, session_phase::stopped, 60s));
        auto settled =
            control(supervisor, session_operation::resume, 1, checkpoint, resume->request);
        REQUIRE(settled && settled->code == result_code::admission_failed && settled->final);
        REQUIRE(f.harness.observed.births == 1 && f.harness.revocations.size() == 1);
        REQUIRE(f.run_count() == 0);
        REQUIRE(supervisor.snapshot().projection.generation == 2);
        const auto order = kinds(supervisor.journal());
        REQUIRE(index_of(order, "prepare_failed") < order.size());
        REQUIRE(control(supervisor, session_operation::shutdown, 2)->code == result_code::ok);
        REQUIRE(runner.join());
    }
    {
        // Unknown ownership: a durable record says a generation was launched
        // and never resolved. Nothing is adopted, relaunched or swept.
        supervisor_fixture f{root / "unknown-owner"};
        REQUIRE(f.prepare());
        auto id = mint_session_id();
        REQUIRE(id);
        auto digest = native_startup_policy_digest(
            f.harness.policy(), glove::net::endpoint_provider::anthropic, std::string{fixture_model}
        );
        REQUIRE(digest);
        {
            auto store = native_session_store::create(
                f.root / "sessions",
                {.session = *id,
                 .runtime_id = "claude",
                 .harness_id = "claude",
                 .runtime_digest = std::string(64, 'd'),
                 .history_format = std::string{claude_history_format},
                 .workspace = f.workspace().string(),
                 .policy_digest = *digest,
                 .conversation_id = std::string{fixture_conversation}}
            );
            REQUIRE(store);
            journal_event intent{
                .seq = 0,
                .kind = "intent",
                .epoch = std::string(32, '1'),
                .generation = 1,
                .request = std::string(32, '2'),
                .body_digest = std::string(64, '3'),
                .op = "start",
                .code = {},
                .checkpoint = {},
                .detail = {}
            };
            REQUIRE(store->append(intent));
            REQUIRE(store->append(
                {.seq = 0,
                 .kind = "launched",
                 .epoch = std::string(32, '1'),
                 .generation = 1,
                 .request = {},
                 .body_digest = {},
                 .op = {},
                 .code = {},
                 .checkpoint = {},
                 .detail = {}}
            ));
        }
        REQUIRE(private_directory(f.runs() / ("run-" + std::string(48, 'a'))));
        REQUIRE(write_file(f.runs() / ("run-" + std::string(48, 'a')) / "marker", "retained"));
        auto created = native_session_supervisor::create(f.options(*id), f.harness);
        REQUIRE_CREATED(created);
        auto& supervisor = **created;
        REQUIRE(supervisor.snapshot().projection.phase == session_phase::recovery_required);
        REQUIRE(supervisor.snapshot().projection.effects == effects_status::incomplete);
        running_supervisor runner{supervisor};
        auto status = control(supervisor, session_operation::status, 0);
        REQUIRE(
            status && status->state == session_phase::recovery_required && status->generation == 1
        );
        REQUIRE(
            control(supervisor, session_operation::start, 1)->code == result_code::invalid_state
        );
        REQUIRE(
            control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
            result_code::invalid_state
        );
        REQUIRE(
            control(supervisor, session_operation::stop, 1)->code == result_code::invalid_state
        );
        REQUIRE(f.harness.observed.births == 0);
        REQUIRE(fs::exists(f.runs() / ("run-" + std::string(48, 'a')) / "marker"));
        REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
        REQUIRE(runner.join());
        REQUIRE(fs::exists(f.runs() / ("run-" + std::string(48, 'a')) / "marker"));
    }
    {
        // Lease exclusivity: a second supervisor on the same session refuses.
        supervisor_fixture f{root / "lease"};
        REQUIRE(f.prepare());
        auto created = native_session_supervisor::create(f.options(), f.harness);
        REQUIRE_CREATED(created);
        const auto session = (*created)->snapshot().session;
        auto competitor = native_session_supervisor::create(f.options(session), f.harness);
        REQUIRE(!competitor && competitor.error().find("live owner") != std::string::npos);
        // Composition drift (different model → different policy digest) refuses reopen.
        created->reset();
        auto options = f.options(session);
        options.model = "another-model";
        auto drifted = native_session_supervisor::create(options, f.harness);
        REQUIRE(!drifted);
        options = f.options(session);
        options.runtime_digest = std::string(64, 'e');
        REQUIRE(!native_session_supervisor::create(options, f.harness));
        REQUIRE(native_session_supervisor::create(f.options(session), f.harness));
    }
    return 0;
}

auto listener_recovery(const fs::path& root) -> int {
    supervisor_fixture f{root / "listener"};
    REQUIRE(f.prepare());
    auto created = native_session_supervisor::create(f.options(), f.harness);
    REQUIRE_CREATED(created);
    auto& supervisor = **created;
    running_supervisor runner{supervisor};
    REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
    REQUIRE(reached(supervisor, session_phase::running, 60s));
    const auto identity = supervisor.management().listener_identity();
    const auto path = supervisor.control_directory() / "s";
    REQUIRE(::unlink(path.c_str()) == 0);
    // The owner demonstrably survives (its generation keeps running); the
    // listener is recreated with a fresh socket identity and journaled.
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (supervisor.management().recreations() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    REQUIRE(supervisor.management().recreations() == 1);
    REQUIRE(supervisor.management().listener_identity() != identity);
    auto status = control(supervisor, session_operation::status, 1);
    REQUIRE(status && status->state == session_phase::running && status->generation == 1);
    REQUIRE(f.harness.observed.births == 1);
    const auto order = kinds(supervisor.journal());
    REQUIRE(index_of(order, "listener_recreated") < order.size());
    REQUIRE(control(supervisor, session_operation::stop, 1)->code == result_code::accepted);
    REQUIRE(reached(supervisor, session_phase::stopped, 60s));
    REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
    REQUIRE(runner.join());
    // Stale pathname after the owner exits: a client refuses, nothing restarts.
    created->reset();
    REQUIRE(!fs::exists(path));
    return 0;
}

} // namespace

auto main() -> int {
    (void)::signal(SIGPIPE, SIG_IGN);
    temporary_directory root;
    REQUIRE(!root.path.empty());
    REQUIRE(::chmod(root.path.c_str(), 0700) == 0);
    REQUIRE(full_sleep_wake_cycle(root.path) == 0);
    REQUIRE(preparation_cancellation(root.path) == 0);
    REQUIRE(persistence_and_uncertainty(root.path) == 0);
    REQUIRE(history_classification(root.path) == 0);
    REQUIRE(corrupted_checkpoint_and_unknown_ownership(root.path) == 0);
    REQUIRE(listener_recovery(root.path) == 0);
    return 0;
}
