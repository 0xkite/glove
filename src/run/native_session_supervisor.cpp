#include "native_session_supervisor.hpp"

#include "glove/detail/descriptor_acl.hpp"

#include "native_private_state.hpp"
#include "pi_private_files.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <mutex>
#include <span>
#include <stop_token>
#include <utility>

namespace glove::run::detail {
namespace {

template<typename T> using result = std::expected<T, std::string>;
using private_files::descriptor;
using private_files::directory_flags;
using private_files::failure;

constexpr int file_create_flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

auto leaf_component(std::string_view name) -> bool {
    return !name.empty() && name.size() <= 255 && name != "." && name != ".." &&
           !name.contains('/') && !name.contains('\0');
}

// Best-effort bookkeeping: the failure is logged by the caller's sink; the
// surrounding lifecycle decision does not depend on it.
template<typename T>
void note(
    const std::function<void(std::string_view)>& log,
    std::string_view what,
    std::expected<T, std::string> outcome
) {
    if (!outcome && log) {
        log(std::string{what} + ": " + outcome.error());
    }
}

auto event(std::string kind, std::string epoch, std::uint64_t generation) -> journal_event {
    return {
        .seq = 0,
        .kind = std::move(kind),
        .epoch = std::move(epoch),
        .generation = generation,
        .request = {},
        .body_digest = {},
        .op = {},
        .code = {},
        .checkpoint = {},
        .detail = {}
    };
}

// Opens (creating when `create`) the directory chain below the agent
// descriptor without following links; returns the final directory.
auto open_chain(int agent_fd, std::span<const std::string> directories, bool create)
    -> result<descriptor> {
    descriptor current{::dup(agent_fd)};
    if (current.get() < 0) {
        return failure("duplicate agent descriptor");
    }
    for (const auto& component : directories) {
        if (!leaf_component(component)) {
            return std::unexpected("invalid history location component");
        }
        if (create && ::mkdirat(current.get(), component.c_str(), 0700) != 0 && errno != EEXIST) {
            return failure("create history directory");
        }
        descriptor next{::openat(current.get(), component.c_str(), directory_flags)};
        const int open_error = errno;
        struct stat info{};
        if (next.get() < 0) {
            if (open_error == ENOENT && !create) {
                return std::unexpected("absent");
            }
            errno = open_error;
            return failure("open history directory");
        }
        if (::fstat(next.get(), &info) != 0 || !S_ISDIR(info.st_mode) ||
            info.st_uid != ::geteuid()) {
            return failure("inspect history directory");
        }
        if (create && (::fchmod(next.get(), 0700) != 0 || ::fsync(next.get()) != 0)) {
            return failure("persist history directory");
        }
        current = std::move(next);
    }
    return current;
}

} // namespace

struct native_session_supervisor::implementation {
    native_session_supervisor_options options;
    native_session_harness* harness = nullptr;
    std::unique_ptr<native_session_store> store;
    std::string epoch;
    std::unique_ptr<native_session_model> model;
    std::unique_ptr<native_management_server> management;
    std::vector<std::string> history_location;
    history_validator validate;
    std::string policy_digest;

    mutable std::mutex mutex;
    mutable std::condition_variable changed;

    struct launch_intent {
        bool resume = false;
        std::optional<std::string> checkpoint;
        std::uint64_t generation = 0;
    };

    std::optional<launch_intent> pending;
    std::optional<std::stop_source> stop_source;
    bool shutdown = false;
    bool launched = false;
    std::uint64_t launches = 0;
    std::optional<std::string> last_error;
    store_fault injected = store_fault::none;

    void log(std::string_view line) const {
        if (options.log) {
            options.log(line);
        }
    }

    auto journal(journal_event item) -> result<void> {
        auto appended = store->append(std::move(item));
        if (!appended) {
            log("journal failure: " + appended.error());
        }
        return appended;
    }

    auto snapshot_locked() const -> supervisor_snapshot {
        return {
            .session = store->metadata().session,
            .epoch = epoch,
            .projection = model->projection(),
            .launches = launches,
            .generation_active = pending.has_value(),
            .last_error = last_error
        };
    }

    // Durable request-intent admission precedes effects: a preview on a copy
    // decides whether this is a new mutation, the intent is journaled, and only
    // then the live model applies it. Replays never reach the journal twice.
    auto handle(const management_request& request) -> operation_result {
        std::scoped_lock lock{mutex};
        operation_request admitted{
            .epoch = epoch,
            .generation = request.observed_generation,
            .request = request.request,
            .op = request.op,
            .checkpoint = request.checkpoint,
            .body_digest = request.body_digest
        };
        if (shutdown && request.op != session_operation::status) {
            // An admitted shutdown closes mutation admission: nothing can be
            // reserved that no loop will ever run.
            return {
                .op = request.op,
                .code = result_code::invalid_state,
                .final = true,
                .snapshot = model->projection()
            };
        }
        if (request.op == session_operation::interrupt) {
            // No qualified harness interrupt contract exists for this runtime.
            return {
                .op = request.op,
                .code = result_code::unsupported_operation,
                .final = true,
                .snapshot = model->projection()
            };
        }
        native_session_model preview = *model;
        const auto previewed = preview.submit(admitted);
        const bool new_record = preview.operation_records() > model->operation_records();
        if (!new_record) {
            return previewed;
        }
        auto intent = event("intent", epoch, previewed.snapshot.generation);
        intent.request = request.request;
        intent.body_digest = request.body_digest;
        intent.op = std::string{to_string(request.op)};
        if (request.checkpoint) {
            intent.checkpoint = *request.checkpoint;
        }
        if (auto journaled = journal(std::move(intent)); !journaled) {
            return {
                .op = request.op,
                .code = result_code::capacity,
                .final = true,
                .snapshot = model->projection()
            };
        }
        const auto outcome = model->submit(admitted);
        switch (request.op) {
        case session_operation::start:
        case session_operation::resume:
            if (outcome.code == result_code::accepted) {
                pending = launch_intent{
                    .resume = request.op == session_operation::resume,
                    .checkpoint = request.checkpoint,
                    .generation = outcome.snapshot.generation
                };
                stop_source.emplace();
                launched = false;
            }
            break;
        case session_operation::stop:
            if (outcome.code == result_code::accepted && stop_source) {
                stop_source->request_stop();
            }
            break;
        case session_operation::shutdown:
            if (outcome.code == result_code::ok) {
                shutdown = true;
            }
            break;
        case session_operation::status:
        case session_operation::interrupt:
            break;
        }
        changed.notify_all();
        return outcome;
    }

    auto materialize(const native_private_state& state, const std::string& history)
        -> result<void> {
        if (history_location.size() < 2) {
            return std::unexpected("history location requires a directory and a leaf");
        }
        const std::span<const std::string> directories{
            history_location.data(), history_location.size() - 1
        };
        auto directory = open_chain(state.agent_descriptor(), directories, true);
        if (!directory) {
            return std::unexpected(directory.error());
        }
        const auto& name = history_location.back();
        if (!leaf_component(name)) {
            return std::unexpected("invalid history leaf");
        }
        descriptor file{::openat(directory->get(), name.c_str(), file_create_flags, 0600)};
        if (file.get() < 0 || ::fchmod(file.get(), 0600) != 0) {
            return failure("create generation-local history copy");
        }
        if (auto cleared = glove::detail::clear_created_descriptor_acl(file.get()); !cleared) {
            return cleared;
        }
        if (auto written = private_files::write_bytes(file.get(), history); !written) {
            return written;
        }
        if (::fsync(directory->get()) != 0) {
            return failure("persist generation-local history copy");
        }
        return {};
    }

    // Retained finalization before the quiescent marker. Returns an error only
    // for uncertain publication, which keeps the private run retained.
    auto finalize(const native_private_state& state, std::uint64_t generation) -> result<void> {
        std::scoped_lock lock{mutex};
        if (auto journaled = journal(event("outcome_known", epoch, generation)); !journaled) {
            return journaled;
        }
        if (auto known = model->process_outcome_known(); !known) {
            return known;
        }
        changed.notify_all();
        const std::span<const std::string> directories{
            history_location.data(), history_location.size() - 1
        };
        auto directory = open_chain(state.agent_descriptor(), directories, false);
        const auto classify = [&](history_status status, std::string_view detail) -> result<void> {
            auto classified = event("history_classified", epoch, generation);
            classified.code = std::string{to_string(status)};
            classified.detail = std::string{detail.substr(0, 512)};
            if (auto journaled = journal(std::move(classified)); !journaled) {
                return journaled;
            }
            const auto effects = status == history_status::absent ? effects_status::unassessed
                                                                  : effects_status::incomplete;
            if (auto recorded = model->history_classified(status, effects); !recorded) {
                return recorded;
            }
            return {};
        };
        const auto finish = [&]() -> result<void> {
            if (auto journaled = journal(event("finalized", epoch, generation)); !journaled) {
                return journaled;
            }
            auto settled = model->finalized_without_checkpoint();
            changed.notify_all();
            if (!settled) {
                return std::unexpected(settled.error());
            }
            return {};
        };
        if (!directory) {
            if (directory.error() == "absent") {
                if (auto classified = classify(history_status::absent, {}); !classified) {
                    return classified;
                }
                return finish();
            }
            if (auto classified = classify(history_status::failed, directory.error());
                !classified) {
                return classified;
            }
            (void)finish();
            return std::unexpected("history location unresolved: " + directory.error());
        }
        checkpoint_record record{
            .session = store->metadata().session,
            .producing_epoch = epoch,
            .producing_generation = generation,
            .harness_id = store->metadata().harness_id,
            .runtime_digest = store->metadata().runtime_digest,
            .history_format = store->metadata().history_format,
            .workspace = store->metadata().workspace,
            .policy_digest = store->metadata().policy_digest,
            .conversation_id = store->metadata().conversation_id,
            .history_digest = {},
            .history_bytes = 0,
            .history_entries = 0
        };
        const auto fault = std::exchange(injected, store_fault::none);
        auto published = store->publish_checkpoint(
            record, directory->get(), history_location.back(), validate, fault
        );
        if (published) {
            if (auto classified = model->history_classified(
                    history_status::available, effects_status::unassessed
                );
                !classified) {
                return classified;
            }
            auto settled = model->checkpoint_published(*published);
            changed.notify_all();
            if (!settled) {
                return std::unexpected(settled.error());
            }
            log("checkpoint published: " + *published);
            return {};
        }
        switch (published.error().kind) {
        case publish_failure_kind::missing:
            if (auto classified = classify(history_status::absent, {}); !classified) {
                return classified;
            }
            return finish();
        case publish_failure_kind::refused:
            log("history refused: " + published.error().message);
            if (auto classified = classify(history_status::invalid, published.error().message);
                !classified) {
                return classified;
            }
            return finish();
        case publish_failure_kind::failed:
            break;
        }
        log("checkpoint publication failed: " + published.error().message);
        auto failed = event("checkpoint_failed", epoch, generation);
        failed.detail = published.error().message.substr(0, 512);
        note(options.log, "journal checkpoint_failed", journal(std::move(failed)));
        if (auto recorded =
                model->history_classified(history_status::available, effects_status::unassessed);
            !recorded) {
            return recorded;
        }
        note(options.log, "model checkpoint_failed", model->checkpoint_failed());
        changed.notify_all();
        return std::unexpected("checkpoint publication failed: " + published.error().message);
    }

    auto run_generation(const launch_intent& intent) -> void {
        std::string history;
        std::stop_token stop;
        {
            std::scoped_lock lock{mutex};
            stop = stop_source ? stop_source->get_token() : std::stop_token{};
        }
        if (intent.resume) {
            // The journaled-identity check reads the event list the management
            // thread appends to; admission therefore holds the same mutex.
            auto admitted = [&] {
                std::scoped_lock lock{mutex};
                return store->admit_checkpoint(intent.checkpoint.value_or(std::string{}), validate);
            }();
            if (!admitted) {
                std::scoped_lock lock{mutex};
                auto failed = event("prepare_failed", epoch, intent.generation);
                failed.detail = admitted.error().substr(0, 512);
                note(options.log, "journal prepare_failed", journal(std::move(failed)));
                last_error = admitted.error();
                note(options.log, "model prepare_failed", model->prepare_failed());
                pending.reset();
                stop_source.reset();
                changed.notify_all();
                return;
            }
            history = std::move(admitted->history);
        }
        native_launch_context context{
            .directories = options.directories,
            .protected_auth_roots = options.protected_auth_roots,
            .workspace = options.workspace,
            .runs = options.directories.runtime / harness->policy().runtime_id / "runs",
            .policy = harness->policy(),
            .display_name = options.display_name,
            .backend = native_launch_backend::macos,
            .admit_runtime = {},
            .admit_assets = {},
            .revalidate = {},
            .credential = {},
            .start_endpoint = {},
            .execute_owned = {},
            .audit = options.audit,
            .conversation_id = store->metadata().conversation_id,
            .resume = intent.resume,
            .materialize = {},
            .on_launching = {},
            .finalize = {}
        };
        if (auto composed = harness->compose(context); !composed) {
            std::scoped_lock lock{mutex};
            auto failed = event("prepare_failed", epoch, intent.generation);
            failed.detail = composed.error().substr(0, 512);
            note(options.log, "journal prepare_failed", journal(std::move(failed)));
            last_error = composed.error();
            note(options.log, "model prepare_failed", model->prepare_failed());
            pending.reset();
            stop_source.reset();
            changed.notify_all();
            return;
        }
        if (intent.resume) {
            context.materialize = [&](const native_private_state& state) -> result<void> {
                return materialize(state, history);
            };
        }
        context.on_launching = [&] {
            std::scoped_lock lock{mutex};
            launched = true;
            ++launches;
            note(
                options.log,
                "journal launched",
                journal(event("launched", epoch, intent.generation))
            );
            note(options.log, "model launched", model->launched());
            changed.notify_all();
        };
        context.finalize = [&](const native_private_state& state, int) -> result<void> {
            return finalize(state, intent.generation);
        };
        auto exited = launch_native_with_context(context, harness->adapter(), stop);
        std::scoped_lock lock{mutex};
        if (!exited) {
            last_error = exited.error();
            log("generation ended with error: " + exited.error());
        }
        const auto phase = model->projection().phase;
        if (!launched) {
            const bool cancelled = stop.stop_requested();
            auto item =
                event(cancelled ? "prepare_cancelled" : "prepare_failed", epoch, intent.generation);
            if (!exited) {
                item.detail = exited.error().substr(0, 512);
            }
            note(options.log, "journal preparation end", journal(std::move(item)));
            note(
                options.log,
                "model preparation end",
                cancelled ? model->prepare_cancelled() : model->prepare_failed()
            );
        } else if (
            phase == session_phase::running || phase == session_phase::stopping ||
            phase == session_phase::interrupting
        ) {
            // The owned call returned without a known outcome reaching finalize.
            auto item = event("outcome_uncertain", epoch, intent.generation);
            if (!exited) {
                item.detail = exited.error().substr(0, 512);
            }
            note(options.log, "journal outcome_uncertain", journal(std::move(item)));
            note(options.log, "model outcome_uncertain", model->process_outcome_uncertain());
        }
        pending.reset();
        stop_source.reset();
        launched = false;
        changed.notify_all();
    }
};

native_session_supervisor::native_session_supervisor(std::unique_ptr<implementation> state) noexcept
    : state_{std::move(state)} {}

native_session_supervisor::~native_session_supervisor() {
    if (state_) {
        state_->management.reset();
    }
}

auto native_session_supervisor::create(
    native_session_supervisor_options options, native_session_harness& harness
) -> std::expected<std::unique_ptr<native_session_supervisor>, std::string> {
    if (!valid_checkpoint_id(options.runtime_digest) || options.model.empty() ||
        !options.workspace.is_absolute() || options.display_name.empty()) {
        return std::unexpected("invalid native session supervisor options");
    }
    auto digest = native_startup_policy_digest(harness.policy(), options.provider, options.model);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    auto state = std::make_unique<implementation>();
    state->harness = &harness;
    state->policy_digest = *digest;
    if (options.session) {
        auto opened = native_session_store::open(
            options.sessions_parent, *options.session, harness.policy().runtime_id
        );
        if (!opened) {
            return std::unexpected(opened.error());
        }
        state->store = std::make_unique<native_session_store>(std::move(*opened));
        const auto& metadata = state->store->metadata();
        if (metadata.harness_id != harness.harness_id() ||
            metadata.runtime_digest != options.runtime_digest ||
            metadata.history_format != harness.history_format() ||
            metadata.workspace != options.workspace.string() || metadata.policy_digest != *digest) {
            return std::unexpected("native session binding is incompatible with this composition");
        }
    } else {
        if (!valid_conversation_id(options.conversation_id)) {
            return std::unexpected("native session requires a host-minted conversation id");
        }
        auto session = mint_session_id();
        if (!session) {
            return std::unexpected(session.error());
        }
        auto created = native_session_store::create(
            options.sessions_parent,
            {.session = *session,
             .runtime_id = harness.policy().runtime_id,
             .harness_id = std::string{harness.harness_id()},
             .runtime_digest = options.runtime_digest,
             .history_format = std::string{harness.history_format()},
             .workspace = options.workspace.string(),
             .policy_digest = *digest,
             .conversation_id = options.conversation_id}
        );
        if (!created) {
            return std::unexpected(created.error());
        }
        state->store = std::make_unique<native_session_store>(std::move(*created));
    }
    const auto& metadata = state->store->metadata();
    auto location = harness.history_location(metadata.workspace, metadata.conversation_id);
    if (!location || location->size() < 2) {
        return std::unexpected(location ? "history location is too short" : location.error());
    }
    state->history_location = std::move(*location);
    state->validate = harness.validator(metadata.conversation_id);
    if (!state->validate) {
        return std::unexpected("harness supplies no history validator");
    }
    auto epoch = mint_epoch();
    if (!epoch) {
        return std::unexpected(epoch.error());
    }
    state->epoch = *epoch;
    state->model = std::make_unique<native_session_model>(state->epoch);
    if (auto restored = state->model->restore(state->store->durable_projection()); !restored) {
        return std::unexpected(restored.error());
    }
    state->options = std::move(options);
    if (auto journaled = state->journal(
            event("epoch_started", state->epoch, state->model->projection().generation)
        );
        !journaled) {
        return std::unexpected(journaled.error());
    }
    auto* raw = state.get();
    auto management = native_management_server::start(
        state->store->control_directory(),
        metadata.session,
        state->epoch,
        {"status_v1", "stop_v1", "resume_v1"},
        [raw](const management_request& request) { return raw->handle(request); },
        [raw](std::string_view detail) {
            std::scoped_lock lock{raw->mutex};
            auto item =
                event("listener_recreated", raw->epoch, raw->model->projection().generation);
            item.detail = std::string{detail.substr(0, 512)};
            note(raw->options.log, "journal listener", raw->journal(std::move(item)));
        }
    );
    if (!management) {
        return std::unexpected(management.error());
    }
    state->management = std::move(*management);
    return std::unique_ptr<native_session_supervisor>{
        new native_session_supervisor{std::move(state)}
    };
}

auto native_session_supervisor::run() -> std::expected<std::uint64_t, std::string> {
    std::uint64_t generations = 0;
    for (;;) {
        implementation::launch_intent intent;
        {
            std::unique_lock lock{state_->mutex};
            state_->changed.wait(lock, [&] {
                return state_->pending.has_value() || state_->shutdown;
            });
            if (state_->shutdown || !state_->pending) {
                break;
            }
            intent = *state_->pending;
        }
        state_->run_generation(intent);
        ++generations;
    }
    // The listener stays up until destruction so the accepted shutdown reply
    // and any trailing status requests complete; nothing can launch anymore.
    return generations;
}

auto native_session_supervisor::submit(const management_request& request) -> operation_result {
    return state_->handle(request);
}

auto native_session_supervisor::snapshot() const -> supervisor_snapshot {
    std::scoped_lock lock{state_->mutex};
    return state_->snapshot_locked();
}

auto native_session_supervisor::control_directory() const -> std::filesystem::path {
    return state_->store->control_directory();
}

auto native_session_supervisor::session_root() const -> std::filesystem::path {
    return state_->store->root();
}

auto native_session_supervisor::wait_for(
    const std::function<bool(const supervisor_snapshot&)>& predicate,
    std::chrono::milliseconds limit
) const -> bool {
    std::unique_lock lock{state_->mutex};
    return state_->changed.wait_for(lock, limit, [&] {
        return predicate(state_->snapshot_locked());
    });
}

auto native_session_supervisor::journal() const -> std::vector<journal_event> {
    std::scoped_lock lock{state_->mutex};
    return state_->store->events();
}

auto native_session_supervisor::management() const -> const native_management_server& {
    return *state_->management;
}

void native_session_supervisor::inject_store_fault(store_fault fault) {
    std::scoped_lock lock{state_->mutex};
    state_->injected = fault;
}

} // namespace glove::run::detail
