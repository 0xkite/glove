#include "linux_session_executor.hpp"

#include "linux_process_identity.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace glove::control::linux_detail {

namespace {

constexpr std::size_t max_idempotency_namespace_bytes = 112U;

auto valid_identifier(std::string_view value, std::size_t max_bytes = 128U) -> bool {
    return !value.empty() && value.size() <= max_bytes &&
           std::ranges::all_of(value, [](char value_character) {
               const auto character = static_cast<unsigned char>(value_character);
               return std::isalnum(character) != 0 || value_character == '-' ||
                      value_character == '_' || value_character == ':' || value_character == '.';
           });
}

auto current_epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto registry_error(std::string_view operation, const session_registry_error& error)
    -> std::string {
    return std::string{operation} + ": " + error.message;
}

} // namespace

struct linux_pty_session::implementation {
    implementation(
        session_registry& session_registry,
        container::receipt_audit_producer& audit_producer,
        container::receipt_audit_producer::terminal_reservation terminal_reservation,
        session_failure_commitment failure,
        std::string failed_idempotency_key,
        std::string stopping_idempotency_key,
        std::string exited_idempotency_key,
        std::string owned_session_id,
        std::uint64_t launch_started_at_ms
    )
        : registry{&session_registry},
          producer{&audit_producer},
          reservation{std::move(terminal_reservation)},
          failure_commitment{std::move(failure)},
          failed_key{std::move(failed_idempotency_key)},
          stopping_key{std::move(stopping_idempotency_key)},
          exited_key{std::move(exited_idempotency_key)},
          session_id{std::move(owned_session_id)},
          started_at_ms{launch_started_at_ms} {}

    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;

    ~implementation() {
        if (finalizer.joinable() && finalizer.get_id() != std::this_thread::get_id()) {
            finalizer.join();
        }
    }

    auto start_finalizer() -> std::expected<void, std::string> {
        try {
            finalizer = std::thread{[this] { finalize(); }};
            return {};
        } catch (const std::system_error& error) {
            return std::unexpected(std::string{"start Linux PTY finalizer: "} + error.what());
        }
    }

    void finalize() noexcept {
        try {
            auto receipt = managed->wait();
            if (!receipt) {
                close_failed(std::string{"wait for managed PTY session: "} + receipt.error());
                return;
            }
            const std::lock_guard transition_lock{transition_mutex};
            auto terminal = producer->commit_terminal(
                std::move(reservation),
                failure_commitment.session_id,
                failure_commitment.controller_plan_digest,
                *receipt
            );
            if (!terminal) {
                close_failed_locked(
                    std::string{"commit Linux PTY terminal receipt: "} + terminal.error()
                );
                return;
            }
            auto exited = registry->mark_exited(*terminal, *producer, exited_key);
            if (!exited) {
                publish_error(registry_error("project durable Linux PTY receipt", exited.error()));
                return;
            }
            const std::lock_guard lock{state_mutex};
            result = std::move(*exited);
            finished = true;
            state_changed.notify_all();
        } catch (const std::exception& error) {
            close_failed(std::string{"Linux PTY finalizer failed: "} + error.what());
        } catch (...) {
            close_failed(std::string{"Linux PTY finalizer failed"});
        }
    }

    void close_failed(std::string message) noexcept {
        const std::lock_guard transition_lock{transition_mutex};
        close_failed_locked(std::move(message));
    }

    void close_failed_locked(std::string message) noexcept {
        try {
            auto failed = registry->mark_failed(
                failure_commitment, failed_key, std::max(current_epoch_ms(), started_at_ms)
            );
            if (!failed) {
                message += "; failed to close registry: " + failed.error().message;
            }
        } catch (...) {
            message += "; failed to close registry";
        }
        publish_error(std::move(message));
    }

    void publish_error(std::string message) noexcept {
        try {
            const std::lock_guard lock{state_mutex};
            error = std::move(message);
            finished = true;
            state_changed.notify_all();
        } catch (...) {
            const std::lock_guard lock{state_mutex};
            finished = true;
            state_changed.notify_all();
        }
    }

    session_registry* registry = nullptr;
    container::receipt_audit_producer* producer = nullptr;
    container::receipt_audit_producer::terminal_reservation reservation;
    session_failure_commitment failure_commitment;
    std::string failed_key;
    std::string stopping_key;
    std::string exited_key;
    std::string session_id;
    std::uint64_t started_at_ms = 0;
    std::optional<session_running_commitment> running_commitment;
    std::unique_ptr<container::linux_detail::managed_pty_session> managed;
    std::unique_ptr<net::egress_proxy> egress_proxy;
    std::mutex transition_mutex;
    std::mutex state_mutex;
    std::condition_variable state_changed;
    bool finished = false;
    std::optional<session_exited_record> result;
    std::string error;
    std::thread finalizer;
};

struct linux_pty_session_index::implementation {
    explicit implementation(std::size_t session_limit) : max_sessions{session_limit} {}

    std::size_t max_sessions = 0;
    std::map<std::string, std::shared_ptr<linux_pty_session>, std::less<>> sessions;
    mutable std::mutex mutex;
};

struct linux_session_runtime::implementation {
    implementation(
        session_registry& session_registry,
        linux_session_preparer& session_preparer,
        container::linux_detail::managed_pty_session_options pty_options,
        std::unique_ptr<linux_pty_session_index> live_sessions
    )
        : registry{&session_registry},
          preparer{&session_preparer},
          options{pty_options},
          sessions{std::move(live_sessions)} {}

    session_registry* registry = nullptr;
    linux_session_preparer* preparer = nullptr;
    container::linux_detail::managed_pty_session_options options;
    std::unique_ptr<linux_pty_session_index> sessions;
    std::optional<session_reconciliation_report> reconciliation;
    std::mutex start_mutex;
};

linux_pty_session::linux_pty_session(std::unique_ptr<implementation> state) noexcept
    : state_{std::move(state)} {}

linux_pty_session::~linux_pty_session() {
    if (state_ && state_->managed) {
        static_cast<void>(stop());
        static_cast<void>(wait());
    }
}

auto linux_pty_session::read(std::uint64_t cursor, std::size_t max_bytes) const
    -> std::expected<container::linux_detail::pty_transcript_read, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return state_->managed->read(cursor, max_bytes);
}

auto linux_pty_session::wait_read(
    std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms
) -> std::expected<container::linux_detail::pty_transcript_read, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return state_->managed->wait_read(cursor, max_bytes, timeout_ms);
}

auto linux_pty_session::write_input(std::string_view bytes) -> std::expected<void, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return state_->managed->write_input(bytes);
}

auto linux_pty_session::resize(std::uint16_t rows, std::uint16_t columns)
    -> std::expected<void, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return state_->managed->resize(rows, columns);
}

auto linux_pty_session::signal(container::linux_detail::pty_session_signal requested)
    -> std::expected<void, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return state_->managed->signal(requested);
}

auto linux_pty_session::stop() -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    return stop(state_->stopping_key);
}

auto linux_pty_session::stop(std::string_view idempotency_key) -> std::expected<void, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    if (!valid_identifier(idempotency_key)) {
        return std::unexpected(std::string{"invalid Linux PTY stop idempotency key"});
    }
    return state_->managed->stop(
        [state = state_.get(),
         key = std::string{idempotency_key}]() -> std::expected<void, std::string> {
            const std::lock_guard transition_lock{state->transition_mutex};
            if (!state->running_commitment) {
                return std::unexpected(std::string{"Linux PTY session has no running commitment"});
            }
            auto stopping = state->registry->mark_stopping(
                *state->running_commitment, key, std::max(current_epoch_ms(), state->started_at_ms)
            );
            if (!stopping) {
                return std::unexpected(
                    registry_error("mark Linux PTY session stopping", stopping.error())
                );
            }
            return {};
        }
    );
}

auto linux_pty_session::wait() -> std::expected<session_exited_record, std::string> {
    if (!state_ || !state_->managed) {
        return std::unexpected(std::string{"Linux PTY session is not running"});
    }
    std::unique_lock lock{state_->state_mutex};
    state_->state_changed.wait(lock, [this] { return state_->finished; });
    if (!state_->result) {
        return std::unexpected(
            state_->error.empty() ? std::string{"Linux PTY session failed"} : state_->error
        );
    }
    return *state_->result;
}

auto linux_pty_session::session_id() const noexcept -> std::string_view {
    return state_ ? std::string_view{state_->session_id} : std::string_view{};
}

auto linux_pty_session::finished() const -> bool {
    if (!state_) {
        return true;
    }
    const std::lock_guard lock{state_->state_mutex};
    return state_->finished;
}

namespace {

auto indexed_session(
    const linux_pty_session_index::implementation& state, std::string_view session_id
) -> std::expected<std::shared_ptr<linux_pty_session>, std::string> {
    if (!valid_identifier(session_id)) {
        return std::unexpected(std::string{"invalid Linux PTY session identity"});
    }
    const std::lock_guard lock{state.mutex};
    const auto existing = state.sessions.find(session_id);
    if (existing == state.sessions.end()) {
        return std::unexpected(std::string{"Linux PTY session was not found"});
    }
    return existing->second;
}

} // namespace

linux_pty_session_index::linux_pty_session_index(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

linux_pty_session_index::~linux_pty_session_index() = default;

auto linux_pty_session_index::create(std::size_t max_sessions)
    -> std::expected<std::unique_ptr<linux_pty_session_index>, std::string> {
    constexpr std::size_t absolute_max_sessions = 1'024U;
    if (max_sessions == 0 || max_sessions > absolute_max_sessions) {
        return std::unexpected(std::string{"invalid Linux PTY live-session limit"});
    }
    try {
        auto state = std::make_unique<implementation>(max_sessions);
        return std::make_unique<linux_pty_session_index>(construction_token{}, std::move(state));
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux PTY live-session index"});
    }
}

auto linux_pty_session_index::adopt(std::unique_ptr<linux_pty_session> session)
    -> std::expected<void, std::string> {
    if (!state_ || !session || !valid_identifier(session->session_id())) {
        return std::unexpected(std::string{"invalid Linux PTY session owner"});
    }
    try {
        const std::string session_id{session->session_id()};
        auto shared = std::shared_ptr<linux_pty_session>{std::move(session)};
        const std::lock_guard lock{state_->mutex};
        if (state_->sessions.contains(session_id)) {
            return std::unexpected(std::string{"Linux PTY session is already live"});
        }
        if (state_->sessions.size() >= state_->max_sessions) {
            return std::unexpected(std::string{"Linux PTY live-session capacity is exhausted"});
        }
        state_->sessions.emplace(session_id, std::move(shared));
        return {};
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux PTY live-session entry"});
    }
}

auto linux_pty_session_index::contains(std::string_view session_id) const -> bool {
    if (!state_ || !valid_identifier(session_id)) {
        return false;
    }
    const std::lock_guard lock{state_->mutex};
    return state_->sessions.contains(session_id);
}

auto linux_pty_session_index::list() const -> std::expected<std::vector<std::string>, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    try {
        const std::lock_guard lock{state_->mutex};
        std::vector<std::string> sessions;
        sessions.reserve(state_->sessions.size());
        for (const auto& [session_id, owner] : state_->sessions) {
            static_cast<void>(owner);
            sessions.push_back(session_id);
        }
        return sessions;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux PTY live-session inventory"});
    }
}

auto linux_pty_session_index::read(
    std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes
) const -> std::expected<container::linux_detail::pty_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->read(cursor, max_bytes)
                   : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::wait_read(
    std::string_view session_id,
    std::uint64_t cursor,
    std::size_t max_bytes,
    std::uint64_t timeout_ms
) -> std::expected<container::linux_detail::pty_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->wait_read(cursor, max_bytes, timeout_ms)
                   : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::write_input(std::string_view session_id, std::string_view bytes)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->write_input(bytes) : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::resize(
    std::string_view session_id, std::uint16_t rows, std::uint16_t columns
) -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->resize(rows, columns)
                   : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::signal(
    std::string_view session_id, container::linux_detail::pty_session_signal requested
) -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->signal(requested) : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::stop(std::string_view session_id)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->stop() : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::stop(std::string_view session_id, std::string_view idempotency_key)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->stop(idempotency_key)
                   : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::wait(std::string_view session_id)
    -> std::expected<session_exited_record, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    return session ? (*session)->wait() : std::unexpected(std::move(session.error()));
}

auto linux_pty_session_index::cleanup(std::string_view session_id)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux PTY live-session index is empty"});
    }
    auto session = indexed_session(*state_, session_id);
    if (!session) {
        return std::unexpected(std::move(session.error()));
    }
    if (!(*session)->finished()) {
        return std::unexpected(std::string{"Linux PTY session is not terminal"});
    }
    auto terminal = (*session)->wait();
    const std::lock_guard lock{state_->mutex};
    const auto existing = state_->sessions.find(session_id);
    if (existing == state_->sessions.end() || existing->second != *session) {
        return std::unexpected(std::string{"Linux PTY session owner changed before cleanup"});
    }
    state_->sessions.erase(existing);
    if (!terminal) {
        return std::unexpected(terminal.error());
    }
    return {};
}

linux_session_runtime::linux_session_runtime(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

linux_session_runtime::~linux_session_runtime() = default;

auto linux_session_runtime::create(
    session_registry& registry,
    linux_session_preparer& preparer,
    container::linux_detail::managed_pty_session_options options,
    std::size_t max_sessions
) -> std::expected<std::unique_ptr<linux_session_runtime>, std::string> {
    auto sessions = linux_pty_session_index::create(max_sessions);
    if (!sessions) {
        return std::unexpected(sessions.error());
    }
    try {
        auto state =
            std::make_unique<implementation>(registry, preparer, options, std::move(*sessions));
        return std::make_unique<linux_session_runtime>(construction_token{}, std::move(state));
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux session runtime"});
    }
}

auto linux_session_runtime::resource_capabilities() const noexcept
    -> container::resource_enforcement_capabilities {
    return container::linux_detail::managed_session_capabilities();
}

auto linux_session_runtime::start(
    container::receipt_audit_producer& receipt_producer,
    const session_start_authorization& authorization,
    std::string_view idempotency_namespace,
    std::uint64_t now_ms
) -> std::expected<session_record, std::string> {
    if (!state_ || !valid_identifier(idempotency_namespace, max_idempotency_namespace_bytes) ||
        now_ms == 0) {
        return std::unexpected(std::string{"invalid Linux session runtime start request"});
    }
    const std::lock_guard start_lock{state_->start_mutex};
    if (!state_->reconciliation) {
        return std::unexpected(
            std::string{"Linux session runtime requires startup reconciliation"}
        );
    }
    const auto reserve_key = std::string{idempotency_namespace} + ".reserve";
    auto reserved = state_->registry->reserve_start(authorization, reserve_key, now_ms);
    if (!reserved) {
        return std::unexpected(registry_error("reserve Linux PTY session", reserved.error()));
    }
    auto current = state_->registry->status(authorization.session_id);
    if (!current) {
        return std::unexpected(registry_error("read reserved Linux PTY session", current.error()));
    }
    if (current->state != session_state::preparing) {
        return std::move(*current);
    }
    if (state_->sessions->contains(authorization.session_id)) {
        return std::unexpected(std::string{"Linux PTY live-session index is inconsistent"});
    }
    auto session = start_linux_pty_session(
        *state_->registry,
        *state_->preparer,
        receipt_producer,
        {
            .session_id = authorization.session_id,
            .authorization_id = authorization.authorization_id,
            .idempotency_namespace = std::string{idempotency_namespace},
        },
        state_->options
    );
    if (!session) {
        return std::unexpected(session.error());
    }
    if (auto adopted = state_->sessions->adopt(std::move(*session)); !adopted) {
        return std::unexpected(std::string{"adopt Linux PTY session: "} + adopted.error());
    }
    auto status = state_->registry->status(authorization.session_id);
    return status
               ? std::expected<session_record, std::string>{std::move(*status)}
               : std::unexpected(registry_error("read started Linux PTY session", status.error()));
}

auto linux_session_runtime::reconcile(
    container::receipt_audit_producer& receipt_producer, std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string> {
    if (!state_ || now_ms == 0) {
        return std::unexpected(std::string{"invalid Linux session runtime reconciliation"});
    }
    const std::lock_guard start_lock{state_->start_mutex};
    if (state_->reconciliation) {
        return *state_->reconciliation;
    }
    auto report = state_->preparer->reconcile(*state_->registry, receipt_producer, now_ms);
    if (!report) {
        return std::unexpected(report.error());
    }
    if (!report->unresolved_running_session_ids.empty() ||
        !report->live_running_session_ids.empty() ||
        !report->identity_mismatch_session_ids.empty()) {
        return std::unexpected(
            std::string{"Linux session reconciliation left unresolved process ownership"}
        );
    }
    try {
        state_->reconciliation = *report;
        return *state_->reconciliation;
    } catch (const std::bad_alloc&) {
        state_->reconciliation.reset();
        return std::unexpected(std::string{"allocate Linux session reconciliation report"});
    }
}

auto linux_session_runtime::list() const -> std::expected<std::vector<std::string>, std::string> {
    return state_ ? state_->sessions->list()
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto linux_session_runtime::read(
    std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes
) const -> std::expected<session_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux session runtime is empty"});
    }
    auto result = state_->sessions->read(session_id, cursor, max_bytes);
    if (!result) {
        return std::unexpected(result.error());
    }
    return session_transcript_read{
        .oldest_cursor = result->oldest_cursor,
        .next_cursor = result->next_cursor,
        .truncated = result->truncated,
        .eof = result->eof,
        .bytes = std::move(result->bytes),
    };
}

auto linux_session_runtime::wait_read(
    std::string_view session_id,
    std::uint64_t cursor,
    std::size_t max_bytes,
    std::uint64_t timeout_ms
) -> std::expected<session_transcript_read, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux session runtime is empty"});
    }
    auto result = state_->sessions->wait_read(session_id, cursor, max_bytes, timeout_ms);
    if (!result) {
        return std::unexpected(result.error());
    }
    return session_transcript_read{
        .oldest_cursor = result->oldest_cursor,
        .next_cursor = result->next_cursor,
        .truncated = result->truncated,
        .eof = result->eof,
        .bytes = std::move(result->bytes),
    };
}

auto linux_session_runtime::write_input(std::string_view session_id, std::string_view bytes)
    -> std::expected<void, std::string> {
    return state_ ? state_->sessions->write_input(session_id, bytes)
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto linux_session_runtime::resize(
    std::string_view session_id, std::uint16_t rows, std::uint16_t columns
) -> std::expected<void, std::string> {
    return state_ ? state_->sessions->resize(session_id, rows, columns)
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto linux_session_runtime::signal(std::string_view session_id, session_signal requested)
    -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux session runtime is empty"});
    }
    container::linux_detail::pty_session_signal translated;
    switch (requested) {
    case session_signal::interrupt:
        translated = container::linux_detail::pty_session_signal::interrupt;
        break;
    case session_signal::terminate:
        translated = container::linux_detail::pty_session_signal::terminate;
        break;
    case session_signal::hangup:
        translated = container::linux_detail::pty_session_signal::hangup;
        break;
    }
    return state_->sessions->signal(session_id, translated);
}

auto linux_session_runtime::stop(std::string_view session_id) -> std::expected<void, std::string> {
    return state_ ? state_->sessions->stop(session_id)
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto linux_session_runtime::stop(std::string_view session_id, std::string_view idempotency_key)
    -> std::expected<void, std::string> {
    return state_ ? state_->sessions->stop(session_id, idempotency_key)
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto linux_session_runtime::wait(std::string_view session_id)
    -> std::expected<session_terminal_record, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"Linux session runtime is empty"});
    }
    auto exited = state_->sessions->wait(session_id);
    if (!exited) {
        return std::unexpected(exited.error());
    }
    return session_terminal_record{
        .session = exited->session,
        .profile_digest = exited->profile_digest,
        .starting_at_ms = exited->starting_at_ms,
        .running_at_ms = exited->running_at_ms,
        .stopping_at_ms = exited->stopping_at_ms,
        .finished_at_ms = exited->finished_at_ms,
        .receipt_key_id = exited->receipt_key_id,
        .receipt_sequence = exited->receipt_sequence,
        .receipt_digest = exited->receipt_digest,
        .receipt_hmac = exited->receipt_hmac,
        .termination_cause = exited->termination_cause,
        .exit_code = exited->exit_code,
    };
}

auto linux_session_runtime::cleanup(std::string_view session_id)
    -> std::expected<void, std::string> {
    return state_ ? state_->sessions->cleanup(session_id)
                  : std::unexpected(std::string{"Linux session runtime is empty"});
}

auto start_linux_pty_session(
    session_registry& registry,
    linux_session_preparer& preparer,
    container::receipt_audit_producer& receipt_producer,
    const linux_session_execution_request& request,
    container::linux_detail::managed_pty_session_options options
) -> std::expected<std::unique_ptr<linux_pty_session>, std::string> {
    if (!valid_identifier(request.session_id) || !valid_identifier(request.authorization_id) ||
        !valid_identifier(request.idempotency_namespace, max_idempotency_namespace_bytes)) {
        return std::unexpected(std::string{"invalid Linux PTY session execution request"});
    }
    const auto started_at_ms = current_epoch_ms();
    const auto starting_key = request.idempotency_namespace + ".starting";
    const auto running_key = request.idempotency_namespace + ".running";
    const auto failed_key = request.idempotency_namespace + ".failed";
    const auto stopping_key = request.idempotency_namespace + ".stopping";
    const auto exited_key = request.idempotency_namespace + ".exited";
    const auto transition_time = [&]() { return std::max(current_epoch_ms(), started_at_ms); };
    auto inputs =
        registry.resolve_start_inputs(request.session_id, request.authorization_id, started_at_ms);
    if (!inputs) {
        return std::unexpected(registry_error("resolve Linux PTY session inputs", inputs.error()));
    }
    auto prepared = preparer.prepare(std::move(*inputs), started_at_ms);
    if (!prepared) {
        return std::unexpected(std::string{"prepare Linux PTY session: "} + prepared.error());
    }
    auto receipt_reservation = receipt_producer.reserve_terminal(
        prepared->session_id, prepared->controller_plan_digest, prepared->binding.profile_digest
    );
    if (!receipt_reservation) {
        return std::unexpected(
            std::string{"reserve Linux PTY terminal receipt: "} + receipt_reservation.error()
        );
    }
    session_failure_commitment failure_commitment{
        .schema_version = 1,
        .session_id = prepared->session_id,
        .controller_plan_digest = prepared->controller_plan_digest,
        .plan_content_digest = prepared->plan_content_digest,
        .authorization_id = prepared->authorization_id,
        .profile_digest = prepared->binding.profile_digest,
        .code = session_failure_code::supervisor_error,
    };
    std::unique_ptr<linux_pty_session::implementation> state;
    try {
        state = std::make_unique<linux_pty_session::implementation>(
            registry,
            receipt_producer,
            std::move(*receipt_reservation),
            failure_commitment,
            failed_key,
            stopping_key,
            exited_key,
            prepared->session_id,
            started_at_ms
        );
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux PTY session state"});
    }
    std::unique_ptr<linux_pty_session> owner;
    try {
        owner = std::unique_ptr<linux_pty_session>{new linux_pty_session{std::move(state)}};
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Linux PTY session owner"});
    }
    owner->state_->egress_proxy = std::move(prepared->egress_proxy);
    auto starting = registry.mark_starting(
        prepared->execution_binding(), owner->state_->reservation, starting_key, transition_time()
    );
    if (!starting) {
        return std::unexpected(registry_error("mark Linux PTY session starting", starting.error()));
    }

    bool running_committed = false;
    const container::linux_detail::managed_session_start_gate before_child_release =
        [&](::pid_t child_pid) -> std::expected<void, std::string> {
        auto process_identity = capture_linux_process_identity(child_pid);
        if (!process_identity) {
            return std::unexpected(
                std::string{"capture managed PTY child identity: "} + process_identity.error()
            );
        }
        const session_running_commitment running{
            .schema_version = 1,
            .session_id = prepared->session_id,
            .controller_plan_digest = prepared->controller_plan_digest,
            .plan_content_digest = prepared->plan_content_digest,
            .authorization_id = prepared->authorization_id,
            .profile_digest = prepared->binding.profile_digest,
            .process_identity = std::move(*process_identity),
            .filesystem_identity = prepared->filesystem_identity,
        };
        auto marked = registry.mark_running(
            running, owner->state_->reservation, running_key, transition_time()
        );
        if (!marked) {
            return std::unexpected(
                registry_error("mark Linux PTY session running", marked.error())
            );
        }
        owner->state_->running_commitment = running;
        running_committed = true;
        return {};
    };
    auto managed = container::linux_detail::start_managed_pty_session(
        prepared->profile,
        prepared->argv,
        prepared->binding,
        std::move(prepared->lifecycle),
        options,
        before_child_release
    );
    if (!managed) {
        auto failure = failure_commitment;
        failure.code = running_committed ? session_failure_code::supervisor_error
                                         : session_failure_code::launch_failed;
        std::string message = std::string{"execute Linux PTY session: "} + managed.error();
        auto failed = registry.mark_failed(failure, failed_key, transition_time());
        if (!failed) {
            message += "; failed to close registry: " + failed.error().message;
        }
        return std::unexpected(std::move(message));
    }
    owner->state_->managed = std::move(*managed);
    auto finalizing = owner->state_->start_finalizer();
    if (!finalizing) {
        static_cast<void>(owner->state_->managed->stop());
        owner->state_->finalize();
        return std::unexpected(finalizing.error());
    }
    return owner;
}

auto execute_linux_session(
    session_registry& registry,
    linux_session_preparer& preparer,
    container::receipt_audit_producer& receipt_producer,
    const linux_session_execution_request& request
) -> std::expected<session_exited_record, std::string> {
    if (!valid_identifier(request.session_id) || !valid_identifier(request.authorization_id) ||
        !valid_identifier(request.idempotency_namespace, max_idempotency_namespace_bytes)) {
        return std::unexpected(std::string{"invalid Linux session execution request"});
    }
    const auto started_at_ms = current_epoch_ms();
    const auto starting_key = request.idempotency_namespace + ".starting";
    const auto running_key = request.idempotency_namespace + ".running";
    const auto failed_key = request.idempotency_namespace + ".failed";
    const auto exited_key = request.idempotency_namespace + ".exited";
    const auto transition_time = [&]() { return std::max(current_epoch_ms(), started_at_ms); };

    auto inputs =
        registry.resolve_start_inputs(request.session_id, request.authorization_id, started_at_ms);
    if (!inputs) {
        return std::unexpected(registry_error("resolve Linux session inputs", inputs.error()));
    }
    auto prepared = preparer.prepare(std::move(*inputs), started_at_ms);
    if (!prepared) {
        return std::unexpected(std::string{"prepare Linux session: "} + prepared.error());
    }
    auto receipt_reservation = receipt_producer.reserve_terminal(
        prepared->session_id, prepared->controller_plan_digest, prepared->binding.profile_digest
    );
    if (!receipt_reservation) {
        return std::unexpected(
            std::string{"reserve Linux terminal receipt: "} + receipt_reservation.error()
        );
    }
    auto starting = registry.mark_starting(
        prepared->execution_binding(), *receipt_reservation, starting_key, transition_time()
    );
    if (!starting) {
        return std::unexpected(registry_error("mark Linux session starting", starting.error()));
    }

    const session_failure_commitment failure_commitment{
        .schema_version = 1,
        .session_id = prepared->session_id,
        .controller_plan_digest = prepared->controller_plan_digest,
        .plan_content_digest = prepared->plan_content_digest,
        .authorization_id = prepared->authorization_id,
        .profile_digest = prepared->binding.profile_digest,
        .code = session_failure_code::supervisor_error,
    };
    const auto close_failed = [&](
                                  session_failure_code code, std::string message
                              ) -> std::expected<session_exited_record, std::string> {
        auto commitment = failure_commitment;
        commitment.code = code;
        auto failed = registry.mark_failed(commitment, failed_key, transition_time());
        if (!failed) {
            message += "; failed to close registry: " + failed.error().message;
        }
        return std::unexpected(std::move(message));
    };

    bool running_committed = false;
    const container::linux_detail::managed_session_start_gate before_child_release =
        [&](::pid_t child_pid) -> std::expected<void, std::string> {
        auto process_identity = capture_linux_process_identity(child_pid);
        if (!process_identity) {
            return std::unexpected(
                std::string{"capture managed child identity: "} + process_identity.error()
            );
        }
        const session_running_commitment running{
            .schema_version = 1,
            .session_id = prepared->session_id,
            .controller_plan_digest = prepared->controller_plan_digest,
            .plan_content_digest = prepared->plan_content_digest,
            .authorization_id = prepared->authorization_id,
            .profile_digest = prepared->binding.profile_digest,
            .process_identity = std::move(*process_identity),
            .filesystem_identity = prepared->filesystem_identity,
        };
        auto marked =
            registry.mark_running(running, *receipt_reservation, running_key, transition_time());
        if (!marked) {
            return std::unexpected(registry_error("mark Linux session running", marked.error()));
        }
        running_committed = true;
        return {};
    };

    auto receipt = container::linux_detail::exec_managed_session(
        prepared->profile,
        prepared->argv,
        prepared->binding,
        std::move(prepared->lifecycle),
        before_child_release
    );
    if (!receipt) {
        const auto code = running_committed ? session_failure_code::supervisor_error
                                            : session_failure_code::launch_failed;
        return close_failed(code, std::string{"execute Linux session: "} + receipt.error());
    }
    auto terminal = receipt_producer.commit_terminal(
        std::move(*receipt_reservation),
        prepared->session_id,
        prepared->controller_plan_digest,
        *receipt
    );
    if (!terminal) {
        return close_failed(
            session_failure_code::supervisor_error,
            std::string{"commit Linux terminal receipt: "} + terminal.error()
        );
    }
    auto exited = registry.mark_exited(*terminal, receipt_producer, exited_key);
    if (!exited) {
        return std::unexpected(
            registry_error("project durable Linux terminal receipt", exited.error())
        );
    }
    return std::move(*exited);
}

} // namespace glove::control::linux_detail
