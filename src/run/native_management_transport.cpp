#include "native_management_wire.hpp"

namespace glove::run::detail {
using namespace management_detail; // NOLINT(google-build-using-namespace)

namespace {

struct bound_listener {
    descriptor fd;
    struct stat identity{};
};

// Binds a fresh listener at control/sock. An existing object at that name is
// never unlinked here: a stale or foreign object refuses, the owner decides.
auto bind_listener(const pinned_parent& control, const std::filesystem::path& path)
    -> result<bound_listener> {
    struct stat existing{};
    if (::fstatat(control.fd(), socket_name.data(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        return std::unexpected("management socket name is occupied");
    }
    if (errno != ENOENT) {
        return failure("inspect management socket name");
    }
    auto address = sockaddr_for(path);
    if (!address) {
        return std::unexpected("management socket path exceeds sun_path");
    }
    descriptor fd{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (fd.get() < 0 || !make_nonblocking(fd.get())) {
        return failure("create management socket");
    }
    const mode_t previous = ::umask(0177);
    const int bound = ::bind(
        fd.get(),
        reinterpret_cast<const ::sockaddr*>(&*address),
        static_cast<::socklen_t>(sizeof(*address))
    );
    (void)::umask(previous);
    if (bound != 0) {
        return failure("bind management socket");
    }
    bound_listener listener{.fd = std::move(fd)};
    if (::fstatat(control.fd(), socket_name.data(), &listener.identity, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(listener.identity.st_mode) || listener.identity.st_uid != ::geteuid() ||
        (listener.identity.st_mode & 07777U) != 0600U ||
        ::fchmodat(control.fd(), socket_name.data(), 0600, 0) != 0) {
        (void)::unlinkat(control.fd(), socket_name.data(), 0);
        return std::unexpected("management socket object is not owner-private");
    }
    if (::listen(listener.fd.get(), static_cast<int>(management_max_connections)) != 0) {
        (void)::unlinkat(control.fd(), socket_name.data(), 0);
        return failure("listen management socket");
    }
    return listener;
}

auto encode_result(
    std::string_view session,
    std::string_view epoch,
    const management_request& request,
    const operation_result& outcome
) -> std::optional<std::string> {
    const result_frame frame{
        .v = 1,
        .type = "result",
        .session = std::string{session},
        .epoch = std::string{epoch},
        .generation = format_generation(outcome.snapshot.generation),
        .request = request.request,
        .op = std::string{to_string(outcome.op)},
        .state = std::string{to_string(outcome.snapshot.phase)},
        .history = std::string{to_string(outcome.snapshot.history)},
        .checkpoint = outcome.snapshot.checkpoint,
        .effects = std::string{to_string(outcome.snapshot.effects)},
        .code = std::string{to_string(outcome.code)},
        .final = outcome.final
    };
    std::string json;
    if (glz::write_json(frame, json) || json.size() > management_max_frame_bytes) {
        return std::nullopt;
    }
    return json;
}

} // namespace

struct native_management_server::implementation {
    pinned_parent control;
    std::filesystem::path control_path;
    std::filesystem::path socket_path;
    std::string session;
    std::string epoch;
    std::string token;
    std::vector<std::string> capabilities;
    management_handler handler;
    management_listener_hook on_listener;
    bound_listener listener;
    mutable std::mutex mutex;
    std::atomic<std::uint64_t> recreations{0};
    std::atomic<std::uint64_t> refusals{0};
    std::atomic<std::uint64_t> connections{0};
    // The hook reports a lost/refused listener once per episode, not per tick,
    // so a persistent fault cannot flood the owner's journal.
    bool fault_reported = false;
    std::jthread worker;

    // The bound socket object must still be the one at control/sock. A missing
    // name is recreated because this owner demonstrably survives (it runs this
    // code); a foreign object is refused and left alone.
    void check_listener() {
        struct stat named{};
        const int rc = ::fstatat(control.fd(), socket_name.data(), &named, AT_SYMLINK_NOFOLLOW);
        const auto report = [&](std::string message) {
            if (!fault_reported && on_listener) {
                on_listener(message);
            }
            fault_reported = true;
        };
        if (rc == 0) {
            std::scoped_lock lock{mutex};
            if (named.st_dev == listener.identity.st_dev &&
                named.st_ino == listener.identity.st_ino) {
                fault_reported = false;
                return;
            }
            ++refusals;
            report("management socket name replaced by a foreign object; refused");
            return;
        }
        if (errno != ENOENT) {
            return;
        }
        if (auto checked = control.check(); !checked) {
            std::scoped_lock lock{mutex};
            report("control directory changed; listener not recreated");
            return;
        }
        auto fresh = bind_listener(control, socket_path);
        std::scoped_lock lock{mutex};
        if (!fresh) {
            ++refusals;
            report("management listener recreation refused: " + fresh.error());
            return;
        }
        listener = std::move(*fresh);
        ++recreations;
        fault_reported = false;
        if (on_listener) {
            on_listener("management listener recreated with fresh socket identity");
        }
    }

    void serve(int client, std::stop_token stop) {
        if (!verify_peer(client) || !make_nonblocking(client)) {
            return;
        }
        const auto auth_deadline = clock_type::now() + management_auth_timeout;
        auto auth_body = read_frame(client, stop, auth_deadline);
        if (!auth_body || !bounded_json_object(*auth_body, 8)) {
            return;
        }
        auth_frame auth;
        if (glz::read<closed_options>(auth, *auth_body) || !auth.v || *auth.v != 1 || !auth.type ||
            *auth.type != "auth" || !auth.session || !auth.epoch || !auth.capability ||
            *auth.session != session || *auth.epoch != epoch ||
            !constant_time_equal(*auth.capability, token)) {
            // Authentication failure closes without any response or metadata.
            return;
        }
        const ready_frame ready{
            .v = 1,
            .type = "ready",
            .session = session,
            .epoch = epoch,
            .capabilities = capabilities
        };
        std::string ready_json;
        if (glz::write_json(ready, ready_json)) {
            return;
        }
        const auto request_deadline = clock_type::now() + management_request_timeout;
        if (!write_frame(client, ready_json, stop, request_deadline)) {
            return;
        }
        auto body = read_frame(client, stop, request_deadline);
        if (!body || !bounded_json_object(*body, 8)) {
            return;
        }
        request_frame frame;
        if (glz::read<closed_options>(frame, *body) || !frame.v || *frame.v != 1 || !frame.type ||
            *frame.type != "request" || !frame.session || !frame.epoch || !frame.generation ||
            !frame.request || !frame.op) {
            return;
        }
        if (*frame.session != session || *frame.epoch != epoch) {
            return;
        }
        auto generation = parse_generation(*frame.generation);
        auto op = parse_session_operation(*frame.op);
        if (!generation || !op || !valid_request_id(*frame.request) ||
            (frame.checkpoint && !valid_checkpoint_id(*frame.checkpoint))) {
            return;
        }
        auto digest = sha256_of(*body);
        if (!digest) {
            return;
        }
        const management_request request{
            .observed_generation = *generation,
            .request = *frame.request,
            .op = *op,
            .checkpoint = frame.checkpoint,
            .body_digest = *digest
        };
        const auto outcome = handler(request);
        auto encoded = encode_result(session, epoch, request, outcome);
        if (!encoded) {
            return;
        }
        // An admitted operation's reply is written under its deadline even if
        // the owner is already shutting the listener down (shutdown itself).
        (void)write_frame(client, *encoded, std::stop_token{}, request_deadline);
    }

    void run(std::stop_token stop) {
        while (!stop.stop_requested()) {
            check_listener();
            int listener_fd = -1;
            {
                std::scoped_lock lock{mutex};
                listener_fd = listener.fd.get();
            }
            ::pollfd pfd{.fd = listener_fd, .events = POLLIN, .revents = 0};
            const int ready = ::poll(&pfd, 1, poll_tick_ms);
            if (ready <= 0 || (pfd.revents & POLLIN) == 0) {
                continue;
            }
            const int client = ::accept(listener_fd, nullptr, nullptr);
            if (client < 0) {
                continue;
            }
            ++connections;
            serve(client, stop);
            ::close(client);
        }
    }
};

native_management_server::native_management_server(std::unique_ptr<implementation> state) noexcept
    : state_{std::move(state)} {}

native_management_server::~native_management_server() {
    if (!state_) {
        return;
    }
    state_->worker.request_stop();
    if (state_->worker.joinable()) {
        state_->worker.join();
    }
    // Only this owner's socket object is removed; a replaced name is left.
    struct stat named{};
    if (::fstatat(state_->control.fd(), socket_name.data(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        named.st_dev == state_->listener.identity.st_dev &&
        named.st_ino == state_->listener.identity.st_ino) {
        (void)::unlinkat(state_->control.fd(), socket_name.data(), 0);
    }
    (void)::unlinkat(state_->control.fd(), capability_name.data(), 0);
}

auto native_management_server::start(
    const std::filesystem::path& control_directory,
    std::string session,
    std::string epoch,
    std::vector<std::string> capabilities,
    management_handler handler,
    management_listener_hook on_listener
) -> std::expected<std::unique_ptr<native_management_server>, std::string> {
    if (!valid_session_id(session) || !valid_epoch(epoch) || !handler || capabilities.empty() ||
        capabilities.size() > 8) {
        return std::unexpected("invalid management server composition");
    }
    auto control = pin_parent(control_directory);
    if (!control) {
        return std::unexpected(control.error());
    }
    auto state = std::make_unique<implementation>();
    state->control = std::move(*control);
    state->control_path = control_directory;
    state->socket_path = control_directory / std::string{socket_name};
    state->session = std::move(session);
    state->epoch = std::move(epoch);
    state->capabilities = std::move(capabilities);
    state->handler = std::move(handler);
    state->on_listener = std::move(on_listener);
    auto token = mint_request_id();
    auto token_tail = mint_request_id();
    if (!token || !token_tail) {
        return std::unexpected("cannot mint management capability");
    }
    state->token = *token + *token_tail;
    // Remove this epoch's predecessors' capability only; a stale socket name
    // is this owner's own leftover only when the lease proves it (the caller
    // holds the lease), so it is safe to replace here.
    (void)::unlinkat(state->control.fd(), capability_name.data(), 0);
    struct stat stale{};
    if (::fstatat(state->control.fd(), socket_name.data(), &stale, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISSOCK(stale.st_mode) || stale.st_uid != ::geteuid()) {
            return std::unexpected("management socket name holds a foreign object");
        }
        if (::unlinkat(state->control.fd(), socket_name.data(), 0) != 0) {
            return failure("remove stale management socket");
        }
    }
    descriptor capability{::openat(
        state->control.fd(),
        capability_name.data(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0600
    )};
    if (capability.get() < 0 || ::fchmod(capability.get(), 0600) != 0) {
        return failure("create management capability");
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(capability.get()); !cleared) {
        return std::unexpected(cleared.error());
    }
    const std::string bytes = state->session + "\n" + state->epoch + "\n" + state->token + "\n";
    if (auto written = private_files::write_bytes(capability.get(), bytes); !written) {
        return std::unexpected(written.error());
    }
    auto listener = bind_listener(state->control, state->socket_path);
    if (!listener) {
        (void)::unlinkat(state->control.fd(), capability_name.data(), 0);
        return std::unexpected(listener.error());
    }
    state->listener = std::move(*listener);
    auto* raw = state.get();
    state->worker = std::jthread([raw](std::stop_token stop) { raw->run(std::move(stop)); });
    return std::unique_ptr<native_management_server>{
        new native_management_server{std::move(state)}
    };
}

auto native_management_server::socket_path() const -> std::filesystem::path {
    return state_->socket_path;
}

auto native_management_server::listener_identity() const
    -> std::pair<std::uint64_t, std::uint64_t> {
    std::scoped_lock lock{state_->mutex};
    return {
        static_cast<std::uint64_t>(state_->listener.identity.st_dev),
        static_cast<std::uint64_t>(state_->listener.identity.st_ino)
    };
}

auto native_management_server::recreations() const -> std::uint64_t {
    return state_->recreations.load();
}

auto native_management_server::refusals() const -> std::uint64_t {
    return state_->refusals.load();
}

auto native_management_server::connections() const -> std::uint64_t {
    return state_->connections.load();
}
} // namespace glove::run::detail
