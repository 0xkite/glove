// Peer-credential credentials require GNU extensions on Linux; keep the
// guard local to this translation unit.
#if defined(__linux__) && !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#endif

#include "glove/control/observation_intent_unix_server.hpp"

#include "glove/control/guest_channel_transport.hpp"

#include "channel_identifier_grammar.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <sys/param.h>
#    include <sys/ucred.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace glove::control::observation_wire {

struct enqueue_request_v1 {
    std::uint8_t schema_version = 0;
    std::string channel_token;
    glove_observation_body body;
};

struct enqueue_success_v1 {
    std::uint8_t schema_version = 1;
    std::string status = "queued";
    std::uint64_t sequence = 0;
    std::string intent_digest;
};

struct enqueue_error_v1 {
    std::uint8_t schema_version = 1;
    std::string code;
};

} // namespace glove::control::observation_wire

namespace glove::control {
namespace {

using observation_wire::enqueue_error_v1;
using observation_wire::enqueue_request_v1;
using observation_wire::enqueue_success_v1;

constexpr std::uint64_t max_io_timeout_ms = 60'000U;
constexpr std::uint64_t max_intent_ttl_ms = 600'000U;
// Transient wait/accept failures are retried inside serve_one_for with this
// bounded backoff ladder; only persistent or fatal errors are surfaced.
constexpr unsigned max_transient_accept_retries = 8U;
constexpr auto transient_backoff_cap = std::chrono::milliseconds{128};
constexpr glz::opts strict_complete_read_options{
    .error_on_unknown_keys = true,
    .error_on_missing_keys = true,
};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset(std::exchange(other.descriptor_, -1));
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

    void reset(int descriptor = -1) noexcept {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

void wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool {
    const auto maximum = std::max(left.size(), right.size());
    std::uint32_t difference = static_cast<std::uint32_t>(left.size() ^ right.size());
    for (std::size_t index = 0; index < maximum; ++index) {
        const auto left_byte = static_cast<unsigned char>(index < left.size() ? left[index] : 0);
        const auto right_byte = static_cast<unsigned char>(index < right.size() ? right[index] : 0);
        difference |= static_cast<std::uint32_t>(left_byte ^ right_byte);
    }
    return difference == 0U;
}

// Identifier and digest admission grammar is shared with guest_channel and
// the session registry via channel_identifier_grammar.hpp; the rules are
// identical (128-byte bounded charset, 64 lowercase hex).
using detail::valid_identifier;

inline auto valid_hex(std::string_view value) noexcept -> bool {
    return detail::valid_digest(value);
}

auto system_error(std::string_view operation, int code = errno) -> std::string {
    return std::string{operation} + ": " + std::error_code{code, std::generic_category()}.message();
}

auto current_epoch_ms() noexcept -> std::uint64_t {
    using namespace std::chrono;
    const auto value = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    return value < 0 ? 0U : static_cast<std::uint64_t>(value);
}

auto transient_backoff(
    unsigned attempt, guest_channel_deadline accept_deadline, std::stop_token stop
) noexcept -> bool {
    using namespace std::chrono;
    const auto delay =
        std::min(milliseconds{1} * (1U << std::min<unsigned>(attempt, 7U)), transient_backoff_cap);
    const auto wake_at = std::min(steady_clock::now() + delay, accept_deadline);
    for (;;) {
        if (stop.stop_requested()) {
            return false;
        }
        const auto now = steady_clock::now();
        if (now >= accept_deadline) {
            return false;
        }
        if (now >= wake_at) {
            return true;
        }
        std::this_thread::sleep_for(
            std::min(wake_at - now, duration_cast<steady_clock::duration>(milliseconds{5}))
        );
    }
}

auto validate_socket_path(const std::filesystem::path& path) -> std::expected<void, std::string> {
    if (!path.is_absolute() || path.filename().empty() || path.filename() == "." ||
        path.filename() == "..") {
        return std::unexpected(std::string{"observation socket path is invalid"});
    }
    const auto parent = path.parent_path();
    unique_fd directory{::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (directory.get() < 0) {
        return std::unexpected(system_error("open observation socket directory"));
    }
    struct stat metadata{};
    if (::fstat(directory.get(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"observation socket directory must be owner-only"});
    }
    struct stat existing{};
    if (::lstat(path.c_str(), &existing) == 0 || errno != ENOENT) {
        return std::unexpected(std::string{"observation socket path already exists"});
    }
    return {};
}

auto socket_address(const std::filesystem::path& path)
    -> std::expected<::sockaddr_un, std::string> {
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto value = path.string();
    if (value.empty() || value.size() >= sizeof(address.sun_path)) {
        return std::unexpected(std::string{"observation socket address exceeds its bound"});
    }
    std::memcpy(address.sun_path, value.c_str(), value.size() + 1U);
    return address;
}

auto create_listener() -> std::expected<unique_fd, std::string> {
    int socket_type = SOCK_STREAM;
#if defined(SOCK_CLOEXEC)
    socket_type |= SOCK_CLOEXEC;
#endif
#if defined(SOCK_NONBLOCK)
    socket_type |= SOCK_NONBLOCK;
#endif
    unique_fd descriptor{::socket(AF_UNIX, socket_type, 0)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("create observation socket"));
    }
#if !defined(SOCK_CLOEXEC)
    const int descriptor_flags = ::fcntl(descriptor.get(), F_GETFD);
    if (descriptor_flags < 0 ||
        ::fcntl(descriptor.get(), F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return std::unexpected(system_error("protect observation socket descriptor"));
    }
#endif
#if !defined(SOCK_NONBLOCK)
    const int status_flags = ::fcntl(descriptor.get(), F_GETFL);
    if (status_flags < 0 || ::fcntl(descriptor.get(), F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return std::unexpected(system_error("make observation listener nonblocking"));
    }
#endif
    return descriptor;
}

template<typename Value>
auto encode(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded || encoded->empty() || encoded->size() > max_observation_frame_bytes) {
        return std::unexpected(std::string{"encode observation response failed"});
    }
    return std::move(*encoded);
}

auto error_code_for(const session_registry_error& error) -> std::string {
    switch (error.code) {
    case session_registry_error_code::invalid_request:
        return "invalid_request";
    case session_registry_error_code::idempotency_conflict:
        return "idempotency_conflict";
    case session_registry_error_code::capacity:
        return "capacity_exhausted";
    case session_registry_error_code::storage:
        return "storage_failed";
    case session_registry_error_code::invalid_plan:
    case session_registry_error_code::invalid_authorization:
    case session_registry_error_code::invalid_state:
    case session_registry_error_code::session_conflict:
    case session_registry_error_code::not_found:
        return "intent_rejected";
    }
    return "intent_rejected";
}

// One wait/accept/handle round. `error_number` carries the errno of a
// wait/accept failure so callers can classify it as transient; zero means
// the failure is fatal (config error or internal encode failure).
struct attempt_outcome {
    std::expected<bool, std::string> served{false};
    int error_number = 0;
};

auto send_response(
    guest_channel_transport& channel,
    std::string_view response,
    guest_channel_deadline deadline,
    std::stop_token stop
) -> attempt_outcome {
    return {
        .served = classify_observation_response_send(channel.send_frame(response, deadline, stop)),
        .error_number = 0
    };
}

} // namespace

auto classify_observation_response_send(guest_channel_transport_result<void> sent)
    -> std::expected<bool, std::string> {
    if (sent) {
        return true;
    }
    if (sent.error().code == guest_channel_transport_error_code::cancelled) {
        return false;
    }
    return std::unexpected(std::move(sent.error().message));
}

struct observation_intent_unix_server::implementation {
    observation_intent_unix_server_config config;
    unique_fd listener;
    ::dev_t socket_device = 0;
    ::ino_t socket_inode = 0;
    bool owns_socket_path = false;

    ~implementation() {
        wipe(config.channel_token);
        listener.reset();
        if (!owns_socket_path) {
            return;
        }
        struct stat metadata{};
        if (::lstat(config.socket_path.c_str(), &metadata) == 0 && S_ISSOCK(metadata.st_mode) &&
            metadata.st_dev == socket_device && metadata.st_ino == socket_inode) {
            static_cast<void>(::unlink(config.socket_path.c_str()));
        }
    }

    auto handle(std::string_view frame, std::uint64_t now_ms)
        -> std::expected<std::string, std::string> {
        enqueue_request_v1 request{};
        if (frame.empty() || frame.size() > max_observation_frame_bytes ||
            glz::read<strict_complete_read_options>(request, frame) ||
            request.schema_version != 1U) {
            wipe(request.channel_token);
            return encode(enqueue_error_v1{.code = "invalid_request"});
        }
        const bool authorized = constant_time_equal(request.channel_token, config.channel_token);
        wipe(request.channel_token);
        if (!authorized) {
            return encode(enqueue_error_v1{.code = "unauthorized"});
        }

        const auto ttl_ceiling =
            now_ms > std::numeric_limits<std::uint64_t>::max() - max_intent_ttl_ms
                ? std::numeric_limits<std::uint64_t>::max()
                : now_ms + max_intent_ttl_ms;
        const auto expires_at_ms = std::min(config.session_expires_at_ms, ttl_ceiling);
        const observation_intent_context context{
            .session_id = config.session_id,
            .controller_plan_digest = config.controller_plan_digest,
            .profile_digest = config.profile_digest,
            .runtime_id = config.runtime_id,
            .projection_digest = config.projection_digest,
            .policy_revision = config.policy_revision,
            .channel_id = config.service_channel_id,
            .channel_generation = config.channel_generation,
            .issued_at_ms = now_ms,
            .expires_at_ms = expires_at_ms,
        };
        auto queued = config.sessions->enqueue_observation_intent(request.body, context, now_ms);
        if (!queued) {
            const auto code = now_ms == 0U || expires_at_ms <= now_ms
                                  ? std::string{"intent_expired"}
                                  : error_code_for(queued.error());
            return encode(enqueue_error_v1{.code = code});
        }
        enqueue_success_v1 response{
            .sequence = queued->sequence,
            .intent_digest = queued->intent_digest,
        };
        return encode(response);
    }
};

auto serve_attempt(
    observation_intent_unix_server::implementation& state,
    guest_channel_deadline accept_deadline,
    std::stop_token stop
) -> attempt_outcome {
    for (;;) {
        if (stop.stop_requested()) {
            return {.served = false};
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= accept_deadline) {
            return {.served = false};
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(accept_deadline - now);
        const int timeout = static_cast<int>(std::clamp<std::int64_t>(remaining.count(), 1, 25));
        ::pollfd event{.fd = state.listener.get(), .events = POLLIN, .revents = 0};
        const int ready = ::poll(&event, 1, timeout);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready == 0) {
            continue;
        }
        if (ready < 0 || (event.revents & POLLIN) == 0) {
            const int error_number = errno;
            return {
                .served =
                    std::unexpected(system_error("wait for observation connection", error_number)),
                .error_number = error_number
            };
        }
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= accept_deadline) {
            return {.served = false};
        }
        break;
    }
#if defined(__linux__) && defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    unique_fd client{
        ::accept4(state.listener.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK)
    };
#else
    unique_fd client{::accept(state.listener.get(), nullptr, nullptr)};
#endif
    if (client.get() < 0) {
        const int error_number = errno;
        return {
            .served = std::unexpected(system_error("accept observation connection", error_number)),
            .error_number = error_number
        };
    }
    auto channel = guest_channel_transport::adopt(
        client.release(), max_observation_frame_bytes, state.config.expected_peer_uid
    );
    if (!channel) {
        return {.served = true};
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{state.config.io_timeout_ms};
    auto frame = (*channel)->receive_frame(deadline, stop);
    if (!frame) {
        if (frame.error().code == guest_channel_transport_error_code::cancelled) {
            return {.served = false};
        }
        if (frame.error().code == guest_channel_transport_error_code::frame_too_large) {
            auto response = encode(enqueue_error_v1{.code = "invalid_request"});
            if (!response) {
                return {.served = std::unexpected(response.error()), .error_number = 0};
            }
            return send_response(**channel, *response, deadline, stop);
        }
        return {.served = true};
    }
    // Registry persistence is synchronous trusted local work. These checks
    // prevent starting it after cancellation/expiry and suppress a late
    // response, but cannot forcibly interrupt persistence already in progress.
    if (stop.stop_requested()) {
        wipe(*frame);
        return {.served = false};
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        wipe(*frame);
        return {
            .served = std::unexpected(std::string{"guest channel deadline exceeded"}),
            .error_number = 0
        };
    }
    auto response = state.handle(*frame, current_epoch_ms());
    wipe(*frame);
    if (stop.stop_requested()) {
        return {.served = false};
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        return {
            .served = std::unexpected(std::string{"guest channel deadline exceeded"}),
            .error_number = 0
        };
    }
    if (!response) {
        return {.served = std::unexpected(response.error()), .error_number = 0};
    }
    return send_response(**channel, *response, deadline, stop);
}

observation_intent_unix_server::observation_intent_unix_server(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

observation_intent_unix_server::~observation_intent_unix_server() = default;

auto observation_intent_unix_server::create(observation_intent_unix_server_config config)
    -> std::expected<std::unique_ptr<observation_intent_unix_server>, std::string> {
    if (!config.sessions || !valid_identifier(config.session_id) ||
        !valid_identifier(config.runtime_id) || !valid_hex(config.controller_plan_digest) ||
        !valid_hex(config.profile_digest) || !valid_hex(config.projection_digest) ||
        config.policy_revision == 0U || !valid_identifier(config.service_channel_id) ||
        config.channel_generation == 0U || config.session_expires_at_ms == 0U ||
        !valid_hex(config.channel_token) || config.io_timeout_ms == 0U ||
        config.io_timeout_ms > max_io_timeout_ms) {
        wipe(config.channel_token);
        return std::unexpected(std::string{"invalid observation server configuration"});
    }
    if (auto valid = validate_socket_path(config.socket_path); !valid) {
        wipe(config.channel_token);
        return std::unexpected(valid.error());
    }
    auto address = socket_address(config.socket_path);
    auto listener = create_listener();
    if (!address || !listener) {
        wipe(config.channel_token);
        return std::unexpected(address ? listener.error() : address.error());
    }
    auto state = std::make_unique<implementation>();
    state->config = std::move(config);
    state->listener = std::move(*listener);
    const auto address_size = static_cast<socklen_t>(
        offsetof(::sockaddr_un, sun_path) + state->config.socket_path.string().size() + 1U
    );
    if (::bind(
            state->listener.get(), reinterpret_cast<const ::sockaddr*>(&*address), address_size
        ) != 0) {
        return std::unexpected(system_error("bind observation socket"));
    }
    state->owns_socket_path = true;
    if (::chmod(state->config.socket_path.c_str(), 0600) != 0) {
        return std::unexpected(system_error("protect observation socket"));
    }
    struct stat metadata{};
    if (::lstat(state->config.socket_path.c_str(), &metadata) != 0 || !S_ISSOCK(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U) {
        return std::unexpected(std::string{"observation socket identity is unsafe"});
    }
    state->socket_device = metadata.st_dev;
    state->socket_inode = metadata.st_ino;
    if (::listen(state->listener.get(), 8) != 0) {
        return std::unexpected(system_error("listen on observation socket"));
    }
    return std::make_unique<observation_intent_unix_server>(construction_token{}, std::move(state));
}

auto observation_intent_unix_server::serve_one_for(
    std::uint64_t accept_timeout_ms, std::stop_token stop
) -> std::expected<bool, std::string> {
    if (!state_ || accept_timeout_ms > max_io_timeout_ms) {
        return std::unexpected(std::string{"invalid observation accept timeout"});
    }
    // One absolute accept deadline governs every wait, accept retry, and
    // transient backoff in this call. Retries must never renew it.
    const auto accept_deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{accept_timeout_ms};
    for (unsigned attempt = 0;; ++attempt) {
        auto outcome = serve_attempt(*state_, accept_deadline, stop);
        if (outcome.served.has_value()) {
            return outcome.served;
        }
        if (outcome.error_number == 0 ||
            !observation_transient_accept_error(outcome.error_number) ||
            attempt + 1U >= max_transient_accept_retries) {
            return std::unexpected(std::move(outcome.served.error()));
        }
        if (!transient_backoff(attempt, accept_deadline, stop)) {
            return false;
        }
    }
}

auto observation_intent_unix_server::socket_path() const -> const std::filesystem::path& {
    static const std::filesystem::path empty;
    return state_ ? state_->config.socket_path : empty;
}

} // namespace glove::control
