// Peer-credential credentials require GNU extensions on Linux; keep the
// guard local to this translation unit.
#if defined(__linux__) && !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#endif

#include "glove/control/observation_intent_unix_server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
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
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
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
constexpr std::size_t max_replay_cache_capacity = 65'536U;
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

    void reset(int descriptor = -1) noexcept {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

struct replay_record {
    glove_observation_body body;
    enqueue_success_v1 response;
};

// Bounded least-recently-used replay cache. Eviction is safe: the durable
// session registry remains the authoritative idempotency layer, so a replay
// that misses an evicted entry still resolves through the registry queue.
class replay_cache {
public:
    explicit replay_cache(std::size_t capacity) noexcept : capacity_{capacity} {}

    auto find(const std::string& intent_id) -> const replay_record* {
        const auto found = entries_.find(intent_id);
        if (found == entries_.end()) {
            return nullptr;
        }
        order_.splice(order_.begin(), order_, found->second.order);
        return &found->second.record;
    }

    void insert(std::string intent_id, replay_record record) {
        if (capacity_ == 0U) {
            return;
        }
        if (entries_.contains(intent_id)) {
            return;
        }
        if (entries_.size() >= capacity_) {
            const auto& evicted = order_.back();
            entries_.erase(evicted);
            order_.pop_back();
        }
        order_.emplace_front(intent_id);
        entries_.emplace(
            std::move(intent_id), cache_entry{.record = std::move(record), .order = order_.begin()}
        );
    }

private:
    struct cache_entry {
        replay_record record;
        std::list<std::string>::const_iterator order;
    };

    std::size_t capacity_ = 0;
    std::list<std::string> order_;
    std::unordered_map<std::string, cache_entry> entries_;
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

auto valid_identifier(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= 128U &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_hex(std::string_view value) noexcept -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto system_error(std::string_view operation, int code = errno) -> std::string {
    return std::string{operation} + ": " + std::error_code{code, std::generic_category()}.message();
}

auto current_epoch_ms() noexcept -> std::uint64_t {
    using namespace std::chrono;
    const auto value = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    return value < 0 ? 0U : static_cast<std::uint64_t>(value);
}

void transient_backoff(unsigned attempt) noexcept {
    using namespace std::chrono;
    const auto delay = std::min(
        std::chrono::milliseconds{1} * (1U << std::min<unsigned>(attempt, 7U)),
        transient_backoff_cap
    );
    std::this_thread::sleep_for(delay);
}

// Returns the peer uid, or nullopt when the platform exposes no peer-credential
// facility or the getsockopt probe fails.
auto peer_uid(int descriptor) -> std::optional<std::uint32_t> {
#if defined(SO_PEERCRED)
    struct ::ucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return std::nullopt;
    }
    return credentials.uid;
#elif defined(LOCAL_PEERCRED)
    struct xucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &length) != 0 ||
        credentials.cr_version != XUCRED_VERSION) {
        return std::nullopt;
    }
    return credentials.cr_uid;
#else
    (void)descriptor;
    return std::nullopt;
#endif
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
#if defined(SOCK_CLOEXEC)
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
#else
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM, 0)};
#endif
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("create observation socket"));
    }
#if !defined(SOCK_CLOEXEC)
    if (::fcntl(descriptor.get(), F_SETFD, FD_CLOEXEC) != 0) {
        return std::unexpected(system_error("protect observation socket descriptor"));
    }
#endif
    return descriptor;
}

auto set_io_timeout(int descriptor, std::uint64_t timeout_ms) -> std::expected<void, std::string> {
    const ::timeval timeout{
        .tv_sec = static_cast<time_t>(timeout_ms / 1'000U),
        .tv_usec = static_cast<suseconds_t>((timeout_ms % 1'000U) * 1'000U),
    };
    if (::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return std::unexpected(system_error("set observation socket timeout"));
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return std::unexpected(system_error("set observation socket no-sigpipe"));
    }
#endif
    return {};
}

auto read_exact(int descriptor, void* output, std::size_t size)
    -> std::expected<void, std::string> {
    auto* bytes = static_cast<std::byte*>(output);
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto result = ::read(descriptor, bytes + consumed, size - consumed);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return std::unexpected(std::string{"observation request timed out"});
        }
        if (result <= 0) {
            return std::unexpected(
                result < 0 ? system_error("read observation request")
                           : std::string{"observation request ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto write_exact(int descriptor, const void* input, std::size_t size)
    -> std::expected<void, std::string> {
    const auto* bytes = static_cast<const std::byte*>(input);
    std::size_t written = 0;
    while (written < size) {
#if defined(MSG_NOSIGNAL)
        const auto result = ::send(descriptor, bytes + written, size - written, MSG_NOSIGNAL);
#else
        const auto result = ::write(descriptor, bytes + written, size - written);
#endif
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(system_error("write observation response"));
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

template<typename Value>
auto encode(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded || encoded->empty() || encoded->size() > max_observation_frame_bytes) {
        return std::unexpected(std::string{"encode observation response failed"});
    }
    return std::move(*encoded);
}

auto send_frame(int descriptor, std::string_view payload) -> std::expected<void, std::string> {
    if (payload.empty() || payload.size() > max_observation_frame_bytes ||
        payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"observation response exceeds its bound"});
    }
    const auto length = htonl(static_cast<std::uint32_t>(payload.size()));
    if (auto written = write_exact(descriptor, &length, sizeof(length)); !written) {
        return written;
    }
    return write_exact(descriptor, payload.data(), payload.size());
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

} // namespace

struct observation_intent_unix_server::implementation {
    observation_intent_unix_server_config config;
    unique_fd listener;
    ::dev_t socket_device = 0;
    ::ino_t socket_inode = 0;
    bool owns_socket_path = false;
    std::mutex request_mutex;
    replay_cache replays;

    implementation() : replays{config.replay_cache_capacity} {}

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

        std::lock_guard lock{request_mutex};
        if (const auto* replay = replays.find(request.body.intent_id); replay != nullptr) {
            if (replay->body != request.body) {
                return encode(enqueue_error_v1{.code = "idempotency_conflict"});
            }
            return encode(replay->response);
        }
        const auto ttl_ceiling =
            now_ms > std::numeric_limits<std::uint64_t>::max() - max_intent_ttl_ms
                ? std::numeric_limits<std::uint64_t>::max()
                : now_ms + max_intent_ttl_ms;
        const auto expires_at_ms = std::min(config.session_expires_at_ms, ttl_ceiling);
        if (now_ms == 0U || expires_at_ms <= now_ms) {
            return encode(enqueue_error_v1{.code = "intent_expired"});
        }
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
            return encode(enqueue_error_v1{.code = error_code_for(queued.error())});
        }
        enqueue_success_v1 response{
            .sequence = queued->sequence,
            .intent_digest = queued->intent_digest,
        };
        std::string intent_id = request.body.intent_id;
        replays.insert(
            std::move(intent_id),
            replay_record{.body = std::move(request.body), .response = response}
        );
        return encode(response);
    }
};

auto serve_attempt(
    observation_intent_unix_server::implementation& state, std::uint64_t accept_timeout_ms
) -> attempt_outcome {
    const int timeout =
        accept_timeout_ms > static_cast<std::uint64_t>(std::numeric_limits<int>::max())
            ? std::numeric_limits<int>::max()
            : static_cast<int>(accept_timeout_ms);
    ::pollfd event{.fd = state.listener.get(), .events = POLLIN, .revents = 0};
    int ready = 0;
    do {
        ready = ::poll(&event, 1, timeout);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0) {
        return {.served = false};
    }
    if (ready < 0 || (event.revents & POLLIN) == 0) {
        return {
            .served = std::unexpected(system_error("wait for observation connection")),
            .error_number = errno
        };
    }
#if defined(SOCK_CLOEXEC)
    unique_fd client{::accept4(state.listener.get(), nullptr, nullptr, SOCK_CLOEXEC)};
#else
    unique_fd client{::accept(state.listener.get(), nullptr, nullptr)};
#endif
    if (client.get() < 0) {
        return {
            .served = std::unexpected(system_error("accept observation connection")),
            .error_number = errno
        };
    }
#if !defined(SOCK_CLOEXEC)
    if (::fcntl(client.get(), F_SETFD, FD_CLOEXEC) != 0) {
        return {.served = true};
    }
#endif
    // Defense-in-depth peer-credential check: reject connections whose
    // peer-uid differs from the configured expectation before any frame is
    // read. A socket-file permission gap then cannot grant another local
    // account access to the channel.
    if (state.config.expected_peer_uid.has_value()) {
        const auto uid = peer_uid(client.get());
        if (!uid || *uid != *state.config.expected_peer_uid) {
            return {.served = true};
        }
    }
    if (auto timeout_set = set_io_timeout(client.get(), state.config.io_timeout_ms); !timeout_set) {
        return {.served = true};
    }
    std::uint32_t network_length = 0;
    if (auto read = read_exact(client.get(), &network_length, sizeof(network_length)); !read) {
        return {.served = true};
    }
    const auto frame_size = static_cast<std::size_t>(ntohl(network_length));
    if (frame_size == 0U || frame_size > max_observation_frame_bytes) {
        auto response = encode(enqueue_error_v1{.code = "invalid_request"});
        if (!response) {
            return {.served = std::unexpected(response.error()), .error_number = 0};
        }
        static_cast<void>(send_frame(client.get(), *response));
        return {.served = true};
    }
    std::string frame(frame_size, '\0');
    if (auto read = read_exact(client.get(), frame.data(), frame.size()); !read) {
        wipe(frame);
        return {.served = true};
    }
    auto response = state.handle(frame, current_epoch_ms());
    wipe(frame);
    if (!response) {
        return {.served = std::unexpected(response.error()), .error_number = 0};
    }
    static_cast<void>(send_frame(client.get(), *response));
    return {.served = true};
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
        config.io_timeout_ms > max_io_timeout_ms || config.replay_cache_capacity == 0U ||
        config.replay_cache_capacity > max_replay_cache_capacity) {
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
    state->replays = replay_cache{state->config.replay_cache_capacity};
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

auto observation_intent_unix_server::serve_one_for(std::uint64_t accept_timeout_ms)
    -> std::expected<bool, std::string> {
    if (!state_ || accept_timeout_ms > max_io_timeout_ms) {
        return std::unexpected(std::string{"invalid observation accept timeout"});
    }
    // A transient wait/accept failure (EINTR, fd exhaustion, aborted
    // connection) must not permanently kill the observation channel worker:
    // retry here with a bounded backoff ladder and only surface persistent
    // or fatal errors to the caller.
    for (unsigned attempt = 0;; ++attempt) {
        auto outcome = serve_attempt(*state_, accept_timeout_ms);
        if (outcome.served.has_value()) {
            return outcome.served;
        }
        if (outcome.error_number == 0 ||
            !observation_transient_accept_error(outcome.error_number) ||
            attempt + 1U >= max_transient_accept_retries) {
            return std::unexpected(std::move(outcome.served.error()));
        }
        transient_backoff(attempt);
    }
}

auto observation_intent_unix_server::socket_path() const -> const std::filesystem::path& {
    static const std::filesystem::path empty;
    return state_ ? state_->config.socket_path : empty;
}

} // namespace glove::control
