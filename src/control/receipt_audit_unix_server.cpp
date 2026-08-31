#include "glove/control/receipt_audit_unix_server.hpp"

#include "glove/audit/event.hpp"
#include "glove/control/receipt_audit_protocol.hpp"

#include "receipt_audit_unix_server_detail.hpp"
#include "receipt_wire.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::control {

namespace {

constexpr std::uint64_t max_secret_file_bytes = 128U;
constexpr std::uint64_t max_io_timeout_ms = 60'000U;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    void reset(int descriptor) noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

void wipe(std::string& value) noexcept {
    if (value.empty()) {
        return;
    }
    volatile char* bytes = value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

class sensitive_secret {
public:
    sensitive_secret(std::string bytes, std::size_t begin, std::size_t length)
        : bytes_{std::move(bytes)}, begin_{begin}, length_{length} {}

    sensitive_secret(const sensitive_secret&) = delete;
    auto operator=(const sensitive_secret&) -> sensitive_secret& = delete;

    sensitive_secret(sensitive_secret&& other) noexcept
        : bytes_{std::move(other.bytes_)},
          begin_{std::exchange(other.begin_, 0)},
          length_{std::exchange(other.length_, 0)} {
        wipe(other.bytes_);
    }

    auto operator=(sensitive_secret&&) -> sensitive_secret& = delete;

    ~sensitive_secret() { wipe(bytes_); }

    [[nodiscard]] auto value() const noexcept -> std::string_view {
        return {bytes_.data() + begin_, length_};
    }

private:
    std::string bytes_;
    std::size_t begin_ = 0;
    std::size_t length_ = 0;
};

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto ascii_whitespace(char value) noexcept -> bool {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' ||
           value == '\v';
}

auto modification_time_matches(const struct stat& before, const struct stat& after) noexcept
    -> bool {
#if defined(__APPLE__)
    return before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
#else
    return before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
#endif
}

auto change_time_matches(const struct stat& before, const struct stat& after) noexcept -> bool {
#if defined(__APPLE__)
    return before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    return before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

auto same_file(const struct stat& before, const struct stat& after) noexcept -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           modification_time_matches(before, after) && change_time_matches(before, after);
}

auto load_bootstrap_secret(const std::filesystem::path& path)
    -> std::expected<sensitive_secret, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open bootstrap secret"));
    }

    struct stat before{};

    if (::fstat(descriptor.get(), &before) != 0) {
        return std::unexpected(system_error("inspect bootstrap secret"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(before.st_mode) & permission_mask;
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid() ||
        permissions != owner_permissions || before.st_nlink != 1 || before.st_size < 64 ||
        static_cast<std::uint64_t>(before.st_size) > max_secret_file_bytes) {
        return std::unexpected(
            std::string{"bootstrap secret must be an owner-only, single-link regular file"}
        );
    }
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto result = ::pread(
            descriptor.get(),
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            const auto error = result < 0 ? system_error("read bootstrap secret")
                                          : std::string{"bootstrap secret ended unexpectedly"};
            wipe(bytes);
            return std::unexpected(error);
        }
        consumed += static_cast<std::size_t>(result);
    }

    struct stat after{};

    if (::fstat(descriptor.get(), &after) != 0 || !same_file(before, after)) {
        wipe(bytes);
        return std::unexpected(std::string{"bootstrap secret changed while loading"});
    }
    std::size_t begin = 0;
    while (begin < bytes.size() && ascii_whitespace(bytes[begin])) {
        ++begin;
    }
    std::size_t end = bytes.size();
    while (end > begin && ascii_whitespace(bytes[end - 1U])) {
        --end;
    }
    const auto valid = end - begin == 64U && std::all_of(
                                                 bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                                                 bytes.begin() + static_cast<std::ptrdiff_t>(end),
                                                 [](char value) {
                                                     return (value >= '0' && value <= '9') ||
                                                            (value >= 'a' && value <= 'f');
                                                 }
                                             );
    if (!valid) {
        wipe(bytes);
        return std::unexpected(std::string{"bootstrap secret must be 32-byte lowercase hex"});
    }
    return sensitive_secret{std::move(bytes), begin, end - begin};
}

auto validate_runtime_directory(const std::filesystem::path& socket_path)
    -> std::expected<void, std::string> {
    if (!socket_path.is_absolute()) {
        return std::unexpected(std::string{"control socket path must be absolute"});
    }
    const auto filename = socket_path.filename().string();
    const auto parent = socket_path.parent_path();
    if (filename.empty() || filename == "." || filename == ".." || parent.empty()) {
        return std::unexpected(std::string{"control socket path is invalid"});
    }
    const unique_fd descriptor{
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
    };
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open control runtime directory"));
    }

    struct stat metadata{};

    if (::fstat(descriptor.get(), &metadata) != 0) {
        return std::unexpected(system_error("inspect control runtime directory"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0700U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        permissions != owner_permissions) {
        return std::unexpected(std::string{"control runtime directory must be owner-only"});
    }
    return {};
}

auto socket_address(const std::filesystem::path& path)
    -> std::expected<std::pair<::sockaddr_un, ::socklen_t>, std::string> {
    const auto value = path.string();
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (value.empty() || value.size() >= sizeof(address.sun_path)) {
        return std::unexpected(std::string{"control socket path exceeds the platform bound"});
    }
    // `sun_path` is a C array required by the POSIX socket ABI.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    std::memcpy(address.sun_path, value.c_str(), value.size() + 1U);
    const auto length = offsetof(::sockaddr_un, sun_path) + value.size() + 1U;
    if (length > static_cast<std::size_t>(std::numeric_limits<::socklen_t>::max())) {
        return std::unexpected(std::string{"control socket address exceeds the platform bound"});
    }
    return std::pair{address, static_cast<::socklen_t>(length)};
}

auto create_listener_socket() -> std::expected<int, std::string> {
#if defined(__linux__)
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if (descriptor < 0) {
        return std::unexpected(system_error("create control socket"));
    }
#if !defined(__linux__)
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        const auto error = system_error("protect control socket descriptor");
        (void)::close(descriptor);
        return std::unexpected(error);
    }
#endif
    return descriptor;
}

auto verify_peer_owner_impl(int descriptor, ::uid_t expected_owner)
    -> std::expected<void, std::string> {
#if defined(__linux__)
    struct ucred credentials{};

    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return std::unexpected(system_error("inspect control peer credentials"));
    }
    if (credentials.uid != expected_owner || credentials.pid <= 0) {
        return std::unexpected(std::string{"control peer uid does not match the supervisor"});
    }
#elif defined(__APPLE__)
    ::uid_t user = 0;
    ::gid_t group = 0;
    if (::getpeereid(descriptor, &user, &group) != 0) {
        return std::unexpected(system_error("inspect control peer credentials"));
    }
    if (user != expected_owner) {
        return std::unexpected(std::string{"control peer uid does not match the supervisor"});
    }
#else
    (void)descriptor;
    return std::unexpected(std::string{"control peer credentials are unsupported"});
#endif
    return {};
}

auto apply_timeout(int descriptor, std::uint64_t timeout_ms) -> std::expected<void, std::string> {
    const ::timeval timeout{
        .tv_sec = static_cast<decltype(::timeval::tv_sec)>(timeout_ms / 1'000U),
        .tv_usec = static_cast<decltype(::timeval::tv_usec)>((timeout_ms % 1'000U) * 1'000U),
    };
    if (::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return std::unexpected(system_error("set control socket timeout"));
    }
#if defined(__APPLE__)
    const int enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return std::unexpected(system_error("set control socket no-sigpipe"));
    }
#endif
    return {};
}

auto read_exact(int descriptor, void* output, std::size_t size)
    -> std::expected<void, std::string> {
    auto* bytes = static_cast<std::byte*>(output);
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto result = ::recv(descriptor, bytes + consumed, size - consumed, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return std::unexpected(std::string{"control frame read timed out"});
        }
        if (result < 0) {
            return std::unexpected(system_error("read control frame"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"control peer closed the frame"});
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto send_exact(int descriptor, const void* input, std::size_t size)
    -> std::expected<void, std::string> {
    const auto* bytes = static_cast<const std::byte*>(input);
    std::size_t sent = 0;
    while (sent < size) {
#if defined(MSG_NOSIGNAL)
        const auto result = ::send(descriptor, bytes + sent, size - sent, MSG_NOSIGNAL);
#else
        const auto result = ::send(descriptor, bytes + sent, size - sent, 0);
#endif
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return std::unexpected(std::string{"control frame write timed out"});
        }
        if (result < 0) {
            return std::unexpected(system_error("write control frame"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"control frame write made no progress"});
        }
        sent += static_cast<std::size_t>(result);
    }
    return {};
}

auto decode_frame_size(const std::array<std::uint8_t, 4>& bytes) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
}

auto encode_frame_size(std::uint32_t size) noexcept -> std::array<std::uint8_t, 4> {
    return {
        static_cast<std::uint8_t>(size >> 24U),
        static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U),
        static_cast<std::uint8_t>(size),
    };
}

auto epoch_milliseconds() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    return milliseconds < 0 ? 0U : static_cast<std::uint64_t>(milliseconds);
}

} // namespace

namespace detail {

auto verify_peer_owner(int descriptor, ::uid_t expected_owner) -> std::expected<void, std::string> {
    return verify_peer_owner_impl(descriptor, expected_owner);
}

namespace {

auto record_control_delivery_audit(
    const std::shared_ptr<audit::sink>& control_audit,
    std::string_view method,
    std::string_view session_id,
    bool replay,
    std::string_view transport_error
) -> void {
    if (!control_audit) {
        return;
    }
    std::string subject{method};
    if (replay) {
        subject += ":replay";
    }
    if (!session_id.empty()) {
        subject += ':';
        subject += session_id;
    }
    const audit::event record{
        .what = audit::action::control,
        .tool_name = std::move(subject),
        .arguments_json = {},
        .status = mcp::tool_call_status::transport_error,
        .error_message = std::string{transport_error},
    };
    // Control-audit recording is best-effort by policy (unlike the
    // receipt-chain audit, which stays fail-closed): a sink write failure is
    // surfaced as a structured operator log instead of being silently
    // discarded, and it must never turn a connection-scoped delivery failure
    // into a daemon-fatal error.
    if (auto recorded = control_audit->record(record); !recorded) {
        std::fprintf(
            stderr,
            "gloved: control audit event %s was not recorded: %s\n",
            record.tool_name.c_str(),
            recorded.error().c_str()
        );
    }
}

} // namespace

auto degrade_failed_delivery(
    const receipt_audit_unix_server_config& config,
    const receipt_control_outcome& outcome,
    std::string_view transport_error
) -> void {
    // The outcome metadata was produced by the real dispatch in handle_frame.
    // The raw frame is never re-decoded here: re-decoding carries no
    // authentication, schema, deadline, or application evidence, so it can
    // never grant teardown authority.
    record_control_delivery_audit(
        config.control_audit, outcome.method, outcome.session_id, outcome.replay, transport_error
    );

    // A guest launched by a genuinely fresh, applied start_session would
    // outlive its vanished controller connection. Tear it down through the
    // normal idempotent stop path, which preserves the pending-before-release
    // audit guarantees and produces the authenticated terminal receipt. Every
    // other outcome — wrong secret, unauthenticated peer, expired deadline,
    // schema mismatch, rejected start, an idempotent start replay (the
    // already-running guest was launched by an earlier, delivered request),
    // or a non-start method — gets no stop attempt: only the
    // connection-scoped audit event above. Stop failures are recorded and
    // logged, never fatal: integrity failures cannot reach this path because
    // handle_frame applied the request and only the transport write failed.
    const bool degradable = outcome.authenticated && outcome.applied && outcome.response_success &&
                            outcome.method == "start_session" && !outcome.session_id.empty();
    if (!degradable || !config.runtime || !config.runtime->lifecycle_operational()) {
        return;
    }
    if (auto stopped = config.runtime->stop(outcome.session_id); !stopped) {
        std::fprintf(
            stderr,
            "gloved: degraded session %s after control delivery failure: %s\n",
            outcome.session_id.c_str(),
            stopped.error().c_str()
        );
        record_control_delivery_audit(
            config.control_audit, "degrade_stop", outcome.session_id, false, stopped.error()
        );
        return;
    }
    std::fprintf(
        stderr,
        "gloved: degraded session %s after control delivery failure: guest stopped\n",
        outcome.session_id.c_str()
    );
}

} // namespace detail

struct receipt_audit_unix_server::implementation {
    receipt_audit_unix_server_config config;
    unique_fd listener;
    std::unique_ptr<receipt_audit_protocol> protocol;
    std::mutex serve_mutex;
    ::dev_t socket_device = 0;
    ::ino_t socket_inode = 0;
    bool owns_socket_path = false;

    implementation() = default;
    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;
    implementation(implementation&&) = delete;
    auto operator=(implementation&&) -> implementation& = delete;

    ~implementation() {
        if (!owns_socket_path) {
            return;
        }

        struct stat metadata{};

        if (::lstat(config.socket_path.c_str(), &metadata) == 0 &&
            metadata.st_dev == socket_device && metadata.st_ino == socket_inode &&
            S_ISSOCK(metadata.st_mode)) {
            (void)::unlink(config.socket_path.c_str());
        }
    }
};

receipt_audit_unix_server::receipt_audit_unix_server(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

receipt_audit_unix_server::~receipt_audit_unix_server() = default;

auto receipt_audit_unix_server::create(receipt_audit_unix_server_config config)
    -> std::expected<std::unique_ptr<receipt_audit_unix_server>, std::string> {
    if (config.io_timeout_ms == 0 || config.io_timeout_ms > max_io_timeout_ms ||
        config.bootstrap_secret_path.empty() || config.producer.key_path.empty() ||
        config.producer.journal_path.empty()) {
        return std::unexpected(std::string{"receipt audit Unix server configuration is invalid"});
    }
    if (auto valid = validate_runtime_directory(config.socket_path); !valid) {
        return std::unexpected(valid.error());
    }
    auto address = socket_address(config.socket_path);
    if (!address) {
        return std::unexpected(address.error());
    }

    struct stat existing{};

    if (::lstat(config.socket_path.c_str(), &existing) == 0 || errno != ENOENT) {
        return std::unexpected(
            std::string{"control socket path already exists or is inaccessible"}
        );
    }
    auto secret = load_bootstrap_secret(config.bootstrap_secret_path);
    if (!secret) {
        return std::unexpected(secret.error());
    }
    // The session runtime is shared, not moved: the protocol needs it to
    // dispatch start_session, and the degrade path below needs the SAME live
    // pointer after construction to tear a guest down when the response write
    // to its controller fails. Moving it into the protocol would leave the
    // stored config with an empty pointer, silently disabling guest teardown
    // forever after construction.
    auto protocol = receipt_audit_protocol::create(
        secret->value(),
        config.producer,
        config.plan_validator,
        config.sessions,
        config.runtime,
        config.path_exposures,
        std::move(config.materialization_root),
        config.local_services
    );
    if (!protocol) {
        return std::unexpected(protocol.error());
    }

    auto state = std::make_unique<implementation>();
    state->config = std::move(config);
    state->protocol = std::move(*protocol);
    auto listener = create_listener_socket();
    if (!listener) {
        return std::unexpected(listener.error());
    }
    state->listener.reset(*listener);
    if (::bind(
            state->listener.get(),
            // POSIX intentionally aliases protocol-specific addresses through `sockaddr`.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const ::sockaddr*>(&address->first),
            address->second
        ) != 0) {
        return std::unexpected(system_error("bind control socket"));
    }
    state->owns_socket_path = true;
    if (::chmod(state->config.socket_path.c_str(), 0600) != 0) {
        return std::unexpected(system_error("protect control socket"));
    }

    struct stat metadata{};

    if (::lstat(state->config.socket_path.c_str(), &metadata) != 0 || !S_ISSOCK(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U) {
        return std::unexpected(std::string{"control socket identity or permissions are unsafe"});
    }
    state->socket_device = metadata.st_dev;
    state->socket_inode = metadata.st_ino;
    if (::listen(state->listener.get(), 16) != 0) {
        return std::unexpected(system_error("listen on control socket"));
    }
    return std::make_unique<receipt_audit_unix_server>(construction_token{}, std::move(state));
}

auto receipt_audit_unix_server::serve_one()
    -> std::expected<receipt_audit_serve_outcome, std::string> {
    const std::scoped_lock lock{state_->serve_mutex};
    int accepted = -1;
    do {
#if defined(__linux__)
        accepted = ::accept4(state_->listener.get(), nullptr, nullptr, SOCK_CLOEXEC);
#else
        accepted = ::accept(state_->listener.get(), nullptr, nullptr);
#endif
    } while (accepted < 0 && errno == EINTR);
    if (accepted < 0) {
        return std::unexpected(system_error("accept control connection"));
    }
    const unique_fd connection{accepted};
#if !defined(__linux__)
    if (::fcntl(connection.get(), F_SETFD, FD_CLOEXEC) != 0) {
        return std::unexpected(system_error("protect control connection descriptor"));
    }
#endif
    if (auto peer = detail::verify_peer_owner(connection.get(), ::geteuid()); !peer) {
        return std::unexpected(peer.error());
    }
    if (auto timeout = apply_timeout(connection.get(), state_->config.io_timeout_ms); !timeout) {
        return std::unexpected(timeout.error());
    }
    std::array<std::uint8_t, 4> size_bytes{};
    if (auto read = read_exact(connection.get(), size_bytes.data(), size_bytes.size()); !read) {
        return std::unexpected(read.error());
    }
    const auto frame_size = decode_frame_size(size_bytes);
    if (frame_size == 0 || frame_size > max_control_frame_bytes) {
        return std::unexpected(std::string{"invalid control frame size"});
    }
    std::string frame(frame_size, '\0');
    if (auto read = read_exact(connection.get(), frame.data(), frame.size()); !read) {
        return std::unexpected(read.error());
    }
    // Structured authenticated/applied outcome metadata from the real
    // dispatch. This — never a re-decode of the raw frame — is the only
    // input the degrade path may act on.
    receipt_control_outcome request_outcome;
    auto response = state_->protocol->handle_frame(frame, epoch_milliseconds(), &request_outcome);
    if (!response) {
        wipe(frame);
        return std::unexpected(response.error());
    }
    if (response->empty() || response->size() > max_control_frame_bytes ||
        response->size() > std::numeric_limits<std::uint32_t>::max()) {
        wipe(frame);
        return std::unexpected(std::string{"invalid control response size"});
    }
    const auto response_size = encode_frame_size(static_cast<std::uint32_t>(response->size()));
    // From here the only possible failure is a transport-level write to the
    // already-authenticated connection: the client vanished (broken pipe) or
    // stopped reading. That failure is scoped to this connection. Degrade the
    // request's session (structured audit event, guest teardown) and keep the
    // daemon serving; audit-chain and integrity failures cannot reach this
    // path because handle_frame already applied and validated everything.
    if (auto sent = send_exact(connection.get(), response_size.data(), response_size.size());
        !sent) {
        detail::degrade_failed_delivery(state_->config, request_outcome, sent.error());
        wipe(frame);
        return receipt_audit_serve_outcome::connection_failed;
    }
    if (auto sent = send_exact(connection.get(), response->data(), response->size()); !sent) {
        detail::degrade_failed_delivery(state_->config, request_outcome, sent.error());
        wipe(frame);
        return receipt_audit_serve_outcome::connection_failed;
    }
    wipe(frame);
    return receipt_audit_serve_outcome::served;
}

auto receipt_audit_unix_server::serve_one_for(std::uint64_t accept_timeout_ms)
    -> std::expected<std::optional<receipt_audit_serve_outcome>, std::string> {
    if (accept_timeout_ms == 0 || accept_timeout_ms > max_io_timeout_ms) {
        return std::unexpected(std::string{"control accept timeout is invalid"});
    }

    ::pollfd readiness{
        .fd = state_->listener.get(),
        .events = POLLIN,
        .revents = 0,
    };
    const auto result = ::poll(&readiness, 1, static_cast<int>(accept_timeout_ms));
    if (result < 0 && errno == EINTR) {
        return std::nullopt;
    }
    if (result < 0) {
        return std::unexpected(system_error("poll control listener"));
    }
    if (result == 0) {
        return std::nullopt;
    }
    const auto ready_events = static_cast<unsigned short>(readiness.revents);
    if ((ready_events & static_cast<unsigned short>(POLLIN)) == 0U) {
        return std::unexpected(std::string{"control listener became unavailable"});
    }
    return serve_one();
}

} // namespace glove::control
