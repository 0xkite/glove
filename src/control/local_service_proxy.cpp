#include "glove/control/local_service_proxy.hpp"

#include "glove/container/digest.hpp"
#include "glove/control/guest_channel_transport.hpp"

#include "linux_session_executor.hpp"

#include <fcntl.h>
#include <linux/mount.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <exception>
#include <new>
#include <optional>
#include <set>
#include <stop_token>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>

namespace glove::control::linux_detail {
namespace {

constexpr std::size_t max_frame_bytes = std::size_t{16} * 1024U;
constexpr std::size_t max_session_id_bytes = 128U;
constexpr std::size_t max_path_ancestors = 256U;

auto next_factory_generation() noexcept -> std::uint64_t {
    static std::atomic_uint64_t generation{[]() noexcept {
        timespec now{};
        static_cast<void>(::clock_gettime(CLOCK_MONOTONIC, &now));
        return (static_cast<std::uint64_t>(now.tv_sec) << 32U) ^
               static_cast<std::uint64_t>(now.tv_nsec) ^ static_cast<std::uint64_t>(::getpid());
    }()};
    return generation.fetch_add(1U);
}

auto next_session_generation() noexcept -> std::uint64_t {
    static std::atomic_uint64_t generation{1U};
    return generation.fetch_add(1U);
}

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            if (descriptor_ >= 0) {
                static_cast<void>(::close(descriptor_));
            }
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    int descriptor_ = -1;
};

struct file_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t uid = 0;
    std::uint32_t mode = 0;
    std::uint64_t links = 0;

    auto operator==(const file_identity&) const -> bool = default;
};

struct pinned_endpoint {
    std::string alias;
    std::vector<std::string> runtime_ids;
    unique_fd parent;
    file_identity parent_identity;
    std::vector<file_identity> parent_ancestors;
    std::string name;
    file_identity identity;
};

struct listener_record {
    std::shared_ptr<const pinned_endpoint> endpoint;
    unique_fd listener;
    file_identity identity;
};

struct inherited_stream_record {
    std::shared_ptr<const pinned_endpoint> endpoint;
    unique_fd supervisor;
    unique_fd guest;
    file_identity supervisor_identity;
    file_identity guest_identity;
    int child_fd = -1;
};

auto valid_identifier(std::string_view value, std::size_t max_bytes = 64U) -> bool {
    return !value.empty() && value.size() <= max_bytes && value != "." && value != ".." &&
           std::ranges::all_of(value, [](const char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto valid_runtime_id(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 64U && value.front() >= 'a' && value.front() <= 'z' &&
           std::ranges::all_of(value, [](const char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') || byte == '-';
           });
}

auto identity(const struct stat& status) -> file_identity {
    return {
        .device = static_cast<std::uint64_t>(status.st_dev),
        .inode = static_cast<std::uint64_t>(status.st_ino),
        .uid = static_cast<std::uint32_t>(status.st_uid),
        .mode = static_cast<std::uint32_t>(status.st_mode),
        .links = static_cast<std::uint64_t>(status.st_nlink),
    };
}

auto same_identity(const file_identity& expected, const struct stat& status) -> bool {
    return expected == identity(status);
}

// The runtime root's link count must not participate in the operational
// identity. On ext4, tmpfs, and APFS a directory's st_nlink is 2 plus its
// subdirectory count, so every legitimate prepare_session - which mkdirat(2)s
// a svc-* staging directory under the root - and its inode-safe teardown
// necessarily changes the root's link count. That term therefore could never
// distinguish sanctioned staging from tampering (only subdirectory creation
// moves it; files and symlinks do not) while it rejected any second
// operational check sharing the root as false "identity drift": a second
// factory over the same runtime root, or the same factory's next session,
// failed once one session existed (Workflow #218 Ghost E2E, baseline
// LastTest.log line 666, root nlink 2 -> 3 verified by instrumentation).
// Entry-level enumeration whitelisting would not add a real enforcement
// claim either: the production runtime root is shared with the gloved
// instance lock and control socket (src/gloved_main.cpp), and same-UID
// writes to this owner-only root are trusted operator authority per
// docs/session-policy.md. Genuine drift still fails closed: the root's
// dev/ino (replacement), uid, and mode (permission drift) terms stay exact,
// and the descriptor-pinned endpoint parents and their sockets retain the
// exact dev/ino/uid/mode/nlink recheck in endpoint_current(), which is where
// the recorded endpoint identity drift claim (docs/architecture.md) is
// enforced.
auto root_identity_current(const file_identity& expected, const struct stat& status) noexcept
    -> bool {
    return expected.device == static_cast<std::uint64_t>(status.st_dev) &&
           expected.inode == static_cast<std::uint64_t>(status.st_ino) &&
           expected.uid == static_cast<std::uint32_t>(status.st_uid) &&
           expected.mode == static_cast<std::uint32_t>(status.st_mode);
}

auto same_object(const file_identity& left, const file_identity& right) noexcept -> bool {
    return left.device == right.device && left.inode == right.inode;
}

auto errno_message(int error) -> std::string {
    return std::error_code{error, std::generic_category()}.message();
}

class bound_socket_rollback {
public:
    bound_socket_rollback(int directory, const std::string& alias) noexcept
        : directory_{directory}, alias_{&alias} {
        struct stat current{};
        if (::fstatat(directory_, alias_->c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISSOCK(current.st_mode)) {
            identity_ = identity(current);
            active_ = true;
        }
    }

    bound_socket_rollback(const bound_socket_rollback&) = delete;
    auto operator=(const bound_socket_rollback&) -> bound_socket_rollback& = delete;
    bound_socket_rollback(bound_socket_rollback&&) = delete;
    auto operator=(bound_socket_rollback&&) -> bound_socket_rollback& = delete;

    ~bound_socket_rollback() {
        if (!active_) {
            return;
        }
        struct stat current{};
        if (::fstatat(directory_, alias_->c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_identity(identity_, current)) {
            static_cast<void>(::unlinkat(directory_, alias_->c_str(), 0));
        }
    }

    void dismiss() noexcept { active_ = false; }

private:
    int directory_ = -1;
    const std::string* alias_ = nullptr;
    file_identity identity_;
    bool active_ = false;
};

auto directory_ancestors(int descriptor) -> std::expected<std::vector<file_identity>, std::string> {
    unique_fd current{::fcntl(descriptor, F_DUPFD_CLOEXEC, 3)};
    if (current.get() < 0) {
        return std::unexpected(std::string{"local service endpoint is unavailable"});
    }
    std::vector<file_identity> ancestors;
    ancestors.reserve(16U);
    for (;;) {
        if (ancestors.size() == max_path_ancestors) {
            return std::unexpected(std::string{"local service endpoint is unavailable"});
        }
        struct stat current_status{};
        if (::fstat(current.get(), &current_status) != 0 || !S_ISDIR(current_status.st_mode)) {
            return std::unexpected(std::string{"local service endpoint is unavailable"});
        }
        const auto current_identity = identity(current_status);
        ancestors.push_back(current_identity);
        unique_fd parent{
            ::openat(current.get(), "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        struct stat parent_status{};
        if (parent.get() < 0 || ::fstat(parent.get(), &parent_status) != 0 ||
            !S_ISDIR(parent_status.st_mode)) {
            return std::unexpected(std::string{"local service endpoint is unavailable"});
        }
        if (same_object(current_identity, identity(parent_status))) {
            return ancestors;
        }
        current = std::move(parent);
    }
}

auto inspect_socket(int parent, std::string_view name)
    -> std::expected<file_identity, std::string> {
    struct stat status{};
    if (::fstatat(parent, std::string{name}.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(status.st_mode) || status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(status.st_mode) & 0777U) != 0600U || status.st_nlink != 1 ||
        status.st_dev == 0 || status.st_ino == 0) {
        return std::unexpected(std::string{"local service endpoint is unavailable"});
    }
    return identity(status);
}

auto create_inherited_socketpair() -> std::expected<std::pair<unique_fd, unique_fd>, std::string> {
    int descriptors[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, descriptors) != 0) {
        return std::unexpected(std::string{"local service inherited stream is unavailable"});
    }
    unique_fd first{descriptors[0]};
    unique_fd second{descriptors[1]};
    if (::fchmod(first.get(), 0600) != 0 || ::fchmod(second.get(), 0600) != 0) {
        return std::unexpected(std::string{"local service inherited stream is unavailable"});
    }
    for (const int descriptor : {first.get(), second.get()}) {
        struct stat status{};
        int domain = 0;
        int type = 0;
        int accept_connection = 0;
        const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
        const int status_flags = ::fcntl(descriptor, F_GETFL);
        socklen_t size = sizeof(int);
        if (::fstat(descriptor, &status) != 0 || !S_ISSOCK(status.st_mode) ||
            status.st_uid != ::geteuid() || status.st_nlink != 1 || status.st_dev == 0 ||
            status.st_ino == 0 || (static_cast<unsigned int>(status.st_mode) & 0777U) != 0600U ||
            descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0 || status_flags < 0 ||
            (status_flags & O_NONBLOCK) == 0 ||
            ::getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &domain, &size) != 0 ||
            domain != AF_UNIX || ::getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
            type != SOCK_STREAM ||
            ::getsockopt(descriptor, SOL_SOCKET, SO_ACCEPTCONN, &accept_connection, &size) != 0 ||
            accept_connection != 0) {
            return std::unexpected(std::string{"local service inherited stream is unavailable"});
        }
    }
    return std::pair{std::move(first), std::move(second)};
}

auto endpoint_current(const pinned_endpoint& endpoint) noexcept -> bool {
    struct stat parent_status{};
    struct stat status{};
    return ::fstat(endpoint.parent.get(), &parent_status) == 0 &&
           same_identity(endpoint.parent_identity, parent_status) &&
           ::fstatat(endpoint.parent.get(), endpoint.name.c_str(), &status, AT_SYMLINK_NOFOLLOW) ==
               0 &&
           same_identity(endpoint.identity, status);
}

auto proc_path(int directory_fd, std::string_view name = {}) -> std::string {
    auto path = std::string{"/proc/self/fd/"} + std::to_string(directory_fd);
    if (!name.empty()) {
        path.push_back('/');
        path.append(name);
    }
    return path;
}

auto socket_address(std::string_view path)
    -> std::expected<std::pair<sockaddr_un, socklen_t>, std::string> {
    if (path.empty() || path.size() >= sizeof(sockaddr_un::sun_path)) {
        return std::unexpected(std::string{"local service endpoint is unavailable"});
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.data(), path.size());
    address.sun_path[path.size()] = '\0';
    return std::pair{
        address,
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1U),
    };
}

auto remaining_milliseconds(guest_channel_deadline deadline) -> int {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return 0;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    return static_cast<int>(
        std::min<std::int64_t>(std::max<std::int64_t>(remaining.count(), 1), 50)
    );
}

auto connect_endpoint(
    const pinned_endpoint& endpoint, guest_channel_deadline deadline, const std::stop_token& stop
) -> std::expected<int, std::string> {
    if (!endpoint_current(endpoint)) {
        return std::unexpected(std::string{"local service endpoint is unavailable"});
    }
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (descriptor.get() < 0) {
        return std::unexpected(std::string{"local service connection failed"});
    }
    auto address = socket_address(proc_path(endpoint.parent.get(), endpoint.name));
    if (!address) {
        return std::unexpected(address.error());
    }
    if (::connect(
            descriptor.get(), reinterpret_cast<const sockaddr*>(&address->first), address->second
        ) != 0) {
        if (errno != EINPROGRESS) {
            return std::unexpected(std::string{"local service connection failed"});
        }
        while (!stop.stop_requested() && std::chrono::steady_clock::now() < deadline) {
            pollfd wait{.fd = descriptor.get(), .events = POLLOUT, .revents = 0};
            const int ready = ::poll(&wait, 1, remaining_milliseconds(deadline));
            if (ready == 0 || (ready < 0 && errno == EINTR)) {
                continue;
            }
            int socket_error = 0;
            socklen_t length = sizeof(socket_error);
            if (ready < 0 ||
                ::getsockopt(descriptor.get(), SOL_SOCKET, SO_ERROR, &socket_error, &length) != 0 ||
                socket_error != 0) {
                return std::unexpected(std::string{"local service connection failed"});
            }
            break;
        }
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            return std::unexpected(std::string{"local service connection failed"});
        }
    }
    if (!endpoint_current(endpoint)) {
        return std::unexpected(std::string{"local service endpoint is unavailable"});
    }
    return descriptor.release();
}

void append_u64(std::vector<unsigned char>& bytes, std::uint64_t value) {
    for (std::uint32_t shift = 56U;; shift -= 8U) {
        bytes.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
        if (shift == 0U) {
            break;
        }
    }
}

void append_string(std::vector<unsigned char>& bytes, std::string_view value) {
    append_u64(bytes, value.size());
    bytes.insert(bytes.end(), value.begin(), value.end());
}

auto endpoint_manifest(
    std::uint64_t generation,
    std::string_view runtime_id,
    const std::vector<std::shared_ptr<const pinned_endpoint>>& endpoints
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> bytes;
    append_string(bytes, "glove.local-service-proxy");
    append_u64(bytes, 1U);
    append_u64(bytes, generation);
    append_string(bytes, runtime_id);
    append_u64(bytes, endpoints.size());
    for (const auto& endpoint : endpoints) {
        append_string(bytes, endpoint->alias);
        append_u64(bytes, endpoint->parent_identity.device);
        append_u64(bytes, endpoint->parent_identity.inode);
        append_u64(bytes, endpoint->parent_identity.uid);
        append_u64(bytes, endpoint->parent_identity.mode);
        append_u64(bytes, endpoint->parent_identity.links);
        append_u64(bytes, endpoint->identity.device);
        append_u64(bytes, endpoint->identity.inode);
        append_u64(bytes, endpoint->identity.uid);
        append_u64(bytes, endpoint->identity.mode);
        append_u64(bytes, endpoint->identity.links);
    }
    return container::sha256_hex(bytes);
}

} // namespace

struct local_service_proxy_factory::implementation {
    unique_fd runtime_root_fd;
    file_identity runtime_root_identity;
    std::uint64_t io_timeout_ms = 0;
    std::uint32_t max_concurrency = 0;
    std::uint64_t generation = 0;
    std::vector<std::shared_ptr<const pinned_endpoint>> endpoints;
    std::shared_ptr<audit::sink> audit;
    std::shared_ptr<const guest_channel_adapter_binding> guest_channel_adapter;
    bool adapter_catalog_admits_schema = false;
    std::shared_ptr<session_registry> registry;
};

struct local_service_proxy_session::implementation {
    implementation() = default;
    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;
    implementation(implementation&&) = delete;
    auto operator=(implementation&&) -> implementation& = delete;

    ~implementation() {
        for (auto& thread : workers) {
            thread.request_stop();
        }
        for (auto& listener : listeners) {
            if (listener.listener.get() >= 0) {
                static_cast<void>(::shutdown(listener.listener.get(), SHUT_RDWR));
            }
        }
        for (auto& stream : inherited_streams) {
            if (stream.supervisor.get() >= 0) {
                static_cast<void>(::shutdown(stream.supervisor.get(), SHUT_RDWR));
            }
            if (stream.guest.get() >= 0) {
                static_cast<void>(::shutdown(stream.guest.get(), SHUT_RDWR));
            }
        }
        workers.clear();
        for (const auto& listener : listeners) {
            struct stat status{};
            if (::fstatat(
                    directory.get(), listener.endpoint->alias.c_str(), &status, AT_SYMLINK_NOFOLLOW
                ) == 0 &&
                same_identity(listener.identity, status)) {
                static_cast<void>(::unlinkat(directory.get(), listener.endpoint->alias.c_str(), 0));
            }
        }
        listeners.clear();
        struct stat status{};
        if (root_fd.get() >= 0 && directory.get() >= 0 && ::fstat(directory.get(), &status) == 0 &&
            same_identity(directory_identity, status)) {
            directory = unique_fd{};
            struct stat current{};
            if (::fstatat(root_fd.get(), directory_name.c_str(), &current, AT_SYMLINK_NOFOLLOW) ==
                    0 &&
                same_identity(directory_identity, current)) {
                static_cast<void>(::unlinkat(root_fd.get(), directory_name.c_str(), AT_REMOVEDIR));
            }
        }
    }

    unique_fd directory;
    unique_fd root_fd;
    std::string directory_name;
    file_identity directory_identity;
    std::string session_id;
    std::string manifest;
    std::optional<std::string> adapter_environment;
    bool inherited = false;
    std::uint64_t io_timeout_ms = 0;
    std::shared_ptr<audit::sink> audit;
    std::vector<std::shared_ptr<const pinned_endpoint>> endpoints;
    std::vector<listener_record> listeners;
    std::vector<inherited_stream_record> inherited_streams;
    std::vector<std::vector<pollfd>> worker_poll_sets;
    std::vector<std::jthread> workers;
};

namespace {

struct audit_append_result {
    bool recorded = false;
    bool within_deadline = false;
};

auto append_delivery_audit(
    local_service_proxy_session::implementation& state,
    std::size_t endpoint_index,
    std::string_view phase,
    mcp::tool_call_status status,
    std::chrono::steady_clock::time_point started,
    guest_channel_deadline deadline
) noexcept -> audit_append_result {
    if (std::chrono::steady_clock::now() >= deadline) {
        return {};
    }
    try {
        const audit::event record{
            .what = audit::action::local_service,
            .tool_name = state.session_id + ":" + state.endpoints[endpoint_index]->alias,
            .arguments_json = {},
            .status = status,
            .error_message = std::string{phase},
            .latency = std::chrono::steady_clock::now() - started,
        };
        const auto appended = state.audit->record(record);
        return {
            .recorded = appended.has_value(),
            .within_deadline = appended.has_value() && std::chrono::steady_clock::now() < deadline,
        };
    } catch (...) {
        return {};
    }
}

auto exchange_upstream(
    const pinned_endpoint& endpoint,
    std::string_view request,
    guest_channel_deadline deadline,
    const std::stop_token& stop
) -> std::optional<std::string> {
    auto connected = connect_endpoint(endpoint, deadline, stop);
    if (!connected) {
        return std::nullopt;
    }
    auto upstream = guest_channel_transport::adopt(
        *connected, max_frame_bytes, static_cast<std::uint32_t>(::geteuid())
    );
    if (!upstream || !(*upstream)->send_frame(request, deadline, stop)) {
        return std::nullopt;
    }
    auto response = (*upstream)->receive_frame(deadline, stop);
    return response ? std::optional<std::string>{std::move(*response)} : std::nullopt;
}

void serve_connection(
    local_service_proxy_session::implementation& state,
    std::size_t endpoint_index,
    int accepted,
    const std::stop_token& stop
) noexcept {
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + std::chrono::milliseconds{state.io_timeout_ms};
    const auto append_failure = [&] {
        static_cast<void>(append_delivery_audit(
            state,
            endpoint_index,
            "delivery_failed",
            mcp::tool_call_status::transport_error,
            started,
            deadline
        ));
    };
    try {
        auto guest = guest_channel_transport::adopt(
            accepted, max_frame_bytes, static_cast<std::uint32_t>(::geteuid())
        );
        if (!guest) {
            append_failure();
            return;
        }
        auto request = (*guest)->receive_frame(deadline, stop);
        if (!request) {
            append_failure();
            return;
        }
        auto response =
            exchange_upstream(*state.endpoints[endpoint_index], *request, deadline, stop);
        if (!response) {
            append_failure();
            return;
        }
        const auto pending = append_delivery_audit(
            state,
            endpoint_index,
            "delivery_pending",
            mcp::tool_call_status::transport_error,
            started,
            deadline
        );
        if (!pending.recorded || !pending.within_deadline) {
            return;
        }
        if ((*guest)->send_frame(*response, deadline, stop)) {
            static_cast<void>(append_delivery_audit(
                state, endpoint_index, "delivered", mcp::tool_call_status::ok, started, deadline
            ));
            return;
        }
        append_failure();
    } catch (...) {
        // Construction and transport failures follow the same conservative terminal audit.
        append_failure();
    }
}

void inherited_worker(
    local_service_proxy_session::implementation& state,
    std::size_t endpoint_index,
    const std::stop_token& stop
) noexcept {
    const int socket = state.inherited_streams[endpoint_index].supervisor.get();

    struct shutdown_guard {
        int descriptor = -1;

        ~shutdown_guard() {
            if (descriptor >= 0) {
                static_cast<void>(::shutdown(descriptor, SHUT_RDWR));
            }
        }
    } shutdown_on_exit{socket};

    const int duplicate = ::fcntl(socket, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        return;
    }
    auto guest = guest_channel_transport::adopt(
        duplicate, max_frame_bytes, static_cast<std::uint32_t>(::geteuid())
    );
    if (!guest) {
        return;
    }
    while (!stop.stop_requested()) {
        pollfd readiness{.fd = socket, .events = POLLIN, .revents = 0};
        const int ready = ::poll(&readiness, 1, 100);
        if (ready == 0 || (ready < 0 && errno == EINTR)) {
            continue;
        }
        if (ready < 0 || (static_cast<unsigned short>(readiness.revents) &
                          static_cast<unsigned short>(POLLIN | POLLHUP | POLLERR)) == 0U) {
            return;
        }
        const auto started = std::chrono::steady_clock::now();
        const auto deadline = started + std::chrono::milliseconds{state.io_timeout_ms};
        const auto append_failure = [&] {
            static_cast<void>(append_delivery_audit(
                state,
                endpoint_index,
                "delivery_failed",
                mcp::tool_call_status::transport_error,
                started,
                deadline
            ));
        };
        auto request = (*guest)->receive_frame(deadline, stop);
        if (!request) {
            if (!stop.stop_requested()) {
                append_failure();
            }
            return;
        }
        const auto request_boundary_clean = [&] {
            char trailing = 0;
            const auto pending = ::recv(socket, &trailing, 1, MSG_PEEK | MSG_DONTWAIT);
            return pending < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
        };
        if (!request_boundary_clean()) {
            append_failure();
            return;
        }
        auto response =
            exchange_upstream(*state.endpoints[endpoint_index], *request, deadline, stop);
        if (!response || !request_boundary_clean()) {
            append_failure();
            return;
        }
        const auto audit = append_delivery_audit(
            state,
            endpoint_index,
            "delivery_pending",
            mcp::tool_call_status::transport_error,
            started,
            deadline
        );
        if (!audit.recorded || !audit.within_deadline || !request_boundary_clean() ||
            !(*guest)->send_frame(*response, deadline, stop) || !request_boundary_clean()) {
            append_failure();
            return;
        }
        static_cast<void>(append_delivery_audit(
            state, endpoint_index, "delivered", mcp::tool_call_status::ok, started, deadline
        ));
    }
}

void worker(
    local_service_proxy_session::implementation& state,
    std::size_t worker_index,
    const std::stop_token& stop
) noexcept {
    auto& descriptors = state.worker_poll_sets[worker_index];
    std::size_t cursor = worker_index % descriptors.size();
    while (!stop.stop_requested()) {
        for (std::size_t index = 0; index < state.listeners.size(); ++index) {
            descriptors[index] = {
                .fd = state.listeners[index].listener.get(),
                .events = POLLIN,
                .revents = 0,
            };
        }
        const int ready = ::poll(descriptors.data(), descriptors.size(), 100);
        if (ready <= 0) {
            continue;
        }
        for (std::size_t offset = 0; offset < descriptors.size(); ++offset) {
            const auto index = (cursor + offset) % descriptors.size();
            if ((static_cast<unsigned short>(descriptors[index].revents) &
                 static_cast<unsigned short>(POLLIN)) == 0U) {
                continue;
            }
            cursor = (index + 1U) % descriptors.size();
            const int accepted =
                ::accept4(descriptors[index].fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (accepted >= 0) {
                serve_connection(state, index, accepted, stop);
            }
            break;
        }
    }
}

} // namespace

local_service_proxy_session::local_service_proxy_session(
    std::unique_ptr<implementation> state
) noexcept
    : state_{std::move(state)} {}

local_service_proxy_session::~local_service_proxy_session() = default;

auto local_service_proxy_session::mount() const
    -> std::expected<supervisor::linux_detail::session_mount, std::string> {
    if (!state_ || state_->inherited || state_->directory.get() < 0) {
        return std::unexpected(std::string{"local service session is unavailable"});
    }
    struct stat status{};
    if (::fstat(state_->directory.get(), &status) != 0 ||
        !same_identity(state_->directory_identity, status)) {
        return std::unexpected(std::string{"local service session is unavailable"});
    }
    // bind_session_mount installs this descriptor with move_mount(2), which
    // accepts only a detached mount, never a plain directory descriptor. Clone
    // the verified session directory as a detached open_tree mount so the
    // local-services mount matches every other session mount path.
    const int cloned = static_cast<int>(
        // Linux has no typed libc wrapper for open_tree(2).
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::syscall(
            SYS_open_tree,
            state_->directory.get(),
            "",
            AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
        )
    );
    if (cloned < 0) {
        return std::unexpected(
            std::string{"clone local service session mount: "} + errno_message(errno)
        );
    }
    unique_fd descriptor{cloned};
    try {
        supervisor::linux_detail::session_mount mount;
        mount.target_path = local_service_guest_directory;
        mount.alias = "local-services";
        mount.source_identity = supervisor::path_identity{
            .device = static_cast<std::uint64_t>(status.st_dev),
            .inode = static_cast<std::uint64_t>(status.st_ino),
            .mode = static_cast<std::uint32_t>(status.st_mode),
        };
        mount.service_proxy_manifest_digest = state_->manifest;
        mount.directory = true;
        using mount_result = std::expected<supervisor::linux_detail::session_mount, std::string>;
        static_assert(std::is_nothrow_move_constructible_v<mount_result>);
        mount_result result{std::in_place, std::move(mount)};
        result->descriptor_fd = descriptor.release();
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service mount"});
    }
}

auto local_service_proxy_session::release_inherited_streams()
    -> std::expected<std::vector<local_service_inherited_stream>, std::string> {
    if (!state_ || !state_->inherited || state_->inherited_streams.empty()) {
        return std::unexpected(std::string{"local service inherited stream is unavailable"});
    }
    try {
        std::vector<local_service_inherited_stream> result;
        result.reserve(state_->inherited_streams.size());
        for (const auto& stream : state_->inherited_streams) {
            struct stat guest_status{};
            struct stat supervisor_status{};
            if (stream.guest.get() < 3 || !endpoint_current(*stream.endpoint) ||
                ::fstat(stream.guest.get(), &guest_status) != 0 ||
                ::fstat(stream.supervisor.get(), &supervisor_status) != 0 ||
                !same_identity(stream.guest_identity, guest_status) ||
                !same_identity(stream.supervisor_identity, supervisor_status)) {
                return std::unexpected(
                    std::string{"local service inherited stream is unavailable"}
                );
            }
            result.push_back({
                .alias = stream.endpoint->alias,
                .descriptor_fd = -1,
                .child_fd = stream.child_fd,
                .device = stream.guest_identity.device,
                .inode = stream.guest_identity.inode,
                .uid = stream.guest_identity.uid,
                .mode = stream.guest_identity.mode,
                .links = stream.guest_identity.links,
                .peer_device = stream.supervisor_identity.device,
                .peer_inode = stream.supervisor_identity.inode,
                .peer_uid = stream.supervisor_identity.uid,
                .peer_mode = stream.supervisor_identity.mode,
                .peer_links = stream.supervisor_identity.links,
                .manifest_digest = state_->manifest,
            });
        }
        for (std::size_t index = 0; index < result.size(); ++index) {
            result[index].descriptor_fd = state_->inherited_streams[index].guest.release();
        }
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service inherited stream set"});
    }
}

auto local_service_proxy_session::adapter_environment() const -> std::optional<std::string> {
    return state_ ? state_->adapter_environment : std::nullopt;
}

auto local_service_proxy_session::inherited() const noexcept -> bool {
    return state_ && state_->inherited;
}

auto local_service_proxy_session::inherited_environment() const
    -> std::expected<std::string, std::string> {
    if (!state_ || !state_->inherited || state_->inherited_streams.empty()) {
        return std::unexpected(std::string{"local service inherited stream is unavailable"});
    }
    try {
        std::string result{inherited_stream_environment_name};
        result += "={";
        for (std::size_t index = 0; index < state_->inherited_streams.size(); ++index) {
            if (index != 0U) {
                result.push_back(',');
            }
            result += "\"" + state_->inherited_streams[index].endpoint->alias +
                      "\":" + std::to_string(state_->inherited_streams[index].child_fd);
        }
        result.push_back('}');
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service inherited environment"});
    }
}

local_service_proxy_factory::local_service_proxy_factory(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
) noexcept
    : state_{std::move(state)} {}

local_service_proxy_factory::~local_service_proxy_factory() = default;

auto local_service_proxy_factory::create(
    local_service_proxy_options options, std::shared_ptr<session_registry> registry
) -> std::expected<std::shared_ptr<local_service_proxy_factory>, std::string> {
    try {
        const auto& adapter = options.guest_channel_adapter;
        const bool adapter_valid =
            !adapter ||
            (valid_identifier(adapter->adapter_id, 128U) &&
             valid_identifier(adapter->channel_schema_id, 128U) &&
             (adapter->transport_id.empty() ||
              adapter->transport_id == inherited_stream_transport) &&
             (adapter->transport_id == inherited_stream_transport
                  ? adapter->service_alias && valid_identifier(*adapter->service_alias) &&
                        adapter->service_alias_environment &&
                        !adapter->service_alias_environment->empty() &&
                        adapter->service_alias_environment->find('\0') == std::string::npos
                  : !adapter->service_alias && !adapter->service_alias_environment) &&
             !adapter->runtime_ids.empty() && std::ranges::is_sorted(adapter->runtime_ids) &&
             std::ranges::adjacent_find(adapter->runtime_ids) == adapter->runtime_ids.end() &&
             std::ranges::all_of(adapter->runtime_ids, valid_runtime_id) && adapter->channels &&
             adapter->channels->frozen() && !adapter->channels->empty() &&
             adapter->channels->admits(adapter->channel_schema_id) != nullptr && registry &&
             registry->uses_channel_host(adapter->channels));
        if (!registry || !adapter_valid || !options.audit || options.io_timeout_ms == 0U ||
            options.io_timeout_ms > 60'000U || options.max_concurrency == 0U ||
            options.max_concurrency > 16U || options.endpoints.empty() ||
            options.endpoints.size() > 16U || !options.runtime_root.is_absolute() ||
            options.runtime_root.lexically_normal() != options.runtime_root ||
            !std::ranges::is_sorted(options.endpoints, {}, &local_service_endpoint::alias)) {
            return std::unexpected(std::string{"local service proxy configuration is invalid"});
        }
        unique_fd runtime_root{
            ::open(options.runtime_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        struct stat root_status{};
        if (runtime_root.get() < 0 || ::fstat(runtime_root.get(), &root_status) != 0 ||
            !S_ISDIR(root_status.st_mode) || root_status.st_uid != ::geteuid() ||
            root_status.st_nlink == 0 || root_status.st_dev == 0 || root_status.st_ino == 0 ||
            (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
            return std::unexpected(std::string{"local service proxy runtime is unavailable"});
        }
        auto state = std::make_unique<implementation>();
        state->runtime_root_fd = std::move(runtime_root);
        state->runtime_root_identity = identity(root_status);
        state->io_timeout_ms = options.io_timeout_ms;
        state->max_concurrency = options.max_concurrency;
        state->generation = next_factory_generation();
        state->audit = std::move(options.audit);
        state->guest_channel_adapter = std::move(options.guest_channel_adapter);
        state->adapter_catalog_admits_schema = state->guest_channel_adapter != nullptr;
        state->registry = std::move(registry);
        state->endpoints.reserve(options.endpoints.size());
        std::set<std::pair<std::uint64_t, std::uint64_t>> endpoint_identities;
        for (const auto& endpoint : options.endpoints) {
            const auto parent_path = endpoint.socket_path.parent_path();
            const auto name = endpoint.socket_path.filename().string();
            if (!valid_identifier(endpoint.alias) ||
                endpoint.socket_path.string().find('\0') != std::string::npos ||
                !endpoint.socket_path.is_absolute() ||
                endpoint.socket_path == endpoint.socket_path.root_path() ||
                endpoint.socket_path.lexically_normal() != endpoint.socket_path || name.empty() ||
                name == "." || name == ".." || endpoint.runtime_ids.empty() ||
                !std::ranges::is_sorted(endpoint.runtime_ids) ||
                std::ranges::adjacent_find(endpoint.runtime_ids) != endpoint.runtime_ids.end() ||
                !std::ranges::all_of(endpoint.runtime_ids, valid_runtime_id) ||
                (!state->endpoints.empty() && state->endpoints.back()->alias == endpoint.alias)) {
                return std::unexpected(std::string{"local service proxy configuration is invalid"});
            }
            unique_fd parent{
                ::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            };
            struct stat parent_status{};
            if (parent.get() < 0 || ::fstat(parent.get(), &parent_status) != 0 ||
                !S_ISDIR(parent_status.st_mode) || parent_status.st_uid != ::geteuid() ||
                parent_status.st_nlink == 0 ||
                (static_cast<unsigned int>(parent_status.st_mode) & 0777U) != 0700U) {
                return std::unexpected(std::string{"local service endpoint is unavailable"});
            }
            auto ancestors = directory_ancestors(parent.get());
            auto pinned = inspect_socket(parent.get(), name);
            if (!ancestors || !pinned ||
                !endpoint_identities.emplace(pinned->device, pinned->inode).second) {
                return std::unexpected(std::string{"local service endpoint is unavailable"});
            }
            state->endpoints.push_back(
                std::make_shared<const pinned_endpoint>(pinned_endpoint{
                    .alias = endpoint.alias,
                    .runtime_ids = endpoint.runtime_ids,
                    .parent = std::move(parent),
                    .parent_identity = identity(parent_status),
                    .parent_ancestors = std::move(*ancestors),
                    .name = name,
                    .identity = *pinned,
                })
            );
        }
        if (state->guest_channel_adapter &&
            state->guest_channel_adapter->transport_id == inherited_stream_transport) {
            const auto selected = std::ranges::find(
                state->endpoints,
                *state->guest_channel_adapter->service_alias,
                [](const auto& endpoint) -> std::string_view { return endpoint->alias; }
            );
            if (selected == state->endpoints.end() ||
                !std::ranges::all_of(
                    state->guest_channel_adapter->runtime_ids, [&](const auto& runtime_id) {
                        return std::ranges::binary_search((*selected)->runtime_ids, runtime_id);
                    }
                )) {
                return std::unexpected(std::string{"local service proxy configuration is invalid"});
            }
        }
        return std::shared_ptr<local_service_proxy_factory>{
            new local_service_proxy_factory{construction_token{}, std::move(state)}
        };
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service proxy factory"});
    } catch (const std::exception&) {
        return std::unexpected(std::string{"local service proxy configuration is invalid"});
    }
}

auto local_service_proxy_factory::manages_runtime(std::string_view runtime_id) const noexcept
    -> bool {
    return state_ && std::ranges::any_of(state_->endpoints, [&](const auto& endpoint) {
               return std::ranges::binary_search(endpoint->runtime_ids, runtime_id);
           });
}

auto local_service_proxy_factory::operational() const noexcept -> bool {
    struct stat root_status{};
    return state_ && ::fstat(state_->runtime_root_fd.get(), &root_status) == 0 &&
           root_identity_current(state_->runtime_root_identity, root_status) && state_->registry &&
           (!state_->guest_channel_adapter ||
            (state_->adapter_catalog_admits_schema && state_->guest_channel_adapter->channels &&
             state_->guest_channel_adapter->channels->frozen() &&
             !state_->guest_channel_adapter->channels->empty() &&
             state_->registry->uses_channel_host(state_->guest_channel_adapter->channels))) &&
           std::ranges::all_of(state_->endpoints, [](const auto& endpoint) {
               return endpoint_current(*endpoint);
           });
}

auto local_service_proxy_factory::validate_path_grants(
    std::span<const supervisor::resolved_path_grant> grants
) const -> std::expected<void, std::string> {
    try {
        if (!operational()) {
            return std::unexpected(std::string{"local service path boundary is unavailable"});
        }
        for (const auto& grant : grants) {
            struct stat status{};
            if (grant.descriptor_fd() < 0 || ::fstat(grant.descriptor_fd(), &status) != 0) {
                return std::unexpected(std::string{"local service path grant is unavailable"});
            }
            const auto grant_identity = identity(status);
            for (const auto& endpoint : state_->endpoints) {
                if (same_object(grant_identity, endpoint->identity) ||
                    std::ranges::any_of(endpoint->parent_ancestors, [&](const auto& ancestor) {
                        return same_object(grant_identity, ancestor);
                    })) {
                    return std::unexpected(std::string{"local service path grant conflicts"});
                }
            }
        }
        return {};
    } catch (const std::exception&) {
        return std::unexpected(std::string{"local service path grant is unavailable"});
    }
}

auto local_service_proxy_factory::prepare_session(
    std::string_view session_id, std::string_view runtime_id
) -> std::expected<std::unique_ptr<local_service_proxy_session>, std::string> {
    try {
        if (!operational() || !valid_identifier(session_id, max_session_id_bytes) ||
            !valid_runtime_id(runtime_id)) {
            return std::unexpected(std::string{"local service session is unavailable"});
        }
        std::vector<std::shared_ptr<const pinned_endpoint>> selected;
        selected.reserve(state_->endpoints.size());
        const bool inherited =
            state_->guest_channel_adapter &&
            state_->guest_channel_adapter->transport_id == inherited_stream_transport;
        for (const auto& endpoint : state_->endpoints) {
            if (std::ranges::binary_search(endpoint->runtime_ids, runtime_id) &&
                (!inherited || endpoint->alias == *state_->guest_channel_adapter->service_alias)) {
                selected.push_back(endpoint);
            }
        }
        if (selected.empty()) {
            return std::unexpected(std::string{"local service runtime is not configured"});
        }
        auto manifest = endpoint_manifest(state_->generation, runtime_id, selected);
        if (!manifest) {
            return std::unexpected(std::string{"local service session is unavailable"});
        }
        const auto generation = next_session_generation();
        auto directory_name = "svc-" + std::to_string(state_->generation) + "-" +
                              std::to_string(generation) + "-" + std::string{session_id};

        auto session = std::make_unique<local_service_proxy_session::implementation>();
        session->session_id = session_id;
        session->manifest = std::move(*manifest);
        session->io_timeout_ms = state_->io_timeout_ms;
        session->audit = state_->audit;
        session->endpoints = std::move(selected);
        session->inherited = inherited;
        if (session->inherited) {
            session->adapter_environment = state_->guest_channel_adapter->service_alias_environment;
            session->inherited_streams.reserve(session->endpoints.size());
            for (std::size_t index = 0; index < session->endpoints.size(); ++index) {
                auto pair = create_inherited_socketpair();
                if (!pair) {
                    return std::unexpected(pair.error());
                }
                struct stat supervisor_status{};
                struct stat guest_status{};
                if (::fstat(pair->first.get(), &supervisor_status) != 0 ||
                    ::fstat(pair->second.get(), &guest_status) != 0) {
                    return std::unexpected(
                        std::string{"local service inherited stream is unavailable"}
                    );
                }
                session->inherited_streams.push_back({
                    .endpoint = session->endpoints[index],
                    .supervisor = std::move(pair->first),
                    .guest = std::move(pair->second),
                    .supervisor_identity = identity(supervisor_status),
                    .guest_identity = identity(guest_status),
                    .child_fd = static_cast<int>(index + 3U),
                });
            }
            session->workers.reserve(session->inherited_streams.size());
            for (std::size_t index = 0; index < session->inherited_streams.size(); ++index) {
                session->workers.emplace_back([owned = session.get(),
                                               index](const std::stop_token& stop) {
                    inherited_worker(*owned, index, stop);
                });
            }
            return std::unique_ptr<local_service_proxy_session>{
                new local_service_proxy_session{std::move(session)}
            };
        }
        session->listeners.reserve(session->endpoints.size());
        session->workers.reserve(state_->max_concurrency);
        session->worker_poll_sets.reserve(state_->max_concurrency);
        for (std::uint32_t index = 0; index < state_->max_concurrency; ++index) {
            session->worker_poll_sets.emplace_back(session->endpoints.size());
        }

        if (::mkdirat(state_->runtime_root_fd.get(), directory_name.c_str(), 0700) != 0) {
            return std::unexpected(std::string{"local service session is unavailable"});
        }
        unique_fd directory{::openat(
            state_->runtime_root_fd.get(),
            directory_name.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )};
        struct stat directory_status{};
        if (directory.get() < 0 || ::fstat(directory.get(), &directory_status) != 0 ||
            !S_ISDIR(directory_status.st_mode) || directory_status.st_uid != ::geteuid() ||
            directory_status.st_nlink == 0 || directory_status.st_dev == 0 ||
            directory_status.st_ino == 0 ||
            (static_cast<unsigned int>(directory_status.st_mode) & 0777U) != 0700U) {
            directory = unique_fd{};
            static_cast<void>(
                ::unlinkat(state_->runtime_root_fd.get(), directory_name.c_str(), AT_REMOVEDIR)
            );
            return std::unexpected(std::string{"local service session is unavailable"});
        }
        unique_fd root_fd{::fcntl(state_->runtime_root_fd.get(), F_DUPFD_CLOEXEC, 3)};
        if (root_fd.get() < 0) {
            directory = unique_fd{};
            static_cast<void>(
                ::unlinkat(state_->runtime_root_fd.get(), directory_name.c_str(), AT_REMOVEDIR)
            );
            return std::unexpected(std::string{"local service session is unavailable"});
        }
        session->directory_name = std::move(directory_name);
        session->directory = std::move(directory);
        session->root_fd = std::move(root_fd);
        session->directory_identity = identity(directory_status);

        for (const auto& endpoint : session->endpoints) {
            unique_fd listener{::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
            auto address = socket_address(proc_path(session->directory.get(), endpoint->alias));
            if (listener.get() < 0 || !address ||
                ::bind(
                    listener.get(),
                    reinterpret_cast<const sockaddr*>(&address->first),
                    address->second
                ) != 0) {
                return std::unexpected(std::string{"local service session is unavailable"});
            }
            bound_socket_rollback remove_bound_listener{session->directory.get(), endpoint->alias};
            if (::chmod(proc_path(session->directory.get(), endpoint->alias).c_str(), 0600) != 0 ||
                ::listen(listener.get(), static_cast<int>(state_->max_concurrency)) != 0) {
                return std::unexpected(std::string{"local service session is unavailable"});
            }
            auto listener_identity = inspect_socket(session->directory.get(), endpoint->alias);
            if (!listener_identity) {
                return std::unexpected(listener_identity.error());
            }
            session->listeners.push_back({
                .endpoint = endpoint,
                .listener = std::move(listener),
                .identity = *listener_identity,
            });
            remove_bound_listener.dismiss();
        }
        for (std::uint32_t index = 0; index < state_->max_concurrency; ++index) {
            session->workers.emplace_back([owned = session.get(),
                                           index](const std::stop_token& stop) {
                worker(*owned, index, stop);
            });
        }
        return std::unique_ptr<local_service_proxy_session>{
            new local_service_proxy_session{std::move(session)}
        };
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service session"});
    } catch (const std::system_error&) {
        return std::unexpected(std::string{"start local service workers"});
    } catch (const std::exception&) {
        return std::unexpected(std::string{"local service session is unavailable"});
    }
}

local_service_proxy_capability::local_service_proxy_capability(
    [[maybe_unused]] construction_token token, std::shared_ptr<const linux_session_runtime> runtime
) noexcept
    : runtime_{std::move(runtime)} {}

auto local_service_proxy_capability::operational_for(
    const session_runtime* runtime, const session_registry* registry
) const noexcept -> bool {
    if (!runtime_ || runtime_.get() != runtime) {
        return false;
    }
    const auto* factory = runtime_->local_service_factory();
    const auto* owned_registry = runtime_->registry_identity();
    return factory != nullptr && owned_registry != nullptr && owned_registry == registry &&
           factory->capability_current(*owned_registry);
}

auto local_service_proxy_factory::adapter_manages_runtime(
    std::string_view runtime_id
) const noexcept -> bool {
    return state_ && state_->guest_channel_adapter &&
           std::ranges::binary_search(state_->guest_channel_adapter->runtime_ids, runtime_id) &&
           manages_runtime(runtime_id);
}

auto local_service_proxy_factory::capability_current(
    const session_registry& registry
) const noexcept -> bool {
    return operational() && state_->registry.get() == &registry && state_->guest_channel_adapter &&
           state_->guest_channel_adapter->transport_id == inherited_stream_transport &&
           state_->guest_channel_adapter->service_alias.has_value() &&
           state_->guest_channel_adapter->service_alias_environment.has_value() &&
           state_->adapter_catalog_admits_schema;
}

auto local_service_proxy_factory::sealed_for(
    const linux_session_runtime& runtime, const session_registry& registry
) const noexcept -> bool {
    return capability_current(registry) && runtime.local_service_factory() == this &&
           runtime.registry_identity() == &registry && runtime.lifecycle_operational() &&
           runtime.resource_capabilities().complete() &&
           runtime.local_service_runtime_intersection(*this);
}

auto local_service_proxy_factory::try_seal(std::shared_ptr<const linux_session_runtime> runtime)
    -> capability_result {
    if (!runtime || !state_ || !state_->registry) {
        return std::unexpected(std::string{"local service proxy composition is unavailable"});
    }
    if (!state_->guest_channel_adapter ||
        state_->guest_channel_adapter->transport_id != inherited_stream_transport ||
        !runtime->local_service_runtime_intersection(*this)) {
        return std::optional<std::shared_ptr<const local_service_proxy_capability>>{};
    }
    if (!sealed_for(*runtime, *state_->registry)) {
        return std::unexpected(std::string{"local service proxy composition is unavailable"});
    }
    try {
        return std::optional<std::shared_ptr<const local_service_proxy_capability>>{
            std::shared_ptr<const local_service_proxy_capability>{
                new local_service_proxy_capability{
                    local_service_proxy_capability::construction_token{}, std::move(runtime)
                }
            }
        };
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate local service proxy capability"});
    } catch (const std::exception&) {
        return std::unexpected(std::string{"construct local service proxy capability"});
    }
}

} // namespace glove::control::linux_detail
