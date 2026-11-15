#pragma once

// Private shared wire/framing detail of the management transport (server and
// client translation units). Not a public interface.
#include "glove/detail/descriptor_acl.hpp"

#include "json_shape.hpp"
#include "native_management_transport.hpp"
#include "native_session_store.hpp"
#include "pi_private_files.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <sys/param.h>
#    include <sys/ucred.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

namespace glove::run::detail {
namespace management_wire {

struct auth_frame {
    std::optional<int> v;
    std::optional<std::string> type;
    std::optional<std::string> session;
    std::optional<std::string> epoch;
    std::optional<std::string> capability;
};

struct ready_frame {
    int v = 1;
    std::string type = "ready";
    std::string session;
    std::string epoch;
    std::vector<std::string> capabilities;
};

struct request_frame {
    std::optional<int> v;
    std::optional<std::string> type;
    std::optional<std::string> session;
    std::optional<std::string> epoch;
    std::optional<std::string> generation;
    std::optional<std::string> request;
    std::optional<std::string> op;
    std::optional<std::string> checkpoint;
};

struct request_out {
    int v = 1;
    std::string type = "request";
    std::string session;
    std::string epoch;
    std::string generation;
    std::string request;
    std::string op;
};

struct request_out_checkpoint {
    int v = 1;
    std::string type = "request";
    std::string session;
    std::string epoch;
    std::string generation;
    std::string request;
    std::string op;
    std::string checkpoint;
};

struct result_frame {
    int v = 1;
    std::string type = "result";
    std::string session;
    std::string epoch;
    std::string generation;
    std::string request;
    std::string op;
    std::string state;
    std::string history;
    std::optional<std::string> checkpoint;
    std::string effects;
    std::string code;
    bool final = true;
};

} // namespace management_wire

namespace management_detail {
template<typename T> using result = std::expected<T, std::string>;
using management_wire::auth_frame;
using management_wire::ready_frame;
using management_wire::request_frame;
using management_wire::result_frame;
using private_files::descriptor;
using private_files::failure;
using private_files::pin_parent;
using private_files::pinned_parent;
using private_files::private_file;

inline constexpr glz::opts closed_options{
    .error_on_unknown_keys = true, .error_on_missing_keys = false
};
inline constexpr glz::opts strict_options{
    .error_on_unknown_keys = true, .error_on_missing_keys = true
};
inline constexpr int poll_tick_ms = 50;
inline constexpr std::string_view socket_name{management_socket_name};
inline constexpr std::string_view capability_name{management_capability_name};

using clock_type = std::chrono::steady_clock;

inline auto peer_uid(int fd) -> std::optional<uid_t> {
#if defined(LOCAL_PEERCRED)
    struct xucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &length) != 0 ||
        credentials.cr_version != XUCRED_VERSION) {
        return std::nullopt;
    }
    return credentials.cr_uid;
#elif defined(SO_PEERCRED)
    struct ::ucred credentials{};
    ::socklen_t length = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0) {
        return std::nullopt;
    }
    return credentials.uid;
#else
    (void)fd;
    return std::nullopt;
#endif
}

inline auto verify_peer(int fd) -> bool {
    int type = 0;
    ::socklen_t size = sizeof(type);
    if (::getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) != 0 || type != SOCK_STREAM) {
        return false;
    }
    const auto uid = peer_uid(fd);
    return uid && *uid == ::geteuid();
}

inline auto make_nonblocking(int fd) -> bool {
    const int status = ::fcntl(fd, F_GETFL);
    const int flags = ::fcntl(fd, F_GETFD);
    if (status < 0 || flags < 0 || ::fcntl(fd, F_SETFL, status | O_NONBLOCK) != 0 ||
        ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return false;
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
    return true;
}

inline auto wait_ready(int fd, short events, std::stop_token stop, clock_type::time_point deadline)
    -> bool {
    while (!stop.stop_requested()) {
        const auto now = clock_type::now();
        if (now >= deadline) {
            return false;
        }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        ::pollfd pfd{.fd = fd, .events = events, .revents = 0};
        const int ready =
            ::poll(&pfd, 1, static_cast<int>(std::min<long long>(left.count(), poll_tick_ms)));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ready > 0 && (pfd.revents & (events | POLLHUP | POLLERR)) != 0) {
            return true;
        }
    }
    return false;
}

inline auto
read_exact(int fd, std::size_t wanted, std::stop_token stop, clock_type::time_point deadline)
    -> std::optional<std::string> {
    std::string out;
    while (out.size() < wanted) {
        if (!wait_ready(fd, POLLIN, stop, deadline)) {
            return std::nullopt;
        }
        std::array<char, 4096> chunk{};
        const auto got = ::read(fd, chunk.data(), std::min(chunk.size(), wanted - out.size()));
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return std::nullopt;
        }
        if (got == 0) {
            return std::nullopt;
        }
        out.append(chunk.data(), static_cast<std::size_t>(got));
    }
    return out;
}

inline auto
write_all(int fd, std::string_view bytes, std::stop_token stop, clock_type::time_point deadline)
    -> bool {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        if (!wait_ready(fd, POLLOUT, stop, deadline)) {
            return false;
        }
#if defined(MSG_NOSIGNAL)
        const auto written = ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
#else
        const auto written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
#endif
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

// Exactly four octets big-endian, body 1..65536 bytes.
inline auto read_frame(int fd, std::stop_token stop, clock_type::time_point deadline)
    -> std::optional<std::string> {
    auto prefix = read_exact(fd, 4, stop, deadline);
    if (!prefix) {
        return std::nullopt;
    }
    std::uint32_t length = 0;
    for (const auto byte : *prefix) {
        length = (length << 8U) | static_cast<unsigned char>(byte);
    }
    if (length == 0 || length > management_max_frame_bytes) {
        return std::nullopt;
    }
    return read_exact(fd, length, stop, deadline);
}

inline auto
write_frame(int fd, std::string_view body, std::stop_token stop, clock_type::time_point deadline)
    -> bool {
    if (body.empty() || body.size() > management_max_frame_bytes) {
        return false;
    }
    std::string frame;
    const auto length = static_cast<std::uint32_t>(body.size());
    frame.push_back(static_cast<char>((length >> 24U) & 0xffU));
    frame.push_back(static_cast<char>((length >> 16U) & 0xffU));
    frame.push_back(static_cast<char>((length >> 8U) & 0xffU));
    frame.push_back(static_cast<char>(length & 0xffU));
    frame += body;
    return write_all(fd, frame, stop, deadline);
}

inline auto constant_time_equal(std::string_view left, std::string_view right) -> bool {
    unsigned difference = static_cast<unsigned>(left.size() ^ right.size());
    for (std::size_t index = 0; index < right.size(); ++index) {
        const unsigned byte = index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        difference |= byte ^ static_cast<unsigned char>(right[index]);
    }
    return difference == 0;
}

inline auto sockaddr_for(const std::filesystem::path& path) -> std::optional<::sockaddr_un> {
    const auto& text = path.native();
    ::sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (text.empty() || text.size() >= sizeof(address.sun_path)) {
        return std::nullopt;
    }
    std::memcpy(address.sun_path, text.c_str(), text.size() + 1U);
    return address;
}

inline auto parse_phase(std::string_view text) -> std::optional<session_phase> {
    for (const auto phase :
         {session_phase::fresh,
          session_phase::preparing,
          session_phase::running,
          session_phase::interrupting,
          session_phase::stopping,
          session_phase::finalizing,
          session_phase::stopped,
          session_phase::recovery_required}) {
        if (to_string(phase) == text) {
            return phase;
        }
    }
    return std::nullopt;
}

inline auto parse_history(std::string_view text) -> std::optional<history_status> {
    for (const auto value :
         {history_status::absent,
          history_status::available,
          history_status::published,
          history_status::invalid,
          history_status::failed}) {
        if (to_string(value) == text) {
            return value;
        }
    }
    return std::nullopt;
}

inline auto parse_effects(std::string_view text) -> std::optional<effects_status> {
    for (const auto value :
         {effects_status::unassessed, effects_status::incomplete, effects_status::reconciled}) {
        if (to_string(value) == text) {
            return value;
        }
    }
    return std::nullopt;
}

inline auto parse_code(std::string_view text) -> std::optional<result_code> {
    for (const auto value :
         {result_code::ok,
          result_code::accepted,
          result_code::unauthorized,
          result_code::unsupported_version,
          result_code::unsupported_operation,
          result_code::malformed,
          result_code::stale_epoch,
          result_code::stale_generation,
          result_code::invalid_state,
          result_code::request_conflict,
          result_code::capacity,
          result_code::admission_failed,
          result_code::checkpoint_failed,
          result_code::outcome_uncertain}) {
        if (to_string(value) == text) {
            return value;
        }
    }
    return std::nullopt;
}

} // namespace management_detail
} // namespace glove::run::detail
