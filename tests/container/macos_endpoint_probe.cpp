#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <string>
#include <string_view>

namespace {

using clock_type = std::chrono::steady_clock;
using deadline = clock_type::time_point;

struct failure {
    std::string_view operation;
    int code;
};

template<typename T> using result = std::expected<T, failure>;

class descriptor {
public:
    explicit descriptor(int fd) noexcept : fd_(fd) {}

    ~descriptor() {
        if (fd_ >= 0) {
            // Retrying close after EINTR risks closing a reused descriptor.
            static_cast<void>(::close(fd_));
        }
    }

    descriptor(const descriptor&) = delete;
    descriptor& operator=(const descriptor&) = delete;
    descriptor(descriptor&&) = delete;
    descriptor& operator=(descriptor&&) = delete;

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

private:
    int fd_;
};

struct endpoint {
    int family = AF_UNSPEC;
    sockaddr_in ipv4{};
    sockaddr_in6 ipv6{};

    [[nodiscard]] auto address() const noexcept -> const sockaddr* {
        // POSIX socket APIs require a sockaddr view of the live, correctly sized address.
        if (family == AF_INET) {
            return reinterpret_cast<const sockaddr*>(&ipv4);
        }
        return reinterpret_cast<const sockaddr*>(&ipv6);
    }

    [[nodiscard]] auto size() const noexcept -> socklen_t {
        return family == AF_INET ? sizeof(ipv4) : sizeof(ipv6);
    }
};

auto parse_number(std::string_view text, int low, int high) -> result<int> {
    if (text.empty() || text.size() > 5 ||
        !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
        return std::unexpected(failure{"numeric argument", EINVAL});
    }
    int value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value < low || value > high) {
        return std::unexpected(failure{"numeric argument", EINVAL});
    }
    return value;
}

auto parse_endpoint(const char* family, const char* ip, const char* port) -> result<endpoint> {
    const auto number = parse_number(port, 1, 65535);
    if (!number) {
        return std::unexpected(number.error());
    }
    endpoint value{};
    if (std::string_view{family} == "4") {
        value.family = AF_INET;
        value.ipv4.sin_len = sizeof(value.ipv4);
        value.ipv4.sin_family = AF_INET;
        value.ipv4.sin_port = htons(static_cast<std::uint16_t>(*number));
        if (::inet_pton(AF_INET, ip, &value.ipv4.sin_addr) != 1) {
            return std::unexpected(failure{"numeric IPv4 argument", EINVAL});
        }
    } else if (std::string_view{family} == "6") {
        value.family = AF_INET6;
        value.ipv6.sin6_len = sizeof(value.ipv6);
        value.ipv6.sin6_family = AF_INET6;
        value.ipv6.sin6_port = htons(static_cast<std::uint16_t>(*number));
        if (::inet_pton(AF_INET6, ip, &value.ipv6.sin6_addr) != 1) {
            return std::unexpected(failure{"numeric IPv6 argument", EINVAL});
        }
    } else {
        return std::unexpected(failure{"family argument", EINVAL});
    }
    return value;
}

auto configure_socket(int fd) -> result<void> {
    const int descriptor_flags = ::fcntl(fd, F_GETFD);
    if (descriptor_flags < 0 || ::fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        return std::unexpected(failure{"socket CLOEXEC", errno});
    }
    const int status_flags = ::fcntl(fd, F_GETFL);
    if (status_flags < 0 || ::fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) < 0) {
        return std::unexpected(failure{"socket nonblocking", errno});
    }
    const int enabled = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        return std::unexpected(failure{"socket NOSIGPIPE", errno});
    }
    return {};
}

auto wait_ready(int fd, short events, deadline until) -> result<void> {
    for (;;) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(until - clock_type::now());
        if (remaining.count() <= 0) {
            return std::unexpected(failure{"deadline", ETIMEDOUT});
        }
        pollfd item{.fd = fd, .events = events, .revents = 0};
        const int ready = ::poll(&item, 1, static_cast<int>(remaining.count()));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(failure{"poll", errno});
        }
        if (ready == 0) {
            return std::unexpected(failure{"deadline", ETIMEDOUT});
        }
        if ((item.revents & POLLNVAL) != 0) {
            return std::unexpected(failure{"poll invalid descriptor", EBADF});
        }
        if ((item.revents & (events | POLLERR | POLLHUP)) != 0) {
            return {};
        }
    }
}

auto connect_socket(int fd, const endpoint& peer, deadline until) -> result<void> {
    if (clock_type::now() >= until) {
        return std::unexpected(failure{"deadline", ETIMEDOUT});
    }
    if (::connect(fd, peer.address(), peer.size()) != 0) {
        const int code = errno;
        if (code != EINPROGRESS && code != EINTR && code != EALREADY) {
            return std::unexpected(failure{"connect", code});
        }
        const auto ready = wait_ready(fd, POLLOUT, until);
        if (!ready) {
            return ready;
        }
    }
    int code = 0;
    socklen_t size = sizeof(code);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &code, &size) != 0) {
        return std::unexpected(failure{"SO_ERROR", errno});
    }
    if (size != sizeof(code)) {
        return std::unexpected(failure{"SO_ERROR size", EIO});
    }
    if (code != 0) {
        return std::unexpected(failure{"SO_ERROR", code});
    }
    return {};
}

auto send_datagram(int fd, const endpoint& peer, deadline until) -> result<void> {
    constexpr std::string_view fixture = "glove-endpoint-fixture";
    while (clock_type::now() < until) {
        const auto sent =
            ::sendto(fd, fixture.data(), fixture.size(), 0, peer.address(), peer.size());
        if (sent >= 0) {
            if (static_cast<std::size_t>(sent) != fixture.size()) {
                return std::unexpected(failure{"partial datagram", EIO});
            }
            return {};
        }
        const int code = errno;
        if (code == EINTR) {
            continue;
        }
        if (code != EAGAIN && code != EWOULDBLOCK) {
            return std::unexpected(failure{"sendto", code});
        }
        const auto ready = wait_ready(fd, POLLOUT, until);
        if (!ready) {
            return ready;
        }
    }
    return std::unexpected(failure{"deadline", ETIMEDOUT});
}

auto check_expectation(result<void> observed, bool deny, bool filesystem = false) -> result<void> {
    if (!deny) {
        return observed;
    }
    if (!observed) {
        const auto& error = observed.error();
        const bool permitted_stage =
            filesystem ? error.operation == "open" || error.operation == "read"
                       : error.operation == "socket" || error.operation == "connect" ||
                             error.operation == "SO_ERROR" || error.operation == "sendto";
        if (permitted_stage && (error.code == EPERM || error.code == EACCES)) {
            return {};
        }
        return observed;
    }
    return std::unexpected(failure{"unexpected permission", EIO});
}

auto http_exchange(int fd, std::string_view nonce, int status, deadline until) -> result<void> {
    const std::string request =
        "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: " +
        std::string{nonce} + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    std::size_t offset = 0;
    while (offset < request.size()) {
        if (clock_type::now() >= until) {
            return std::unexpected(failure{"deadline", ETIMEDOUT});
        }
        const auto sent = ::send(fd, request.data() + offset, request.size() - offset, 0);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        const int code = sent == 0 ? EIO : errno;
        if (code == EINTR) {
            continue;
        }
        if (code != EAGAIN && code != EWOULDBLOCK) {
            return std::unexpected(failure{"HTTP send", code});
        }
        const auto ready = wait_ready(fd, POLLOUT, until);
        if (!ready) {
            return ready;
        }
    }

    constexpr std::size_t response_limit = 64 * 1024;
    std::string response;
    std::array<char, 4096> buffer{};
    while (response.size() < response_limit) {
        if (clock_type::now() >= until) {
            return std::unexpected(failure{"deadline", ETIMEDOUT});
        }
        const auto received =
            ::recv(fd, buffer.data(), std::min(buffer.size(), response_limit - response.size()), 0);
        if (received > 0) {
            response.append(buffer.data(), static_cast<std::size_t>(received));
            const auto end = response.find("\r\n");
            if (end != std::string::npos) {
                const std::string_view line{response.data(), end};
                if (line.size() < 13 ||
                    (!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) ||
                    line[12] != ' ') {
                    return std::unexpected(failure{"HTTP status line", EPROTO});
                }
                const auto actual = parse_number(line.substr(9, 3), 100, 599);
                if (!actual || *actual != status) {
                    return std::unexpected(failure{"HTTP unexpected status", EPROTO});
                }
                return {};
            }
            continue;
        }
        const int code = received == 0 ? EPROTO : errno;
        if (code == EINTR) {
            continue;
        }
        if (code != EAGAIN && code != EWOULDBLOCK) {
            return std::unexpected(failure{"HTTP receive", code});
        }
        const auto ready = wait_ready(fd, POLLIN, until);
        if (!ready) {
            return ready;
        }
    }
    return std::unexpected(failure{"HTTP response limit", EMSGSIZE});
}

auto filesystem_probe(const char* path, std::string_view expected) -> result<void> {
    if (expected != "read" && expected != "read-link" && expected != "deny-read" &&
        expected != "deny-write") {
        return std::unexpected(failure{"filesystem expectation", EINVAL});
    }
    const bool write = expected == "deny-write";
    const descriptor file{::open(
        path,
        (write ? O_WRONLY : O_RDONLY) | O_NONBLOCK | O_CLOEXEC |
            (expected == "read-link" ? 0 : O_NOFOLLOW)
    )};
    result<void> observed;
    if (file.get() < 0) {
        observed = std::unexpected(failure{"open", errno});
    } else if (!write) {
        const auto until = clock_type::now() + std::chrono::seconds{1};
        for (;;) {
            char byte = 0;
            const auto count = ::read(file.get(), &byte, 1);
            if (count == 1) {
                break;
            }
            const int code = count == 0 ? EIO : errno;
            if (code == EINTR && clock_type::now() < until) {
                continue;
            }
            observed = std::unexpected(failure{"read", code});
            break;
        }
    }
    return check_expectation(observed, expected != "read" && expected != "read-link", true);
}

class mapped_byte {
public:
    explicit mapped_byte(int fd) noexcept
        : data_{::mmap(nullptr, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)} {}

    mapped_byte(const mapped_byte&) = delete;
    auto operator=(const mapped_byte&) -> mapped_byte& = delete;
    mapped_byte(mapped_byte&&) = delete;
    auto operator=(mapped_byte&&) -> mapped_byte& = delete;

    ~mapped_byte() {
        if (data_ != MAP_FAILED) {
            ::munmap(data_, 1);
        }
    }

    [[nodiscard]] auto get() const noexcept -> void* { return data_; }

    auto release() noexcept -> result<void> {
        const auto data = std::exchange(data_, MAP_FAILED);
        if (::munmap(data, 1) != 0) {
            return std::unexpected(failure{"mapping cleanup", errno});
        }
        return {};
    }

private:
    void* data_;
};

auto mutation_probe(
    std::string_view action, const char* source, const char* target, std::string_view expected
) -> result<void> {
    if (expected != "allow" && expected != "deny") {
        return std::unexpected(failure{"mutation expectation", EINVAL});
    }
    result<void> observed;
    if (action == "link" || action == "rename" || action == "unlink" || action == "chmod" ||
        action == "symlink" || action == "mkdir") {
        const int rc = action == "link"      ? ::link(source, target)
                       : action == "rename"  ? ::rename(source, target)
                       : action == "unlink"  ? ::unlink(source)
                       : action == "symlink" ? ::symlink(source, target)
                       : action == "mkdir"   ? ::mkdir(source, 0700)
                                             : ::chmod(source, 0600);
        if (rc != 0) {
            observed = std::unexpected(failure{"mutation", errno});
        }
    } else if (
        action == "write" || action == "create" || action == "map" || action == "follow-write" ||
        action == "follow-map"
    ) {
        const bool create = action == "create";
        const bool map = action == "map" || action == "follow-map";
        const bool follow = action.starts_with("follow-");
        const descriptor file{::open(
            source,
            (map ? O_RDWR : O_WRONLY) | O_NONBLOCK | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW) |
                (create ? O_CREAT | O_EXCL : 0),
            0600
        )};
        if (file.get() < 0) {
            observed = std::unexpected(failure{"mutation", errno});
        } else if (map) {
            mapped_byte mapping{file.get()};
            if (mapping.get() == MAP_FAILED) {
                observed = std::unexpected(failure{"mutation", errno});
            } else {
                *static_cast<char*>(mapping.get()) = '!';
                if (::msync(mapping.get(), 1, MS_SYNC) != 0) {
                    observed = std::unexpected(failure{"mapping sync", errno});
                }
                if (auto released = mapping.release(); !released) {
                    observed = std::unexpected(released.error());
                }
            }
        } else if (::write(file.get(), "!", 1) != 1) {
            observed = std::unexpected(failure{"mutation write", errno});
        }
    } else {
        return std::unexpected(failure{"mutation action", EINVAL});
    }
    if (expected == "allow") {
        return observed;
    }
    if (!observed && observed.error().operation == "mutation" &&
        (observed.error().code == EPERM || observed.error().code == EACCES)) {
        return {};
    }
    if (!observed) {
        return observed;
    }
    return std::unexpected(failure{"mutation unexpectedly permitted", EIO});
}

auto run(int argc, char** argv) -> result<void> {
    if (argc < 2 || argc > 7) {
        return std::unexpected(failure{"argument count", EINVAL});
    }
    for (int index = 1; index < argc; ++index) {
        if (::strnlen(argv[index], 4097) > 4096) {
            return std::unexpected(failure{"argument length", EINVAL});
        }
    }
    const std::string_view mode{argv[1]};
    if (mode == "fs" && argc == 4) {
        return filesystem_probe(argv[2], argv[3]);
    }
    if (mode == "mutate" && argc == 6) {
        return mutation_probe(argv[2], argv[3], argv[4], argv[5]);
    }
    const bool http = mode == "http";
    const bool udp = mode == "udp";
    if ((!http && !udp && mode != "connect") || argc != (http ? 7 : 6)) {
        return std::unexpected(failure{"protocol arguments", EINVAL});
    }
    const auto peer = parse_endpoint(argv[2], argv[3], argv[4]);
    if (!peer) {
        return std::unexpected(peer.error());
    }
    const std::string_view expected{argv[5]};
    int status = 0;
    if (http) {
        if (expected.empty() || expected.size() > 128 || !std::ranges::all_of(expected, [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                       c == '-' || c == '_';
            })) {
            return std::unexpected(failure{"fixture nonce", EINVAL});
        }
        const auto parsed = parse_number(argv[6], 100, 599);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        status = *parsed;
    } else if (expected != "allow" && expected != "deny") {
        return std::unexpected(failure{"network expectation", EINVAL});
    }
    const auto started = clock_type::now();
    const auto connect_until = started + std::chrono::seconds{1};
    const auto http_until = started + std::chrono::seconds{2};
    const descriptor socket{::socket(peer->family, udp ? SOCK_DGRAM : SOCK_STREAM, 0)};
    if (socket.get() < 0) {
        return check_expectation(
            std::unexpected(failure{"socket", errno}), !http && expected == "deny"
        );
    }
    const auto configured = configure_socket(socket.get());
    if (!configured) {
        return configured;
    }
    const auto observed = udp ? send_datagram(socket.get(), *peer, connect_until)
                              : connect_socket(socket.get(), *peer, connect_until);
    if (!http) {
        return check_expectation(observed, expected == "deny");
    }
    if (!observed) {
        return observed;
    }
    return http_exchange(socket.get(), expected, status, http_until);
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        const auto outcome = run(argc, argv);
        if (!outcome) {
            const auto& error = outcome.error();
            std::fprintf(
                stderr,
                "probe: %.*s: %s (%d)\n",
                static_cast<int>(error.operation.size()),
                error.operation.data(),
                std::strerror(error.code),
                error.code
            );
            return 1;
        }
        std::fputs("probe-ok\n", stdout);
        return 0;
    } catch (...) {
        std::fputs("probe: unexpected exception\n", stderr);
        return 1;
    }
}
