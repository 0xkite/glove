#include "tls_stream.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace glove::net {

namespace {

constexpr int poll_tick_ms = 100;
// One address may not spend the whole request deadline: with a blackholed
// first family (commonly IPv6), the next resolved address must still get a
// turn before the request runs out.
constexpr auto per_address_connect_budget = std::chrono::seconds{10};

struct ssl_ctx_deleter {
    void operator()(SSL_CTX* ctx) const noexcept { SSL_CTX_free(ctx); }
};

struct ssl_deleter {
    void operator()(SSL* ssl) const noexcept { SSL_free(ssl); }
};

using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;
using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

class unique_fd {
public:
    explicit unique_fd(int fd = -1) noexcept : fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    unique_fd& operator=(unique_fd&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.fd_, -1));
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

// OpenSSL's socket BIO writes with plain write(2), so a provider that resets
// the connection would raise SIGPIPE, whose default action terminates the
// whole host process. Block it on this thread for the duration of a write and
// consume any instance the write raised before restoring the mask.
class sigpipe_guard {
public:
    sigpipe_guard() noexcept {
        ::sigemptyset(&pipe_);
        ::sigaddset(&pipe_, SIGPIPE);
        ::sigset_t pending;
        ::sigemptyset(&pending);
        // A SIGPIPE already pending before the guard is not ours to consume.
        already_pending_ = ::sigpending(&pending) == 0 && ::sigismember(&pending, SIGPIPE) == 1;
        blocked_ = ::pthread_sigmask(SIG_BLOCK, &pipe_, &previous_) == 0;
    }

    sigpipe_guard(const sigpipe_guard&) = delete;
    sigpipe_guard& operator=(const sigpipe_guard&) = delete;
    sigpipe_guard(sigpipe_guard&&) = delete;
    sigpipe_guard& operator=(sigpipe_guard&&) = delete;

    ~sigpipe_guard() {
        if (!blocked_) {
            return;
        }
        if (!already_pending_) {
            const ::timespec zero{.tv_sec = 0, .tv_nsec = 0};
            while (::sigtimedwait(&pipe_, nullptr, &zero) == SIGPIPE) {}
        }
        ::pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
    }

private:
    ::sigset_t pipe_{};
    ::sigset_t previous_{};
    bool already_pending_ = false;
    bool blocked_ = false;
};

enum class wait_result : std::uint8_t {
    ready,
    stopped,
    timed_out,
    failed,
};

auto wait_fd(int fd, short events, const std::stop_token& stop, byte_stream::deadline until)
    -> wait_result {
    while (!stop.stop_requested()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= until) {
            return wait_result::timed_out;
        }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - now);
        const int tick = static_cast<int>(std::min<long long>(left.count(), poll_tick_ms));
        ::pollfd pfd{.fd = fd, .events = events, .revents = 0};
        const int ready = ::poll(&pfd, 1, tick);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return wait_result::failed;
        }
        if (ready > 0) {
            return wait_result::ready;
        }
    }
    return wait_result::stopped;
}

auto unavailable(wait_result result, std::string_view phase) -> std::string {
    switch (result) {
    case wait_result::stopped:
        return std::string{phase} + ": cancelled";
    case wait_result::timed_out:
        return std::string{phase} + ": deadline exceeded";
    case wait_result::ready:
    case wait_result::failed:
        break;
    }
    return std::string{phase} + ": poll failed";
}

// The most recent queued OpenSSL error, for diagnostics. Drains the queue so
// an error from this exchange does not surface on the next one.
auto openssl_error() -> std::string {
    unsigned long code = 0;
    unsigned long last = 0;
    while ((code = ERR_get_error()) != 0) {
        last = code;
    }
    if (last == 0) {
        return "unknown TLS error";
    }
    std::array<char, 256> text{};
    ERR_error_string_n(last, text.data(), text.size());
    return std::string{text.data()};
}

// Resolve once and connect to a result. Name resolution itself is not
// interruptible here; connect is non-blocking and bounded by the deadline.
auto dial(
    const std::string& host,
    std::uint16_t port,
    const std::stop_token& stop,
    byte_stream::deadline until
) -> std::expected<unique_fd, std::string> {
    if (auto refused = already_unavailable(stop, until, "connect")) {
        return std::unexpected(*refused);
    }
    ::addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ::addrinfo* results = nullptr;
    const std::string port_string = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_string.c_str(), &hints, &results) != 0) {
        return std::unexpected(std::string{"connect: DNS resolution failed"});
    }
    std::unique_ptr<::addrinfo, decltype(&::freeaddrinfo)> owned{results, &::freeaddrinfo};
    std::string last_error = "no usable address";
    for (auto* item = results; item != nullptr; item = item->ai_next) {
        if (auto refused = already_unavailable(stop, until, "connect")) {
            return std::unexpected(*refused);
        }
        unique_fd fd{
            ::socket(item->ai_family, item->ai_socktype | SOCK_CLOEXEC, item->ai_protocol)
        };
        if (fd.get() < 0) {
            continue;
        }
        const int flags = ::fcntl(fd.get(), F_GETFL);
        if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK) != 0) {
            continue;
        }
        if (::connect(fd.get(), item->ai_addr, item->ai_addrlen) == 0) {
            return fd;
        }
        if (errno != EINPROGRESS) {
            last_error = std::strerror(errno);
            continue;
        }
        const auto attempt_until =
            std::min(until, std::chrono::steady_clock::now() + per_address_connect_budget);
        const auto waited = wait_fd(fd.get(), POLLOUT, stop, attempt_until);
        if (waited == wait_result::stopped ||
            (waited == wait_result::timed_out && attempt_until >= until)) {
            return std::unexpected(unavailable(waited, "connect"));
        }
        if (waited == wait_result::timed_out) {
            last_error = "connect timed out";
            continue;
        }
        int error = 0;
        ::socklen_t length = sizeof(error);
        if (waited == wait_result::ready &&
            ::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0) {
            return fd;
        }
        last_error = error != 0 ? std::strerror(error) : std::string{"connect failed"};
    }
    return std::unexpected("connect: " + last_error);
}

// Drive one non-blocking SSL operation to completion, waiting for whichever
// direction OpenSSL asks for.
template<class Operation>
auto drive(
    SSL* ssl,
    int fd,
    Operation operation,
    std::string_view phase,
    const std::stop_token& stop,
    byte_stream::deadline until
) -> std::expected<int, std::string> {
    while (true) {
        // Before every attempt, not only between waits: an SSL_write that can
        // complete immediately would otherwise send after cancellation.
        if (auto refused = already_unavailable(stop, until, phase)) {
            return std::unexpected(*refused);
        }
        ERR_clear_error();
        const int result = operation();
        if (result > 0) {
            return result;
        }
        const int error = SSL_get_error(ssl, result);
        short events = 0;
        if (error == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else if (error == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else if (error == SSL_ERROR_ZERO_RETURN) {
            return 0;
        } else {
            return std::unexpected(std::string{phase} + ": " + openssl_error());
        }
        const auto waited = wait_fd(fd, events, stop, until);
        if (waited != wait_result::ready) {
            return std::unexpected(unavailable(waited, phase));
        }
    }
}

class tls_stream final : public byte_stream {
public:
    tls_stream(ssl_ctx_ptr ctx, ssl_ptr ssl, unique_fd fd)
        : ctx_{std::move(ctx)}, ssl_{std::move(ssl)}, fd_{std::move(fd)} {}

    auto write_all(std::string_view data, std::stop_token stop, deadline until)
        -> std::expected<void, std::string> override {
        const sigpipe_guard no_sigpipe;
        while (!data.empty()) {
            const int chunk = static_cast<int>(std::min<std::size_t>(data.size(), INT_MAX));
            auto written = drive(
                ssl_.get(),
                fd_.get(),
                [&] { return SSL_write(ssl_.get(), data.data(), chunk); },
                "write",
                stop,
                until
            );
            if (!written) {
                return std::unexpected(written.error());
            }
            if (*written == 0) {
                return std::unexpected(std::string{"write: peer closed the connection"});
            }
            data.remove_prefix(static_cast<std::size_t>(*written));
        }
        return {};
    }

    auto read_some(std::span<char> into, std::stop_token stop, deadline until)
        -> std::expected<std::size_t, std::string> override {
        // TLS 1.3 key updates make SSL_read write too.
        const sigpipe_guard no_sigpipe;
        const int wanted = static_cast<int>(std::min<std::size_t>(into.size(), INT_MAX));
        auto got = drive(
            ssl_.get(),
            fd_.get(),
            [&] { return SSL_read(ssl_.get(), into.data(), wanted); },
            "read",
            stop,
            until
        );
        if (!got) {
            return std::unexpected(got.error());
        }
        return static_cast<std::size_t>(*got);
    }

private:
    ssl_ctx_ptr ctx_;
    ssl_ptr ssl_;
    unique_fd fd_;
};

} // namespace

auto connect_tls(
    const std::string& host, std::uint16_t port, std::stop_token stop, byte_stream::deadline until
) -> std::expected<std::unique_ptr<byte_stream>, std::string> {
    ssl_ctx_ptr ctx{SSL_CTX_new(TLS_client_method())};
    if (!ctx) {
        return std::unexpected("tls: " + openssl_error());
    }
    // System trust store, peer verification required, nothing below TLS 1.2.
    if (SSL_CTX_set_default_verify_paths(ctx.get()) != 1 ||
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) != 1) {
        return std::unexpected("tls: " + openssl_error());
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    auto fd = dial(host, port, stop, until);
    if (!fd) {
        return std::unexpected(fd.error());
    }

    ssl_ptr ssl{SSL_new(ctx.get())};
    if (!ssl) {
        return std::unexpected("tls: " + openssl_error());
    }
    // SNI plus hostname verification against the certificate; without
    // SSL_set1_host OpenSSL checks the chain but not that it names this host.
    SSL_set_hostflags(ssl.get(), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (SSL_set_tlsext_host_name(ssl.get(), host.c_str()) != 1 ||
        SSL_set1_host(ssl.get(), host.c_str()) != 1 || SSL_set_fd(ssl.get(), fd->get()) != 1) {
        return std::unexpected("tls: " + openssl_error());
    }
    static constexpr unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (SSL_set_alpn_protos(ssl.get(), alpn, sizeof(alpn)) != 0) {
        return std::unexpected("tls: " + openssl_error());
    }

    const sigpipe_guard no_sigpipe;
    auto handshake = drive(
        ssl.get(), fd->get(), [&] { return SSL_connect(ssl.get()); }, "handshake", stop, until
    );
    if (!handshake) {
        const long verify = SSL_get_verify_result(ssl.get());
        if (verify != X509_V_OK) {
            return std::unexpected(
                std::string{"handshake: certificate verification failed ("} +
                X509_verify_cert_error_string(verify) + ")"
            );
        }
        return std::unexpected(handshake.error());
    }
    if (*handshake == 0) {
        return std::unexpected(std::string{"handshake: peer closed the connection"});
    }
    return std::make_unique<tls_stream>(std::move(ctx), std::move(ssl), std::move(*fd));
}

} // namespace glove::net
