#include "tls_stream.hpp"

#include <dispatch/dispatch.h>
#include <Network/Network.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace glove::net {

namespace {

// Network.framework is callback-driven; the forwarder seam is synchronous with
// a stop token and deadline. Callbacks run on a private serial queue and post
// into this shared state, and the calling thread waits on it in short slices
// so stop and deadline are observed promptly. The state is shared with every
// in-flight block, so a callback that fires after the stream is gone writes
// into live memory rather than a destroyed object.
struct connection_state {
    std::mutex mutex;
    std::condition_variable changed;

    nw_connection_state_t state = nw_connection_state_invalid;
    std::string state_error;

    bool send_complete = false;
    std::string send_error;

    bool receive_complete = false;
    std::string receive_error;
    std::string received;
    bool peer_closed = false;
};

constexpr auto wait_slice = std::chrono::milliseconds{100};

enum class wait_result : std::uint8_t {
    ready,
    stopped,
    timed_out,
};

template<class Predicate>
auto wait_for(
    connection_state& shared,
    std::unique_lock<std::mutex>& lock,
    Predicate ready,
    const std::stop_token& stop,
    byte_stream::deadline until
) -> wait_result {
    while (!ready()) {
        if (stop.stop_requested()) {
            return wait_result::stopped;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= until) {
            return wait_result::timed_out;
        }
        shared.changed.wait_until(lock, std::min(until, now + wait_slice));
    }
    return wait_result::ready;
}

auto describe(nw_error_t error) -> std::string {
    if (error == nullptr) {
        return "unknown error";
    }
    const int code = nw_error_get_error_code(error);
    // Not a switch: the SDK adds domains, and an unknown one still needs a
    // message rather than a build break.
    const auto domain = nw_error_get_error_domain(error);
    if (domain == nw_error_domain_posix) {
        return std::string{std::strerror(code)};
    }
    if (domain == nw_error_domain_dns) {
        return "DNS resolution failed (" + std::to_string(code) + ")";
    }
    if (domain == nw_error_domain_tls) {
        return "TLS handshake or verification failed (OSStatus " + std::to_string(code) + ")";
    }
    return "network error " + std::to_string(code);
}

auto unavailable(wait_result result, std::string_view phase) -> std::string {
    return std::string{phase} +
           (result == wait_result::stopped ? ": cancelled" : ": deadline exceeded");
}

class tls_stream final : public byte_stream {
public:
    tls_stream(
        nw_connection_t connection, dispatch_queue_t queue, std::shared_ptr<connection_state> shared
    )
        : connection_{connection}, queue_{queue}, shared_{std::move(shared)} {}

    tls_stream(const tls_stream&) = delete;
    tls_stream& operator=(const tls_stream&) = delete;
    tls_stream(tls_stream&&) = delete;
    tls_stream& operator=(tls_stream&&) = delete;

    ~tls_stream() override {
        // Cancel tears down the connection and drops its handlers; any block
        // still queued holds its own reference to the shared state.
        nw_connection_cancel(connection_);
        nw_release(connection_);
        dispatch_release(queue_);
    }

    auto write_all(std::string_view data, std::stop_token stop, deadline until)
        -> std::expected<void, std::string> override {
        if (auto refused = already_unavailable(stop, until, "write")) {
            return std::unexpected(*refused);
        }
        {
            const std::scoped_lock lock{shared_->mutex};
            shared_->send_complete = false;
            shared_->send_error.clear();
        }
        // DEFAULT destructor copies the bytes, so `data` need not outlive the send.
        dispatch_data_t content = dispatch_data_create(
            data.data(), data.size(), queue_, DISPATCH_DATA_DESTRUCTOR_DEFAULT
        );
        auto shared = shared_;
        nw_connection_send(
            connection_,
            content,
            NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
            false,
            ^(nw_error_t error) {
              const std::scoped_lock lock{shared->mutex};
              if (error != nullptr) {
                  shared->send_error = describe(error);
              }
              shared->send_complete = true;
              shared->changed.notify_all();
            }
        );
        dispatch_release(content);

        std::unique_lock lock{shared_->mutex};
        const auto result =
            wait_for(*shared_, lock, [this] { return shared_->send_complete; }, stop, until);
        if (result != wait_result::ready) {
            lock.unlock();
            nw_connection_cancel(connection_);
            return std::unexpected(unavailable(result, "write"));
        }
        if (!shared_->send_error.empty()) {
            return std::unexpected("write: " + shared_->send_error);
        }
        return {};
    }

    auto read_some(std::span<char> into, std::stop_token stop, deadline until)
        -> std::expected<std::size_t, std::string> override {
        if (auto refused = already_unavailable(stop, until, "read")) {
            return std::unexpected(*refused);
        }
        std::unique_lock lock{shared_->mutex};
        // A completion can carry neither data nor end-of-stream; that is not
        // EOF, so ask again rather than report a clean close.
        while (shared_->received.empty() && !shared_->peer_closed) {
            shared_->receive_complete = false;
            shared_->receive_error.clear();
            lock.unlock();
            auto shared = shared_;
            nw_connection_receive(
                connection_,
                1,
                static_cast<std::uint32_t>(std::min<std::size_t>(into.size(), 65536U)),
                ^(dispatch_data_t content,
                  nw_content_context_t /*context*/,
                  bool is_complete,
                  nw_error_t error) {
                  const std::scoped_lock inner{shared->mutex};
                  if (content != nullptr) {
                      dispatch_data_apply(
                          content,
                          ^bool(
                              dispatch_data_t /*region*/,
                              size_t /*offset*/,
                              const void* buffer,
                              size_t size
                          ) {
                            shared->received.append(static_cast<const char*>(buffer), size);
                            return true;
                          }
                      );
                  }
                  if (error != nullptr) {
                      shared->receive_error = describe(error);
                  } else if (is_complete) {
                      shared->peer_closed = true;
                  }
                  shared->receive_complete = true;
                  shared->changed.notify_all();
                }
            );
            lock.lock();
            const auto result =
                wait_for(*shared_, lock, [this] { return shared_->receive_complete; }, stop, until);
            if (result != wait_result::ready) {
                lock.unlock();
                nw_connection_cancel(connection_);
                return std::unexpected(unavailable(result, "read"));
            }
            if (!shared_->receive_error.empty() && shared_->received.empty()) {
                return std::unexpected("read: " + shared_->receive_error);
            }
        }
        const auto count = std::min(into.size(), shared_->received.size());
        std::memcpy(into.data(), shared_->received.data(), count);
        shared_->received.erase(0, count);
        return count;
    }

private:
    nw_connection_t connection_;
    dispatch_queue_t queue_;
    std::shared_ptr<connection_state> shared_;
};

} // namespace

auto connect_tls(
    const std::string& host, std::uint16_t port, std::stop_token stop, byte_stream::deadline until
) -> std::expected<std::unique_ptr<byte_stream>, std::string> {
    if (auto refused = already_unavailable(stop, until, "connect")) {
        return std::unexpected(*refused);
    }
    const std::string port_string = std::to_string(port);
    nw_endpoint_t endpoint = nw_endpoint_create_host(host.c_str(), port_string.c_str());
    if (endpoint == nullptr) {
        return std::unexpected(std::string{"connect: invalid upstream host"});
    }

    // System trust, SNI and hostname verification come from the endpoint
    // host; the only change from the defaults is refusing anything below 1.2.
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t tls_options) {
          sec_protocol_options_t security = nw_tls_copy_sec_protocol_options(tls_options);
          sec_protocol_options_set_min_tls_protocol_version(security, tls_protocol_version_TLSv12);
          sec_protocol_options_add_tls_application_protocol(security, "http/1.1");
          sec_release(security);
        },
        NW_PARAMETERS_DEFAULT_CONFIGURATION
    );
    // Reach the provider directly when the network allows it. A host-wide
    // proxy is operator configuration, and TLS still terminates at the
    // provider, so a proxy that is required remains usable.
    nw_parameters_set_prefer_no_proxy(parameters, true);

    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    nw_release(endpoint);
    nw_release(parameters);
    if (connection == nullptr) {
        return std::unexpected(std::string{"connect: could not create connection"});
    }

    dispatch_queue_t queue = dispatch_queue_create("glove.net.tls", DISPATCH_QUEUE_SERIAL);
    auto shared = std::make_shared<connection_state>();
    nw_connection_set_queue(connection, queue);
    nw_connection_set_state_changed_handler(
        connection, ^(nw_connection_state_t state, nw_error_t error) {
          const std::scoped_lock lock{shared->mutex};
          shared->state = state;
          if (error != nullptr && shared->state_error.empty()) {
              shared->state_error = describe(error);
          }
          shared->changed.notify_all();
        }
    );
    // The stream owns the connection and queue from here, so every early
    // return below releases them.
    auto stream = std::make_unique<tls_stream>(connection, queue, shared);
    nw_connection_start(connection);

    std::unique_lock lock{shared->mutex};
    // `waiting` means the path is unusable right now (refused, unreachable, no
    // route). Network.framework would retry when it changes; a request with a
    // deadline should fail instead.
    const auto result = wait_for(
        *shared,
        lock,
        [&] {
            return shared->state == nw_connection_state_ready ||
                   shared->state == nw_connection_state_waiting ||
                   shared->state == nw_connection_state_failed ||
                   shared->state == nw_connection_state_cancelled;
        },
        stop,
        until
    );
    if (result != wait_result::ready) {
        return std::unexpected(unavailable(result, "connect"));
    }
    if (shared->state != nw_connection_state_ready) {
        return std::unexpected(
            "connect: " +
            (shared->state_error.empty() ? std::string{"connection failed"} : shared->state_error)
        );
    }
    return stream;
}

} // namespace glove::net
