#pragma once

#include "wallet_status_bridge.hpp"

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace glove::control {

struct wallet_status_managed_session_options {
    bool enabled = false;
    std::chrono::milliseconds request_timeout{max_wallet_status_request_ttl_ms};
    std::chrono::steady_clock::time_point session_deadline;
    uid_t expected_peer_uid = static_cast<uid_t>(-1);
};

// Private synthetic owner for exactly one unnamed per-session Unix stream
// socketpair. No production launcher, capability registry, or daemon constructs
// this type.
class wallet_status_managed_session final {
public:
    class construction_token {
    private:
        construction_token() = default;
        friend class wallet_status_managed_session;
    };

    wallet_status_managed_session(
        construction_token,
        std::unique_ptr<wallet_status_bridge> bridge,
        wallet_status_managed_session_options options,
        int host_descriptor,
        int guest_descriptor
    );
    wallet_status_managed_session(const wallet_status_managed_session&) = delete;
    auto operator=(const wallet_status_managed_session&) -> wallet_status_managed_session& = delete;
    wallet_status_managed_session(wallet_status_managed_session&&) = delete;
    auto operator=(wallet_status_managed_session&&) -> wallet_status_managed_session& = delete;
    ~wallet_status_managed_session();

    [[nodiscard]] static auto create(
        std::unique_ptr<wallet_status_bridge> bridge, wallet_status_managed_session_options options
    ) -> std::expected<std::unique_ptr<wallet_status_managed_session>, std::string>;

    // Starts one exclusive sequential host worker. There is no reconnect or
    // multiplexing path.
    [[nodiscard]] auto start() -> std::expected<void, std::string>;
    // Transfers the verified guest endpoint exactly once. It remains
    // nonblocking and CLOEXEC; no child mapping is implemented here.
    [[nodiscard]] auto take_guest_descriptor() -> std::expected<int, std::string>;
    // Cancels framing, shuts down the host endpoint, joins, and closes every
    // descriptor still owned by this object. Safe to call repeatedly.
    auto close() noexcept -> void;

    [[nodiscard]] auto closed() const noexcept -> bool;

private:
    auto run(const std::stop_token& stop) noexcept -> void;
    auto reap_owned_descriptors() noexcept -> void;

    std::unique_ptr<wallet_status_bridge> bridge_;
    wallet_status_managed_session_options options_;
    int host_descriptor_ = -1;
    int guest_descriptor_ = -1;
    mutable std::mutex mutex_;
    std::condition_variable close_condition_;
    bool started_ = false;
    bool guest_released_ = false;
    bool closing_ = false;
    bool join_in_progress_ = false;
    bool worker_joinable_ = false;
    bool worker_running_ = false;
    std::thread::id worker_id_{};
    std::stop_source worker_stop_source_{std::nostopstate};
    std::atomic<bool> closed_ = false;
    // Declared last so its destructor joins before worker-observed state ends
    // if an invariant outside the explicit close path is ever violated.
    std::jthread worker_;
};

} // namespace glove::control
