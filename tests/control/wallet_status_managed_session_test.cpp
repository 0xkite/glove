#include "wallet_status_managed_session.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace allocation_failure {
std::atomic<bool> next{false};
} // namespace allocation_failure

void* operator new(std::size_t size) {
    if (allocation_failure::next.exchange(false)) {
        throw std::bad_alloc{};
    }
    if (void* memory = std::malloc(size); memory != nullptr) {
        return memory;
    }
    throw std::bad_alloc{};
}

void operator delete(void* memory) noexcept {
    std::free(memory);
}

void operator delete(void* memory, std::size_t /*size*/) noexcept {
    std::free(memory);
}

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using steady_time = std::chrono::steady_clock::time_point;

struct reentrant_close_state {
    std::mutex mutex;
    std::condition_variable condition;
    glove::control::wallet_status_managed_session* managed = nullptr;
    bool authority_entered = false;
    bool permit_reentrant_close = false;
};

[[nodiscard]] auto session() -> glove::control::session_record {
    return {
        .schema_version = 1,
        .session_id = "synthetic-wallet-session",
        .controller_plan_digest = std::string(64U, 'a'),
        .plan_content_digest = std::string(64U, 'b'),
        .state = glove::control::session_state::running,
        .policy_revision = 1,
        .expires_at_ms = 20'000U,
        .created_at_ms = 1'000U,
    };
}

[[nodiscard]] auto policy() -> glove::control::wallet_status_bridge_policy {
    return {
        .schema_version = 1,
        .tool_policy_id = "synthetic-wallet-status",
        .wallet_server_alias = "synthetic-wallet-host",
        .wallet_server_node_digest = std::string(64U, 'c'),
        .allowed_chain_ids = {8453U},
        .maximum_status_age_ms = 5'000U,
    };
}

[[nodiscard]] auto binding() -> glove::control::wallet_status_plan_binding {
    const auto current = session();
    return {
        .session_id = current.session_id,
        .controller_plan_digest = current.controller_plan_digest,
        .plan_content_digest = current.plan_content_digest,
        .policy_revision = current.policy_revision,
        .expires_at_ms = current.expires_at_ms,
        .generation = 1U,
    };
}

class fixed_clock final : public glove::control::wallet_status_clock {
public:
    [[nodiscard]] auto now() noexcept -> glove::control::wallet_status_time override {
        return {.unix_time_ms = 10'000U, .monotonic_time = std::chrono::steady_clock::now()};
    }
};

class plan_authority final : public glove::control::wallet_status_plan_authority {
public:
    explicit plan_authority(std::shared_ptr<reentrant_close_state> close_state = {})
        : close_state_(std::move(close_state)) {}

    [[nodiscard]] auto snapshot(steady_time /*deadline*/) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_plan_snapshot> override {
        if (close_state_) {
            glove::control::wallet_status_managed_session* managed = nullptr;
            {
                std::unique_lock lock{close_state_->mutex};
                close_state_->authority_entered = true;
                close_state_->condition.notify_all();
                close_state_->condition.wait(lock, [this] {
                    return close_state_->permit_reentrant_close;
                });
                managed = close_state_->managed;
            }
            managed->close();
        }
        return glove::control::wallet_status_plan_snapshot{
            .binding = binding(),
            .session = session(),
            .policy = policy(),
            .adapter_command_digest = std::string(64U, 'd'),
        };
    }

private:
    std::shared_ptr<reentrant_close_state> close_state_;
};

class readiness_authority final : public glove::control::wallet_status_readiness_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_readiness_snapshot> override {
        return glove::control::wallet_status_readiness_snapshot{
            .binding = current,
            .audit_generation = 1U,
            .journal_generation = 1U,
        };
    }
};

class adapter_authority final : public glove::control::wallet_status_adapter_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_adapter_snapshot> override {
        return glove::control::wallet_status_adapter_snapshot{
            .binding = current,
            .adapter_command_digest = std::string(64U, 'd'),
        };
    }
};

class server_authority final : public glove::control::wallet_status_server_authority {
public:
    [[nodiscard]] auto snapshot(
        const glove::control::wallet_status_plan_binding& current, steady_time /*deadline*/
    ) const
        -> glove::control::wallet_status_authority_result<
            glove::control::wallet_status_server_snapshot> override {
        return glove::control::wallet_status_server_snapshot{
            .binding = current,
            .wallet_server_node_digest = std::string(64U, 'c'),
            .observation = {
                .connected = true,
                .observed_at_ms = 9'000U,
                .wallet_server_alias = "synthetic-wallet-host",
                .allowed_chain_ids = {8453U},
            },
        };
    }
};

[[nodiscard]] auto bridge(std::shared_ptr<reentrant_close_state> close_state = {})
    -> std::unique_ptr<glove::control::wallet_status_bridge> {
    return std::make_unique<glove::control::wallet_status_bridge>(
        std::make_unique<plan_authority>(std::move(close_state)),
        std::make_unique<readiness_authority>(),
        std::make_unique<adapter_authority>(),
        std::make_unique<server_authority>(),
        std::make_unique<fixed_clock>()
    );
}

[[nodiscard]] auto options(
    std::chrono::milliseconds request_timeout = std::chrono::seconds{1},
    std::chrono::milliseconds session_lifetime = std::chrono::seconds{5}
) -> glove::control::wallet_status_managed_session_options {
    return {
        .enabled = true,
        .request_timeout = request_timeout,
        .session_deadline = std::chrono::steady_clock::now() + session_lifetime,
        .expected_peer_uid = ::geteuid(),
    };
}

[[nodiscard]] auto composed(
    std::chrono::milliseconds request_timeout = std::chrono::seconds{1},
    std::chrono::milliseconds session_lifetime = std::chrono::seconds{5}
) -> std::expected<std::unique_ptr<glove::control::wallet_status_managed_session>, std::string> {
    return glove::control::wallet_status_managed_session::create(
        bridge(), options(request_timeout, session_lifetime)
    );
}

[[nodiscard]] auto wait_closed(
    const glove::control::wallet_status_managed_session& managed,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{500}
) -> bool {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!managed.closed() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return managed.closed();
}

[[nodiscard]] auto open_descriptor_count() -> int {
    int count = 0;
    const auto limit = ::getdtablesize();
    for (int descriptor = 0; descriptor < limit; ++descriptor) {
        errno = 0;
        if (::fcntl(descriptor, F_GETFD) >= 0 || errno != EBADF) {
            ++count;
        }
    }
    return count;
}

[[nodiscard]] auto write_raw(int descriptor, const unsigned char* data, std::size_t size) -> bool {
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = ::write(descriptor, data + offset, size - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

[[nodiscard]] auto run() -> int {
    using namespace glove::control;

    auto disabled_options = options();
    disabled_options.enabled = false;
    REQUIRE(!wallet_status_managed_session::create(bridge(), disabled_options).has_value());
    REQUIRE(!wallet_status_managed_session::create(nullptr, options()).has_value());
    auto wrong_owner = options();
    wrong_owner.expected_peer_uid = ::geteuid() + 1U;
    REQUIRE(!wallet_status_managed_session::create(bridge(), wrong_owner).has_value());
    REQUIRE(
        !wallet_status_managed_session::create(bridge(), options(std::chrono::milliseconds::zero()))
             .has_value()
    );
    REQUIRE(!wallet_status_managed_session::create(bridge(), options(std::chrono::seconds{6}))
                 .has_value());
    REQUIRE(!wallet_status_managed_session::create(
                 bridge(), options(std::chrono::seconds{1}, std::chrono::milliseconds{-1})
    )
                 .has_value());

    auto allocation_bridge = bridge();
    const auto allocation_options = options();
    const auto descriptors_before_allocation_failure = open_descriptor_count();
    bool allocation_failed = false;
    allocation_failure::next.store(true);
    try {
        (void)wallet_status_managed_session::create(
            std::move(allocation_bridge), allocation_options
        );
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    allocation_failure::next.store(false);
    REQUIRE(allocation_failed);
    REQUIRE(open_descriptor_count() == descriptors_before_allocation_failure);

    const auto descriptors_before_untransferred_expiry = open_descriptor_count();
    auto untransferred_expiry = composed(std::chrono::seconds{1}, std::chrono::milliseconds{50});
    REQUIRE(untransferred_expiry.has_value());
    REQUIRE((*untransferred_expiry)->start().has_value());
    REQUIRE(wait_closed(**untransferred_expiry));
    REQUIRE(open_descriptor_count() == descriptors_before_untransferred_expiry);
    (*untransferred_expiry)->close();

    const auto descriptors_before_worker_allocation_failure = open_descriptor_count();
    auto worker_allocation_failure = composed();
    REQUIRE(worker_allocation_failure.has_value());
    auto worker_allocation_guest = (*worker_allocation_failure)->take_guest_descriptor();
    REQUIRE(worker_allocation_guest.has_value());
    REQUIRE((*worker_allocation_failure)->start().has_value());
    constexpr std::array<unsigned char, 2> worker_header_prefix{0x00U, 0x00U};
    constexpr std::array<unsigned char, 2> worker_header_suffix{0x00U, 0x40U};
    REQUIRE(write_raw(
        *worker_allocation_guest, worker_header_prefix.data(), worker_header_prefix.size()
    ));
    allocation_failure::next.store(true);
    REQUIRE(write_raw(
        *worker_allocation_guest, worker_header_suffix.data(), worker_header_suffix.size()
    ));
    REQUIRE(wait_closed(**worker_allocation_failure));
    allocation_failure::next.store(false);
    REQUIRE(open_descriptor_count() == descriptors_before_worker_allocation_failure + 1);
    (*worker_allocation_failure)->close();
    REQUIRE(::close(*worker_allocation_guest) == 0);
    REQUIRE(open_descriptor_count() == descriptors_before_worker_allocation_failure);

    std::array<int, 2> sentinel{-1, -1};
    REQUIRE(::pipe(sentinel.data()) == 0);
    auto live = composed();
    REQUIRE(live.has_value());
    auto guest = (*live)->take_guest_descriptor();
    REQUIRE(guest.has_value());
    REQUIRE(!(*live)->take_guest_descriptor().has_value());

    struct stat guest_status{};
    int socket_type = 0;
    socklen_t socket_type_length = sizeof(socket_type);
    sockaddr_storage local{};
    sockaddr_storage peer{};
    socklen_t local_length = sizeof(local);
    socklen_t peer_length = sizeof(peer);
    REQUIRE(::fstat(*guest, &guest_status) == 0);
    REQUIRE(S_ISSOCK(guest_status.st_mode));
    REQUIRE(guest_status.st_uid == ::geteuid());
    REQUIRE((::fcntl(*guest, F_GETFD) & FD_CLOEXEC) != 0);
    REQUIRE((::fcntl(*guest, F_GETFL) & O_NONBLOCK) != 0);
    REQUIRE(::getsockopt(*guest, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length) == 0);
    REQUIRE(socket_type == SOCK_STREAM);
    REQUIRE(::getsockname(*guest, reinterpret_cast<sockaddr*>(&local), &local_length) == 0);
    REQUIRE(::getpeername(*guest, reinterpret_cast<sockaddr*>(&peer), &peer_length) == 0);
    REQUIRE(local.ss_family == AF_UNIX);
    REQUIRE(peer.ss_family == AF_UNIX);

    REQUIRE((*live)->start().has_value());
    REQUIRE(!(*live)->start().has_value());
    auto request = encode_wallet_status_request("managed-status-1", 1'000U);
    REQUIRE(request.has_value());
    for (int round = 0; round < 2; ++round) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
        REQUIRE(write_wallet_status_frame(*guest, *request, deadline).has_value());
        auto response = read_wallet_status_frame(*guest, deadline);
        REQUIRE(response.has_value());
        auto decoded = decode_wallet_status_response(*response);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->available_actions == std::vector<std::string>{"status"});
        REQUIRE(decoded->mutating_actions.empty());
        REQUIRE(response->find("private_key") == std::string::npos);
        REQUIRE(response->find(session().controller_plan_digest) == std::string::npos);
    }
    const auto close_started = std::chrono::steady_clock::now();
    (*live)->close();
    (*live)->close();
    REQUIRE((*live)->closed());
    REQUIRE(std::chrono::steady_clock::now() - close_started < std::chrono::milliseconds{500});
    REQUIRE(::fcntl(sentinel[0], F_GETFD) >= 0);
    REQUIRE(::fcntl(sentinel[1], F_GETFD) >= 0);
    REQUIRE(::close(*guest) == 0);
    REQUIRE(::close(sentinel[0]) == 0);
    REQUIRE(::close(sentinel[1]) == 0);

    auto partial_header = composed(std::chrono::milliseconds{200});
    REQUIRE(partial_header.has_value());
    auto partial_header_guest = (*partial_header)->take_guest_descriptor();
    REQUIRE(partial_header_guest.has_value());
    REQUIRE((*partial_header)->start().has_value());
    constexpr std::array<unsigned char, 2> short_header{0x00U, 0x00U};
    REQUIRE(write_raw(*partial_header_guest, short_header.data(), short_header.size()));
    REQUIRE(::shutdown(*partial_header_guest, SHUT_WR) == 0);
    REQUIRE(wait_closed(**partial_header));
    (*partial_header)->close();
    REQUIRE(::close(*partial_header_guest) == 0);

    auto partial_body = composed(std::chrono::milliseconds{200});
    REQUIRE(partial_body.has_value());
    auto partial_body_guest = (*partial_body)->take_guest_descriptor();
    REQUIRE(partial_body_guest.has_value());
    REQUIRE((*partial_body)->start().has_value());
    constexpr std::array<unsigned char, 6> short_body{0x00U, 0x00U, 0x00U, 0x08U, 'x', 'y'};
    REQUIRE(write_raw(*partial_body_guest, short_body.data(), short_body.size()));
    REQUIRE(::shutdown(*partial_body_guest, SHUT_WR) == 0);
    REQUIRE(wait_closed(**partial_body));
    (*partial_body)->close();
    REQUIRE(::close(*partial_body_guest) == 0);

    for (const auto header : {
             std::array<unsigned char, 4>{0x00U, 0x00U, 0x00U, 0x00U},
             std::array<unsigned char, 4>{0x00U, 0x01U, 0x00U, 0x01U},
         }) {
        auto invalid_frame = composed();
        REQUIRE(invalid_frame.has_value());
        auto invalid_guest = (*invalid_frame)->take_guest_descriptor();
        REQUIRE(invalid_guest.has_value());
        REQUIRE((*invalid_frame)->start().has_value());
        REQUIRE(write_raw(*invalid_guest, header.data(), header.size()));
        REQUIRE(wait_closed(**invalid_frame));
        (*invalid_frame)->close();
        REQUIRE(::close(*invalid_guest) == 0);
    }

    auto malformed = composed();
    REQUIRE(malformed.has_value());
    auto malformed_guest = (*malformed)->take_guest_descriptor();
    REQUIRE(malformed_guest.has_value());
    REQUIRE((*malformed)->start().has_value());
    const auto malformed_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE(write_wallet_status_frame(*malformed_guest, "{", malformed_deadline).has_value());
    REQUIRE(wait_closed(**malformed));
    (*malformed)->close();
    REQUIRE(::close(*malformed_guest) == 0);

    auto timed_out = composed(std::chrono::milliseconds{50});
    REQUIRE(timed_out.has_value());
    auto timed_out_guest = (*timed_out)->take_guest_descriptor();
    REQUIRE(timed_out_guest.has_value());
    REQUIRE((*timed_out)->start().has_value());
    constexpr unsigned char one_byte = 0x00U;
    REQUIRE(write_raw(*timed_out_guest, &one_byte, 1U));
    REQUIRE(wait_closed(**timed_out));
    (*timed_out)->close();
    REQUIRE(::close(*timed_out_guest) == 0);

    auto cancelled = composed();
    REQUIRE(cancelled.has_value());
    auto cancelled_guest = (*cancelled)->take_guest_descriptor();
    REQUIRE(cancelled_guest.has_value());
    REQUIRE((*cancelled)->start().has_value());
    REQUIRE(write_raw(*cancelled_guest, &one_byte, 1U));
    const auto cancel_started = std::chrono::steady_clock::now();
    (*cancelled)->close();
    REQUIRE(std::chrono::steady_clock::now() - cancel_started < std::chrono::milliseconds{500});
    REQUIRE((*cancelled)->closed());
    REQUIRE(::close(*cancelled_guest) == 0);

    auto peer_exit = composed();
    REQUIRE(peer_exit.has_value());
    auto peer_exit_guest = (*peer_exit)->take_guest_descriptor();
    REQUIRE(peer_exit_guest.has_value());
    REQUIRE((*peer_exit)->start().has_value());
    REQUIRE(::close(*peer_exit_guest) == 0);
    REQUIRE(wait_closed(**peer_exit));
    (*peer_exit)->close();

    auto response_peer_exit = composed();
    REQUIRE(response_peer_exit.has_value());
    auto response_peer_exit_guest = (*response_peer_exit)->take_guest_descriptor();
    REQUIRE(response_peer_exit_guest.has_value());
    REQUIRE((*response_peer_exit)->start().has_value());
    const auto response_peer_exit_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE(
        write_wallet_status_frame(*response_peer_exit_guest, *request, response_peer_exit_deadline)
            .has_value()
    );
    REQUIRE(::close(*response_peer_exit_guest) == 0);
    REQUIRE(wait_closed(**response_peer_exit));
    (*response_peer_exit)->close();

    const auto descriptors_before_concurrent_close = open_descriptor_count();
    auto concurrent_close = composed();
    REQUIRE(concurrent_close.has_value());
    REQUIRE((*concurrent_close)->start().has_value());
    std::vector<std::thread> closers;
    closers.reserve(8U);
    for (int index = 0; index < 8; ++index) {
        closers.emplace_back([&concurrent_close] { (*concurrent_close)->close(); });
    }
    for (auto& closer : closers) {
        closer.join();
    }
    REQUIRE((*concurrent_close)->closed());
    REQUIRE(open_descriptor_count() == descriptors_before_concurrent_close);

    auto reentrant_state = std::make_shared<reentrant_close_state>();
    auto reentrant_close =
        wallet_status_managed_session::create(bridge(reentrant_state), options());
    REQUIRE(reentrant_close.has_value());
    {
        const std::scoped_lock lock{reentrant_state->mutex};
        reentrant_state->managed = reentrant_close->get();
    }
    auto reentrant_guest = (*reentrant_close)->take_guest_descriptor();
    REQUIRE(reentrant_guest.has_value());
    REQUIRE((*reentrant_close)->start().has_value());
    const auto reentrant_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE(write_wallet_status_frame(*reentrant_guest, *request, reentrant_deadline).has_value());
    bool authority_entered = false;
    {
        std::unique_lock lock{reentrant_state->mutex};
        authority_entered = reentrant_state->condition.wait_for(
            lock, std::chrono::milliseconds{500}, [&reentrant_state] {
                return reentrant_state->authority_entered;
            }
        );
        if (!authority_entered) {
            reentrant_state->permit_reentrant_close = true;
        }
    }
    if (!authority_entered) {
        reentrant_state->condition.notify_all();
        (*reentrant_close)->close();
        (void)::close(*reentrant_guest);
        REQUIRE(authority_entered);
    }
    std::thread external_closer{[&reentrant_close] { (*reentrant_close)->close(); }};
    pollfd reentrant_event{.fd = *reentrant_guest, .events = POLLIN, .revents = 0};
    const auto reentrant_poll = ::poll(&reentrant_event, 1, 500);
    {
        const std::scoped_lock lock{reentrant_state->mutex};
        reentrant_state->permit_reentrant_close = true;
    }
    reentrant_state->condition.notify_all();
    external_closer.join();
    REQUIRE(reentrant_poll > 0);
    REQUIRE((reentrant_event.revents & (POLLIN | POLLHUP)) != 0);
    REQUIRE((*reentrant_close)->closed());
    REQUIRE(::close(*reentrant_guest) == 0);

    auto session_expiry = composed(std::chrono::seconds{1}, std::chrono::milliseconds{50});
    REQUIRE(session_expiry.has_value());
    auto expiring_guest = (*session_expiry)->take_guest_descriptor();
    REQUIRE(expiring_guest.has_value());
    REQUIRE((*session_expiry)->start().has_value());
    REQUIRE(wait_closed(**session_expiry));
    (*session_expiry)->close();
    REQUIRE(::close(*expiring_guest) == 0);

    return 0;
}

} // namespace

int main() {
    return run();
}
