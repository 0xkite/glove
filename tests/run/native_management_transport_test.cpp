#include "native_management_transport.hpp"
#include "native_session_store.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using namespace glove::run::detail;
using clock_type = std::chrono::steady_clock;

struct temporary_directory {
    fs::path path;

    temporary_directory() {
        char pattern[] = "/tmp/gmg-XXXXXX";
        if (const auto* created = ::mkdtemp(pattern)) {
            std::error_code error;
            path = fs::canonical(created, error);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        if (!path.empty()) {
            std::error_code error;
            fs::remove_all(path, error);
        }
    }
};

const std::string session = "ns-" + std::string(32, '5');
const std::string epoch(32, '6');

// Raw peer for malformed-frame cases: connect, send bytes, expect closure.
class raw_peer {
public:
    explicit raw_peer(const fs::path& path) {
        fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        ::sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
        if (fd_ >= 0 &&
            ::connect(fd_, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    raw_peer(const raw_peer&) = delete;
    auto operator=(const raw_peer&) -> raw_peer& = delete;

    ~raw_peer() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] auto connected() const -> bool { return fd_ >= 0; }

    auto send_frame(std::string_view body, std::uint32_t declared) -> bool {
        std::string frame;
        for (int shift = 24; shift >= 0; shift -= 8) {
            frame.push_back(static_cast<char>((declared >> shift) & 0xffU));
        }
        frame += body;
        return ::write(fd_, frame.data(), frame.size()) == static_cast<ssize_t>(frame.size());
    }

    // Returns true when the server closed without sending any byte.
    auto closed_silently(std::chrono::milliseconds wait) -> bool {
        const auto deadline = clock_type::now() + wait;
        while (clock_type::now() < deadline) {
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 50) > 0) {
                char byte = 0;
                const auto got = ::read(fd_, &byte, 1);
                return got == 0;
            }
        }
        return false;
    }

    auto read_frame() -> std::string {
        std::string out;
        char buffer[4096];
        for (;;) {
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&pfd, 1, 2000) <= 0) {
                return out;
            }
            const auto got = ::read(fd_, buffer, sizeof(buffer));
            if (got <= 0) {
                return out;
            }
            out.append(buffer, static_cast<std::size_t>(got));
            if (out.size() >= 4) {
                std::uint32_t length = 0;
                for (std::size_t index = 0; index < 4; ++index) {
                    length = (length << 8U) | static_cast<unsigned char>(out[index]);
                }
                if (out.size() >= 4 + length) {
                    return out.substr(4, length);
                }
            }
        }
    }

private:
    int fd_ = -1;
};

auto write_file(const fs::path& path, std::string_view bytes) -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

struct recorded_request {
    management_request request;
};

auto wait_until(const std::function<bool()>& condition, std::chrono::milliseconds limit) -> bool {
    const auto deadline = clock_type::now() + limit;
    while (clock_type::now() < deadline) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return condition();
}

auto roundtrip_and_refusals(const fs::path& root) -> int {
    const auto control = root / "control";
    fs::create_directories(control);
    REQUIRE(::chmod(control.c_str(), 0700) == 0);
    std::mutex mutex;
    std::vector<management_request> seen;
    std::vector<std::string> listener_notes;
    auto server = native_management_server::start(
        control,
        session,
        epoch,
        {"status_v1", "stop_v1", "resume_v1"},
        [&](const management_request& request) {
            std::scoped_lock lock{mutex};
            seen.push_back(request);
            operation_result result{
                .op = request.op,
                .code = request.op == session_operation::status ? result_code::ok
                                                                : result_code::accepted,
                .final = request.op == session_operation::status,
                .snapshot = {
                    .phase = session_phase::running,
                    .generation = 3,
                    .history = history_status::absent,
                    .effects = effects_status::unassessed,
                    .checkpoint = std::string(64, 'c')
                }
            };
            return result;
        },
        [&](std::string_view detail) {
            std::scoped_lock lock{mutex};
            listener_notes.emplace_back(detail);
        }
    );
    REQUIRE(server);
    REQUIRE(fs::is_socket((*server)->socket_path()));
    struct stat sock{};
    REQUIRE(
        ::lstat((*server)->socket_path().c_str(), &sock) == 0 && (sock.st_mode & 07777U) == 0600
    );
    struct stat capability{};
    REQUIRE(
        ::lstat((control / "cap").c_str(), &capability) == 0 &&
        (capability.st_mode & 07777U) == 0600
    );
    auto read_capability = read_management_capability(control, session);
    REQUIRE(read_capability && read_capability->first == epoch);
    REQUIRE(!read_management_capability(control, "ns-" + std::string(32, '0')));

    // Authenticated status round trip.
    auto status = management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '1'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(status);
    REQUIRE(
        status->code == result_code::ok && status->final && status->state == session_phase::running
    );
    REQUIRE(status->generation == 3 && status->checkpoint == std::string(64, 'c'));
    REQUIRE(status->op == session_operation::status && status->request == std::string(32, '1'));
    {
        std::scoped_lock lock{mutex};
        REQUIRE(seen.size() == 1 && seen.front().observed_generation == 0);
        REQUIRE(valid_checkpoint_id(seen.front().body_digest));
    }
    // Resume with checkpoint, and exact-body replay yields the same body digest.
    auto body = render_management_request(
        session, epoch, 3, std::string(32, '2'), session_operation::resume, std::string(64, 'c')
    );
    REQUIRE(body);
    auto first = management_request_raw(control, session, *body);
    auto second = management_request_raw(control, session, *body);
    REQUIRE(first && second && first->code == result_code::accepted && !first->final);
    {
        std::scoped_lock lock{mutex};
        REQUIRE(seen.size() == 3);
        REQUIRE(seen[1].body_digest == seen[2].body_digest);
        REQUIRE(
            seen[1].checkpoint == std::string(64, 'c') && seen[1].op == session_operation::resume
        );
        REQUIRE(seen[0].body_digest != seen[1].body_digest);
    }
    // Reordered members with the same request id differ in digest (no canonicalization).
    const std::string reordered =
        "{\"type\":\"request\",\"v\":1,\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
        "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, '2') +
        "\",\"op\":\"resume\",\"checkpoint\":\"" + std::string(64, 'c') + "\"}";
    REQUIRE(management_request_raw(control, session, reordered));
    {
        std::scoped_lock lock{mutex};
        REQUIRE(seen.size() == 4 && seen[3].body_digest != seen[2].body_digest);
    }

    // Malformed frames close without any byte and without reaching the handler.
    const auto path = (*server)->socket_path();
    const std::vector<std::pair<std::string, std::uint32_t>> bad_auth{
        {"", 0},
        {std::string(70000, '{'), 70000},
        {"{\"v\":2,\"type\":\"auth\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
             "\",\"capability\":\"" + std::string(64, '0') + "\"}",
         0},
        {"{\"v\":1,\"type\":\"auth\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
             "\",\"capability\":\"" + std::string(64, '0') + "\",\"signal\":9}",
         0},
        {"{\"v\":1,\"type\":\"auth\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch + "\"}",
         0},
        {"not json", 0},
        {"{\"v\":1,\"v\":1,\"type\":\"auth\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
             "\",\"capability\":\"" + std::string(64, '0') + "\"}",
         0},
        {"{\"v\":1,\"type\":\"auth\",\"session\":\"" + session + "\",\"epoch\":\"" +
             std::string(32, '9') + "\",\"capability\":\"" + std::string(64, '0') + "\"}",
         0},
    };
    for (const auto& [frame, declared] : bad_auth) {
        raw_peer peer{path};
        REQUIRE(peer.connected());
        // An oversized declared length is refused at the prefix, so the write
        // of the remaining bytes may fail with EPIPE; closure is the evidence.
        const bool sent = peer.send_frame(
            frame, declared == 0 ? static_cast<std::uint32_t>(frame.size()) : declared
        );
        REQUIRE(sent || declared > management_max_frame_bytes);
        REQUIRE(peer.closed_silently(std::chrono::seconds{4}));
    }
    // A wrong capability (right shape) also closes silently: the client reports refusal.
    const auto capability_path = control / "cap";
    const auto saved = [&] {
        std::ifstream input{capability_path};
        return std::string{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    }();
    REQUIRE(
        write_file(capability_path, session + "\n" + epoch + "\n" + std::string(64, '0') + "\n")
    );
    auto refused = management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '1'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(!refused && refused.error().code == management_client_error::authentication_refused);
    REQUIRE(write_file(capability_path, saved));
    // Authenticated, then malformed requests: closed silently, handler untouched.
    const std::size_t handled_before = [&] {
        std::scoped_lock lock{mutex};
        return seen.size();
    }();
    auto token = read_management_capability(control, session);
    REQUIRE(token);
    const std::string good_auth = "{\"v\":1,\"type\":\"auth\",\"session\":\"" + session +
                                  "\",\"epoch\":\"" + epoch + "\",\"capability\":\"" +
                                  token->second + "\"}";
    const std::vector<std::string> bad_requests{
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, '2') +
            "\",\"op\":\"status\",\"checkpoint\":\"" + std::string(64, 'c') +
            "\",\"signal\":\"TERM\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"3\",\"request\":\"" + std::string(32, '2') +
            "\",\"op\":\"status\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, 'G') +
            "\",\"op\":\"status\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, '2') +
            "\",\"op\":\"kill\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, '2') +
            "\",\"op\":\"resume\",\"checkpoint\":\"" + std::string(63, 'c') + "\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" +
            std::string(32, '9') + "\",\"generation\":\"0000000000000003\",\"request\":\"" +
            std::string(32, '2') + "\",\"op\":\"status\"}",
        "{\"v\":1,\"type\":\"request\",\"session\":\"" + session + "\",\"epoch\":\"" + epoch +
            "\",\"generation\":\"0000000000000003\",\"request\":\"" + std::string(32, '2') +
            "\",\"op\":\"status\"}\n",
    };
    for (const auto& request : bad_requests) {
        raw_peer peer{path};
        REQUIRE(peer.connected());
        REQUIRE(peer.send_frame(good_auth, static_cast<std::uint32_t>(good_auth.size())));
        REQUIRE(peer.read_frame().find("\"type\":\"ready\"") != std::string::npos);
        REQUIRE(peer.send_frame(request, static_cast<std::uint32_t>(request.size())));
        if (!peer.closed_silently(std::chrono::seconds{6})) {
            std::fprintf(stderr, "not closed for request: %s\n", request.c_str());
            return 1;
        }
    }
    {
        std::scoped_lock lock{mutex};
        REQUIRE(seen.size() == handled_before);
    }
    // Status with a checkpoint is a schema violation the handler never sees
    // (the model would also refuse it); the transport treats op/checkpoint
    // pairing as the model's rule, so here it reaches the handler as data.

    // Listener recovery: the owner survives, the socket name is lost.
    const auto identity = (*server)->listener_identity();
    REQUIRE(::unlink(path.c_str()) == 0);
    REQUIRE(wait_until([&] { return (*server)->recreations() == 1; }, std::chrono::seconds{5}));
    REQUIRE((*server)->listener_identity() != identity);
    REQUIRE(fs::is_socket(path));
    auto after = management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '7'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(after && after->code == result_code::ok);
    {
        std::scoped_lock lock{mutex};
        REQUIRE(
            !listener_notes.empty() && listener_notes.back().find("recreated") != std::string::npos
        );
    }
    // A foreign object at the name is refused and never unlinked; once the
    // operator removes it, the owner recreates its own listener.
    REQUIRE(::unlink(path.c_str()) == 0);
    REQUIRE(write_file(path, "foreign"));
    REQUIRE(wait_until([&] { return (*server)->refusals() >= 1; }, std::chrono::seconds{5}));
    auto blocked = management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '8'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(!blocked);
    REQUIRE(fs::is_regular_file(path));
    REQUIRE(::unlink(path.c_str()) == 0);
    REQUIRE(wait_until([&] { return (*server)->recreations() == 2; }, std::chrono::seconds{5}));
    REQUIRE(management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '9'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    ));
    const auto connections = (*server)->connections();
    REQUIRE(connections >= 6);

    // Stale pathname after the owner is gone: refused, nothing is resurrected.
    server->reset();
    REQUIRE(!fs::exists(path));
    REQUIRE(!fs::exists(capability_path));
    {
        // Simulate a leftover socket name from a crashed owner.
        const int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
        ::sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
        REQUIRE(::bind(stale, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) == 0);
        ::close(stale);
        REQUIRE(write_file(capability_path, saved));
        REQUIRE(::chmod(capability_path.c_str(), 0600) == 0);
    }
    REQUIRE(fs::is_socket(path));
    auto stale = management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '1'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(!stale && stale.error().code == management_client_error::connection_refused);
    REQUIRE(fs::is_socket(path));
    // A new epoch owner replaces only its own-UID stale socket and mints a fresh capability.
    auto restarted = native_management_server::start(
        control,
        session,
        std::string(32, 'a'),
        {"status_v1"},
        [](const management_request& request) {
            return operation_result{
                .op = request.op, .code = result_code::ok, .final = true, .snapshot = {}
            };
        }
    );
    REQUIRE(restarted);
    auto fresh = read_management_capability(control, session);
    REQUIRE(fresh && fresh->first == std::string(32, 'a') && fresh->second != token->second);
    REQUIRE(management_request_once(
        control,
        session,
        {.observed_generation = 0,
         .request = std::string(32, '1'),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    ));
    // Old-epoch frames refuse under the new owner.
    {
        raw_peer peer{path};
        REQUIRE(peer.connected());
        REQUIRE(peer.send_frame(good_auth, static_cast<std::uint32_t>(good_auth.size())));
        REQUIRE(peer.closed_silently(std::chrono::seconds{4}));
    }
    return 0;
}

} // namespace

auto main() -> int {
    // Raw peers deliberately write into closed connections.
    (void)::signal(SIGPIPE, SIG_IGN);
    temporary_directory root;
    REQUIRE(!root.path.empty());
    REQUIRE(::chmod(root.path.c_str(), 0700) == 0);
    REQUIRE(roundtrip_and_refusals(root.path) == 0);
    return 0;
}
