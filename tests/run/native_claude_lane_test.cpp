// Actual-Claude offline lane. Opt-in: requires the exact executable path,
// its SHA-256 and its version label in the environment. Without them this
// test reports the lane as unsupported and exits with the ctest skip code.
#include "claude_lane_fixture.hpp"
#include "native_session_fixture.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

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
using namespace glove::run::test_support;
using namespace std::chrono_literals;

constexpr int skip_code = 77;

unsigned request_counter = 0;

auto next_request() -> std::string {
    char buffer[40];
    std::snprintf(buffer, sizeof(buffer), "%032x", ++request_counter);
    return buffer;
}

auto control(
    const native_session_supervisor& supervisor,
    session_operation op,
    std::uint64_t observed,
    std::optional<std::string> checkpoint = std::nullopt,
    std::string request = {}
) -> std::expected<management_result, management_client_failure> {
    if (request.empty()) {
        request = next_request();
    }
    return management_request_once(
        supervisor.control_directory(),
        supervisor.snapshot().session,
        {.observed_generation = observed,
         .request = request,
         .op = op,
         .checkpoint = std::move(checkpoint),
         .body_digest = {}}
    );
}

auto kinds(const std::vector<journal_event>& events) -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& event : events) {
        out.push_back(event.kind + (event.op.empty() ? "" : ":" + event.op));
    }
    return out;
}

auto index_of(const std::vector<std::string>& items, std::string_view value) -> std::size_t {
    for (std::size_t index = 0; index < items.size(); ++index) {
        if (items[index] == value) {
            return index;
        }
    }
    return items.size();
}

auto settled(session_phase phase) {
    return [phase](const supervisor_snapshot& snapshot) {
        return snapshot.projection.phase == phase && !snapshot.generation_active;
    };
}

class running_supervisor {
public:
    explicit running_supervisor(native_session_supervisor& supervisor) : supervisor_{supervisor} {
        thread_ = std::thread([this] { result_ = supervisor_.run(); });
    }

    running_supervisor(const running_supervisor&) = delete;
    auto operator=(const running_supervisor&) -> running_supervisor& = delete;

    ~running_supervisor() {
        if (thread_.joinable()) {
            // A failed assertion must not hang the test: cancel any owned
            // generation, wait for it to settle, then request shutdown
            // through the same admission path and join.
            const auto submit = [&](session_operation op) {
                const auto snapshot = supervisor_.snapshot();
                return supervisor_.submit(
                    {.observed_generation = snapshot.projection.generation,
                     .request = next_request(),
                     .op = op,
                     .checkpoint = std::nullopt,
                     .body_digest = std::string(64, '0')}
                );
            };
            if (submit(session_operation::shutdown).code != result_code::ok) {
                (void)submit(session_operation::stop);
                (void)supervisor_.wait_for(
                    [](const supervisor_snapshot& snapshot) { return !snapshot.generation_active; },
                    std::chrono::seconds{120}
                );
                (void)submit(session_operation::shutdown);
            }
            thread_.join();
        }
    }

    auto join() -> std::expected<std::uint64_t, std::string> {
        if (thread_.joinable()) {
            thread_.join();
        }
        return result_;
    }

private:
    native_session_supervisor& supervisor_;
    std::thread thread_;
    std::expected<std::uint64_t, std::string> result_;
};

struct lane_root {
    fs::path root;
    glove::host::directories directories;
    std::vector<std::string> log;
    std::mutex log_mutex;

    auto prepare(const fs::path& base) -> bool {
        root = base;
        if (!private_directory(root)) {
            return false;
        }
        directories = {root / "config", root / "state", root / "data", root / "cache", root / "rt"};
        for (const auto& directory :
             {directories.config,
              directories.state,
              directories.data,
              directories.cache,
              directories.runtime,
              root / "ws",
              root / "sessions",
              root / "host-auth",
              root / "payload"}) {
            if (!private_directory(directory)) {
                return false;
            }
        }
        return ::chmod((root / "payload").c_str(), 0500) == 0;
    }

    auto options(const std::string& digest, std::optional<std::string> session = std::nullopt)
        -> native_session_supervisor_options {
        return {
            .directories = directories,
            .protected_auth_roots = {root / "host-auth"},
            .workspace = root / "ws",
            .sessions_parent = root / "sessions",
            .session = std::move(session),
            .runtime_digest = digest,
            .model = "claude-fixture-model",
            .provider = glove::net::endpoint_provider::anthropic,
            .conversation_id = std::string{fixture_conversation},
            .display_name = "claude-lane",
            .audit = {},
            .log = [this](std::string_view line) {
                std::scoped_lock lock{log_mutex};
                log.emplace_back(line);
                std::fprintf(
                    stderr, "[supervisor] %.*s\n", static_cast<int>(line.size()), line.data()
                );
            }
        };
    }

    auto run_count() const -> std::size_t {
        std::error_code error;
        std::size_t count = 0;
        for (const auto& entry :
             fs::directory_iterator(directories.runtime / "claude/runs", error)) {
            if (entry.path().filename().string().starts_with("run-")) {
                ++count;
            }
        }
        return count;
    }
};

void dump_transcripts(claude_lane_harness& harness) {
    std::scoped_lock lock{harness.mutex};
    for (const auto& [path, bytes] : harness.transcripts) {
        std::fprintf(
            stderr, "[transcript] %s (%zu bytes)\n%s\n", path.c_str(), bytes.size(), bytes.c_str()
        );
    }
}

void dump_requests(const anthropic_fixture_responder& responder) {
    for (const auto& request : responder.requests()) {
        std::fprintf(
            stderr,
            "[responder] %s %s model=%s version=%s stream=%d messages=%zu bytes=%zu\n",
            request.method.c_str(),
            request.target.c_str(),
            request.model.c_str(),
            request.anthropic_version.c_str(),
            request.stream ? 1 : 0,
            request.messages,
            request.body.size()
        );
    }
}

auto headless_first_turn_and_resume(const claude_lane_binding& binding, const fs::path& base)
    -> int {
    lane_root lane;
    REQUIRE(lane.prepare(base / "headless"));
    claude_lane_harness harness{binding, claude_launch_mode::headless};
    harness.responder.script({"pong", "pong-again"});
    auto created = native_session_supervisor::create(lane.options(binding.sha256), harness);
    if (!created) {
        std::fprintf(stderr, "create: %s\n", created.error().c_str());
    }
    REQUIRE(created);
    auto& supervisor = **created;
    const auto session = supervisor.snapshot().session;
    running_supervisor runner{supervisor};

    // Row: contained startup + first assistant reply + actual history persistence.
    auto started = control(supervisor, session_operation::start, 0);
    REQUIRE(started && started->code == result_code::accepted);
    REQUIRE(supervisor.wait_for(settled(session_phase::stopped), 120s));
    dump_requests(harness.responder);
    dump_transcripts(harness);
    const auto snapshot = supervisor.snapshot();
    if (snapshot.last_error) {
        std::fprintf(stderr, "last_error: %s\n", snapshot.last_error->c_str());
    }
    REQUIRE(harness.observed.births == 1);
    // Closed environment: no operator credential, proxy or home leaks.
    for (const auto& entry : harness.observed.environment) {
        REQUIRE(
            entry.find("/Users/") == std::string::npos ||
            entry.find("/private/") != std::string::npos ||
            entry.starts_with("CLAUDE_CONFIG_DIR=") || entry.starts_with("PATH=")
        );
        REQUIRE(!entry.starts_with("ANTHROPIC_AUTH_TOKEN=") && !entry.starts_with("HTTPS_PROXY="));
        REQUIRE(!entry.starts_with("CLAUDE_CODE_OAUTH_TOKEN="));
    }
    REQUIRE(harness.observed.nonce.starts_with("glove-session-"));
    const auto requests = harness.responder.requests();
    REQUIRE(!requests.empty());
    REQUIRE(std::ranges::all_of(requests, [](const fixture_request& r) {
        return r.method == "POST" && r.target.substr(0, r.target.find('?')) == "/v1/messages";
    }));
    REQUIRE(std::ranges::all_of(requests, [](const fixture_request& r) {
        return r.secret_seen == "fixture-sentinel-not-a-credential";
    }));
    REQUIRE(harness.responder.refusals() == 0);
    REQUIRE(snapshot.projection.history == history_status::published);
    REQUIRE(snapshot.projection.checkpoint);
    const auto first_checkpoint = *snapshot.projection.checkpoint;
    const auto history =
        read_file(supervisor.session_root() / "checkpoints" / first_checkpoint / "history.jsonl");
    std::fprintf(
        stderr,
        "[history] %zu bytes, %ld lines\n",
        history.size(),
        std::count(history.begin(), history.end(), '\n')
    );
    REQUIRE(history.find("\"type\":\"assistant\"") != std::string::npos);
    REQUIRE(history.find("pong") != std::string::npos);
    REQUIRE(history.find(std::string{fixture_conversation}) != std::string::npos);
    REQUIRE(lane.run_count() == 0);
    const auto first_nonce = harness.observed.nonce;
    const auto first_port = harness.observed.port;
    const auto first_config = harness.observed.config_dir;

    // Row: stop/wake. Resume the exact checkpoint in a fresh generation; the
    // real process must carry the prior exchange into its next request.
    harness.prompt = "Now reply with exactly the single word pong-again.";
    auto resumed = control(supervisor, session_operation::resume, 1, first_checkpoint);
    REQUIRE(resumed && resumed->code == result_code::accepted && resumed->generation == 2);
    REQUIRE(supervisor.wait_for(settled(session_phase::stopped), 120s));
    dump_requests(harness.responder);
    const auto second = supervisor.snapshot();
    if (second.last_error) {
        std::fprintf(stderr, "last_error: %s\n", second.last_error->c_str());
    }
    REQUIRE(harness.observed.births == 2);
    REQUIRE(harness.observed.nonce != first_nonce);
    REQUIRE(harness.observed.port != first_port || harness.observed.config_dir != first_config);
    REQUIRE(std::ranges::find(harness.observed.argv, "--resume") != harness.observed.argv.end());
    const auto second_requests = harness.responder.requests();
    REQUIRE(second_requests.size() > requests.size());
    const auto& continuation = second_requests.back();
    REQUIRE(continuation.body.find("pong") != std::string::npos);
    REQUIRE(continuation.messages >= 3);
    REQUIRE(second.projection.history == history_status::published);
    REQUIRE(second.projection.checkpoint && *second.projection.checkpoint != first_checkpoint);
    const auto second_history = read_file(
        supervisor.session_root() / "checkpoints" / *second.projection.checkpoint / "history.jsonl"
    );
    REQUIRE(second_history.size() > history.size());
    REQUIRE(second_history.find("pong-again") != std::string::npos);
    REQUIRE(lane.run_count() == 0);
    REQUIRE(control(supervisor, session_operation::shutdown, 2)->code == result_code::ok);
    REQUIRE(runner.join());
    std::fprintf(
        stderr,
        "[lane] session=%s first=%s second=%s\n",
        session.c_str(),
        first_checkpoint.c_str(),
        second.projection.checkpoint->c_str()
    );
    return 0;
}

auto held_stream_detach_stop_and_listener(const claude_lane_binding& binding, const fs::path& base)
    -> int {
    lane_root lane;
    REQUIRE(lane.prepare(base / "held"));
    claude_lane_harness harness{binding, claude_launch_mode::headless};
    harness.responder.hold_next();
    auto created = native_session_supervisor::create(lane.options(binding.sha256), harness);
    REQUIRE(created);
    auto& supervisor = **created;
    running_supervisor runner{supervisor};
    REQUIRE(control(supervisor, session_operation::start, 0)->code == result_code::accepted);
    // The real process is now blocked inside its provider request.
    REQUIRE(harness.responder.wait_held(60s));
    REQUIRE(supervisor.snapshot().projection.phase == session_phase::running);
    const auto epoch = supervisor.snapshot().epoch;
    // Row: detach/wake. Five fresh frontend connections observe the same owned
    // generation; no second launch, no replayed request.
    for (int attempt = 0; attempt < 5; ++attempt) {
        auto status = control(supervisor, session_operation::status, 0);
        REQUIRE(status && status->state == session_phase::running && status->generation == 1);
        REQUIRE(status->epoch == epoch);
    }
    REQUIRE(harness.observed.births == 1 && harness.responder.requests().size() == 1);
    REQUIRE(lane.run_count() == 1);
    // Row: surviving-owner listener recovery while the real process runs.
    const auto identity = supervisor.management().listener_identity();
    const auto socket_path = supervisor.control_directory() / "s";
    REQUIRE(::unlink(socket_path.c_str()) == 0);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (supervisor.management().recreations() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    REQUIRE(supervisor.management().recreations() == 1);
    REQUIRE(supervisor.management().listener_identity() != identity);
    auto after = control(supervisor, session_operation::status, 1);
    REQUIRE(after && after->state == session_phase::running && after->generation == 1);
    REQUIRE(harness.observed.births == 1);
    // Row: controlled mock-stream cancellation. Stop is owned cancellation of
    // the real process; the held reply is cancelled, never completed.
    auto stop = control(supervisor, session_operation::stop, 1);
    REQUIRE(stop && stop->code == result_code::accepted);
    REQUIRE(supervisor.wait_for(settled(session_phase::stopped), 120s));
    dump_requests(harness.responder);
    dump_transcripts(harness);
    const auto snapshot = supervisor.snapshot();
    REQUIRE(harness.responder.cancelled_holds() == 1);
    REQUIRE(harness.responder.requests().size() == 1);
    auto settled_stop =
        control(supervisor, session_operation::stop, 1, std::nullopt, stop->request);
    REQUIRE(settled_stop && settled_stop->final && settled_stop->code == result_code::ok);
    // A stopped initial turn has no completed exchange: no checkpoint, no
    // silent new conversation; disposable state is cleaned after a known outcome.
    REQUIRE(!snapshot.projection.checkpoint);
    REQUIRE(
        snapshot.projection.history == history_status::invalid ||
        snapshot.projection.history == history_status::absent
    );
    REQUIRE(lane.run_count() == 0);
    REQUIRE(
        control(supervisor, session_operation::resume, 1, std::string(64, 'c'))->code ==
        result_code::admission_failed
    );
    const auto order = kinds(supervisor.journal());
    const auto stop_intent = index_of(order, "intent:stop");
    const auto known = index_of(order, "outcome_known");
    const auto finalized = index_of(order, "finalized");
    REQUIRE(stop_intent < known && known < finalized);
    REQUIRE(control(supervisor, session_operation::shutdown, 1)->code == result_code::ok);
    REQUIRE(runner.join());
    // Row: stale socket after the owner exits refuses; nothing is resurrected.
    const auto control_directory = supervisor.control_directory();
    const auto session = snapshot.session;
    created->reset();
    REQUIRE(!fs::exists(socket_path));
    auto stale = management_request_once(
        control_directory,
        session,
        {.observed_generation = 0,
         .request = next_request(),
         .op = session_operation::status,
         .checkpoint = std::nullopt,
         .body_digest = {}}
    );
    REQUIRE(!stale);
    std::fprintf(
        stderr,
        "[lane] held-stream row complete; history=%s\n",
        std::string{to_string(snapshot.projection.history)}.c_str()
    );
    return 0;
}

} // namespace

auto main() -> int {
    (void)::signal(SIGPIPE, SIG_IGN);
    const char* executable = std::getenv("GLOVE_TEST_CLAUDE_EXECUTABLE");
    const char* sha256 = std::getenv("GLOVE_TEST_CLAUDE_SHA256");
    const char* version = std::getenv("GLOVE_TEST_CLAUDE_VERSION");
    const char* root = std::getenv("GLOVE_TEST_CLAUDE_ROOT");
    if (executable == nullptr || sha256 == nullptr || version == nullptr || root == nullptr) {
        std::fprintf(
            stderr,
            "unsupported lane: set GLOVE_TEST_CLAUDE_EXECUTABLE, GLOVE_TEST_CLAUDE_SHA256, "
            "GLOVE_TEST_CLAUDE_VERSION and GLOVE_TEST_CLAUDE_ROOT to run the actual-Claude lane\n"
        );
        return skip_code;
    }
    const fs::path base{root};
    if (!private_directory(base)) {
        return 1;
    }
    claude_lane_binding binding{
        .executable = executable,
        .sha256 = sha256,
        .version = version,
        .payload = base / "headless/payload"
    };
    REQUIRE(headless_first_turn_and_resume(binding, base) == 0);
    binding.payload = base / "held/payload";
    REQUIRE(held_stream_detach_stop_and_listener(binding, base) == 0);
    return 0;
}
