// Test-support executable for the stock-tmux lane: `serve` runs one native
// session supervisor (actual admitted Claude executable, fixture responder,
// real owned contained execution) inside a pane; `ctl`/`wait` drive it over
// the protected management transport from another process. Not a product CLI.
#include "claude_lane_fixture.hpp"
#include "native_session_fixture.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
using namespace glove::run::detail;
using namespace glove::run::test_support;
using namespace std::chrono_literals;

auto usage() -> int {
    std::fprintf(
        stderr,
        "usage:\n"
        "  native_session_fixture serve --root DIR --executable PATH --sha256 HEX --version V\n"
        "      [--mode headless|interactive] [--session ns-ID] [--prompt TEXT] [--reply TEXT]\n"
        "      [--hold-first --release-file PATH] [--auto-start] [--announce FILE]\n"
        "  native_session_fixture ctl --control DIR --session ns-ID --op OP\n"
        "      [--generation N] [--checkpoint HEX] [--request HEX]\n"
        "  native_session_fixture wait --control DIR --session ns-ID --state PHASE --timeout-ms N\n"
    );
    return 2;
}

auto argument(std::vector<std::string>& args, std::string_view flag) -> std::optional<std::string> {
    for (std::size_t index = 0; index + 1 < args.size(); ++index) {
        if (args[index] == flag) {
            auto value = args[index + 1];
            args.erase(
                args.begin() + static_cast<std::ptrdiff_t>(index),
                args.begin() + static_cast<std::ptrdiff_t>(index) + 2
            );
            return value;
        }
    }
    return std::nullopt;
}

auto flag(std::vector<std::string>& args, std::string_view name) -> bool {
    const auto found = std::find(args.begin(), args.end(), name);
    if (found == args.end()) {
        return false;
    }
    args.erase(found);
    return true;
}

auto print_result(const management_result& result) -> void {
    std::printf(
        "{\"session\":\"%s\",\"epoch\":\"%s\",\"generation\":%llu,\"request\":\"%s\",\"op\":\"%s\","
        "\"state\":\"%s\",\"history\":\"%s\",\"checkpoint\":%s%s%s,\"effects\":\"%s\",\"code\":\"%"
        "s\","
        "\"final\":%s}\n",
        result.session.c_str(),
        result.epoch.c_str(),
        static_cast<unsigned long long>(result.generation),
        result.request.c_str(),
        std::string{to_string(result.op)}.c_str(),
        std::string{to_string(result.state)}.c_str(),
        std::string{to_string(result.history)}.c_str(),
        result.checkpoint ? "\"" : "",
        result.checkpoint ? result.checkpoint->c_str() : "null",
        result.checkpoint ? "\"" : "",
        std::string{to_string(result.effects)}.c_str(),
        std::string{to_string(result.code)}.c_str(),
        result.final ? "true" : "false"
    );
    std::fflush(stdout);
}

auto serve(std::vector<std::string> args) -> int {
    const auto root = argument(args, "--root");
    const auto executable = argument(args, "--executable");
    const auto sha256 = argument(args, "--sha256");
    const auto version = argument(args, "--version");
    const auto mode = argument(args, "--mode").value_or("headless");
    const auto session = argument(args, "--session");
    const auto prompt = argument(args, "--prompt");
    const auto release_file = argument(args, "--release-file");
    const auto announce = argument(args, "--announce");
    const bool hold_first = flag(args, "--hold-first");
    const bool auto_start = flag(args, "--auto-start");
    std::vector<std::string> replies;
    while (auto reply = argument(args, "--reply")) {
        replies.push_back(*reply);
    }
    if (!root || !executable || !sha256 || !version || !args.empty() ||
        (mode != "headless" && mode != "interactive") || (hold_first && !release_file)) {
        return usage();
    }
    const fs::path base{*root};
    glove::host::directories directories{
        base / "config", base / "state", base / "data", base / "cache", base / "rt"
    };
    for (const auto& directory :
         {base,
          directories.config,
          directories.state,
          directories.data,
          directories.cache,
          directories.runtime,
          base / "ws",
          base / "sessions",
          base / "host-auth",
          base / "payload"}) {
        if (!private_directory(directory)) {
            std::fprintf(stderr, "cannot prepare %s\n", directory.c_str());
            return 1;
        }
    }
    if (::chmod((base / "payload").c_str(), 0500) != 0) {
        return 1;
    }
    claude_lane_harness harness{
        {.executable = *executable,
         .sha256 = *sha256,
         .version = *version,
         .payload = base / "payload"},
        mode == "headless" ? claude_launch_mode::headless : claude_launch_mode::interactive
    };
    if (prompt) {
        harness.prompt = *prompt;
    } else if (mode == "interactive") {
        harness.prompt.clear();
    }
    harness.responder.script(replies);
    if (hold_first) {
        harness.responder.hold_next();
    }
    std::vector<std::string> compose_args;
    native_session_supervisor_options options{
        .directories = directories,
        .protected_auth_roots = {base / "host-auth"},
        .workspace = base / "ws",
        .sessions_parent = base / "sessions",
        .session = session,
        .runtime_digest = *sha256,
        .model = "claude-fixture-model",
        .provider = glove::net::endpoint_provider::anthropic,
        .conversation_id = std::string{fixture_conversation},
        .display_name = "claude-lane",
        .audit = {},
        .log = [](std::string_view line) {
            std::fprintf(stderr, "[supervisor] %.*s\n", static_cast<int>(line.size()), line.data());
        }
    };
    auto created = native_session_supervisor::create(options, harness);
    if (!created) {
        std::fprintf(stderr, "create: %s\n", created.error().c_str());
        return 1;
    }
    auto& supervisor = **created;
    const auto snapshot = supervisor.snapshot();
    std::fprintf(
        stderr,
        "[serve] session=%s epoch=%s control=%s pid=%d\n",
        snapshot.session.c_str(),
        snapshot.epoch.c_str(),
        supervisor.control_directory().c_str(),
        ::getpid()
    );
    if (announce) {
        const auto temporary = fs::path{*announce + ".tmp"};
        std::ofstream output{temporary};
        output << snapshot.session << "\n"
               << snapshot.epoch << "\n"
               << supervisor.control_directory().string() << "\n"
               << ::getpid() << "\n";
        output.close();
        (void)::rename(temporary.c_str(), announce->c_str());
    }
    std::thread releaser;
    if (hold_first) {
        releaser = std::thread([&] {
            // Bounded file latch for the frontend driver; no shell sleep loop.
            const auto deadline = std::chrono::steady_clock::now() + 180s;
            while (std::chrono::steady_clock::now() < deadline) {
                struct stat info{};
                if (::stat(release_file->c_str(), &info) == 0) {
                    harness.responder.release();
                    return;
                }
                std::this_thread::sleep_for(50ms);
            }
            harness.responder.release();
        });
    }
    if (auto_start) {
        auto request = mint_request_id();
        (void)supervisor.submit(
            {.observed_generation = snapshot.projection.generation,
             .request = request.value_or(std::string(32, '0')),
             .op = session_operation::start,
             .checkpoint = std::nullopt,
             .body_digest = std::string(64, '0')}
        );
    }
    auto generations = supervisor.run();
    if (releaser.joinable()) {
        harness.responder.release();
        releaser.join();
    }
    const auto final_snapshot = supervisor.snapshot();
    std::fprintf(
        stderr,
        "[serve] exit generations=%llu state=%s requests=%zu refusals=%llu\n",
        generations ? static_cast<unsigned long long>(*generations) : 0ULL,
        std::string{to_string(final_snapshot.projection.phase)}.c_str(),
        harness.responder.requests().size(),
        static_cast<unsigned long long>(harness.responder.refusals())
    );
    for (const auto& request : harness.responder.requests()) {
        std::fprintf(
            stderr,
            "[responder] %s %s stream=%d messages=%zu\n",
            request.method.c_str(),
            request.target.c_str(),
            request.stream ? 1 : 0,
            request.messages
        );
    }
    return generations ? 0 : 1;
}

auto ctl(std::vector<std::string> args) -> int {
    const auto control = argument(args, "--control");
    const auto session = argument(args, "--session");
    const auto op_text = argument(args, "--op");
    const auto generation = argument(args, "--generation").value_or("0");
    const auto checkpoint = argument(args, "--checkpoint");
    auto request = argument(args, "--request");
    if (!control || !session || !op_text || !args.empty()) {
        return usage();
    }
    const auto op = parse_session_operation(*op_text);
    if (!op) {
        return usage();
    }
    if (!request) {
        request = mint_request_id().value_or(std::string(32, '0'));
    }
    auto result = management_request_once(
        *control,
        *session,
        {.observed_generation =
             static_cast<std::uint64_t>(std::strtoull(generation.c_str(), nullptr, 10)),
         .request = *request,
         .op = *op,
         .checkpoint = checkpoint,
         .body_digest = {}}
    );
    if (!result) {
        std::printf(
            "{\"error\":\"%s\",\"code\":%d}\n",
            result.error().message.c_str(),
            static_cast<int>(result.error().code)
        );
        return 3;
    }
    print_result(*result);
    return 0;
}

auto wait(std::vector<std::string> args) -> int {
    auto control = argument(args, "--control");
    auto session = argument(args, "--session");
    const auto announce = argument(args, "--announce");
    const auto state = argument(args, "--state");
    const auto timeout = argument(args, "--timeout-ms").value_or("30000");
    if ((!announce && (!control || !session)) || !state || !args.empty()) {
        return usage();
    }
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds{std::strtoll(timeout.c_str(), nullptr, 10)};
    if (announce) {
        // Bounded barrier on the supervisor's announcement, written atomically.
        for (;;) {
            std::ifstream input{*announce};
            std::string line_session;
            std::string line_epoch;
            std::string line_control;
            if (input && std::getline(input, line_session) && std::getline(input, line_epoch) &&
                std::getline(input, line_control) && valid_session_id(line_session)) {
                session = line_session;
                control = line_control;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                std::printf("{\"error\":\"announcement not observed before deadline\"}\n");
                return 4;
            }
            std::this_thread::sleep_for(50ms);
        }
        std::fprintf(stderr, "[wait] session=%s control=%s\n", session->c_str(), control->c_str());
    }
    std::expected<management_result, management_client_failure> last{
        std::unexpected(management_client_failure{})
    };
    while (std::chrono::steady_clock::now() < deadline) {
        last = management_request_once(
            *control,
            *session,
            {.observed_generation = 0,
             .request = mint_request_id().value_or(std::string(32, '0')),
             .op = session_operation::status,
             .checkpoint = std::nullopt,
             .body_digest = {}}
        );
        if (last && to_string(last->state) == *state) {
            print_result(*last);
            return 0;
        }
        std::this_thread::sleep_for(100ms);
    }
    if (last) {
        print_result(*last);
    } else {
        std::printf("{\"error\":\"%s\"}\n", last.error().message.c_str());
    }
    return 4;
}

} // namespace

auto main(int argc, char** argv) -> int {
    (void)::signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        return usage();
    }
    std::vector<std::string> args{argv + 2, argv + argc};
    const std::string_view command{argv[1]};
    if (command == "serve") {
        return serve(std::move(args));
    }
    if (command == "ctl") {
        return ctl(std::move(args));
    }
    if (command == "wait") {
        return wait(std::move(args));
    }
    return usage();
}
