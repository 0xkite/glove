// The denial trace writer creates only a new file, records what the trace
// format accepts in arrival order with elapsed times, counts what it cannot
// record, and writes nothing after finish.

#include "glove/container/denial_trace.hpp"

#include "denial_trace_writer.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::denial_context;
using glove::container::denial_monitor_report;
using glove::container::denial_telemetry_state;
using glove::container::max_denial_trace_events;
using glove::container::parse_denial_trace;
using glove::container::sandbox_denial;
using glove::run::detail::denial_trace_writer;
using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "glove-trace-writer-XXXXXX").string();
        if (const auto* created = ::mkdtemp(pattern.data())) {
            path_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto context() -> denial_context {
    return {.workspace_roots = {"/w"}, .home = "/h"};
}

auto denial(std::string target) -> sandbox_denial {
    sandbox_denial out;
    out.kind = "file_read";
    out.operation = "file-read-data";
    out.target = std::move(target);
    out.comm = "cat";
    out.pid = 7;
    return out;
}

auto live_report() -> denial_monitor_report {
    return {
        .state = denial_telemetry_state::live,
        .reason = {},
        .stream_events = 3,
        .stream_rejected = 0,
        .end_proof = true
    };
}

auto records(const temporary_tree& tree) -> int {
    const auto path = tree.path() / "trace.jsonl";
    auto now = clock_type::time_point{} + milliseconds{1000};
    auto writer = denial_trace_writer::create(path, context(), [&] { return now; });
    REQUIRE(writer.has_value());
    struct stat info{};
    REQUIRE(::stat(path.c_str(), &info) == 0 && (info.st_mode & 0777U) == 0600U);
    now += milliseconds{5};
    (*writer)->on_denial(denial("/w/a"));
    now += milliseconds{20};
    (*writer)->on_denial(denial("/bad\"quote"));
    (*writer)->on_denial(denial("/h/b"));
    now += milliseconds{100};
    REQUIRE((*writer)->finish(live_report()).has_value());
    (*writer)->on_denial(denial("/after"));
    REQUIRE((*writer)->finish(live_report()).has_value());

    const auto trace = parse_denial_trace(read_file(path));
    REQUIRE(trace.has_value());
    REQUIRE(trace->context.home == "/h");
    REQUIRE(trace->events.size() == 2);
    REQUIRE(trace->events.at(0).at == milliseconds{5});
    REQUIRE(trace->events.at(0).denial.target == "/w/a");
    REQUIRE(trace->events.at(1).at == milliseconds{25});
    REQUIRE(trace->events.at(1).denial.target == "/h/b");
    REQUIRE(trace->end.has_value() && trace->end->at == milliseconds{125});
    REQUIRE(trace->end->state == denial_telemetry_state::live && trace->end->end_proof);
    REQUIRE(trace->end->dropped == 1 && trace->end->stream_events == 3);
    return 0;
}

auto refuses_existing(const temporary_tree& tree) -> int {
    const auto existing = tree.path() / "existing";
    std::ofstream{existing} << "keep";
    REQUIRE(!denial_trace_writer::create(existing, context()).has_value());
    REQUIRE(read_file(existing) == "keep");
    const auto link = tree.path() / "link";
    REQUIRE(::symlink((tree.path() / "target").c_str(), link.c_str()) == 0);
    REQUIRE(!denial_trace_writer::create(link, context()).has_value());
    REQUIRE(!std::filesystem::exists(tree.path() / "target"));
    REQUIRE(!denial_trace_writer::create(tree.path() / "no" / "dir", context()).has_value());
    const denial_context bad{.workspace_roots = {"relative"}, .home = ""};
    REQUIRE(!denial_trace_writer::create(tree.path() / "bad2", bad).has_value());
    REQUIRE(!std::filesystem::exists(tree.path() / "bad2"));
    return 0;
}

auto bounded(const temporary_tree& tree) -> int {
    const auto path = tree.path() / "cap.jsonl";
    auto writer = denial_trace_writer::create(path, context());
    REQUIRE(writer.has_value());
    for (std::size_t index = 0; index != max_denial_trace_events + 5; ++index) {
        (*writer)->on_denial(denial("/w/x"));
    }
    REQUIRE((*writer)->finish(live_report()).has_value());
    const auto trace = parse_denial_trace(read_file(path));
    REQUIRE(trace.has_value());
    REQUIRE(trace->events.size() == max_denial_trace_events);
    REQUIRE(trace->end && trace->end->dropped == 5);
    return 0;
}

auto concurrent(const temporary_tree& tree) -> int {
    const auto path = tree.path() / "threads.jsonl";
    auto writer = denial_trace_writer::create(path, context());
    REQUIRE(writer.has_value());
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    for (int thread = 0; thread != 4; ++thread) {
        threads.emplace_back([&, thread] {
            while (!go.load()) {
                std::this_thread::yield();
            }
            for (int index = 0; index != 500; ++index) {
                (*writer)->on_denial(
                    denial("/w/" + std::to_string(thread) + "/" + std::to_string(index))
                );
            }
        });
    }
    go.store(true);
    for (auto& thread : threads) {
        thread.join();
    }
    REQUIRE((*writer)->finish(live_report()).has_value());
    const auto trace = parse_denial_trace(read_file(path));
    REQUIRE(trace.has_value());
    REQUIRE(trace->events.size() == 2000);
    return 0;
}

} // namespace

int main() {
    const temporary_tree tree;
    REQUIRE(!tree.path().empty());
    for (auto* step : {records, refuses_existing, bounded, concurrent}) {
        if (const int failed = step(tree); failed != 0) {
            return failed;
        }
    }
    std::printf("denial trace writer ok\n");
    return 0;
}
