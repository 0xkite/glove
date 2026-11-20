// The per-launch denial monitor: a short-lived child's denial is delivered by
// the time finish() returns; a stream that cannot start, never speaks, or
// dies leaves the session sandboxed; two sessions never see each other.

#include "glove/container/denial_telemetry.hpp"
#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"

#include "sandbox_denial_log.hpp"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
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

using glove::container::denial_monitor;
using glove::container::denial_observer;
using glove::container::denial_telemetry_state;
using glove::container::is_encoded_text;
using glove::container::profile;
using glove::container::sandbox_denial;
using glove::container::detail::is_denial_tag;
using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

constexpr int skip_code = 77;
constexpr int trials = 20;
constexpr std::size_t max_recorded = 1024;

auto make_nonce() -> std::string {
    std::array<unsigned char, 16> bytes{};
    ::arc4random_buf(bytes.data(), bytes.size());
    constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    for (const unsigned char byte : bytes) {
        out.push_back(hex.at(byte >> 4U));
        out.push_back(hex.at(byte & 0x0FU));
    }
    return out;
}

class temporary_tree {
public:
    temporary_tree() {
        std::error_code ec;
        const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
        if (ec) {
            return;
        }
        std::string pattern = (base / "glove-denial-monitor-XXXXXX").string();
        if (const auto* created = ::mkdtemp(pattern.data())) {
            path_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

    ~temporary_tree() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

struct recorder {
    std::mutex mutex;
    std::vector<sandbox_denial> seen;
    std::atomic<int> degraded_calls{0};

    auto observer() -> denial_observer {
        return {
            .on_denial =
                [this](const sandbox_denial& denial) {
                    const std::lock_guard lock{mutex};
                    if (seen.size() < max_recorded) {
                        seen.push_back(denial);
                    }
                },
            .on_degraded = [this](std::string_view) { degraded_calls.fetch_add(1); },
        };
    }

    auto holds(std::string_view target) -> bool {
        const std::lock_guard lock{mutex};
        return std::ranges::any_of(seen, [&](const sandbox_denial& denial) {
            return denial.kind == "file_write" && denial.target == target && denial.comm == "touch";
        });
    }

    auto any_target_contains(std::string_view needle) -> bool {
        const std::lock_guard lock{mutex};
        return std::ranges::any_of(seen, [&](const sandbox_denial& denial) {
            return denial.target.contains(needle);
        });
    }

    auto fields_clean(std::string_view tag) -> bool {
        const std::lock_guard lock{mutex};
        return std::ranges::all_of(seen, [&](const sandbox_denial& denial) {
            for (const std::string* field :
                 {&denial.kind, &denial.operation, &denial.target, &denial.comm}) {
                if (!is_encoded_text(*field) || (!tag.empty() && field->contains(tag))) {
                    return false;
                }
            }
            return true;
        });
    }

    auto empty() -> bool {
        const std::lock_guard lock{mutex};
        return seen.empty();
    }
};

auto profile_a(const std::filesystem::path& work) -> profile {
    profile prof;
    prof.filesystem = {{.path = work.string(), .writable = true}};
    prof.home_dir = work.string();
    return prof;
}

// Runs a contained shell whose touch is denied; -1 if the launch failed or
// the denied file exists (the sandbox did not hold).
auto run(const profile& prof, const std::string& nonce) -> int {
    const std::string written = "/private/tmp/glove-mon-" + nonce + "-out";
    const auto code = glove::container::exec_contained(
        prof, {"/bin/sh", "-c", "/usr/bin/touch " + written + "; exit 7"}
    );
    std::error_code ec;
    if (std::filesystem::exists(written, ec)) {
        std::filesystem::remove(written, ec);
        return -1;
    }
    return code ? *code : -1;
}

auto elapsed_ms(clock_type::time_point since) -> long long {
    return std::chrono::duration_cast<milliseconds>(clock_type::now() - since).count();
}

auto delivery(const std::filesystem::path& work) -> int {
    int complete = 0;
    for (int trial = 1; trial <= trials; ++trial) {
        recorder record;
        auto monitor = denial_monitor::start(record.observer());
        REQUIRE(monitor != nullptr);
        if (trial == 1 && monitor->state() == denial_telemetry_state::unavailable) {
            const auto why = monitor->reason();
            std::printf("SKIP denial telemetry unavailable: %s\n", why.c_str());
            return skip_code;
        }
        REQUIRE(monitor->state() == denial_telemetry_state::live);
        REQUIRE(is_denial_tag(monitor->tag()));
        const std::string tag = monitor->tag();
        auto prof = profile_a(work);
        prof.denial_tag = tag;
        const std::string nonce = make_nonce();
        REQUIRE(run(prof, nonce) == 7);
        const auto report = monitor->finish();
        const bool delivered = record.holds("/private/tmp/glove-mon-" + nonce + "-out");
        std::printf(
            "D1 trial %d delivered=%d end_proof=%d\n",
            trial,
            delivered ? 1 : 0,
            report.end_proof ? 1 : 0
        );
        REQUIRE(record.fields_clean(tag));
        if (delivered && report.end_proof) {
            ++complete;
        }
    }
    REQUIRE(complete == trials);
    return 0;
}

auto unavailable(const std::filesystem::path& work) -> int {
    for (const auto& argv :
         {std::vector<std::string>{"/usr/bin/false"},
          std::vector<std::string>{"/bin/sh", "-c", "sleep 30"}}) {
        recorder record;
        const auto started = clock_type::now();
        auto monitor = denial_monitor::start_for_test(record.observer(), argv);
        REQUIRE(elapsed_ms(started) < 4000);
        REQUIRE(monitor != nullptr);
        REQUIRE(monitor->state() == denial_telemetry_state::unavailable);
        REQUIRE(monitor->tag().empty());
        REQUIRE(!monitor->reason().empty());
        REQUIRE(run(profile_a(work), make_nonce()) == 7);
        REQUIRE(monitor->finish().state == denial_telemetry_state::unavailable);
        REQUIRE(record.empty());
    }
    std::printf("D2 ok\n");
    return 0;
}

auto degraded(const std::filesystem::path& work) -> int {
    recorder record;
    auto monitor = denial_monitor::start(record.observer());
    REQUIRE(monitor->state() == denial_telemetry_state::live);
    auto prof = profile_a(work);
    prof.denial_tag = monitor->tag();
    const int pid = monitor->stream_pid_for_test();
    REQUIRE(pid > 0);
    // The monitor's own unreaped child of this process, by PID.
    REQUIRE(::kill(pid, SIGKILL) == 0);
    const auto deadline = clock_type::now() + milliseconds{3000};
    while (monitor->state() != denial_telemetry_state::degraded && clock_type::now() < deadline) {
        std::this_thread::sleep_for(milliseconds{10});
    }
    REQUIRE(monitor->state() == denial_telemetry_state::degraded);
    REQUIRE(record.degraded_calls.load() == 1);
    REQUIRE(run(prof, make_nonce()) == 7);
    const auto report = monitor->finish();
    REQUIRE(report.state == denial_telemetry_state::degraded);
    REQUIRE(!report.end_proof);
    std::printf("D3 ok\n");
    return 0;
}

auto two_sessions(const std::filesystem::path& work) -> int {
    recorder first;
    recorder second;
    auto m1 = denial_monitor::start(first.observer());
    auto m2 = denial_monitor::start(second.observer());
    REQUIRE(m1->state() == denial_telemetry_state::live);
    REQUIRE(m2->state() == denial_telemetry_state::live);
    REQUIRE(m1->tag() != m2->tag());
    auto prof = profile_a(work);
    prof.denial_tag = m1->tag();
    const std::string nonce = make_nonce();
    REQUIRE(run(prof, nonce) == 7);
    (void)m1->finish();
    (void)m2->finish();
    REQUIRE(first.holds("/private/tmp/glove-mon-" + nonce + "-out"));
    REQUIRE(!second.any_target_contains("glove-mon-"));
    std::printf("D4 ok\n");
    return 0;
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    temporary_tree tree;
    REQUIRE(!tree.path().empty());
    const auto& work = tree.path();
    if (const int failed = delivery(work); failed != 0) {
        return failed;
    }
    for (auto* step : {unavailable, degraded, two_sessions}) {
        if (const int failed = step(work); failed != 0) {
            return failed;
        }
    }
    std::printf("monitor ok\n");
    return 0;
}
