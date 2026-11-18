// The per-launch denial tag: every deny rule of a generated profile carries
// it, and every rule family's denial (including a child that exits at once)
// reaches a stream reading only that tag. Telemetry is not wired into any
// launch path; this drives prepare_launch_command and denial_stream directly.

#include "glove/container/profile.hpp"

#include "macos/denial_stream.hpp"
#include "macos/launch_command.hpp"
#include "sandbox_denial_log.hpp"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::profile;
using glove::container::detail::denial_class;
using glove::container::detail::denial_event;
using glove::container::detail::is_denial_tag;
using glove::container::macos_detail::denial_stream;
using glove::container::macos_detail::denial_stream_options;
using glove::container::macos_detail::denial_stream_state;
using glove::container::macos_detail::launch_command;
using glove::container::macos_detail::prepare_launch_command;
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
        std::string pattern = (base / "glove-denial-tag-XXXXXX").string();
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

// Spawns ARGV with ENV, stdio on /dev/null, inheriting nothing else; the
// child stays unreaped until the caller reaps it.
auto spawn_owned(std::vector<std::string> argv, std::vector<std::string> env) -> ::pid_t {
    std::vector<char*> args;
    for (auto& arg : argv) {
        args.push_back(arg.data());
    }
    args.push_back(nullptr);
    std::vector<char*> envp;
    for (auto& entry : env) {
        envp.push_back(entry.data());
    }
    envp.push_back(nullptr);
    ::posix_spawn_file_actions_t actions{};
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    ::posix_spawnattr_t attr{};
    ::posix_spawnattr_init(&attr);
    ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
    ::pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, argv[0].c_str(), &actions, &attr, args.data(), envp.data());
    ::posix_spawn_file_actions_destroy(&actions);
    ::posix_spawnattr_destroy(&attr);
    return rc == 0 ? pid : -1;
}

auto reap(::pid_t pid) -> int {
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return status;
}

void kill_and_reap(::pid_t pid) {
    if (pid <= 0) {
        return;
    }
    (void)::kill(pid, SIGKILL);
    (void)reap(pid);
}

auto wait_for(const auto& condition, milliseconds limit) -> bool {
    const auto deadline = clock_type::now() + limit;
    while (clock_type::now() < deadline) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(milliseconds{10});
    }
    return condition();
}

auto count_of(std::string_view text, std::string_view needle) -> std::size_t {
    std::size_t count = 0;
    for (auto pos = text.find(needle); pos != std::string_view::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

// Every deny rule carries the command's tag; returns the deny count, or 0.
auto tagged_deny_rules(const launch_command& command) -> std::size_t {
    const std::string_view text = command.arguments.at(2);
    const std::string suffix = " (with message \"" + command.denial_tag + "\"))";
    const auto denies = count_of(text, "(deny ");
    if (denies != count_of(text, "(with message \"") || denies != count_of(text, suffix + "\n")) {
        return 0;
    }
    std::size_t start = 0;
    while (start < text.size()) {
        auto end = text.find('\n', start);
        if (end == std::string_view::npos) {
            end = text.size();
        }
        const auto line = text.substr(start, end - start);
        if (line.starts_with("(deny") && !line.ends_with(suffix)) {
            return 0;
        }
        start = end + 1;
    }
    return denies;
}

auto profile_runs(const launch_command& command) -> bool {
    const ::pid_t pid = spawn_owned(
        {"/usr/bin/sandbox-exec", "-p", command.arguments.at(2), "/usr/bin/true"},
        {"PATH=/usr/bin:/bin"}
    );
    if (pid <= 0) {
        return false;
    }
    const int status = reap(pid);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

auto profile_a(const std::filesystem::path& work) -> profile {
    profile prof;
    prof.filesystem = {{.path = work.string(), .writable = true}};
    prof.home_dir = work.string();
    return prof;
}

auto structure(const std::filesystem::path& work, const std::filesystem::path& root) -> int {
    const auto first = prepare_launch_command(profile_a(work), {"/bin/sh", "-c", "true"});
    REQUIRE(first.has_value());
    REQUIRE(is_denial_tag(first->denial_tag));
    REQUIRE(tagged_deny_rules(*first) >= 5);
    const auto second = prepare_launch_command(profile_a(work), {"/bin/sh", "-c", "true"});
    REQUIRE(second.has_value());
    REQUIRE(second->denial_tag != first->denial_tag);
    REQUIRE(profile_runs(*first));

    // A tag chosen by the caller (the runner's monitor) is used as given.
    constexpr std::string_view fixed_tag = "00112233445566778899aabbccddeeff";
    auto fixed_profile = profile_a(work);
    fixed_profile.denial_tag = std::string{fixed_tag};
    const auto fixed = prepare_launch_command(fixed_profile, {"/bin/sh", "-c", "true"});
    REQUIRE(fixed.has_value());
    REQUIRE(fixed->denial_tag == fixed_tag);
    REQUIRE(fixed->arguments.at(2).contains("(with message \"" + std::string{fixed_tag} + "\")"));

    const auto agent = root / "agent";
    const auto workspace = root / "workspace";
    std::error_code ec;
    REQUIRE(std::filesystem::create_directory(agent, ec));
    REQUIRE(std::filesystem::create_directory(workspace, ec));
    std::filesystem::permissions(agent, std::filesystem::perms::owner_all, ec);
    REQUIRE(!ec);
    std::filesystem::permissions(workspace, std::filesystem::perms::owner_all, ec);
    REQUIRE(!ec);
    const auto authority = agent / "models.json";
    {
        std::FILE* file = std::fopen(authority.c_str(), "w");
        REQUIRE(file != nullptr);
        std::fputs("fixture-authority", file);
        REQUIRE(std::fclose(file) == 0);
    }
    std::filesystem::permissions(
        authority, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec
    );
    REQUIRE(!ec);
    profile prof_b;
    prof_b.filesystem = {
        {.path = agent.string(), .writable = true}, {.path = workspace.string(), .writable = true}
    };
    prof_b.immutable_files = {authority.string()};
    prof_b.reserved_entries = {{.parent = workspace.string(), .name = ".pi"}};
    prof_b.proxy = glove::container::proxy_settings{.port = 9, .url = "http://127.0.0.1:9"};
    auto with_b = prepare_launch_command(prof_b, {"/bin/sh", "-c", "true"});
    if (!with_b) {
        std::fprintf(stderr, "profile B with proxy rejected: %s\n", with_b.error().c_str());
        prof_b.proxy.reset();
        with_b = prepare_launch_command(prof_b, {"/bin/sh", "-c", "true"});
        if (!with_b) {
            std::fprintf(stderr, "ESCALATE profile B rejected: %s\n", with_b.error().c_str());
            return 1;
        }
    }
    REQUIRE(is_denial_tag(with_b->denial_tag));
    REQUIRE(tagged_deny_rules(*with_b) >= 9);
    REQUIRE(profile_runs(*with_b));
    std::printf("G1 ok\n");
    return 0;
}

struct recorder {
    std::mutex mutex;
    std::vector<std::pair<denial_class, std::string>> seen;

    void on_event(const denial_event& event) {
        if (event.readings.size() != 1) {
            return;
        }
        const std::lock_guard lock{mutex};
        if (seen.size() < max_recorded) {
            seen.emplace_back(event.readings.front().kind, event.readings.front().target);
        }
    }

    auto any(const auto& predicate) -> bool {
        const std::lock_guard lock{mutex};
        return std::ranges::any_of(seen, [&](const auto& entry) {
            return predicate(entry.first, entry.second);
        });
    }
};

auto delivery(const std::filesystem::path& work) -> int {
    int complete = 0;
    for (int trial = 1; trial <= trials; ++trial) {
        const std::string nonce = make_nonce();
        const std::string written = "/private/tmp/glove-tag-" + nonce + "-out";
        const std::string script = "/usr/bin/touch " + written + "; /bin/chmod 755 " +
                                   work.string() +
                                   "; /usr/bin/nc -w 1 127.0.0.1 9; /usr/bin/pbpaste; sleep 1";
        auto command = prepare_launch_command(profile_a(work), {"/bin/sh", "-c", script});
        REQUIRE(command.has_value());
        recorder record;
        auto started = denial_stream::start(
            denial_stream_options{
                .tag = command->denial_tag,
                .argv = {},
                .on_event = [&record](const denial_event& event) { record.on_event(event); },
                .on_degraded = {},
            }
        );
        REQUIRE(started.has_value());
        auto stream = std::move(*started);
        if (trial == 1) {
            const bool degraded = wait_for(
                [&] { return stream->state() == denial_stream_state::degraded; }, milliseconds{2000}
            );
            if (degraded || !stream->prove_live(milliseconds{10000})) {
                std::printf("SKIP log stream unavailable\n");
                return skip_code;
            }
        } else {
            REQUIRE(stream->prove_live(milliseconds{10000}).has_value());
        }
        const ::pid_t child = spawn_owned(command->arguments, command->environment);
        REQUIRE(child > 0);
        const auto write = [&] {
            return record.any([&](denial_class kind, const std::string& target) {
                return kind == denial_class::file_write && target == written;
            });
        };
        const auto guard = [&] {
            return record.any([&](denial_class kind, const std::string& target) {
                return kind == denial_class::file_write && target == work.string();
            });
        };
        const auto network = [&] {
            return record.any([](denial_class kind, const std::string&) {
                return kind == denial_class::network;
            });
        };
        const auto mach = [&] {
            return record.any([](denial_class kind, const std::string& target) {
                return kind == denial_class::mach && target.starts_with("com.apple.pasteboard");
            });
        };
        (void)wait_for(
            [&] { return write() && guard() && network() && mach(); }, milliseconds{10000}
        );
        const bool got_write = write();
        const bool got_guard = guard();
        const bool got_network = network();
        const bool got_mach = mach();
        std::printf(
            "G2 trial %d write=%d guard=%d network=%d mach=%d\n",
            trial,
            got_write ? 1 : 0,
            got_guard ? 1 : 0,
            got_network ? 1 : 0,
            got_mach ? 1 : 0
        );
        const bool tag_leaked = record.any([&](denial_class, const std::string& target) {
            return target.ends_with(command->denial_tag);
        });
        kill_and_reap(child);
        stream.reset();
        // The guard must have held: chmod 755 was attempted on a 0700 W.
        struct stat work_status{};
        REQUIRE(::stat(work.c_str(), &work_status) == 0);
        REQUIRE((work_status.st_mode & 07777) == 0700);
        REQUIRE(!tag_leaked);
        if (got_write && got_guard && got_network && got_mach) {
            ++complete;
        }
    }
    REQUIRE(complete == trials);
    std::printf("tag ok\n");
    return 0;
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    // W is one new canonical directory; profile B's tree is separate.
    temporary_tree work_tree;
    temporary_tree b_tree;
    REQUIRE(!work_tree.path().empty() && !b_tree.path().empty());
    const auto& work = work_tree.path();
    if (const int failed = structure(work, b_tree.path()); failed != 0) {
        return failed;
    }
    return delivery(work);
}
