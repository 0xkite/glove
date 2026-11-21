// The default audit journal: one launch gets the shared journal; a launch
// that finds it held gets its own journal beside it; an unsafe journal is an
// error, never worked around; and old journals of finished concurrent
// launches are removed, but never one a live launch still holds.

#include "glove/audit/event.hpp"

#include "audit_journal.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
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

using glove::run::detail::is_overflow_audit_journal_name;
using glove::run::detail::max_overflow_audit_journals;
using glove::run::detail::open_default_audit_journal;

auto record(glove::audit::sink& sink, std::string tool) -> bool {
    glove::audit::event event;
    event.what = glove::audit::action::agent_launch;
    event.tool_name = std::move(tool);
    event.arguments_json = "{}";
    return sink.record(event).has_value();
}

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto overflow_names(const std::filesystem::path& directory) -> std::vector<std::string> {
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator{directory}) {
        const auto name = entry.path().filename().string();
        if (is_overflow_audit_journal_name(name, "session", ".jsonl")) {
            names.push_back(name);
        }
    }
    return names;
}

auto names() -> int {
    REQUIRE(is_overflow_audit_journal_name("session.0123456789abcdef.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session.0123456789abcde.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session.0123456789ABCDEF.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session.0123456789abcdeg.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session-0123456789abcdef.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("other.0123456789abcdef.jsonl", "session", ".jsonl"));
    REQUIRE(!is_overflow_audit_journal_name("session.0123456789abcdef.json", "session", ".jsonl"));
    return 0;
}

auto concurrent(const std::filesystem::path& root) -> int {
    const auto directory = root / "logs";
    REQUIRE(std::filesystem::create_directory(directory));
    REQUIRE(::chmod(directory.c_str(), 0700) == 0);
    const auto shared = directory / "session.jsonl";

    auto first = open_default_audit_journal(shared, {});
    REQUIRE(first.has_value());
    REQUIRE(first->path == shared && !first->overflow);
    REQUIRE(record(*first->sink, "first"));

    // Two more launches while the first lives: each gets its own journal.
    auto second = open_default_audit_journal(shared, {});
    auto third = open_default_audit_journal(shared, {});
    REQUIRE(second.has_value() && third.has_value());
    REQUIRE(second->overflow && third->overflow);
    REQUIRE(second->path != third->path && second->path.parent_path() == directory);
    REQUIRE(is_overflow_audit_journal_name(second->path.filename().string(), "session", ".jsonl"));
    REQUIRE(record(*second->sink, "second") && record(*third->sink, "third"));
    struct stat metadata{};
    REQUIRE(::stat(second->path.c_str(), &metadata) == 0);
    REQUIRE((metadata.st_mode & 0777U) == 0600U);
    // Records never interleave across launches.
    REQUIRE(read_file(shared).contains("\"first\"") && !read_file(shared).contains("second"));
    REQUIRE(read_file(second->path).contains("\"second\""));
    REQUIRE(!read_file(second->path).contains("third"));

    // When the first launch ends, the next one gets the shared journal again
    // and appends to it.
    first->sink.reset();
    auto fourth = open_default_audit_journal(shared, {});
    REQUIRE(fourth.has_value() && fourth->path == shared && !fourth->overflow);
    REQUIRE(record(*fourth->sink, "fourth"));
    REQUIRE(read_file(shared).contains("\"first\"") && read_file(shared).contains("\"fourth\""));
    return 0;
}

auto unsafe(const std::filesystem::path& root) -> int {
    const auto directory = root / "unsafe";
    REQUIRE(std::filesystem::create_directory(directory));
    const auto shared = directory / "session.jsonl";
    // A journal that is not this launch's to trust is an error, not a reason
    // to write somewhere else.
    { const std::ofstream wide{shared}; }
    REQUIRE(::chmod(shared.c_str(), 0644) == 0);
    REQUIRE(!open_default_audit_journal(shared, {}).has_value());
    REQUIRE(overflow_names(directory).empty());
    REQUIRE(::unlink(shared.c_str()) == 0);
    REQUIRE(::symlink("/dev/null", shared.c_str()) == 0);
    REQUIRE(!open_default_audit_journal(shared, {}).has_value());
    REQUIRE(overflow_names(directory).empty());
    REQUIRE(!open_default_audit_journal("relative/session.jsonl", {}).has_value());
    return 0;
}

auto retention(const std::filesystem::path& root) -> int {
    const auto directory = root / "many";
    REQUIRE(std::filesystem::create_directory(directory));
    const auto shared = directory / "session.jsonl";
    auto holder = open_default_audit_journal(shared, {});
    REQUIRE(holder.has_value() && !holder->overflow);

    // One overflow journal a live launch still holds, made the oldest.
    auto live = open_default_audit_journal(shared, {});
    REQUIRE(live.has_value() && live->overflow);
    const auto old_time =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{24 * 365};
    std::filesystem::last_write_time(live->path, old_time);
    // Finished launches' journals, oldest first, up to the limit in total.
    std::vector<std::filesystem::path> finished;
    for (std::size_t index = 0; index + 1 < max_overflow_audit_journals; ++index) {
        char name[64];
        std::snprintf(name, sizeof(name), "session.%016zx.jsonl", index + 1);
        finished.push_back(directory / name);
        { const std::ofstream file{finished.back()}; }
        REQUIRE(::chmod(finished.back().c_str(), 0600) == 0);
        std::filesystem::last_write_time(
            finished.back(), old_time + std::chrono::hours{static_cast<long>(index + 1)}
        );
    }
    // Files that only look similar are never touched.
    const auto bystander = directory / "session.notes.jsonl";
    { const std::ofstream file{bystander}; }
    REQUIRE(overflow_names(directory).size() == max_overflow_audit_journals);

    auto next = open_default_audit_journal(shared, {});
    REQUIRE(next.has_value() && next->overflow);
    REQUIRE(overflow_names(directory).size() == max_overflow_audit_journals);
    REQUIRE(std::filesystem::exists(live->path));      // oldest, but held
    REQUIRE(!std::filesystem::exists(finished.at(0))); // oldest finished
    REQUIRE(std::filesystem::exists(finished.at(1)));
    REQUIRE(std::filesystem::exists(bystander) && std::filesystem::exists(shared));
    return 0;
}

// Launches that open their journals at the same moment, with every older
// journal held by a live launch, so each retention pass can only pick a file
// another thread has created and not yet locked. A sink must never come back
// on a file retention removed: its records would have no name to be read by.
// Model: formal/AuditJournal.tla, invariant WriterIsNamed.
auto retention_race(const std::filesystem::path& root) -> int {
    const auto directory = root / "race";
    REQUIRE(std::filesystem::create_directory(directory));
    const auto shared = directory / "session.jsonl";
    auto holder = open_default_audit_journal(shared, {});
    REQUIRE(holder.has_value() && !holder->overflow);
    std::vector<glove::run::detail::default_audit_journal> live;
    for (std::size_t index = 0; index != max_overflow_audit_journals; ++index) {
        auto journal = open_default_audit_journal(shared, {});
        REQUIRE(journal.has_value() && journal->overflow);
        live.push_back(std::move(*journal));
    }

    constexpr int threads = 8;
    constexpr int rounds = 1500;
    std::atomic<int> unnamed{0};
    std::atomic<int> unexpected_errors{0};
    std::atomic<int> opened{0};
    {
        std::vector<std::jthread> workers;
        for (int worker = 0; worker != threads; ++worker) {
            workers.emplace_back([&] {
                for (int round = 0; round != rounds; ++round) {
                    auto journal = open_default_audit_journal(shared, {});
                    if (!journal) {
                        // Running out of names under this contention is
                        // allowed; any other error is not.
                        if (journal.error() != glove::audit::jsonl_sink_busy &&
                            journal.error() != glove::audit::jsonl_sink_removed) {
                            if (unexpected_errors.fetch_add(1) == 0) {
                                std::fprintf(
                                    stderr, "retention race: %s\n", journal.error().c_str()
                                );
                            }
                        }
                        continue;
                    }
                    opened.fetch_add(1);
                    struct stat named{};
                    if (!record(*journal->sink, "race") ||
                        ::lstat(journal->path.c_str(), &named) != 0 || named.st_size == 0) {
                        unnamed.fetch_add(1);
                    }
                }
            });
        }
    }
    std::fprintf(stderr, "retention race: %d opened\n", opened.load());
    REQUIRE(unexpected_errors.load() == 0);
    REQUIRE(unnamed.load() == 0);
    REQUIRE(opened.load() > threads * rounds / 2);
    for (const auto& journal : live) {
        REQUIRE(std::filesystem::exists(journal.path));
    }
    return 0;
}

} // namespace

int main() {
    std::error_code ec;
    const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
    std::string pattern = (base / "glove_audit_journal_test_XXXXXX").string();
    if (ec || ::mkdtemp(pattern.data()) == nullptr) {
        return 1;
    }
    const std::filesystem::path root{pattern};
    int failed = names();
    for (auto* step : {concurrent, unsafe, retention, retention_race}) {
        if (failed == 0) {
            failed = step(root);
        }
    }
    std::filesystem::remove_all(root, ec);
    if (failed == 0) {
        std::printf("audit journal ok\n");
    }
    return failed;
}
