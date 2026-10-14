#include "native_session_store.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

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

struct temporary_directory {
    fs::path path;

    temporary_directory() {
        char pattern[] = "/tmp/glove-native-store-XXXXXX";
        if (const auto* created = ::mkdtemp(pattern)) {
            std::error_code error;
            path = fs::canonical(created, error);
            if (error) {
                path.clear();
            }
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        if (!path.empty()) {
            std::error_code error;
            for (const auto& entry : fs::recursive_directory_iterator(path, error)) {
                if (fs::is_directory(entry.symlink_status(error))) {
                    fs::permissions(
                        entry.path(), fs::perms::owner_write, fs::perm_options::add, error
                    );
                }
            }
            fs::remove_all(path, error);
        }
    }
};

auto write_file(const fs::path& path, std::string_view bytes, mode_t mode = 0600) -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto read_file(const fs::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

auto mode_of(const fs::path& path) -> mode_t {
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0 ? (info.st_mode & 07777U) : 0;
}

auto count_entries(const fs::path& directory) -> std::size_t {
    std::size_t count = 0;
    std::error_code error;
    for (const auto& entry : fs::directory_iterator(directory, error)) {
        (void)entry;
        ++count;
    }
    return count;
}

const std::string runtime_digest(64, 'd');
const std::string policy_digest(64, 'e');
const std::string epoch(32, '7');

auto metadata_for(std::string session) -> session_metadata {
    return {
        .session = std::move(session),
        .runtime_id = "claude",
        .harness_id = "claude",
        .runtime_digest = runtime_digest,
        .history_format = "fixture-jsonl-v1",
        .workspace = "/workspace/fixture",
        .policy_digest = policy_digest,
        .conversation_id = "11111111-2222-3333-4444-555555555555"
    };
}

auto record_for(const session_metadata& metadata, std::uint64_t generation) -> checkpoint_record {
    return {
        .session = metadata.session,
        .producing_epoch = epoch,
        .producing_generation = generation,
        .harness_id = metadata.harness_id,
        .runtime_digest = metadata.runtime_digest,
        .history_format = metadata.history_format,
        .workspace = metadata.workspace,
        .policy_digest = metadata.policy_digest,
        .conversation_id = metadata.conversation_id,
        .history_digest = {},
        .history_bytes = 0,
        .history_entries = 0
    };
}

auto line_validator(std::string_view bytes) -> std::expected<history_summary, std::string> {
    if (bytes.find("CORRUPT") != std::string_view::npos) {
        return std::unexpected("fixture corruption marker");
    }
    history_summary summary;
    for (const auto byte : bytes) {
        if (byte == '\n') {
            ++summary.entries;
        }
    }
    return summary;
}

class source_directory {
public:
    explicit source_directory(fs::path path) : path_{std::move(path)} {
        fs::create_directories(path_);
        (void)::chmod(path_.c_str(), 0700);
        fd_ = ::open(path_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }

    source_directory(const source_directory&) = delete;
    auto operator=(const source_directory&) -> source_directory& = delete;

    ~source_directory() {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    [[nodiscard]] auto fd() const -> int { return fd_; }

    [[nodiscard]] auto path() const -> const fs::path& { return path_; }

private:
    fs::path path_;
    int fd_ = -1;
};

auto journal_event_of(std::string kind) -> journal_event {
    return {
        .seq = 0,
        .kind = std::move(kind),
        .epoch = epoch,
        .generation = 1,
        .request = {},
        .body_digest = {},
        .op = {},
        .code = {},
        .checkpoint = {},
        .detail = {}
    };
}

auto lease_and_metadata(const fs::path& root) -> int {
    const auto sessions = root / "sessions";
    fs::create_directories(sessions);
    REQUIRE(::chmod(sessions.c_str(), 0700) == 0);
    auto id = mint_session_id();
    REQUIRE(id && valid_session_id(*id));
    REQUIRE(!native_session_store::create(sessions, metadata_for("ns-bad")));
    auto malformed = metadata_for(*id);
    malformed.runtime_digest = "short";
    REQUIRE(!native_session_store::create(sessions, malformed));
    REQUIRE(count_entries(sessions) == 0);
    {
        auto store = native_session_store::create(sessions, metadata_for(*id));
        if (!store) {
            std::fprintf(stderr, "create: %s\n", store.error().c_str());
        }
        REQUIRE(store);
        REQUIRE(store->root() == sessions / *id);
        REQUIRE(mode_of(store->root()) == 0700);
        REQUIRE(mode_of(store->root() / "meta.json") == 0400);
        REQUIRE(mode_of(store->root() / "lease") == 0600);
        REQUIRE(mode_of(store->root() / "journal.log") == 0600);
        REQUIRE(mode_of(store->control_directory()) == 0700);
        REQUIRE(store->events().size() == 1 && store->events().front().kind == "session_created");
        REQUIRE(store->durable_projection() == session_projection{});
        // The lease is descriptor-bound: a second owner refuses while this one lives.
        auto second = native_session_store::open(sessions, *id, "claude");
        REQUIRE(!second && second.error().find("live owner") != std::string::npos);
        // Pathname presence proves nothing: the same path admits once the lease is released.
    }
    {
        auto reopened = native_session_store::open(sessions, *id, "claude");
        REQUIRE(reopened);
        REQUIRE(reopened->metadata() == metadata_for(*id));
        REQUIRE(!native_session_store::open(sessions, *id, "pi"));
        REQUIRE(!native_session_store::open(sessions, "ns-" + std::string(32, '0'), "claude"));
        REQUIRE(!native_session_store::create(sessions, metadata_for(*id)));
    }
    return 0;
}

auto journal_reconstruction(const fs::path& root) -> int {
    const auto sessions = root / "journal-sessions";
    fs::create_directories(sessions);
    REQUIRE(::chmod(sessions.c_str(), 0700) == 0);
    auto id = mint_session_id();
    REQUIRE(id);
    {
        auto store = native_session_store::create(sessions, metadata_for(*id));
        REQUIRE(store);
        auto intent = journal_event_of("intent");
        intent.op = "start";
        intent.request = std::string(32, '1');
        intent.body_digest = std::string(64, '2');
        REQUIRE(store->append(intent));
        REQUIRE(store->durable_projection().phase == session_phase::preparing);
        REQUIRE(store->durable_projection().generation == 1);
        REQUIRE(store->append(journal_event_of("launched")));
        REQUIRE(store->durable_projection().phase == session_phase::running);
        auto stop = journal_event_of("intent");
        stop.op = "stop";
        stop.request = std::string(32, '3');
        stop.body_digest = std::string(64, '4');
        REQUIRE(store->append(stop));
        REQUIRE(store->durable_projection().phase == session_phase::stopping);
        auto unknown = journal_event_of("signal_sent");
        REQUIRE(!store->append(unknown));
        auto oversized = journal_event_of("note");
        oversized.detail.assign(5000, 'x');
        REQUIRE(!store->append(oversized));
        auto bad_epoch = journal_event_of("note");
        bad_epoch.epoch = "NOTHEX";
        REQUIRE(!store->append(bad_epoch));
        REQUIRE(store->events().size() == 4);
    }
    {
        auto reopened = native_session_store::open(sessions, *id, "claude");
        REQUIRE(reopened);
        REQUIRE(reopened->events().size() == 4);
        // An interrupted generation reconstructs as stopping; the model turns it
        // into recovery_required rather than relaunching.
        REQUIRE(reopened->durable_projection().phase == session_phase::stopping);
        REQUIRE(reopened->append(journal_event_of("outcome_known")));
        REQUIRE(reopened->durable_projection().phase == session_phase::finalizing);
    }
    {
        // External corruption refuses recovery instead of guessing.
        const auto journal = sessions / *id / "journal.log";
        const auto original = read_file(journal);
        REQUIRE(write_file(journal, original + "{\"seq\":9,\"kind\":\"launched\"}\n"));
        REQUIRE(!native_session_store::open(sessions, *id, "claude"));
        REQUIRE(write_file(journal, original + "{\"seq\":6,\"kind\":\"launched\""));
        REQUIRE(!native_session_store::open(sessions, *id, "claude"));
        REQUIRE(write_file(journal, original.substr(0, original.size() / 2)));
        REQUIRE(!native_session_store::open(sessions, *id, "claude"));
        REQUIRE(write_file(journal, original));
        REQUIRE(native_session_store::open(sessions, *id, "claude"));
        REQUIRE(write_file(journal, original, 0644));
        REQUIRE(!native_session_store::open(sessions, *id, "claude"));
    }
    return 0;
}

auto publication_and_admission(const fs::path& root) -> int {
    const auto sessions = root / "publish-sessions";
    fs::create_directories(sessions);
    REQUIRE(::chmod(sessions.c_str(), 0700) == 0);
    auto id = mint_session_id();
    REQUIRE(id);
    source_directory source{root / "generation-history"};
    REQUIRE(source.fd() >= 0);
    const std::string history = "{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n";
    REQUIRE(write_file(source.path() / "history.jsonl", history));
    auto store = native_session_store::create(sessions, metadata_for(*id));
    REQUIRE(store);
    const auto metadata = store->metadata();
    auto published = store->publish_checkpoint(
        record_for(metadata, 1), source.fd(), "history.jsonl", line_validator
    );
    if (!published) {
        std::fprintf(stderr, "publish_checkpoint: %s\n", published.error().message.c_str());
    }
    REQUIRE(published && valid_checkpoint_id(*published));
    const auto checkpoint = store->root() / "checkpoints" / *published;
    REQUIRE(mode_of(checkpoint) == 0500);
    REQUIRE(mode_of(checkpoint / "history.jsonl") == 0400);
    REQUIRE(mode_of(checkpoint / "record.json") == 0400);
    REQUIRE(read_file(checkpoint / "history.jsonl") == history);
    REQUIRE(store->latest_checkpoint() == *published);
    REQUIRE(store->checkpoint_count() == 1);
    REQUIRE(store->events().back().kind == "checkpoint_published");
    REQUIRE(store->durable_projection().history == history_status::published);
    auto admitted = store->admit_checkpoint(*published, line_validator);
    REQUIRE(admitted);
    REQUIRE(admitted->history == history);
    REQUIRE(admitted->record.history_entries == 2);
    REQUIRE(admitted->record.producing_generation == 1);
    REQUIRE(admitted->record.history_bytes == history.size());
    REQUIRE(!store->admit_checkpoint(std::string(64, '0'), line_validator));
    REQUIRE(!store->admit_checkpoint(published->substr(1), line_validator));
    // The same content from a later generation is a distinct identity.
    auto second = store->publish_checkpoint(
        record_for(metadata, 2), source.fd(), "history.jsonl", line_validator
    );
    REQUIRE(second && *second != *published);
    REQUIRE(store->latest_checkpoint() == *second);
    // Re-publishing an identical record is refused, not silently reused.
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 2), source.fd(), "history.jsonl", line_validator
    ));
    REQUIRE(store->latest_checkpoint() == *second);

    // Source refusals: symlink, hard link, group-readable, missing, empty, corrupt.
    fs::create_symlink("history.jsonl", source.path() / "alias.jsonl");
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "alias.jsonl", line_validator
    ));
    fs::create_hard_link(source.path() / "history.jsonl", source.path() / "linked.jsonl");
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "linked.jsonl", line_validator
    ));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "history.jsonl", line_validator
    ));
    fs::remove(source.path() / "linked.jsonl");
    REQUIRE(write_file(source.path() / "shared.jsonl", history, 0640));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "shared.jsonl", line_validator
    ));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "missing.jsonl", line_validator
    ));
    REQUIRE(write_file(source.path() / "empty.jsonl", ""));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "empty.jsonl", line_validator
    ));
    REQUIRE(write_file(source.path() / "corrupt.jsonl", "{\"CORRUPT\":1}\n"));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "corrupt.jsonl", line_validator
    ));
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 3), source.fd(), "../history.jsonl", line_validator
    ));
    auto foreign = record_for(metadata, 3);
    foreign.workspace = "/elsewhere";
    REQUIRE(!store->publish_checkpoint(foreign, source.fd(), "history.jsonl", line_validator));
    REQUIRE(store->checkpoint_count() == 2);
    REQUIRE(count_entries(store->root() / "checkpoints") == 2);
    REQUIRE(store->events().size() == 3);

    // Admission rechecks bytes, modes and record identity on every resume.
    const auto tampered = store->root() / "checkpoints" / *second;
    REQUIRE(::chmod(tampered.c_str(), 0700) == 0);
    REQUIRE(!store->admit_checkpoint(*second, line_validator));
    REQUIRE(::chmod(tampered.c_str(), 0500) == 0);
    REQUIRE(store->admit_checkpoint(*second, line_validator));
    REQUIRE(::chmod(tampered.c_str(), 0700) == 0);
    REQUIRE(::chmod((tampered / "history.jsonl").c_str(), 0600) == 0);
    REQUIRE(!store->admit_checkpoint(*second, line_validator));
    REQUIRE(::chmod((tampered / "history.jsonl").c_str(), 0600) == 0);
    REQUIRE(write_file(tampered / "history.jsonl", history + "{\"type\":\"user\"}\n", 0400));
    REQUIRE(!store->admit_checkpoint(*second, line_validator));
    REQUIRE(::chmod((tampered / "history.jsonl").c_str(), 0600) == 0);
    REQUIRE(write_file(tampered / "history.jsonl", history, 0400));
    REQUIRE(::chmod(tampered.c_str(), 0500) == 0);
    REQUIRE(store->admit_checkpoint(*second, line_validator));
    // A refusing validator at resume time blocks a previously published checkpoint.
    REQUIRE(!store->admit_checkpoint(*second, [](std::string_view) {
        return std::expected<history_summary, std::string>{std::unexpected("unsupported format")};
    }));
    return 0;
}

auto fault_injection(const fs::path& root) -> int {
    const auto sessions = root / "fault-sessions";
    fs::create_directories(sessions);
    REQUIRE(::chmod(sessions.c_str(), 0700) == 0);
    source_directory source{root / "fault-history"};
    REQUIRE(write_file(source.path() / "history.jsonl", "{\"type\":\"user\"}\n"));
    auto id = mint_session_id();
    REQUIRE(id);
    auto store = native_session_store::create(sessions, metadata_for(*id));
    REQUIRE(store);
    const auto metadata = store->metadata();
    auto prior = store->publish_checkpoint(
        record_for(metadata, 1), source.fd(), "history.jsonl", line_validator
    );
    REQUIRE(prior);
    const auto events_before = store->events().size();
    std::uint64_t generation = 2;
    for (const auto fault :
         {store_fault::copy,
          store_fault::history_fsync,
          store_fault::record_fsync,
          store_fault::publish_rename}) {
        auto failed = store->publish_checkpoint(
            record_for(metadata, generation), source.fd(), "history.jsonl", line_validator, fault
        );
        REQUIRE(!failed);
        REQUIRE(store->latest_checkpoint() == *prior);
        REQUIRE(store->events().size() == events_before);
        REQUIRE(store->checkpoint_count() == 1);
        REQUIRE(count_entries(store->root() / "checkpoints") == 1);
        ++generation;
    }
    for (const auto fault : {store_fault::parent_sync, store_fault::journal_append}) {
        auto failed = store->publish_checkpoint(
            record_for(metadata, generation), source.fd(), "history.jsonl", line_validator, fault
        );
        REQUIRE(!failed);
        // The directory may exist but it is not journaled: never admitted.
        REQUIRE(store->latest_checkpoint() == *prior);
        REQUIRE(store->events().size() == events_before);
        REQUIRE(store->checkpoint_count() == 1);
        std::size_t unjournaled = 0;
        for (const auto& entry : fs::directory_iterator(store->root() / "checkpoints")) {
            const auto name = entry.path().filename().string();
            if (name != *prior) {
                ++unjournaled;
                REQUIRE(!store->admit_checkpoint(name, line_validator));
            }
        }
        REQUIRE(unjournaled == generation - 5);
        ++generation;
    }
    REQUIRE(!store->append(journal_event_of("note"), store_fault::journal_append));
    REQUIRE(store->events().size() == events_before);
    REQUIRE(store->append(journal_event_of("note")));
    REQUIRE(store->events().size() == events_before + 1);
    auto reopened_id = *id;
    { native_session_store released{std::move(*store)}; }
    auto reopened = native_session_store::open(sessions, reopened_id, "claude");
    REQUIRE(reopened);
    REQUIRE(reopened->latest_checkpoint() == *prior);
    REQUIRE(reopened->checkpoint_count() == 1);
    return 0;
}

auto bounds(const fs::path& root) -> int {
    const auto sessions = root / "bound-sessions";
    fs::create_directories(sessions);
    REQUIRE(::chmod(sessions.c_str(), 0700) == 0);
    source_directory source{root / "bound-history"};
    REQUIRE(write_file(source.path() / "history.jsonl", "{\"type\":\"user\"}\n"));
    auto id = mint_session_id();
    REQUIRE(id);
    auto store = native_session_store::create(sessions, metadata_for(*id));
    REQUIRE(store);
    const auto metadata = store->metadata();
    for (std::uint64_t generation = 1; generation <= max_checkpoints_per_session; ++generation) {
        REQUIRE(store->publish_checkpoint(
            record_for(metadata, generation), source.fd(), "history.jsonl", line_validator
        ));
    }
    REQUIRE(store->checkpoint_count() == max_checkpoints_per_session);
    auto exhausted = store->publish_checkpoint(
        record_for(metadata, 99), source.fd(), "history.jsonl", line_validator
    );
    REQUIRE(!exhausted && exhausted.error().kind == publish_failure_kind::failed);
    REQUIRE(!store->publish_checkpoint(
        record_for(metadata, 99), source.fd(), "history.jsonl", history_validator{}
    ));
    return 0;
}

} // namespace

auto main() -> int {
    temporary_directory root;
    REQUIRE(!root.path.empty());
    REQUIRE(lease_and_metadata(root.path) == 0);
    REQUIRE(journal_reconstruction(root.path) == 0);
    REQUIRE(publication_and_admission(root.path) == 0);
    REQUIRE(fault_injection(root.path) == 0);
    REQUIRE(bounds(root.path) == 0);
    return 0;
}
