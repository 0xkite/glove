#include "glove/supervisor/change_apply_journal.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <system_error>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-change-apply-journal-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

class fault_injecting_journal_io final : public glove::supervisor::change_apply_journal_io {
public:
    void fail_next_append_after_partial_write() { fail_write_ = true; }

    void fail_next_sync() { fail_sync_ = true; }

    auto write_at(int descriptor, std::string_view bytes, std::uint64_t offset) const
        -> glove::supervisor::result<std::size_t> override {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return std::unexpected(std::string{"test write offset is invalid"});
        }
        std::size_t count = bytes.size();
        if (fail_write_) {
            if (partial_write_complete_) {
                fail_write_ = false;
                partial_write_complete_ = false;
                return std::unexpected(std::string{"injected disk full"});
            }
            count = std::max(std::size_t{1}, bytes.size() / 2U);
            partial_write_complete_ = true;
        }
        const auto written = ::pwrite(descriptor, bytes.data(), count, static_cast<off_t>(offset));
        if (written <= 0) {
            return std::unexpected(std::string{"test write failed"});
        }
        return static_cast<std::size_t>(written);
    }

    auto truncate(int descriptor, std::uint64_t size) const
        -> glove::supervisor::result<void> override {
        if (size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
            ::ftruncate(descriptor, static_cast<off_t>(size)) != 0) {
            return std::unexpected(std::string{"test truncate failed"});
        }
        return {};
    }

    auto sync(int descriptor) const -> glove::supervisor::result<void> override {
        if (fail_sync_) {
            fail_sync_ = false;
            return std::unexpected(std::string{"injected sync failure"});
        }
        if (::fsync(descriptor) != 0) {
            return std::unexpected(std::string{"test sync failed"});
        }
        return {};
    }

private:
    mutable bool fail_write_ = false;
    mutable bool partial_write_complete_ = false;
    mutable bool fail_sync_ = false;
};

auto reservation(
    std::string grant_id = "grant-1",
    char authorization = 'a',
    char manifest = 'b',
    std::uint64_t reserved_at_ms = 1'000
) -> glove::supervisor::change_apply_reservation_record {
    return {
        .grant_id = std::move(grant_id),
        .authorization_digest = std::string(64, authorization),
        .manifest_digest = std::string(64, manifest),
        .session_id = "session-1",
        .exposure_id = "workspace",
        .generation = 7,
        .scope_digest = std::string(64, 'c'),
        .source_identity_digest = std::string(64, 'd'),
        .baseline_tree_digest = std::string(64, 'e'),
        .staged_tree_digest = std::string(64, 'f'),
        .reserved_at_ms = reserved_at_ms,
    };
}

auto terminal() -> glove::supervisor::change_apply_terminal_record {
    return {
        .grant_id = "grant-1",
        .authorization_digest = std::string(64, 'a'),
        .manifest_digest = std::string(64, 'b'),
        .state = glove::supervisor::change_apply_terminal_state::applied,
        .receipt_digest = std::string(64, 'c'),
        .final_source_identity_digest = std::string(64, 'd'),
        .failure_code = {},
        .completed_at_ms = 2'000,
    };
}

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto journal_path = temporary.root() / "apply.journal";
    {
        auto journal = change_apply_journal::open(journal_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->records().empty());
        REQUIRE(journal->reserve(reservation()).has_value());
        REQUIRE(!journal->reserve(reservation()).has_value());
        REQUIRE(!journal->reserve(reservation("grant-2", 'a', 'd')).has_value());
        REQUIRE(!journal->reserve(reservation("grant-3", 'c', 'b')).has_value());
        REQUIRE(journal->finalize(terminal()).has_value());
        REQUIRE(!journal->finalize(terminal()).has_value());
        const auto found = journal->find("grant-1");
        REQUIRE(found.has_value());
        REQUIRE(found->reservation.session_id == "session-1");
        REQUIRE(found->reservation.exposure_id == "workspace");
        REQUIRE(found->reservation.generation == 7);
        REQUIRE(found->reservation.baseline_tree_digest == std::string(64, 'e'));
        REQUIRE(found->reservation.staged_tree_digest == std::string(64, 'f'));
        REQUIRE(found->terminal.has_value());
        REQUIRE(found->terminal->final_source_identity_digest == std::string(64, 'd'));
        REQUIRE(found->terminal->state == change_apply_terminal_state::applied);
        REQUIRE(found->terminal->failure_code.empty());
        REQUIRE(!change_apply_journal::open(journal_path).has_value());
    }
    {
        auto replayed = change_apply_journal::open(journal_path);
        REQUIRE(replayed.has_value());
        REQUIRE(replayed->records().size() == 1U);
        const auto found = replayed->find("grant-1");
        REQUIRE(found.has_value());
        REQUIRE(found->reservation.scope_digest == std::string(64, 'c'));
        REQUIRE(found->terminal.has_value());
        REQUIRE(found->terminal->failure_code.empty());
        REQUIRE(!replayed->reserve(reservation()).has_value());
    }

    const auto interrupted_path = temporary.root() / "interrupted.journal";
    {
        auto journal = change_apply_journal::open(interrupted_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->reserve(reservation("grant-crash", 'd', 'e')).has_value());
    }
    {
        auto recovered = change_apply_journal::open(interrupted_path);
        REQUIRE(recovered.has_value());
        const auto found = recovered->find("grant-crash");
        REQUIRE(found.has_value());
        REQUIRE(!found->terminal.has_value());
        REQUIRE(!recovered->reserve(reservation("grant-crash", 'd', 'e')).has_value());
    }

    const auto corrupt_path = temporary.root() / "corrupt.journal";
    {
        auto journal = change_apply_journal::open(corrupt_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->reserve(reservation()).has_value());
    }
    const int corrupt = ::open(corrupt_path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(corrupt >= 0);
    struct stat metadata{};
    REQUIRE(::fstat(corrupt, &metadata) == 0);
    REQUIRE(metadata.st_size > 4);
    unsigned char changed = 0;
    REQUIRE(::pread(corrupt, &changed, 1, metadata.st_size - 3) == 1);
    changed ^= 1U;
    REQUIRE(::pwrite(corrupt, &changed, 1, metadata.st_size - 3) == 1);
    REQUIRE(::fsync(corrupt) == 0);
    REQUIRE(::close(corrupt) == 0);
    REQUIRE(!change_apply_journal::open(corrupt_path).has_value());

    const auto truncated_path = temporary.root() / "truncated.journal";
    {
        auto journal = change_apply_journal::open(truncated_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->reserve(reservation()).has_value());
    }
    struct stat truncated_metadata{};
    REQUIRE(::stat(truncated_path.c_str(), &truncated_metadata) == 0);
    REQUIRE(::truncate(truncated_path.c_str(), truncated_metadata.st_size - 1) == 0);
    REQUIRE(!change_apply_journal::open(truncated_path).has_value());

    const auto bounded_path = temporary.root() / "bounded.journal";
    {
        auto bounded = change_apply_journal::open(bounded_path, 64);
        REQUIRE(bounded.has_value());
        REQUIRE(!bounded->reserve(reservation()).has_value());
    }

    const auto weak_path = temporary.root() / "weak.journal";
    const int weak = ::open(weak_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    REQUIRE(weak >= 0);
    REQUIRE(::close(weak) == 0);
    REQUIRE(!change_apply_journal::open(weak_path).has_value());

    const auto malformed_path = temporary.root() / "malformed.journal";
    const int malformed =
        ::open(malformed_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    REQUIRE(malformed >= 0);
    constexpr std::string_view journal_magic = "GLOVE-CHANGE-APPLY1\n";
    constexpr std::array malformed_record{'{', '\0', '}', '\n'};
    REQUIRE(
        ::write(malformed, journal_magic.data(), journal_magic.size()) ==
        static_cast<ssize_t>(journal_magic.size())
    );
    REQUIRE(
        ::write(malformed, malformed_record.data(), malformed_record.size()) ==
        static_cast<ssize_t>(malformed_record.size())
    );
    REQUIRE(::close(malformed) == 0);
    REQUIRE(!change_apply_journal::open(malformed_path).has_value());

    const auto fault_path = temporary.root() / "fault.journal";
    const auto fault_io = std::make_shared<fault_injecting_journal_io>();
    {
        auto journal =
            change_apply_journal::open(fault_path, default_change_apply_journal_bytes, fault_io);
        REQUIRE(journal.has_value());
        struct stat before{};
        REQUIRE(::stat(fault_path.c_str(), &before) == 0);

        fault_io->fail_next_append_after_partial_write();
        REQUIRE(!journal->reserve(reservation("grant-write-failure", 'e', 'f')).has_value());
        struct stat after_write_failure{};
        REQUIRE(::stat(fault_path.c_str(), &after_write_failure) == 0);
        REQUIRE(after_write_failure.st_size == before.st_size);
        REQUIRE(journal->records().empty());

        fault_io->fail_next_sync();
        REQUIRE(!journal->reserve(reservation("grant-sync-failure", 'e', 'f')).has_value());
        struct stat after_sync_failure{};
        REQUIRE(::stat(fault_path.c_str(), &after_sync_failure) == 0);
        REQUIRE(after_sync_failure.st_size == before.st_size);
        REQUIRE(journal->records().empty());

        REQUIRE(journal->reserve(reservation("grant-retry", 'e', 'f')).has_value());
    }
    {
        auto replayed = change_apply_journal::open(fault_path);
        REQUIRE(replayed.has_value());
        REQUIRE(replayed->records().size() == 1U);
        REQUIRE(replayed->find("grant-retry").has_value());
    }
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
