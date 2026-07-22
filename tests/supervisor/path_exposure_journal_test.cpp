#include "glove/supervisor/path_exposure_journal.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
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
        std::string pattern = "/tmp/glove-path-exposure-journal-test-XXXXXX";
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

auto create_record() -> glove::supervisor::path_exposure_create_record {
    using namespace glove::supervisor;
    return {
        .descriptor =
            path_exposure_descriptor{
                .schema_version = 1,
                .exposure_id = "sage-workspace",
                .generation = 1,
                .root_id = "projects",
                .source_identity_digest = std::string(64, 'a'),
                .scope_digest = std::string(64, 'b'),
                .display_label = "Sage protocol",
                .allowed_modes =
                    {
                        path_exposure_mode{
                            .access = path_access::read,
                            .materialization = path_materialization::bind,
                            .max_bytes = 0,
                            .cleanup_policy = path_cleanup_policy::retain,
                        },
                        path_exposure_mode{
                            .access = path_access::retained_write,
                            .materialization = path_materialization::copy,
                            .max_bytes = 1'048'576,
                            .cleanup_policy = path_cleanup_policy::retain,
                        },
                    },
                .expires_at_ms = 3'601'000,
                .allowed_runtime_template_ids = {"codex-safe"},
                .state = path_exposure_state::active,
            },
        .request_id = "request-1",
        .request_digest = std::string(64, 'c'),
        .host_path = "/srv/projects/sage-protocol",
        .parent_identity_digest = std::string(64, 'd'),
    };
}

auto run() -> int {
    using namespace glove::supervisor;

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto journal_path = temporary.root() / "exposures.journal";
    const path_exposure_journal_record create = create_record();
    const path_exposure_journal_record revoke = path_exposure_revoke_record{
        .request_id = "revoke-1",
        .request_digest = std::string(64, 'd'),
        .exposure_id = "sage-workspace",
        .generation = 1,
        .state = path_exposure_state::revoked,
        .revoked_at_ms = 2'000,
    };

    {
        auto journal = path_exposure_journal::open(journal_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->records().empty());
        REQUIRE(journal->append(create).has_value());
        REQUIRE(journal->append(revoke).has_value());
        REQUIRE(journal->records().size() == 2U);
        REQUIRE(!path_exposure_journal::open(journal_path).has_value());
    }
    {
        auto replayed = path_exposure_journal::open(journal_path);
        REQUIRE(replayed.has_value());
        REQUIRE(replayed->records().size() == 2U);
        REQUIRE(replayed->records().front() == create);
        REQUIRE(replayed->records().back() == revoke);
    }

    const auto corrupt_path = temporary.root() / "corrupt.journal";
    {
        auto journal = path_exposure_journal::open(corrupt_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->append(create).has_value());
    }
    const int corrupt = ::open(corrupt_path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(corrupt >= 0);
    struct stat metadata{};
    REQUIRE(::fstat(corrupt, &metadata) == 0);
    REQUIRE(metadata.st_size > 0);
    unsigned char changed = 0;
    REQUIRE(::pread(corrupt, &changed, 1, metadata.st_size - 1) == 1);
    changed ^= 1U;
    REQUIRE(::pwrite(corrupt, &changed, 1, metadata.st_size - 1) == 1);
    REQUIRE(::fsync(corrupt) == 0);
    REQUIRE(::close(corrupt) == 0);
    REQUIRE(!path_exposure_journal::open(corrupt_path).has_value());

    const auto truncated_path = temporary.root() / "truncated.journal";
    {
        auto journal = path_exposure_journal::open(truncated_path);
        REQUIRE(journal.has_value());
        REQUIRE(journal->append(create).has_value());
    }
    struct stat truncated_metadata{};
    REQUIRE(::stat(truncated_path.c_str(), &truncated_metadata) == 0);
    REQUIRE(truncated_metadata.st_size > 0);
    REQUIRE(::truncate(truncated_path.c_str(), truncated_metadata.st_size - 1) == 0);
    REQUIRE(!path_exposure_journal::open(truncated_path).has_value());

    const auto weak_path = temporary.root() / "weak.journal";
    const int weak = ::open(weak_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    REQUIRE(weak >= 0);
    REQUIRE(::close(weak) == 0);
    REQUIRE(!path_exposure_journal::open(weak_path).has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
