#include "glove/container/digest.hpp"
#include "glove/container/receipt_journal.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
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

constexpr std::string_view audit_key =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view controller_plan_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view profile_digest =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-receipt-journal-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto receipt(std::uint64_t cpu_time_ms = 500) -> glove::container::resource_enforcement_receipt {
    return {
        .schema_version = 1,
        .profile_digest = std::string{profile_digest},
        .backend = glove::container::sandbox_backend::linux_production,
        .backend_id = "linux-production:cgroup-v2-v1",
        .configured_limits =
            {
                .cpu_time_ms = 60'000,
                .memory_bytes = std::uint64_t{512} * 1024U * 1024U,
                .pids = 128,
                .wall_time_ms = 120'000,
                .disk_bytes = std::uint64_t{1024} * 1024U * 1024U,
                .terminal_output_bytes = std::uint64_t{16} * 1024U * 1024U,
            },
        .mechanisms =
            {
                .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
                .memory = glove::container::enforcement_mechanism::cgroup_v2,
                .pids = glove::container::enforcement_mechanism::cgroup_v2,
                .wall_time = glove::container::enforcement_mechanism::watchdog,
                .disk = glove::container::enforcement_mechanism::filesystem_quota,
                .terminal_output = glove::container::enforcement_mechanism::byte_counter,
                .receipt_schema_version = 1,
            },
        .observed =
            {
                .cpu_time_ms = cpu_time_ms,
                .peak_memory_bytes = std::uint64_t{16} * 1024U * 1024U,
                .peak_pids = 2,
                .wall_time_ms = 750,
                .disk_bytes = 4096,
                .terminal_output_bytes = 1024,
            },
        .termination_cause = glove::container::resource_termination_cause::exited,
        .exit_code = 0,
        .started_at_ms = 1'000,
        .finished_at_ms = 1'750,
        .library_projections = {},
        .retained_changes = {},
    };
}

auto refinement_receipt(std::uint64_t cpu_time_ms = 500)
    -> glove::container::refinement_evaluation_receipt {
    using namespace glove::container;
    refinement_outcome outcome{
        .schema = std::string{refinement_outcome_schema},
        .encoding = std::string{refinement_outcome_encoding},
        .metrics = {{"failed_assertions", 0}, {"latency_us", 750'000}, {"passed", 1}},
    };
    const auto outcome_bytes = canonical_refinement_outcome_bytes(outcome).value();
    const auto outcome_digest = sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(outcome_bytes.data()), outcome_bytes.size()
        }
    );
    return {
        .schema_version = refinement_evaluation_receipt_schema_version,
        .runtime_template_id = std::string{refinement_runtime_template_id},
        .resource_receipt = receipt(cpu_time_ms),
        .evidence_status = refinement_evidence_status::valid_outcome,
        .variant = refinement_variant::candidate,
        .fixture = {"fixture", std::string(64, 'f'), "fixtures"},
        .base = {"base", std::string(64, 'b'), "skills"},
        .candidate = {"candidate", std::string(64, 'c'), "skills"},
        .matched_context_digest = std::string(64, 'd'),
        .outcome =
            {
                .schema = outcome.schema,
                .encoding = outcome.encoding,
                .digest = *outcome_digest,
                .byte_length = outcome_bytes.size(),
            },
        .evaluated_outcome = outcome,
        .transcript =
            {
                .schema = std::string{raw_pty_transcript_schema},
                .digest = std::string(64, 'e'),
                .byte_count = 1'024,
                .complete = true,
            },
        .evaluator = {
            .schema = std::string{refinement_evaluator_schema},
            .fixture_complete = true,
            .transcript_utf8 = true,
            .required_literals = 1,
            .forbidden_literals = 1,
        },
    };
}

auto read_bytes(const std::filesystem::path& path) -> std::vector<char> {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

auto write_bytes(const std::filesystem::path& path, const std::vector<char>& bytes) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.flush();
    return output.good();
}

auto append_bytes(const std::filesystem::path& path, std::string_view bytes) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::app};
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.flush();
    return output.good();
}

auto persistence_and_reconciliation() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    auto first = (*journal)->append("session-1", controller_plan_digest, receipt());
    REQUIRE(first.has_value());
    const auto first_anchor = (*journal)->anchor();
    auto second = (*journal)->append("session-2", controller_plan_digest, receipt(501));
    REQUIRE(second.has_value());
    REQUIRE((*journal)->record_count() == 2);
    REQUIRE((*journal)->anchor().sequence == 2);
    REQUIRE((*journal)->durable_bytes() == std::filesystem::file_size(path));
    REQUIRE(!glove::container::receipt_audit_journal::open_existing(path, audit_key).has_value());
    journal->reset();

    auto reopened =
        glove::container::receipt_audit_journal::open_existing(path, audit_key, first_anchor);
    REQUIRE(reopened.has_value());
    REQUIRE((*reopened)->record_count() == 2);
    REQUIRE((*reopened)->anchor().head_hmac == second->this_hmac);
    REQUIRE(!(*reopened)->repaired_torn_tail());
    auto page = (*reopened)->page_after(first_anchor, 10);
    REQUIRE(page.has_value());
    REQUIRE(page->envelopes.size() == 1);
    REQUIRE(page->envelopes[0] == *second);
    REQUIRE(!page->has_more);
    auto first_lookup =
        (*reopened)->terminal_for_execution("session-1", controller_plan_digest, profile_digest);
    REQUIRE(first_lookup.has_value());
    REQUIRE(first_lookup->has_value());
    REQUIRE(**first_lookup == *first);
    auto missing_lookup = (*reopened)->terminal_for_execution(
        "session-missing", controller_plan_digest, profile_digest
    );
    REQUIRE(missing_lookup.has_value());
    REQUIRE(!missing_lookup->has_value());
    REQUIRE(!(*reopened)
                 ->terminal_for_execution("../session", controller_plan_digest, profile_digest)
                 .has_value());
    REQUIRE((*reopened)->append("session-1", controller_plan_digest, receipt(502)).has_value());
    REQUIRE(!(*reopened)
                 ->terminal_for_execution("session-1", controller_plan_digest, profile_digest)
                 .has_value());

    auto forged = first_anchor;
    forged.head_hmac[0] = forged.head_hmac[0] == 'a' ? 'b' : 'a';
    REQUIRE(!(*reopened)->page_after(forged, 10).has_value());
    REQUIRE(!(*reopened)->page_after(first_anchor, 0).has_value());
    REQUIRE(!(*reopened)
                 ->page_after(first_anchor, glove::container::max_receipt_reconciliation_page + 1U)
                 .has_value());

    const auto bytes = read_bytes(path);
    REQUIRE(
        std::search(bytes.begin(), bytes.end(), audit_key.begin(), audit_key.end()) == bytes.end()
    );
    return 0;
}

auto concurrent_appends_are_serialized_and_recoverable() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    auto* writer = journal->get();
    std::atomic<std::uint64_t> succeeded = 0;
    {
        std::vector<std::thread> workers;
        workers.reserve(8);
        for (std::uint64_t index = 0; index < 8; ++index) {
            workers.emplace_back([&, index] {
                const auto session = "session-" + std::to_string(index);
                const bool appended =
                    index % 2U == 0
                        ? writer->append(session, controller_plan_digest, receipt(500U + index))
                              .has_value()
                        : writer
                              ->append_refinement(
                                  session, controller_plan_digest, refinement_receipt(500U + index)
                              )
                              .has_value();
                if (appended) {
                    succeeded.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        for (auto& worker : workers) {
            worker.join();
        }
    }
    REQUIRE(succeeded.load(std::memory_order_relaxed) == 8);
    REQUIRE(writer->record_count() == 8);
    REQUIRE(writer->anchor().sequence == 8);
    journal->reset();

    auto reopened = glove::container::receipt_audit_journal::open_existing(path, audit_key);
    REQUIRE(reopened.has_value());
    REQUIRE((*reopened)->record_count() == 8);
    REQUIRE((*reopened)->anchor().sequence == 8);
    return 0;
}

auto mixed_receipts_page_and_recover_without_substitution() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto genesis = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(genesis.has_value());
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    auto resource = (*journal)->append("session-resource", controller_plan_digest, receipt());
    REQUIRE(resource.has_value());
    auto refinement = (*journal)->append_refinement(
        "session-refinement", controller_plan_digest, refinement_receipt()
    );
    REQUIRE(refinement.has_value());
    REQUIRE(resource->sequence == 1);
    REQUIRE(refinement->sequence == 2);
    REQUIRE(refinement->previous_hmac == resource->this_hmac);
    auto page = (*journal)->page_after(**genesis, 10);
    REQUIRE(page.has_value());
    REQUIRE(page->envelopes == std::vector{*resource});
    REQUIRE(page->refinement_envelopes == std::vector{*refinement});
    REQUIRE((*journal)->contains_exact(*resource).value_or(false));
    REQUIRE((*journal)->contains_exact(*refinement).value_or(false));
    journal->reset();

    auto reopened =
        glove::container::receipt_audit_journal::open_existing(path, audit_key, **genesis);
    REQUIRE(reopened.has_value());
    auto found = (*reopened)->refinement_terminal_for_execution(
        "session-refinement", controller_plan_digest, profile_digest
    );
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    REQUIRE(**found == *refinement);
    auto wrong_type = (*reopened)->terminal_for_execution(
        "session-refinement", controller_plan_digest, profile_digest
    );
    REQUIRE(wrong_type.has_value());
    REQUIRE(!wrong_type->has_value());
    return 0;
}

auto external_size_changes_poison_reconciliation() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto genesis = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(genesis.has_value());
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    REQUIRE((*journal)->append("session-1", controller_plan_digest, receipt()).has_value());
    REQUIRE(append_bytes(path, std::string_view{"x", 1}));
    REQUIRE(!(*journal)->page_after(**genesis, 10).has_value());
    REQUIRE(!(*journal)->append("session-2", controller_plan_digest, receipt()).has_value());
    return 0;
}

auto torn_tail_requires_a_trusted_prefix() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto genesis = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(genesis.has_value());
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    auto first = (*journal)->append("session-1", controller_plan_digest, receipt());
    REQUIRE(first.has_value());
    journal->reset();
    REQUIRE(append_bytes(path, std::string_view{"\x00\x00\x01", 3}));
    const auto torn_size = std::filesystem::file_size(path);

    REQUIRE(!glove::container::receipt_audit_journal::open_existing(path, audit_key).has_value());
    REQUIRE(std::filesystem::file_size(path) == torn_size);
    auto repaired =
        glove::container::receipt_audit_journal::open_existing(path, audit_key, **genesis);
    REQUIRE(repaired.has_value());
    REQUIRE((*repaired)->repaired_torn_tail());
    REQUIRE((*repaired)->record_count() == 1);
    REQUIRE((*repaired)->anchor().head_hmac == first->this_hmac);
    REQUIRE(std::filesystem::file_size(path) < torn_size);
    auto pending = (*repaired)->page_after(**genesis, 10);
    REQUIRE(pending.has_value());
    REQUIRE(pending->envelopes.size() == 1);
    REQUIRE(pending->envelopes[0] == *first);
    return 0;
}

auto accepted_tail_truncation_fails_reconciliation() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    REQUIRE((*journal)->append("session-1", controller_plan_digest, receipt()).has_value());
    auto second = (*journal)->append("session-2", controller_plan_digest, receipt(501));
    REQUIRE(second.has_value());
    const auto accepted_anchor = (*journal)->anchor();
    journal->reset();
    const auto size = std::filesystem::file_size(path);
    REQUIRE(size > 5);
    std::filesystem::resize_file(path, size - 5U);
    const auto truncated_size = std::filesystem::file_size(path);

    REQUIRE(
        !glove::container::receipt_audit_journal::open_existing(path, audit_key, accepted_anchor)
             .has_value()
    );
    REQUIRE(std::filesystem::file_size(path) == truncated_size);
    return 0;
}

auto complete_record_tampering_fails_closed() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto genesis = glove::container::receipt_audit_anchor::create(audit_key);
    REQUIRE(genesis.has_value());
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    REQUIRE((*journal)->append("session-1", controller_plan_digest, receipt()).has_value());
    journal->reset();

    auto bytes = read_bytes(path);
    constexpr std::string_view needle = "session-1";
    auto position = std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end());
    REQUIRE(position != bytes.end());
    *position = *position == 's' ? 't' : 's';
    REQUIRE(write_bytes(path, bytes));
    const auto tampered_size = std::filesystem::file_size(path);
    REQUIRE(!glove::container::receipt_audit_journal::open_existing(path, audit_key, **genesis)
                 .has_value());
    REQUIRE(std::filesystem::file_size(path) == tampered_size);
    return 0;
}

auto capacity_failure_does_not_advance_the_chain() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    constexpr std::uint64_t journal_limit = 4096;
    auto journal =
        glove::container::receipt_audit_journal::create_new(path, audit_key, journal_limit);
    REQUIRE(journal.has_value());
    std::uint64_t succeeded = 0;
    for (;;) {
        auto appended =
            (*journal)->append("session-1", controller_plan_digest, receipt(500U + succeeded));
        if (!appended) {
            break;
        }
        ++succeeded;
        REQUIRE(succeeded < 10);
    }
    REQUIRE(succeeded > 0);
    REQUIRE((*journal)->record_count() == succeeded);
    REQUIRE((*journal)->anchor().sequence == succeeded);
    REQUIRE((*journal)->durable_bytes() <= journal_limit);
    const auto stable_anchor = (*journal)->anchor();
    REQUIRE(!(*journal)->append("session-1", controller_plan_digest, receipt()).has_value());
    REQUIRE((*journal)->anchor() == stable_anchor);
    return 0;
}

auto journal_file_identity_and_key_are_fail_closed() -> int {
    temporary_directory temp;
    REQUIRE(!temp.root().empty());
    const auto path = temp.root() / "receipts.journal";
    auto journal = glove::container::receipt_audit_journal::create_new(path, audit_key);
    REQUIRE(journal.has_value());
    REQUIRE(!glove::container::receipt_audit_journal::create_new(path, audit_key).has_value());
    REQUIRE((*journal)->append("session-1", controller_plan_digest, receipt()).has_value());
    journal->reset();

    REQUIRE(!glove::container::receipt_audit_journal::open_existing(
                 path, "1111111111111111111111111111111111111111111111111111111111111111"
    )
                 .has_value());
    REQUIRE(::chmod(path.c_str(), 0644) == 0);
    REQUIRE(!glove::container::receipt_audit_journal::open_existing(path, audit_key).has_value());
    REQUIRE(::chmod(path.c_str(), 0600) == 0);

    const auto symlink_path = temp.root() / "receipt-link.journal";
    std::filesystem::create_symlink(path, symlink_path);
    REQUIRE(
        !glove::container::receipt_audit_journal::open_existing(symlink_path, audit_key).has_value()
    );
    const auto hardlink_path = temp.root() / "receipt-hardlink.journal";
    std::filesystem::create_hard_link(path, hardlink_path);
    REQUIRE(!glove::container::receipt_audit_journal::open_existing(path, audit_key).has_value());
    return 0;
}

auto run() -> int {
    REQUIRE(persistence_and_reconciliation() == 0);
    REQUIRE(concurrent_appends_are_serialized_and_recoverable() == 0);
    REQUIRE(mixed_receipts_page_and_recover_without_substitution() == 0);
    REQUIRE(external_size_changes_poison_reconciliation() == 0);
    REQUIRE(torn_tail_requires_a_trusted_prefix() == 0);
    REQUIRE(accepted_tail_truncation_fails_reconciliation() == 0);
    REQUIRE(complete_record_tampering_fails_closed() == 0);
    REQUIRE(capacity_failure_does_not_advance_the_chain() == 0);
    REQUIRE(journal_file_identity_and_key_are_fail_closed() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
