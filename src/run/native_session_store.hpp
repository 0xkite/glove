#pragma once

#include "native_session_model.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

// Admission/charging bounds for one logical session. These are not filesystem
// quotas or RSS bounds; exceeding them refuses further publication or resume.
inline constexpr std::size_t max_session_metadata_bytes = 1024U * 1024U;
inline constexpr std::size_t max_journal_events = 4096U;
inline constexpr std::size_t max_journal_bytes = 4U * 1024U * 1024U;
inline constexpr std::size_t max_journal_event_bytes = 16U * 1024U;
inline constexpr std::size_t max_checkpoint_bytes = 32U * 1024U * 1024U;
inline constexpr std::size_t max_checkpoint_line_bytes = 1024U * 1024U;
inline constexpr std::size_t max_checkpoint_entries = 65536U;
inline constexpr std::size_t max_checkpoints_per_session = 32U;
inline constexpr std::uint64_t max_checkpoint_aggregate_bytes = 256ULL * 1024U * 1024U;

// Static identity of one logical session. Harness/runtime/workspace/policy
// values are compatibility bindings for resume, never launch authority.
struct session_metadata {
    std::string session;
    std::string runtime_id;
    std::string harness_id;
    std::string runtime_digest;
    std::string history_format;
    std::string workspace;
    std::string policy_digest;
    std::string conversation_id;

    auto operator==(const session_metadata&) const -> bool = default;
};

// One append-only journal record. `kind` is a closed vocabulary (see .cpp).
struct journal_event {
    std::uint64_t seq = 0;
    std::string kind;
    std::string epoch;
    std::uint64_t generation = 0;
    std::string request;
    std::string body_digest;
    std::string op;
    std::string code;
    std::string checkpoint;
    std::string detail;
};

// Provenance of one immutable checkpoint. The identity is the SHA-256 of the
// canonical record bytes; it carries no path and no current authority.
struct checkpoint_record {
    std::string session;
    std::string producing_epoch;
    std::uint64_t producing_generation = 0;
    std::string harness_id;
    std::string runtime_digest;
    std::string history_format;
    std::string workspace;
    std::string policy_digest;
    std::string conversation_id;
    std::string history_digest;
    std::uint64_t history_bytes = 0;
    std::uint64_t history_entries = 0;

    auto operator==(const checkpoint_record&) const -> bool = default;
};

struct history_summary {
    std::uint64_t entries = 0;
};

// Harness-specific format admission of exact history bytes. It runs before
// publication and again on resume admission; it must be pure and bounded.
using history_validator =
    std::function<std::expected<history_summary, std::string>(std::string_view bytes)>;

// Test-only failure points. Production passes the default (none).
enum class store_fault : std::uint8_t {
    none,
    copy,
    history_fsync,
    record_fsync,
    publish_rename,
    parent_sync,
    journal_append
};

struct admitted_checkpoint {
    std::string id;
    checkpoint_record record;
    std::string history;
};

// missing: no history object at the name (nothing was persisted).
// refused: the bytes exist but failed format/bounds/identity admission.
// failed: an I/O, durability or journal failure; publication is uncertain.
enum class publish_failure_kind : std::uint8_t { missing, refused, failed };

struct publish_failure {
    publish_failure_kind kind = publish_failure_kind::failed;
    std::string message;
};

class native_session_store {
public:
    native_session_store(const native_session_store&) = delete;
    auto operator=(const native_session_store&) -> native_session_store& = delete;
    native_session_store(native_session_store&&) noexcept;
    auto operator=(native_session_store&&) noexcept -> native_session_store& = delete;
    ~native_session_store();

    // `parent` is the owner-private sessions namespace. Both hold an exclusive
    // descriptor-bound lease until destruction; a held lease refuses open.
    [[nodiscard]] static auto create(const std::filesystem::path& parent, session_metadata metadata)
        -> std::expected<native_session_store, std::string>;
    [[nodiscard]] static auto open(
        const std::filesystem::path& parent,
        std::string_view session,
        std::string_view expected_runtime_id
    ) -> std::expected<native_session_store, std::string>;

    [[nodiscard]] auto root() const -> const std::filesystem::path&;
    [[nodiscard]] auto control_directory() const -> std::filesystem::path;
    [[nodiscard]] auto metadata() const -> const session_metadata&;

    [[nodiscard]] auto append(journal_event event, store_fault fault = store_fault::none)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto events() const -> const std::vector<journal_event>&;
    // Reconstructs the durable lifecycle projection from the journal alone.
    [[nodiscard]] auto durable_projection() const -> session_projection;
    [[nodiscard]] auto latest_checkpoint() const -> std::optional<std::string>;
    [[nodiscard]] auto checkpoint_count() const -> std::size_t;

    // Copies exact history bytes read through `source_directory_fd`/`name`
    // (regular, owner-only, single-link, stable across two reads) into an
    // immutable checkpoint, then journals checkpoint_published. Any failure
    // leaves the previous checkpoint and journal unchanged.
    [[nodiscard]] auto publish_checkpoint(
        checkpoint_record record,
        int source_directory_fd,
        std::string_view name,
        const history_validator& validate,
        store_fault fault = store_fault::none
    ) -> std::expected<std::string, publish_failure>;

    // Re-admits an exact checkpoint for resume: record digest, history digest,
    // format validation and metadata compatibility are all rechecked.
    [[nodiscard]] auto
    admit_checkpoint(std::string_view id, const history_validator& validate) const
        -> std::expected<admitted_checkpoint, std::string>;

private:
    struct implementation;
    explicit native_session_store(std::unique_ptr<implementation> state) noexcept;
    std::unique_ptr<implementation> state_;
};

[[nodiscard]] auto mint_session_id() -> std::expected<std::string, std::string>;
[[nodiscard]] auto mint_epoch() -> std::expected<std::string, std::string>;
[[nodiscard]] auto mint_request_id() -> std::expected<std::string, std::string>;
[[nodiscard]] auto sha256_of(std::string_view bytes) -> std::expected<std::string, std::string>;

} // namespace glove::run::detail
