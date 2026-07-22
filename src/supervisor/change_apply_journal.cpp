#include "glove/supervisor/change_apply_journal.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace apply_journal_wire {

struct wire_record_body {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string kind;
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string state;
    std::string receipt_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t occurred_at_ms = 0;
    std::string previous_hash;
};

struct wire_record {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string kind;
    std::string grant_id;
    std::string authorization_digest;
    std::string manifest_digest;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string state;
    std::string receipt_digest;
    std::string final_source_identity_digest;
    std::string failure_code;
    std::uint64_t occurred_at_ms = 0;
    std::string previous_hash;
    std::string record_hash;
};

} // namespace apply_journal_wire

namespace {

using apply_journal_wire::wire_record;
using apply_journal_wire::wire_record_body;

constexpr std::string_view journal_magic = "GLOVE-CHANGE-APPLY1\n";
constexpr std::size_t max_record_bytes = std::size_t{4} * 1024U;
constexpr std::size_t max_records = 8'192U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

struct decoded_record {
    std::optional<change_apply_reservation_record> reservation;
    std::optional<change_apply_terminal_record> terminal;
};

struct opened_journal {
    unique_fd parent;
    unique_fd file;
    std::string filename;
    std::uint64_t size = 0;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

class posix_change_apply_journal_io final : public change_apply_journal_io {
public:
    auto write_at(int descriptor, std::string_view bytes, std::uint64_t offset) const
        -> result<std::size_t> override {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return std::unexpected(std::string{"change apply journal offset is too large"});
        }
        while (true) {
            const auto written =
                ::pwrite(descriptor, bytes.data(), bytes.size(), static_cast<off_t>(offset));
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                return std::unexpected(error_message("write change apply journal"));
            }
            return static_cast<std::size_t>(written);
        }
    }

    auto truncate(int descriptor, std::uint64_t size) const -> result<void> override {
        if (size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
            return std::unexpected(std::string{"change apply journal offset is too large"});
        }
        while (::ftruncate(descriptor, static_cast<off_t>(size)) != 0) {
            if (errno != EINTR) {
                return std::unexpected(error_message("truncate change apply journal"));
            }
        }
        return {};
    }

    auto sync(int descriptor) const -> result<void> override {
        while (::fsync(descriptor) != 0) {
            if (errno != EINTR) {
                return std::unexpected(error_message("sync change apply journal"));
            }
        }
        return {};
    }
};

auto default_journal_io() -> std::shared_ptr<const change_apply_journal_io> {
    static const auto instance = std::make_shared<posix_change_apply_journal_io>();
    return instance;
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto terminal_name(change_apply_terminal_state state) -> std::string_view {
    switch (state) {
    case change_apply_terminal_state::applied:
        return "applied";
    case change_apply_terminal_state::rejected:
        return "rejected";
    case change_apply_terminal_state::failed:
        return "failed";
    }
    return {};
}

auto parse_terminal(std::string_view value) -> result<change_apply_terminal_state> {
    if (value == "applied") {
        return change_apply_terminal_state::applied;
    }
    if (value == "rejected") {
        return change_apply_terminal_state::rejected;
    }
    if (value == "failed") {
        return change_apply_terminal_state::failed;
    }
    return std::unexpected(std::string{"change apply journal terminal state is invalid"});
}

auto body(const wire_record& record) -> wire_record_body {
    return {
        .schema_version = record.schema_version,
        .sequence = record.sequence,
        .kind = record.kind,
        .grant_id = record.grant_id,
        .authorization_digest = record.authorization_digest,
        .manifest_digest = record.manifest_digest,
        .session_id = record.session_id,
        .exposure_id = record.exposure_id,
        .generation = record.generation,
        .scope_digest = record.scope_digest,
        .source_identity_digest = record.source_identity_digest,
        .baseline_tree_digest = record.baseline_tree_digest,
        .staged_tree_digest = record.staged_tree_digest,
        .state = record.state,
        .receipt_digest = record.receipt_digest,
        .final_source_identity_digest = record.final_source_identity_digest,
        .failure_code = record.failure_code,
        .occurred_at_ms = record.occurred_at_ms,
        .previous_hash = record.previous_hash,
    };
}

auto record_digest(const wire_record& record) -> result<std::string> {
    auto json = glz::write_json(body(record));
    if (!json) {
        return std::unexpected(std::string{"encode change apply journal record"});
    }
    return container::sha256_hex(
        std::span{
            reinterpret_cast<const unsigned char*>(json->data()),
            json->size(),
        }
    );
}

auto encode(
    const change_apply_reservation_record& record,
    std::uint64_t sequence,
    std::string_view previous_hash
) -> wire_record {
    return {
        .schema_version = 1,
        .sequence = sequence,
        .kind = "reserve",
        .grant_id = record.grant_id,
        .authorization_digest = record.authorization_digest,
        .manifest_digest = record.manifest_digest,
        .session_id = record.session_id,
        .exposure_id = record.exposure_id,
        .generation = record.generation,
        .scope_digest = record.scope_digest,
        .source_identity_digest = record.source_identity_digest,
        .baseline_tree_digest = record.baseline_tree_digest,
        .staged_tree_digest = record.staged_tree_digest,
        .state = "reserved",
        .receipt_digest = {},
        .final_source_identity_digest = {},
        .failure_code = {},
        .occurred_at_ms = record.reserved_at_ms,
        .previous_hash = std::string{previous_hash},
        .record_hash = {},
    };
}

auto encode(
    const change_apply_terminal_record& record,
    std::uint64_t sequence,
    std::string_view previous_hash
) -> wire_record {
    return {
        .schema_version = 1,
        .sequence = sequence,
        .kind = "terminal",
        .grant_id = record.grant_id,
        .authorization_digest = record.authorization_digest,
        .manifest_digest = record.manifest_digest,
        .session_id = {},
        .exposure_id = {},
        .generation = 0,
        .scope_digest = {},
        .source_identity_digest = {},
        .baseline_tree_digest = {},
        .staged_tree_digest = {},
        .state = std::string{terminal_name(record.state)},
        .receipt_digest = record.receipt_digest,
        .final_source_identity_digest = record.final_source_identity_digest,
        .failure_code = record.failure_code,
        .occurred_at_ms = record.completed_at_ms,
        .previous_hash = std::string{previous_hash},
        .record_hash = {},
    };
}

auto decode(const wire_record& record) -> result<decoded_record> {
    if (!valid_identifier(record.grant_id) || !valid_digest(record.authorization_digest) ||
        !valid_digest(record.manifest_digest) || record.occurred_at_ms == 0) {
        return std::unexpected(std::string{"change apply journal record fields are invalid"});
    }
    if (record.kind == "reserve" && record.state == "reserved" && record.receipt_digest.empty() &&
        record.final_source_identity_digest.empty() && record.failure_code.empty() &&
        valid_identifier(record.session_id) && valid_identifier(record.exposure_id) &&
        record.generation != 0 && valid_digest(record.scope_digest) &&
        valid_digest(record.source_identity_digest) && valid_digest(record.baseline_tree_digest) &&
        valid_digest(record.staged_tree_digest)) {
        return decoded_record{
            .reservation =
                change_apply_reservation_record{
                    .grant_id = record.grant_id,
                    .authorization_digest = record.authorization_digest,
                    .manifest_digest = record.manifest_digest,
                    .session_id = record.session_id,
                    .exposure_id = record.exposure_id,
                    .generation = record.generation,
                    .scope_digest = record.scope_digest,
                    .source_identity_digest = record.source_identity_digest,
                    .baseline_tree_digest = record.baseline_tree_digest,
                    .staged_tree_digest = record.staged_tree_digest,
                    .reserved_at_ms = record.occurred_at_ms,
                },
            .terminal = std::nullopt,
        };
    }
    auto state = parse_terminal(record.state);
    const bool valid_failure_code =
        state &&
        ((*state == change_apply_terminal_state::applied && record.failure_code.empty()) ||
         (*state != change_apply_terminal_state::applied && valid_identifier(record.failure_code)));
    if (record.kind != "terminal" || !state || !valid_digest(record.receipt_digest) ||
        !valid_failure_code || !valid_digest(record.final_source_identity_digest) ||
        !record.session_id.empty() || !record.exposure_id.empty() || record.generation != 0 ||
        !record.scope_digest.empty() || !record.source_identity_digest.empty() ||
        !record.baseline_tree_digest.empty() || !record.staged_tree_digest.empty()) {
        return std::unexpected(std::string{"change apply journal record shape is invalid"});
    }
    return decoded_record{
        .reservation = std::nullopt,
        .terminal = change_apply_terminal_record{
            .grant_id = record.grant_id,
            .authorization_digest = record.authorization_digest,
            .manifest_digest = record.manifest_digest,
            .state = *state,
            .receipt_digest = record.receipt_digest,
            .final_source_identity_digest = record.final_source_identity_digest,
            .failure_code = record.failure_code,
            .completed_at_ms = record.occurred_at_ms,
        },
    };
}

auto write_all_at(
    const change_apply_journal_io& io, int descriptor, std::string_view bytes, std::uint64_t offset
) -> result<void> {
    std::size_t written = 0;
    while (written < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - written) {
            return std::unexpected(std::string{"change apply journal offset is too large"});
        }
        const auto result = io.write_at(descriptor, bytes.substr(written), offset + written);
        if (!result) {
            return std::unexpected(result.error());
        }
        if (*result == 0 || *result > bytes.size() - written) {
            return std::unexpected(std::string{"change apply journal write count is invalid"});
        }
        written += *result;
    }
    return {};
}

auto read_all(int descriptor, std::uint64_t size) -> result<std::string> {
    if (size > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(std::string{"change apply journal is too large"});
    }
    std::string bytes(static_cast<std::size_t>(size), '\0');
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto result = ::pread(
            descriptor,
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return std::unexpected(
                result < 0 ? error_message("read change apply journal")
                           : std::string{"change apply journal is truncated"}
            );
        }
        consumed += static_cast<std::size_t>(result);
    }
    return bytes;
}

auto validate_file(int descriptor, std::uint64_t max_bytes) -> result<std::uint64_t> {
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(error_message("inspect change apply journal"));
    }
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & 0777U;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        permissions != 0600U || metadata.st_size < 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_bytes) {
        return std::unexpected(
            std::string{"change apply journal must be a bounded owner-only single-link file"}
        );
    }
    return static_cast<std::uint64_t>(metadata.st_size);
}

auto open_file(
    const std::filesystem::path& path, std::uint64_t max_bytes, const change_apply_journal_io& io
) -> result<opened_journal> {
    if (!path.is_absolute() || path.filename().empty()) {
        return std::unexpected(std::string{"change apply journal path must be absolute"});
    }
    unique_fd parent{
        ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (parent.get() < 0) {
        return std::unexpected(error_message("open change apply journal parent"));
    }
    struct stat parent_metadata{};
    if (::fstat(parent.get(), &parent_metadata) != 0 || !S_ISDIR(parent_metadata.st_mode) ||
        parent_metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(parent_metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"change apply journal parent must be owner-only"});
    }
    const auto filename = path.filename().string();
    int descriptor = ::openat(parent.get(), filename.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    bool created = false;
    if (descriptor < 0 && errno == ENOENT) {
        descriptor = ::openat(
            parent.get(), filename.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        );
        created = descriptor >= 0;
    }
    if (descriptor < 0) {
        return std::unexpected(error_message("open change apply journal"));
    }
    unique_fd file{descriptor};
    while (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno != EINTR) {
            return std::unexpected(error_message("lock change apply journal"));
        }
    }
    auto size = validate_file(file.get(), max_bytes);
    if (!size) {
        return std::unexpected(size.error());
    }
    if (created) {
        const auto discard = [&] {
            (void)::unlinkat(parent.get(), filename.c_str(), 0);
            (void)io.sync(parent.get());
        };
        if (max_bytes < journal_magic.size()) {
            discard();
            return std::unexpected(std::string{"change apply journal capacity is too small"});
        }
        if (auto written = write_all_at(io, file.get(), journal_magic, 0); !written) {
            discard();
            return std::unexpected(written.error());
        }
        if (auto synced = io.sync(file.get()); !synced) {
            discard();
            return std::unexpected(synced.error());
        }
        if (auto synced = io.sync(parent.get()); !synced) {
            discard();
            return std::unexpected(synced.error());
        }
        *size = journal_magic.size();
    }
    return opened_journal{
        .parent = std::move(parent),
        .file = std::move(file),
        .filename = filename,
        .size = *size,
    };
}

} // namespace

struct change_apply_journal::implementation {
    opened_journal opened;
    std::shared_ptr<const change_apply_journal_io> io;
    std::uint64_t max_bytes = 0;
    std::uint64_t sequence = 0;
    std::string head_hash = std::string(64, '0');
    std::map<std::string, change_apply_grant_status, std::less<>> grants;
    std::unordered_set<std::string> authorization_digests;
    std::unordered_set<std::string> manifest_digests;
    mutable std::mutex mutex;
};

namespace {

auto append_record(change_apply_journal::implementation& state, wire_record record)
    -> result<void> {
    if (state.sequence >= max_records) {
        return std::unexpected(std::string{"change apply journal capacity is exhausted"});
    }
    auto digest = record_digest(record);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    record.record_hash = *digest;
    auto json = glz::write_json(record);
    if (!json || json->empty() || json->size() > max_record_bytes) {
        return std::unexpected(std::string{"change apply journal record encoding is invalid"});
    }
    json->push_back('\n');
    if (json->size() > state.max_bytes || state.opened.size > state.max_bytes - json->size()) {
        return std::unexpected(std::string{"change apply journal byte capacity is exhausted"});
    }
    const auto original_size = state.opened.size;
    if (auto written = write_all_at(*state.io, state.opened.file.get(), *json, original_size);
        !written) {
        (void)state.io->truncate(state.opened.file.get(), original_size);
        return std::unexpected(written.error());
    }
    if (auto synced = state.io->sync(state.opened.file.get()); !synced) {
        (void)state.io->truncate(state.opened.file.get(), original_size);
        (void)state.io->sync(state.opened.file.get());
        return std::unexpected(synced.error());
    }
    state.opened.size += json->size();
    state.sequence = record.sequence;
    state.head_hash = std::move(record.record_hash);
    return {};
}

} // namespace

change_apply_journal::change_apply_journal(
    construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {
    (void)token;
}

change_apply_journal::change_apply_journal(change_apply_journal&&) noexcept = default;

auto change_apply_journal::operator=(change_apply_journal&&) noexcept
    -> change_apply_journal& = default;

change_apply_journal::~change_apply_journal() = default;

auto change_apply_journal::open(
    const std::filesystem::path& path,
    std::uint64_t max_bytes,
    std::shared_ptr<const change_apply_journal_io> io
) -> result<change_apply_journal> {
    if (max_bytes < journal_magic.size() + 2U) {
        return std::unexpected(std::string{"change apply journal capacity is invalid"});
    }
    if (!io) {
        io = default_journal_io();
    }
    auto opened = open_file(path, max_bytes, *io);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    auto bytes = read_all(opened->file.get(), opened->size);
    if (!bytes || !bytes->starts_with(journal_magic)) {
        return std::unexpected(std::string{"change apply journal header is invalid"});
    }
    auto state = std::make_unique<implementation>();
    state->opened = std::move(*opened);
    state->io = std::move(io);
    state->max_bytes = max_bytes;
    std::size_t offset = journal_magic.size();
    while (offset < bytes->size()) {
        const auto newline = bytes->find('\n', offset);
        if (newline == std::string::npos || newline == offset ||
            newline - offset > max_record_bytes || state->sequence >= max_records) {
            return std::unexpected(std::string{"change apply journal record framing is invalid"});
        }
        const std::string_view json{bytes->data() + offset, newline - offset};
        wire_record record;
        // Glaze's padded fast path requires mutable, resizable storage. Journal
        // bytes are framed untrusted input, so give the parser an owned buffer.
        std::string parse_buffer{json};
        if (const auto error = glz::read<strict_read_options>(record, parse_buffer);
            error || record.schema_version != 1 || record.sequence != state->sequence + 1U ||
            record.previous_hash != state->head_hash || !valid_digest(record.record_hash)) {
            return std::unexpected(std::string{"change apply journal chain metadata is invalid"});
        }
        auto canonical = glz::write_json(record);
        auto digest = record_digest(record);
        if (!canonical || *canonical != json || !digest || *digest != record.record_hash) {
            return std::unexpected(std::string{"change apply journal record hash mismatch"});
        }
        auto decoded = decode(record);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        if (decoded->reservation) {
            const auto& reservation = *decoded->reservation;
            if (state->grants.contains(reservation.grant_id) ||
                !state->authorization_digests.insert(reservation.authorization_digest).second ||
                !state->manifest_digests.insert(reservation.manifest_digest).second) {
                return std::unexpected(std::string{"change apply journal contains a replay"});
            }
            state->grants.emplace(
                reservation.grant_id,
                change_apply_grant_status{.reservation = reservation, .terminal = std::nullopt}
            );
        } else if (decoded->terminal) {
            const auto& terminal = *decoded->terminal;
            const auto found = state->grants.find(terminal.grant_id);
            if (found == state->grants.end() || found->second.terminal ||
                terminal.authorization_digest != found->second.reservation.authorization_digest ||
                terminal.manifest_digest != found->second.reservation.manifest_digest ||
                terminal.completed_at_ms < found->second.reservation.reserved_at_ms) {
                return std::unexpected(std::string{"change apply journal transition is invalid"});
            }
            found->second.terminal = terminal;
        } else {
            return std::unexpected(std::string{"change apply journal record is empty"});
        }
        state->sequence = record.sequence;
        state->head_hash = std::move(record.record_hash);
        offset = newline + 1U;
    }
    return change_apply_journal{construction_token{}, std::move(state)};
}

auto change_apply_journal::records() const -> std::vector<change_apply_grant_status> {
    const std::scoped_lock lock{state_->mutex};
    std::vector<change_apply_grant_status> records;
    records.reserve(state_->grants.size());
    for (const auto& [grant_id, record] : state_->grants) {
        (void)grant_id;
        records.push_back(record);
    }
    return records;
}

auto change_apply_journal::find(std::string_view grant_id) const
    -> std::optional<change_apply_grant_status> {
    const std::scoped_lock lock{state_->mutex};
    const auto found = state_->grants.find(grant_id);
    return found == state_->grants.end() ? std::nullopt
                                         : std::optional<change_apply_grant_status>{found->second};
}

auto change_apply_journal::reserve(const change_apply_reservation_record& record) -> result<void> {
    const std::scoped_lock lock{state_->mutex};
    if (!valid_identifier(record.grant_id) || !valid_digest(record.authorization_digest) ||
        !valid_digest(record.manifest_digest) || !valid_identifier(record.session_id) ||
        !valid_identifier(record.exposure_id) || record.generation == 0 ||
        !valid_digest(record.scope_digest) || !valid_digest(record.source_identity_digest) ||
        !valid_digest(record.baseline_tree_digest) || !valid_digest(record.staged_tree_digest) ||
        record.reserved_at_ms == 0) {
        return std::unexpected(std::string{"change apply reservation is invalid"});
    }
    if (state_->grants.contains(record.grant_id) ||
        state_->authorization_digests.contains(record.authorization_digest) ||
        state_->manifest_digests.contains(record.manifest_digest)) {
        return std::unexpected(
            std::string{"change apply grant, authorization, or manifest was already consumed"}
        );
    }
    auto encoded = encode(record, state_->sequence + 1U, state_->head_hash);
    if (auto appended = append_record(*state_, std::move(encoded)); !appended) {
        return appended;
    }
    state_->authorization_digests.insert(record.authorization_digest);
    state_->manifest_digests.insert(record.manifest_digest);
    state_->grants.emplace(
        record.grant_id, change_apply_grant_status{.reservation = record, .terminal = std::nullopt}
    );
    return {};
}

auto change_apply_journal::finalize(const change_apply_terminal_record& record) -> result<void> {
    const std::scoped_lock lock{state_->mutex};
    const auto found = state_->grants.find(record.grant_id);
    const bool valid_failure_code =
        (record.state == change_apply_terminal_state::applied && record.failure_code.empty()) ||
        (record.state != change_apply_terminal_state::applied &&
         valid_identifier(record.failure_code));
    if (found == state_->grants.end() || found->second.terminal ||
        record.authorization_digest != found->second.reservation.authorization_digest ||
        record.manifest_digest != found->second.reservation.manifest_digest ||
        terminal_name(record.state).empty() || !valid_digest(record.receipt_digest) ||
        !valid_digest(record.final_source_identity_digest) || !valid_failure_code ||
        record.completed_at_ms < found->second.reservation.reserved_at_ms) {
        return std::unexpected(std::string{"change apply terminal transition is invalid"});
    }
    auto encoded = encode(record, state_->sequence + 1U, state_->head_hash);
    if (auto appended = append_record(*state_, std::move(encoded)); !appended) {
        return appended;
    }
    found->second.terminal = record;
    return {};
}

} // namespace glove::supervisor
