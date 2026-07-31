#include "glove/container/receipt_journal.hpp"

#include "receipt_json.hpp"

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
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

constexpr std::array<unsigned char, 8> journal_magic = {'G', 'L', 'V', 'R', 'J', 'N', 'L', '1'};
constexpr std::size_t digest_hex_bytes = 64;
constexpr std::size_t journal_header_bytes = journal_magic.size() + digest_hex_bytes;
constexpr std::uint32_t max_record_payload_bytes =
    static_cast<std::uint32_t>(max_receipt_journal_record_payload_bytes);
constexpr std::uint64_t min_journal_bytes = 1024U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

auto valid_identifier(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= 128U &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_digest(std::string_view value) noexcept -> bool {
    return value.size() == digest_hex_bytes && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

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

    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

private:
    int descriptor_ = -1;
};

auto system_error(std::string_view operation) -> std::string {
    const auto error_number = errno;
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto append_u32(std::vector<unsigned char>& output, std::uint32_t value) -> void {
    output.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

auto decode_u32(std::span<const unsigned char, 4> input) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) | static_cast<std::uint32_t>(input[3]);
}

auto write_at(int descriptor, std::span<const unsigned char> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t written = 0;
    while (written < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - written) {
            return std::unexpected(std::string{"journal offset exceeds platform range"});
        }
        const auto position = static_cast<off_t>(offset + written);
        const auto result =
            ::pwrite(descriptor, bytes.data() + written, bytes.size() - written, position);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error("journal write"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"journal write made no progress"});
        }
        written += static_cast<std::size_t>(result);
    }
    return {};
}

template<typename Byte, std::size_t Extent>
    requires(sizeof(Byte) == 1)
auto read_at(int descriptor, std::span<Byte, Extent> bytes, std::uint64_t offset)
    -> std::expected<void, std::string> {
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - consumed) {
            return std::unexpected(std::string{"journal offset exceeds platform range"});
        }
        const auto position = static_cast<off_t>(offset + consumed);
        const auto result =
            ::pread(descriptor, bytes.data() + consumed, bytes.size() - consumed, position);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error("journal read"));
        }
        if (result == 0) {
            return std::unexpected(std::string{"journal ended unexpectedly"});
        }
        consumed += static_cast<std::size_t>(result);
    }
    return {};
}

auto sync_descriptor(int descriptor, std::string_view operation)
    -> std::expected<void, std::string> {
    while (::fsync(descriptor) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error(operation));
    }
    return {};
}

auto validate_file(int descriptor) -> std::expected<std::uint64_t, std::string> {
    struct stat metadata{};

    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(system_error("journal fstat"));
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(metadata.st_mode) & permission_mask;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        permissions != owner_permissions || metadata.st_nlink != 1) {
        return std::unexpected(
            std::string{"journal must be an owner-only, single-link regular file"}
        );
    }
    if (metadata.st_size < 0) {
        return std::unexpected(std::string{"journal has a negative size"});
    }
    return static_cast<std::uint64_t>(metadata.st_size);
}

struct opened_path {
    unique_fd parent;
    unique_fd file;
    std::string name;
};

auto remove_created_path(opened_path& opened) -> std::expected<void, std::string> {
    struct stat descriptor_metadata{};

    if (::fstat(opened.file.get(), &descriptor_metadata) != 0) {
        return std::unexpected(system_error("created journal fstat"));
    }

    struct stat path_metadata{};

    if (::fstatat(opened.parent.get(), opened.name.c_str(), &path_metadata, AT_SYMLINK_NOFOLLOW) !=
        0) {
        return std::unexpected(system_error("created journal path fstat"));
    }
    if (descriptor_metadata.st_dev != path_metadata.st_dev ||
        descriptor_metadata.st_ino != path_metadata.st_ino) {
        return std::unexpected(
            std::string{"created journal path identity changed; refusing cleanup"}
        );
    }
    if (::unlinkat(opened.parent.get(), opened.name.c_str(), 0) != 0) {
        return std::unexpected(system_error("created journal unlink"));
    }
    return sync_descriptor(opened.parent.get(), "created journal cleanup directory sync");
}

auto lock_exclusively(int descriptor) -> std::expected<void, std::string> {
    while (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error("journal exclusive lock"));
    }
    return {};
}

auto open_parent(const std::filesystem::path& path) -> std::expected<opened_path, std::string> {
    const auto name = path.filename().string();
    if (name.empty() || name == "." || name == "..") {
        return std::unexpected(std::string{"journal path requires a bounded filename"});
    }
    auto parent_path = path.parent_path();
    if (parent_path.empty()) {
        parent_path = ".";
    }
    const auto flags = static_cast<unsigned int>(O_RDONLY) |
                       static_cast<unsigned int>(O_DIRECTORY) |
                       static_cast<unsigned int>(O_CLOEXEC) | static_cast<unsigned int>(O_NOFOLLOW);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    unique_fd parent{::open(parent_path.c_str(), static_cast<int>(flags))};
    if (parent.get() < 0) {
        return std::unexpected(system_error("journal parent open"));
    }
    return opened_path{.parent = std::move(parent), .file = unique_fd{}, .name = name};
}

auto open_journal_path(const std::filesystem::path& path, bool create)
    -> std::expected<opened_path, std::string> {
    auto opened = open_parent(path);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    auto flags = static_cast<unsigned int>(O_RDWR) | static_cast<unsigned int>(O_CLOEXEC) |
                 static_cast<unsigned int>(O_NOFOLLOW);
    if (create) {
        flags |= static_cast<unsigned int>(O_CREAT) | static_cast<unsigned int>(O_EXCL);
    }
    // NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    opened->file = unique_fd{
        ::openat(opened->parent.get(), opened->name.c_str(), static_cast<int>(flags), 0600)
    };
    // NOLINTEND(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    if (opened->file.get() < 0) {
        return std::unexpected(system_error(create ? "journal create" : "journal open"));
    }
    const auto fail = [&](std::string error) -> std::expected<opened_path, std::string> {
        if (create) {
            auto removed = remove_created_path(*opened);
            if (!removed) {
                error += "; " + removed.error();
            }
        }
        return std::unexpected(std::move(error));
    };
    auto valid = validate_file(opened->file.get());
    if (!valid) {
        return fail(valid.error());
    }
    auto locked = lock_exclusively(opened->file.get());
    if (!locked) {
        return fail(locked.error());
    }
    return opened;
}

auto valid_record(const receipt_journal_record& record) -> bool {
    return (record.kind == "resource_enforcement_v1" && record.resource &&
            !record.refinement) ||
           (record.kind == "refinement_evaluation_v1" && !record.resource &&
            record.refinement);
}

auto encode_record(const receipt_journal_record& record)
    -> std::expected<std::string, std::string> {
    if (!valid_record(record)) {
        return std::unexpected(std::string{"receipt journal record kind is invalid"});
    }
    auto encoded = glz::write_json(record);
    if (!encoded) {
        return std::unexpected(
            std::string{"receipt journal encode: "} +
            glz::format_error(encoded.error(), std::string{})
        );
    }
    if (encoded->empty() || encoded->size() > max_record_payload_bytes) {
        return std::unexpected(std::string{"receipt journal payload exceeds its bound"});
    }
    return *encoded;
}

auto decode_record(std::string_view payload) -> std::expected<receipt_journal_record, std::string> {
    receipt_journal_record record;
    if (const auto error = glz::read<strict_read_options>(record, payload); !error) {
        if (!valid_record(record)) {
            return std::unexpected(std::string{"receipt journal record kind is invalid"});
        }
        return record;
    }
    // Journals created before refinement receipts used a naked resource
    // envelope. Preserve exact recovery while all new writes use tagged records.
    authenticated_resource_enforcement_receipt legacy;
    if (const auto error = glz::read<strict_read_options>(legacy, payload); error) {
        return std::unexpected(
            std::string{"receipt journal decode: "} + glz::format_error(error, payload)
        );
    }
    return receipt_journal_record{
        .kind = "resource_enforcement_v1",
        .resource = std::move(legacy),
        .refinement = std::nullopt,
    };
}

auto make_record(std::string_view payload) -> std::vector<unsigned char> {
    std::vector<unsigned char> record;
    record.reserve(8U + payload.size());
    append_u32(record, static_cast<std::uint32_t>(payload.size()));
    record.insert(record.end(), payload.begin(), payload.end());
    append_u32(record, static_cast<std::uint32_t>(payload.size()));
    return record;
}

auto anchor_is_prefix(
    const receipt_audit_anchor& peer,
    std::string_view key_id,
    const std::vector<receipt_journal_record>& records
) -> bool {
    if (peer.key_id != key_id || peer.sequence > records.size()) {
        return false;
    }
    if (peer.sequence == 0) {
        return peer.head_hmac == std::string(64, '0');
    }
    const auto& record = records[static_cast<std::size_t>(peer.sequence - 1U)];
    return peer.head_hmac ==
           (record.resource ? record.resource->this_hmac : record.refinement->this_hmac);
}

auto validate_header(int descriptor, std::string_view expected_key_id)
    -> std::expected<void, std::string> {
    if (expected_key_id.size() != digest_hex_bytes) {
        return std::unexpected(std::string{"receipt journal expected key identity is invalid"});
    }
    std::array<unsigned char, journal_header_bytes> header{};
    auto header_read = read_at(descriptor, std::span{header}, 0);
    if (!header_read) {
        return std::unexpected(header_read.error());
    }
    if (!std::ranges::equal(journal_magic, std::span{header}.first<journal_magic.size()>())) {
        return std::unexpected(std::string{"receipt journal header magic mismatch"});
    }
    std::array<unsigned char, digest_hex_bytes> expected_key_bytes{};
    std::ranges::transform(expected_key_id, expected_key_bytes.begin(), [](char value) {
        return static_cast<unsigned char>(value);
    });
    if (!std::ranges::equal(
            std::span{header}.subspan<journal_magic.size(), digest_hex_bytes>(), expected_key_bytes
        )) {
        return std::unexpected(std::string{"receipt journal key identity mismatch"});
    }
    return {};
}

struct recovered_journal {
    std::vector<receipt_journal_record> records;
    std::uint64_t durable_size = journal_header_bytes;
    bool torn_tail = false;
};

auto recover_records(
    int descriptor, std::uint64_t file_size, std::string_view key_hex, receipt_audit_anchor& anchor
) -> std::expected<recovered_journal, std::string> {
    recovered_journal recovered;
    while (recovered.durable_size < file_size) {
        if (file_size - recovered.durable_size < 4U) {
            recovered.torn_tail = true;
            break;
        }
        std::array<unsigned char, 4> prefix{};
        auto prefix_read = read_at(descriptor, std::span{prefix}, recovered.durable_size);
        if (!prefix_read) {
            return std::unexpected(prefix_read.error());
        }
        const auto payload_size = decode_u32(prefix);
        if (payload_size == 0 || payload_size > max_record_payload_bytes) {
            return std::unexpected(std::string{"receipt journal record length is invalid"});
        }
        const auto record_bytes = static_cast<std::uint64_t>(payload_size) + 8U;
        if (record_bytes > file_size - recovered.durable_size) {
            recovered.torn_tail = true;
            break;
        }
        std::string payload(payload_size, '\0');
        auto payload_read = read_at(
            descriptor, std::span<char>{payload.data(), payload.size()}, recovered.durable_size + 4U
        );
        if (!payload_read) {
            return std::unexpected(payload_read.error());
        }
        std::array<unsigned char, 4> suffix{};
        auto suffix_read =
            read_at(descriptor, std::span{suffix}, recovered.durable_size + 4U + payload_size);
        if (!suffix_read) {
            return std::unexpected(suffix_read.error());
        }
        if (decode_u32(suffix) != payload_size) {
            return std::unexpected(std::string{"receipt journal record footer mismatch"});
        }
        auto record = decode_record(payload);
        if (!record) {
            return std::unexpected(record.error());
        }
        auto verified = record->resource
                            ? verify_receipt_audit_envelope(
                                  *record->resource,
                                  key_hex,
                                  record->resource->session_id,
                                  record->resource->controller_plan_digest,
                                  anchor
                              )
                            : verify_refinement_receipt_audit_envelope(
                                  *record->refinement,
                                  key_hex,
                                  record->refinement->session_id,
                                  record->refinement->controller_plan_digest,
                                  anchor
                              );
        if (!verified) {
            return std::unexpected(
                std::string{"receipt journal chain verification: "} + verified.error()
            );
        }
        recovered.records.push_back(std::move(*record));
        recovered.durable_size += record_bytes;
    }
    return recovered;
}

} // namespace

struct receipt_audit_journal::implementation {
    mutable std::mutex mutex;
    unique_fd descriptor;
    std::unique_ptr<receipt_audit_chain> chain;
    std::vector<receipt_journal_record> records;
    std::uint64_t durable_size = 0;
    std::uint64_t max_size = 0;
    bool repaired_tail = false;
    bool poisoned = false;
};

receipt_audit_journal::receipt_audit_journal(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

receipt_audit_journal::~receipt_audit_journal() = default;

auto receipt_audit_journal::create_new(
    const std::filesystem::path& path, std::string_view key_hex, std::uint64_t max_bytes
) -> std::expected<std::unique_ptr<receipt_audit_journal>, std::string> {
    if (max_bytes < min_journal_bytes || max_bytes > default_receipt_journal_bytes) {
        return std::unexpected(std::string{"receipt journal size bound is invalid"});
    }
    auto chain = receipt_audit_chain::create(key_hex);
    if (!chain) {
        return std::unexpected(chain.error());
    }
    auto state = std::make_unique<implementation>();
    auto journal = std::make_unique<receipt_audit_journal>(construction_token{}, std::move(state));
    auto opened = open_journal_path(path, true);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    const auto fail = [&](
                          std::string error
                      ) -> std::expected<std::unique_ptr<receipt_audit_journal>, std::string> {
        auto removed = remove_created_path(*opened);
        if (!removed) {
            error += "; " + removed.error();
        }
        return std::unexpected(std::move(error));
    };
    std::array<unsigned char, journal_header_bytes> header{};
    std::ranges::copy(journal_magic, header.begin());
    std::ranges::transform(
        (*chain)->key_id(),
        header.begin() + static_cast<std::ptrdiff_t>(journal_magic.size()),
        [](char value) { return static_cast<unsigned char>(value); }
    );
    auto written = write_at(opened->file.get(), header, 0);
    if (!written) {
        return fail(written.error());
    }
    auto synced = sync_descriptor(opened->file.get(), "journal header sync");
    if (!synced) {
        return fail(synced.error());
    }
    auto directory_synced = sync_descriptor(opened->parent.get(), "journal directory sync");
    if (!directory_synced) {
        return fail(directory_synced.error());
    }
    journal->state_->descriptor = std::move(opened->file);
    journal->state_->chain = std::move(*chain);
    journal->state_->durable_size = journal_header_bytes;
    journal->state_->max_size = max_bytes;
    return journal;
}

auto receipt_audit_journal::open_existing(
    const std::filesystem::path& path,
    std::string_view key_hex,
    std::optional<receipt_audit_anchor> trusted_peer_anchor,
    std::uint64_t max_bytes
) -> std::expected<std::unique_ptr<receipt_audit_journal>, std::string> {
    if (max_bytes < min_journal_bytes || max_bytes > default_receipt_journal_bytes) {
        return std::unexpected(std::string{"receipt journal size bound is invalid"});
    }
    auto chain = receipt_audit_chain::create(key_hex);
    if (!chain) {
        return std::unexpected(chain.error());
    }
    auto anchor = receipt_audit_anchor::create(key_hex);
    if (!anchor) {
        return std::unexpected(anchor.error());
    }
    auto opened = open_journal_path(path, false);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    auto file_size = validate_file(opened->file.get());
    if (!file_size) {
        return std::unexpected(file_size.error());
    }
    if (*file_size < journal_header_bytes || *file_size > max_bytes) {
        return std::unexpected(std::string{"receipt journal file size is invalid"});
    }
    auto valid_header = validate_header(opened->file.get(), (*chain)->key_id());
    if (!valid_header) {
        return std::unexpected(valid_header.error());
    }
    auto recovered = recover_records(opened->file.get(), *file_size, key_hex, **anchor);
    if (!recovered) {
        return std::unexpected(recovered.error());
    }

    if (trusted_peer_anchor &&
        !anchor_is_prefix(*trusted_peer_anchor, (*chain)->key_id(), recovered->records)) {
        return std::unexpected(std::string{"trusted peer anchor is not a journal prefix"});
    }
    if (recovered->torn_tail) {
        if (!trusted_peer_anchor) {
            return std::unexpected(
                std::string{"receipt journal has a torn tail and requires a trusted peer anchor"}
            );
        }
        if (recovered->durable_size >
                static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
            ::ftruncate(opened->file.get(), static_cast<off_t>(recovered->durable_size)) != 0) {
            return std::unexpected(system_error("receipt journal torn-tail truncate"));
        }
        auto synced = sync_descriptor(opened->file.get(), "receipt journal repair sync");
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }

    (*chain)->sequence_ = (**anchor).sequence;
    (*chain)->head_hmac_ = (**anchor).head_hmac;
    auto state = std::make_unique<implementation>();
    state->descriptor = std::move(opened->file);
    state->chain = std::move(*chain);
    state->records = std::move(recovered->records);
    state->durable_size = recovered->durable_size;
    state->max_size = max_bytes;
    state->repaired_tail = recovered->torn_tail;
    return std::make_unique<receipt_audit_journal>(construction_token{}, std::move(state));
}

auto receipt_audit_journal::append(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const resource_enforcement_receipt& receipt
) -> std::expected<authenticated_resource_enforcement_receipt, std::string> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    const auto previous_sequence = state_->chain->sequence_;
    auto previous_hmac = state_->chain->head_hmac_;
    auto envelope = state_->chain->append(session_id, controller_plan_digest, receipt);
    if (!envelope) {
        return std::unexpected(envelope.error());
    }
    state_->chain->sequence_ = previous_sequence;
    state_->chain->head_hmac_.swap(previous_hmac);
    receipt_journal_record journal_record{
        .kind = "resource_enforcement_v1",
        .resource = *envelope,
        .refinement = std::nullopt,
    };
    auto payload = encode_record(journal_record);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    const auto record = make_record(*payload);
    if (record.size() > state_->max_size - state_->durable_size) {
        return std::unexpected(std::string{"receipt journal capacity exhausted"});
    }
    auto next_head = envelope->this_hmac;
    state_->records.push_back(std::move(journal_record));

    const auto rollback = [&]() -> std::expected<void, std::string> {
        if (state_->durable_size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
            ::ftruncate(state_->descriptor.get(), static_cast<off_t>(state_->durable_size)) != 0) {
            state_->poisoned = true;
            return std::unexpected(system_error("receipt journal rollback truncate"));
        }
        auto synced = sync_descriptor(state_->descriptor.get(), "receipt journal rollback sync");
        if (!synced) {
            state_->poisoned = true;
            return std::unexpected(synced.error());
        }
        return {};
    };

    auto written = write_at(state_->descriptor.get(), record, state_->durable_size);
    if (!written) {
        state_->records.pop_back();
        auto restored = rollback();
        return std::unexpected(
            restored ? written.error() : written.error() + "; " + restored.error()
        );
    }
    auto synced = sync_descriptor(state_->descriptor.get(), "receipt journal record sync");
    if (!synced) {
        state_->records.pop_back();
        auto restored = rollback();
        return std::unexpected(
            restored ? synced.error() : synced.error() + "; " + restored.error()
        );
    }
    state_->chain->sequence_ = envelope->sequence;
    state_->chain->head_hmac_.swap(next_head);
    state_->durable_size += record.size();
    return envelope;
}

auto receipt_audit_journal::append_refinement(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const refinement_evaluation_receipt& receipt
) -> std::expected<authenticated_refinement_evaluation_receipt, std::string> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    const auto previous_sequence = state_->chain->sequence_;
    auto previous_hmac = state_->chain->head_hmac_;
    auto envelope =
        state_->chain->append_refinement(session_id, controller_plan_digest, receipt);
    if (!envelope) {
        return std::unexpected(envelope.error());
    }
    state_->chain->sequence_ = previous_sequence;
    state_->chain->head_hmac_.swap(previous_hmac);
    receipt_journal_record journal_record{
        .kind = "refinement_evaluation_v1",
        .resource = std::nullopt,
        .refinement = *envelope,
    };
    auto payload = encode_record(journal_record);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    const auto record = make_record(*payload);
    if (record.size() > state_->max_size - state_->durable_size) {
        return std::unexpected(std::string{"receipt journal capacity exhausted"});
    }
    auto next_head = envelope->this_hmac;
    state_->records.push_back(std::move(journal_record));
    const auto rollback = [&]() -> std::expected<void, std::string> {
        if (state_->durable_size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
            ::ftruncate(state_->descriptor.get(), static_cast<off_t>(state_->durable_size)) != 0) {
            state_->poisoned = true;
            return std::unexpected(system_error("receipt journal rollback truncate"));
        }
        auto synced = sync_descriptor(state_->descriptor.get(), "receipt journal rollback sync");
        if (!synced) {
            state_->poisoned = true;
            return std::unexpected(synced.error());
        }
        return {};
    };
    auto written = write_at(state_->descriptor.get(), record, state_->durable_size);
    if (!written) {
        state_->records.pop_back();
        auto restored = rollback();
        return std::unexpected(
            restored ? written.error() : written.error() + "; " + restored.error()
        );
    }
    auto synced = sync_descriptor(state_->descriptor.get(), "receipt journal record sync");
    if (!synced) {
        state_->records.pop_back();
        auto restored = rollback();
        return std::unexpected(
            restored ? synced.error() : synced.error() + "; " + restored.error()
        );
    }
    state_->chain->sequence_ = envelope->sequence;
    state_->chain->head_hmac_.swap(next_head);
    state_->durable_size += record.size();
    return envelope;
}

auto receipt_audit_journal::page_after(
    const receipt_audit_anchor& trusted_peer_anchor, std::size_t limit
) const -> std::expected<receipt_journal_page, std::string> {
    if (limit == 0 || limit > max_receipt_reconciliation_page) {
        return std::unexpected(std::string{"receipt reconciliation page limit is invalid"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    if (!anchor_is_prefix(trusted_peer_anchor, state_->chain->key_id(), state_->records)) {
        return std::unexpected(std::string{"trusted peer anchor is not a journal prefix"});
    }
    const auto begin = static_cast<std::size_t>(trusted_peer_anchor.sequence);
    const auto remaining = state_->records.size() - begin;
    const auto count = std::min(limit, remaining);
    receipt_journal_page page{
        .envelopes = {},
        .refinement_envelopes = {},
        .has_more = count < remaining,
        .local_anchor = {
            .key_id = std::string{state_->chain->key_id()},
            .sequence = state_->chain->sequence(),
            .head_hmac = std::string{state_->chain->head_hmac()},
        },
    };
    page.envelopes.reserve(count);
    page.refinement_envelopes.reserve(count);
    for (std::size_t index = begin; index < begin + count; ++index) {
        if (state_->records[index].resource) {
            page.envelopes.push_back(*state_->records[index].resource);
        } else {
            page.refinement_envelopes.push_back(*state_->records[index].refinement);
        }
    }
    return page;
}

auto receipt_audit_journal::contains_exact(
    const authenticated_resource_enforcement_receipt& envelope
) const -> std::expected<bool, std::string> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    if (envelope.sequence == 0 || envelope.sequence > state_->records.size()) {
        return false;
    }
    const auto index = static_cast<std::size_t>(envelope.sequence - 1U);
    return state_->records[index].resource &&
           *state_->records[index].resource == envelope;
}

auto receipt_audit_journal::contains_exact(
    const authenticated_refinement_evaluation_receipt& envelope
) const -> std::expected<bool, std::string> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    if (envelope.sequence == 0 || envelope.sequence > state_->records.size()) {
        return false;
    }
    const auto index = static_cast<std::size_t>(envelope.sequence - 1U);
    return state_->records[index].refinement &&
           *state_->records[index].refinement == envelope;
}

auto receipt_audit_journal::terminal_for_execution(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) const -> std::expected<std::optional<authenticated_resource_enforcement_receipt>, std::string> {
    if (!valid_identifier(session_id) || !valid_digest(controller_plan_digest) ||
        !valid_digest(profile_digest)) {
        return std::unexpected(std::string{"receipt execution lookup binding is invalid"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    std::optional<authenticated_resource_enforcement_receipt> match;
    for (const auto& record : state_->records) {
        if (!record.resource) {
            continue;
        }
        const auto& envelope = *record.resource;
        if (envelope.session_id != session_id ||
            envelope.controller_plan_digest != controller_plan_digest ||
            envelope.receipt.profile_digest != profile_digest) {
            continue;
        }
        if (match) {
            return std::unexpected(
                std::string{"multiple terminal receipts exist for one execution"}
            );
        }
        match = envelope;
    }
    return match;
}

auto receipt_audit_journal::refinement_terminal_for_execution(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) const
    -> std::expected<std::optional<authenticated_refinement_evaluation_receipt>, std::string> {
    if (!valid_identifier(session_id) || !valid_digest(controller_plan_digest) ||
        !valid_digest(profile_digest)) {
        return std::unexpected(std::string{"receipt execution lookup binding is invalid"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    std::optional<authenticated_refinement_evaluation_receipt> match;
    for (const auto& record : state_->records) {
        if (!record.refinement) {
            continue;
        }
        const auto& envelope = *record.refinement;
        if (envelope.session_id != session_id ||
            envelope.controller_plan_digest != controller_plan_digest ||
            envelope.receipt.resource_receipt.profile_digest != profile_digest) {
            continue;
        }
        if (match) {
            return std::unexpected(
                std::string{"multiple refinement receipts exist for one execution"}
            );
        }
        match = envelope;
    }
    return match;
}

auto receipt_audit_journal::anchor() const -> receipt_audit_anchor {
    const std::scoped_lock lock{state_->mutex};
    return {
        .key_id = std::string{state_->chain->key_id()},
        .sequence = state_->chain->sequence(),
        .head_hmac = std::string{state_->chain->head_hmac()},
    };
}

auto receipt_audit_journal::record_count() const -> std::uint64_t {
    const std::scoped_lock lock{state_->mutex};
    return state_->records.size();
}

auto receipt_audit_journal::durable_bytes() const -> std::uint64_t {
    const std::scoped_lock lock{state_->mutex};
    return state_->durable_size;
}

auto receipt_audit_journal::remaining_capacity() const
    -> std::expected<std::uint64_t, std::string> {
    const std::scoped_lock lock{state_->mutex};
    if (state_->poisoned) {
        return std::unexpected(std::string{"receipt journal is poisoned"});
    }
    auto observed_size = validate_file(state_->descriptor.get());
    if (!observed_size || *observed_size != state_->durable_size) {
        state_->poisoned = true;
        return std::unexpected(
            observed_size ? std::string{"receipt journal size changed unexpectedly"}
                          : observed_size.error()
        );
    }
    return state_->max_size - state_->durable_size;
}

auto receipt_audit_journal::repaired_torn_tail() const -> bool {
    const std::scoped_lock lock{state_->mutex};
    return state_->repaired_tail;
}

} // namespace glove::container
