#include "glove/container/receipt_producer.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::container {

namespace {

constexpr std::uint64_t max_key_file_bytes = 128U;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

void wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

auto ascii_whitespace(char value) noexcept -> bool {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' ||
           value == '\v';
}

class sensitive_key_file {
public:
    sensitive_key_file(std::string bytes, std::size_t begin, std::size_t length)
        : bytes_{std::move(bytes)}, begin_{begin}, length_{length} {}

    sensitive_key_file(const sensitive_key_file&) = delete;
    auto operator=(const sensitive_key_file&) -> sensitive_key_file& = delete;

    sensitive_key_file(sensitive_key_file&& other) noexcept
        : bytes_{std::move(other.bytes_)},
          begin_{std::exchange(other.begin_, 0)},
          length_{std::exchange(other.length_, 0)} {
        wipe(other.bytes_);
    }

    auto operator=(sensitive_key_file&&) -> sensitive_key_file& = delete;

    ~sensitive_key_file() { wipe(bytes_); }

    [[nodiscard]] auto key_hex() const noexcept -> std::string_view {
        return {bytes_.data() + begin_, length_};
    }

private:
    std::string bytes_;
    std::size_t begin_ = 0;
    std::size_t length_ = 0;
};

auto modification_time_matches(const struct stat& before, const struct stat& after) noexcept
    -> bool {
#if defined(__APPLE__)
    return before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
#else
    return before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
#endif
}

auto change_time_matches(const struct stat& before, const struct stat& after) noexcept -> bool {
#if defined(__APPLE__)
    return before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
    return before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}

auto same_key_file(const struct stat& before, const struct stat& after) noexcept -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
           modification_time_matches(before, after) && change_time_matches(before, after);
}

auto load_key(const std::filesystem::path& path) -> std::expected<sensitive_key_file, std::string> {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(
            std::string{"open receipt audit key: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }

    struct stat before{};

    if (::fstat(descriptor.get(), &before) != 0) {
        return std::unexpected(
            std::string{"inspect receipt audit key: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    constexpr auto permission_mask = 0777U;
    constexpr auto owner_permissions = 0600U;
    const auto permissions = static_cast<unsigned int>(before.st_mode) & permission_mask;
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid() ||
        permissions != owner_permissions || before.st_nlink != 1 || before.st_size < 64 ||
        static_cast<std::uint64_t>(before.st_size) > max_key_file_bytes) {
        return std::unexpected(
            std::string{"receipt audit key must be an owner-only, single-link regular file"}
        );
    }
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < bytes.size()) {
        const auto result = ::pread(
            descriptor.get(),
            bytes.data() + consumed,
            bytes.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            wipe(bytes);
            return std::unexpected(
                std::string{"read receipt audit key: "} +
                std::error_code{errno, std::generic_category()}.message()
            );
        }
        if (result == 0) {
            wipe(bytes);
            return std::unexpected(std::string{"receipt audit key ended unexpectedly"});
        }
        consumed += static_cast<std::size_t>(result);
    }

    struct stat after{};

    if (::fstat(descriptor.get(), &after) != 0 || !same_key_file(before, after)) {
        wipe(bytes);
        return std::unexpected(std::string{"receipt audit key changed while loading"});
    }
    std::size_t begin = 0;
    while (begin < bytes.size() && ascii_whitespace(bytes[begin])) {
        ++begin;
    }
    std::size_t end = bytes.size();
    while (end > begin && ascii_whitespace(bytes[end - 1U])) {
        --end;
    }
    if (end - begin != 64U || !std::all_of(
                                  bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                                  bytes.begin() + static_cast<std::ptrdiff_t>(end),
                                  [](char value) {
                                      return (value >= '0' && value <= '9') ||
                                             (value >= 'a' && value <= 'f');
                                  }
                              )) {
        wipe(bytes);
        return std::unexpected(std::string{"receipt audit key must be 32-byte lowercase hex"});
    }
    return sensitive_key_file{std::move(bytes), begin, end - begin};
}

auto validate_config(const receipt_audit_producer_config& config)
    -> std::expected<void, std::string> {
    if (config.key_path.empty() || config.journal_path.empty() ||
        config.key_path.lexically_normal() == config.journal_path.lexically_normal()) {
        return std::unexpected(std::string{"receipt audit producer paths are invalid"});
    }
    return {};
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U &&
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

} // namespace

receipt_audit_producer::terminal_reservation::terminal_reservation(
    [[maybe_unused]] construction_token token,
    std::shared_ptr<receipt_audit_producer> owner,
    std::string session_id,
    std::string controller_plan_digest,
    std::string profile_digest
)
    : owner_{std::move(owner)},
      session_id_{std::move(session_id)},
      controller_plan_digest_{std::move(controller_plan_digest)},
      profile_digest_{std::move(profile_digest)} {}

receipt_audit_producer::terminal_reservation::terminal_reservation(
    terminal_reservation&& other
) noexcept
    : owner_{std::move(other.owner_)},
      session_id_{std::move(other.session_id_)},
      controller_plan_digest_{std::move(other.controller_plan_digest_)},
      profile_digest_{std::move(other.profile_digest_)} {}

receipt_audit_producer::terminal_reservation::~terminal_reservation() {
    release();
}

void receipt_audit_producer::terminal_reservation::release() noexcept {
    if (owner_) {
        owner_->release_reservation();
        owner_.reset();
    }
}

auto receipt_audit_producer::terminal_reservation::matches_execution(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) const noexcept -> bool {
    return owner_ && !session_id_.empty() && session_id_ == session_id &&
           controller_plan_digest_ == controller_plan_digest && profile_digest_ == profile_digest;
}

receipt_audit_producer::receipt_audit_producer([[maybe_unused]] construction_token token) {}

receipt_audit_producer::~receipt_audit_producer() = default;

auto receipt_audit_producer::initialize(const receipt_audit_producer_config& config)
    -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string> {
    if (auto valid = validate_config(config); !valid) {
        return std::unexpected(valid.error());
    }
    auto producer = std::make_shared<receipt_audit_producer>(construction_token{});
    auto key = load_key(config.key_path);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto journal = receipt_audit_journal::create_new(
        config.journal_path, key->key_hex(), config.max_journal_bytes
    );
    if (!journal) {
        return std::unexpected(journal.error());
    }
    producer->journal_ = std::move(*journal);
    return producer;
}

auto receipt_audit_producer::bootstrap(
    const receipt_audit_producer_config& config, const receipt_audit_anchor& trusted_sage_anchor
) -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string> {
    if (auto valid = validate_config(config); !valid) {
        return std::unexpected(valid.error());
    }

    struct stat metadata{};

    if (::lstat(config.journal_path.c_str(), &metadata) == 0) {
        return recover(config, trusted_sage_anchor);
    }
    if (errno != ENOENT) {
        return std::unexpected(
            std::string{"inspect receipt audit journal: "} +
            std::error_code{errno, std::generic_category()}.message()
        );
    }
    auto producer = initialize(config);
    if (!producer) {
        return producer;
    }
    if ((*producer)->anchor() != trusted_sage_anchor) {
        return std::unexpected(
            std::string{"Sage bootstrap anchor does not match the new journal genesis"}
        );
    }
    return producer;
}

auto receipt_audit_producer::recover(
    const receipt_audit_producer_config& config, const receipt_audit_anchor& trusted_sage_anchor
) -> std::expected<std::shared_ptr<receipt_audit_producer>, std::string> {
    if (auto valid = validate_config(config); !valid) {
        return std::unexpected(valid.error());
    }
    auto producer = std::make_shared<receipt_audit_producer>(construction_token{});
    auto key = load_key(config.key_path);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto journal = receipt_audit_journal::open_existing(
        config.journal_path, key->key_hex(), trusted_sage_anchor, config.max_journal_bytes
    );
    if (!journal) {
        return std::unexpected(journal.error());
    }
    producer->journal_ = std::move(*journal);
    producer->bootstrap_reconciled_ = producer->journal_->anchor() == trusted_sage_anchor;
    return producer;
}

auto receipt_audit_producer::audit_key_id(const receipt_audit_producer_config& config)
    -> std::expected<std::string, std::string> {
    if (auto valid = validate_config(config); !valid) {
        return std::unexpected(valid.error());
    }
    auto key = load_key(config.key_path);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto anchor = receipt_audit_anchor::create(key->key_hex());
    if (!anchor) {
        return std::unexpected(anchor.error());
    }
    return std::move((*anchor)->key_id);
}

auto receipt_audit_producer::acknowledge_bootstrap(const receipt_audit_anchor& sage_anchor)
    -> std::expected<void, std::string> {
    const std::scoped_lock lock{mutex_};
    if (sage_anchor != journal_->anchor()) {
        return std::unexpected(std::string{"Sage bootstrap anchor does not match the local head"});
    }
    bootstrap_reconciled_ = true;
    return {};
}

auto receipt_audit_producer::bootstrap_reconciled() const -> bool {
    const std::scoped_lock lock{mutex_};
    return bootstrap_reconciled_;
}

auto receipt_audit_producer::reserve_terminal()
    -> std::expected<terminal_reservation, std::string> {
    const std::scoped_lock lock{mutex_};
    if (!bootstrap_reconciled_) {
        return std::unexpected(std::string{"receipt audit bootstrap reconciliation is required"});
    }
    auto remaining = journal_->remaining_capacity();
    if (!remaining) {
        return std::unexpected(remaining.error());
    }
    if (reserved_bytes_ > *remaining ||
        max_receipt_journal_record_bytes > *remaining - reserved_bytes_) {
        return std::unexpected(std::string{"receipt audit journal capacity is unavailable"});
    }
    reserved_bytes_ += max_receipt_journal_record_bytes;
    return terminal_reservation{construction_token{}, shared_from_this()};
}

auto receipt_audit_producer::reserve_terminal(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) -> std::expected<terminal_reservation, std::string> {
    if (!valid_identifier(session_id) || !valid_digest(controller_plan_digest) ||
        !valid_digest(profile_digest)) {
        return std::unexpected(std::string{"receipt terminal reservation binding is invalid"});
    }
    const std::scoped_lock lock{mutex_};
    if (!bootstrap_reconciled_) {
        return std::unexpected(std::string{"receipt audit bootstrap reconciliation is required"});
    }
    auto remaining = journal_->remaining_capacity();
    if (!remaining) {
        return std::unexpected(remaining.error());
    }
    if (reserved_bytes_ > *remaining ||
        max_receipt_journal_record_bytes > *remaining - reserved_bytes_) {
        return std::unexpected(std::string{"receipt audit journal capacity is unavailable"});
    }
    reserved_bytes_ += max_receipt_journal_record_bytes;
    return terminal_reservation{
        construction_token{},
        shared_from_this(),
        std::string{session_id},
        std::string{controller_plan_digest},
        std::string{profile_digest},
    };
}

auto receipt_audit_producer::commit_terminal(
    terminal_reservation reservation,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const resource_enforcement_receipt& receipt
) -> std::expected<authenticated_resource_enforcement_receipt, std::string> {
    if (reservation.owner_.get() != this) {
        return std::unexpected(std::string{"terminal reservation belongs to another producer"});
    }
    if (!reservation.session_id_.empty() &&
        !reservation.matches_execution(
            session_id, controller_plan_digest, receipt.profile_digest
        )) {
        return std::unexpected(
            std::string{"terminal reservation does not match the executed session"}
        );
    }
    auto appended = journal_->append(session_id, controller_plan_digest, receipt);
    reservation.release();
    return appended;
}

auto receipt_audit_producer::commit_refinement_terminal(
    terminal_reservation reservation,
    std::string_view session_id,
    std::string_view controller_plan_digest,
    const refinement_evaluation_receipt& receipt
) -> std::expected<authenticated_refinement_evaluation_receipt, std::string> {
    if (reservation.owner_.get() != this) {
        return std::unexpected(std::string{"terminal reservation belongs to another producer"});
    }
    if (!reservation.session_id_.empty() &&
        !reservation.matches_execution(
            session_id, controller_plan_digest, receipt.resource_receipt.profile_digest
        )) {
        return std::unexpected(
            std::string{"terminal reservation does not match the refinement execution"}
        );
    }
    auto appended =
        journal_->append_refinement(session_id, controller_plan_digest, receipt);
    reservation.release();
    return appended;
}

auto receipt_audit_producer::confirms_terminal(
    const authenticated_resource_enforcement_receipt& envelope
) const -> std::expected<bool, std::string> {
    return journal_->contains_exact(envelope);
}

auto receipt_audit_producer::confirms_terminal(
    const authenticated_refinement_evaluation_receipt& envelope
) const -> std::expected<bool, std::string> {
    return journal_->contains_exact(envelope);
}

auto receipt_audit_producer::terminal_for_execution(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) const -> std::expected<std::optional<authenticated_resource_enforcement_receipt>, std::string> {
    return journal_->terminal_for_execution(session_id, controller_plan_digest, profile_digest);
}

auto receipt_audit_producer::refinement_terminal_for_execution(
    std::string_view session_id,
    std::string_view controller_plan_digest,
    std::string_view profile_digest
) const
    -> std::expected<std::optional<authenticated_refinement_evaluation_receipt>, std::string> {
    return journal_->refinement_terminal_for_execution(
        session_id, controller_plan_digest, profile_digest
    );
}

auto receipt_audit_producer::page_after(
    const receipt_audit_anchor& trusted_sage_anchor, std::size_t limit
) const -> std::expected<receipt_journal_page, std::string> {
    return journal_->page_after(trusted_sage_anchor, limit);
}

auto receipt_audit_producer::anchor() const -> receipt_audit_anchor {
    return journal_->anchor();
}

void receipt_audit_producer::release_reservation() noexcept {
    const std::scoped_lock lock{mutex_};
    if (reserved_bytes_ < max_receipt_journal_record_bytes) {
        std::terminate();
    }
    reserved_bytes_ -= max_receipt_journal_record_bytes;
}

} // namespace glove::container
