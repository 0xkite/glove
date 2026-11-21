#include "audit_journal.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::run::detail {

namespace {

constexpr std::size_t overflow_id_hex = 16;
constexpr int overflow_name_attempts = 4;

class descriptor {
public:
    explicit descriptor(int value) noexcept : value_{value} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;
    descriptor(descriptor&&) = delete;
    auto operator=(descriptor&&) -> descriptor& = delete;

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

private:
    int value_;
};

auto random_id() -> std::expected<std::string, std::string> {
    std::array<unsigned char, overflow_id_hex / 2> raw{};
    if (::getentropy(raw.data(), raw.size()) != 0) {
        return std::unexpected(std::string{"cannot draw a name for this launch's audit journal"});
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const unsigned char byte : raw) {
        out.push_back(digits.at(byte >> 4U));
        out.push_back(digits.at(byte & 0x0FU));
    }
    return out;
}

struct finished_journal {
    std::string name;
    struct timespec modified{};
};

auto older(const finished_journal& left, const finished_journal& right) -> bool {
    return left.modified.tv_sec != right.modified.tv_sec
               ? left.modified.tv_sec < right.modified.tv_sec
               : left.modified.tv_nsec < right.modified.tv_nsec;
}

// Removes the oldest overflow journals no live launch holds, keeping at most
// max_overflow_audit_journals - 1 so the one about to be created fits. A
// journal is removed only through its own descriptor's identity: it must be
// this user's single-link regular file, and its lock must be free. Failures
// are ignored; retention is housekeeping and never stops a launch.
void remove_old_overflow_journals(
    const std::filesystem::path& directory, std::string_view stem, std::string_view extension
) noexcept {
    try {
        const descriptor parent{
            ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        };
        if (parent.get() < 0) {
            return;
        }
        std::vector<finished_journal> found;
        std::error_code ec;
        std::size_t seen = 0;
        for (std::filesystem::directory_iterator entry{directory, ec}, end; !ec && entry != end;
             entry.increment(ec)) {
            if (++seen > max_audit_directory_entries) {
                return;
            }
            const auto name = entry->path().filename().string();
            if (!is_overflow_audit_journal_name(name, stem, extension)) {
                continue;
            }
            struct stat metadata{};
            if (::fstatat(parent.get(), name.c_str(), &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(metadata.st_mode)) {
                continue;
            }
#if defined(__APPLE__)
            found.push_back({.name = name, .modified = metadata.st_mtimespec});
#else
            found.push_back({.name = name, .modified = metadata.st_mtim});
#endif
        }
        if (found.size() < max_overflow_audit_journals) {
            return;
        }
        std::ranges::sort(found, older);
        std::size_t excess = found.size() - (max_overflow_audit_journals - 1);
        for (const auto& journal : found) {
            if (excess == 0) {
                break;
            }
            const descriptor file{::openat(
                parent.get(), journal.name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            )};
            struct stat opened{};
            if (file.get() < 0 || ::fstat(file.get(), &opened) != 0 || !S_ISREG(opened.st_mode) ||
                opened.st_uid != ::geteuid() || opened.st_nlink != 1) {
                continue;
            }
            // A held lock means a live launch is still writing it.
            if (::flock(file.get(), LOCK_EX | LOCK_NB) != 0) {
                continue;
            }
            if (::unlinkat(parent.get(), journal.name.c_str(), 0) == 0) {
                --excess;
            }
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): housekeeping never stops a launch
    }
}

} // namespace

auto is_overflow_audit_journal_name(
    std::string_view name, std::string_view shared_stem, std::string_view shared_extension
) -> bool {
    if (name.size() != shared_stem.size() + 1 + overflow_id_hex + shared_extension.size() ||
        !name.starts_with(shared_stem) || !name.ends_with(shared_extension) ||
        name.at(shared_stem.size()) != '.') {
        return false;
    }
    const auto id = name.substr(shared_stem.size() + 1, overflow_id_hex);
    return std::ranges::all_of(id, [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

auto open_default_audit_journal(
    const std::filesystem::path& shared, glove::audit::jsonl_sink_limits limits
) -> std::expected<default_audit_journal, std::string> {
    auto first = glove::audit::make_jsonl_sink(shared, limits);
    if (first) {
        return default_audit_journal{.sink = std::move(*first), .path = shared, .overflow = false};
    }
    if (first.error() != glove::audit::jsonl_sink_busy) {
        return std::unexpected(first.error());
    }
    const auto directory = shared.parent_path();
    const auto stem = shared.stem().string();
    const auto extension = shared.extension().string();
    remove_old_overflow_journals(directory, stem, extension);
    std::string last_error{glove::audit::jsonl_sink_busy};
    for (int attempt = 0; attempt != overflow_name_attempts; ++attempt) {
        const auto id = random_id();
        if (!id) {
            return std::unexpected(id.error());
        }
        auto own_path = directory / (stem + "." + *id + extension);
        auto own = glove::audit::make_jsonl_sink(own_path, limits);
        if (own) {
            return default_audit_journal{
                .sink = std::move(*own), .path = std::move(own_path), .overflow = true
            };
        }
        // Busy: the name collided with a live launch. Removed: another
        // launch's retention pass took the file before this one locked it.
        // Either way another name is drawn.
        if (own.error() != glove::audit::jsonl_sink_busy &&
            own.error() != glove::audit::jsonl_sink_removed) {
            return std::unexpected(own.error());
        }
        last_error = own.error();
    }
    return std::unexpected(last_error);
}

} // namespace glove::run::detail
