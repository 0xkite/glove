#include "decoys.hpp"

#include "glove/host/config.hpp"

#include "../host/runtime_snapshot.hpp"

#include <fcntl.h>
#include <sys/file.h>
#if defined(__APPLE__)
#    include <sys/random.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <ctime>
#include <ranges>
#include <system_error>
#include <utility>

namespace glove::run::detail {
namespace {

constexpr std::size_t max_journal_bytes = 64UZ * 1024UZ;

auto system_message(int error_number) -> std::string {
    return std::error_code{error_number, std::generic_category()}.message();
}

class descriptor {
public:
    explicit descriptor(int fd) : fd_{fd} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;
    descriptor(descriptor&&) = delete;
    auto operator=(descriptor&&) -> descriptor& = delete;

    ~descriptor() {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    [[nodiscard]] auto get() const -> int { return fd_; }

private:
    int fd_;
};

auto random_text(std::size_t bytes, std::string_view alphabet)
    -> std::expected<std::string, std::string> {
    std::array<unsigned char, 32> raw{};
    if (bytes > raw.size() || ::getentropy(raw.data(), bytes) != 0) {
        return std::unexpected(std::string{"cannot draw random bytes for a decoy"});
    }
    std::string out;
    for (std::size_t i = 0; i < bytes; ++i) {
        out.push_back(alphabet.at(raw.at(i) % alphabet.size()));
    }
    return out;
}

auto normal(const std::filesystem::path& path) -> std::filesystem::path {
    std::error_code ec;
    auto resolved = std::filesystem::weakly_canonical(path, ec);
    auto out = (ec ? path : resolved).lexically_normal();
    while (!out.has_filename() && out != out.root_path()) {
        out = out.parent_path();
    }
    return out;
}

auto inside(const std::filesystem::path& inner, const std::filesystem::path& outer) -> bool {
    const auto [end_outer, end_inner] = std::ranges::mismatch(outer, inner);
    static_cast<void>(end_inner);
    return end_outer == outer.end();
}

auto write_all(int fd, std::string_view data) -> bool {
    while (!data.empty()) {
        const auto wrote = ::write(fd, data.data(), data.size());
        if (wrote < 0 && errno == EINTR) {
            continue;
        }
        if (wrote <= 0) {
            return false;
        }
        data.remove_prefix(static_cast<std::size_t>(wrote));
    }
    return true;
}

// Removes PATH only when it is still exactly the canary we wrote.
auto remove_if_ours(const std::filesystem::path& path, std::string_view canary) noexcept -> bool {
    try {
        const descriptor parent{
            ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        };
        if (parent.get() < 0) {
            return false;
        }
        const auto name = path.filename().string();
        const descriptor file{
            ::openat(parent.get(), name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        };
        struct stat metadata{};
        const std::string expected = std::string{canary} + "\n";
        if (file.get() < 0 || ::fstat(file.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
            std::cmp_not_equal(metadata.st_size, expected.size())) {
            return false;
        }
        std::string contents(expected.size(), '\0');
        if (::read(file.get(), contents.data(), contents.size()) !=
                static_cast<ssize_t>(contents.size()) ||
            contents != expected) {
            return false;
        }
        return ::unlinkat(parent.get(), name.c_str(), 0) == 0;
    } catch (...) {
        return false;
    }
}

// Lines "canary\tpath\n" from a journal; malformed lines are skipped.
auto journal_entries(std::string_view text)
    -> std::vector<std::pair<std::string, std::filesystem::path>> {
    std::vector<std::pair<std::string, std::filesystem::path>> out;
    for (const auto raw : std::views::split(text, '\n')) {
        const std::string_view line{raw.begin(), raw.end()};
        const auto tab = line.find('\t');
        if (tab == std::string_view::npos || !line.starts_with("glvc_") ||
            line.substr(tab + 1).empty() || line[tab + 1] != '/') {
            continue;
        }
        out.emplace_back(
            std::string{line.substr(0, tab)}, std::filesystem::path{line.substr(tab + 1)}
        );
    }
    return out;
}

// Whether NAME in PARENT is a regular single-link file of ours holding
// exactly one canary line.
auto is_canary_file(int parent, const std::string& name) -> bool {
    const descriptor file{
        ::openat(parent, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    };
    constexpr std::size_t canary_line = 5 + 26 + 1;
    struct stat metadata{};
    if (file.get() < 0 || ::fstat(file.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        std::cmp_not_equal(metadata.st_size, canary_line)) {
        return false;
    }
    std::string text(canary_line, '\0');
    if (::read(file.get(), text.data(), text.size()) != static_cast<ssize_t>(text.size())) {
        return false;
    }
    return text.starts_with("glvc_") && text.back() == '\n' &&
           std::ranges::all_of(text.substr(5, 26), [](char ch) {
               return (ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7');
           });
}

auto check_template(const std::string& path, std::span<const std::string> exposed)
    -> std::expected<void, std::string> {
    const std::filesystem::path decoy{path};
    if (!decoy.is_absolute() || decoy.lexically_normal() != decoy || !decoy.has_filename() ||
        decoy.parent_path() == decoy.root_path()) {
        return std::unexpected("decoy '" + path + "' must be a normal absolute file path below /");
    }
    const auto resolved = normal(decoy);
    for (const auto& grant : exposed) {
        const auto root = normal(std::filesystem::path{grant});
        if (inside(resolved, root) || inside(decoy, root) || inside(root, resolved)) {
            return std::unexpected(
                "decoy '" + path + "' is inside a path the sandbox can reach ('" + grant + "')"
            );
        }
    }
    return {};
}

} // namespace

decoy_set::decoy_set(decoy_set&& other) noexcept
    : paths_{std::move(other.paths_)},
      canaries_{std::move(other.canaries_)},
      journal_{std::move(other.journal_)},
      journal_fd_{std::exchange(other.journal_fd_, -1)} {
    other.paths_.clear();
    other.canaries_.clear();
    other.journal_.clear();
}

auto decoy_set::operator=(decoy_set&& other) noexcept -> decoy_set& {
    if (this != &other) {
        remove();
        paths_ = std::move(other.paths_);
        canaries_ = std::move(other.canaries_);
        journal_ = std::move(other.journal_);
        journal_fd_ = std::exchange(other.journal_fd_, -1);
        other.paths_.clear();
        other.canaries_.clear();
        other.journal_.clear();
    }
    return *this;
}

decoy_set::~decoy_set() {
    remove();
}

void decoy_set::remove() noexcept {
    for (std::size_t i = 0; i < paths_.size() && i < canaries_.size(); ++i) {
        if (!canaries_[i].empty()) { // empty: shared with the launch that owns it
            static_cast<void>(remove_if_ours(paths_[i], canaries_[i]));
        }
    }
    paths_.clear();
    canaries_.clear();
    if (!journal_.empty()) {
        static_cast<void>(::unlink(journal_.c_str()));
        journal_.clear();
    }
    if (journal_fd_ >= 0) {
        static_cast<void>(::close(journal_fd_));
        journal_fd_ = -1;
    }
}

auto decoy_set::plant(
    std::span<const std::string> templates,
    std::span<const std::string> exposed,
    const std::filesystem::path& journal_directory
) -> std::expected<decoy_set, std::string> {
    decoy_set out;
    if (templates.empty()) {
        return out;
    }
    if (templates.size() > max_decoys) {
        return std::unexpected("at most " + std::to_string(max_decoys) + " decoys per launch");
    }
    auto nonce = random_text(8, "0123456789abcdef");
    auto launch = random_text(16, "0123456789abcdef");
    if (!nonce || !launch) {
        return std::unexpected(std::string{"cannot draw random bytes for decoys"});
    }
    out.journal_ = journal_directory / ("launch-" + *launch + ".list");
    out.journal_fd_ =
        ::open(out.journal_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out.journal_fd_ < 0) {
        const int error = errno;
        out.journal_.clear();
        return std::unexpected("cannot create the decoy journal: " + system_message(error));
    }
    if (::flock(out.journal_fd_, LOCK_EX | LOCK_NB) != 0) {
        return std::unexpected("cannot lock the decoy journal: " + system_message(errno));
    }
    std::vector<std::filesystem::path> seen;
    for (const auto& raw : templates) {
        std::string path = raw;
        for (auto at = path.find(decoy_nonce_placeholder); at != std::string::npos;
             at = path.find(decoy_nonce_placeholder, at + nonce->size())) {
            path.replace(at, decoy_nonce_placeholder.size(), *nonce);
        }
        if (auto ok = check_template(path, exposed); !ok) {
            return std::unexpected(ok.error());
        }
        const std::filesystem::path decoy{path};
        if (std::ranges::find(seen, decoy) != seen.end()) {
            return std::unexpected("decoy '" + path + "' is listed twice");
        }
        seen.push_back(decoy);
        const descriptor parent{
            ::open(decoy.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        };
        struct stat parent_metadata{};
        if (parent.get() < 0 || ::fstat(parent.get(), &parent_metadata) != 0 ||
            parent_metadata.st_uid != ::geteuid() || (parent_metadata.st_mode & 0022U) != 0) {
            return std::unexpected(
                "decoy '" + path +
                "': its directory must exist, be yours, not be a symlink, and not be writable "
                "by group or others (glove never creates it)"
            );
        }
        auto canary = random_text(26, "abcdefghijklmnopqrstuvwxyz234567");
        if (!canary) {
            return std::unexpected(canary.error());
        }
        const std::string token = "glvc_" + *canary;
        // Journal first, so a crash after creating the file still names it.
        if (!write_all(out.journal_fd_, token + "\t" + path + "\n") ||
            ::fsync(out.journal_fd_) != 0) {
            return std::unexpected(std::string{"cannot write the decoy journal"});
        }
        const auto name = decoy.filename().string();
        const descriptor file{::openat(
            parent.get(), name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
        )};
        if (file.get() < 0) {
            const int error = errno;
            // Another live launch's decoy at a fixed name is shared: watched
            // here, owned (and removed) by the launch that planted it. The
            // sweep above already removed decoys of launches that died.
            if (error == EEXIST && is_canary_file(parent.get(), name)) {
                out.paths_.push_back(decoy);
                out.canaries_.emplace_back();
                continue;
            }
            return std::unexpected(
                "decoy '" + path + "': " +
                (error == EEXIST ? std::string{"a file that is not a glove decoy exists there"}
                                 : system_message(error))
            );
        }
        out.paths_.push_back(decoy);
        out.canaries_.push_back(token);
        if (!write_all(file.get(), token + "\n") || ::fsync(file.get()) != 0) {
            return std::unexpected("cannot write decoy '" + path + "'");
        }
    }
    return out;
}

auto sweep_stale_decoys(const std::filesystem::path& journal_directory) noexcept -> std::size_t {
    std::size_t removed = 0;
    try {
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(journal_directory, ec)) {
            const auto& path = entry.path();
            const auto name = path.filename().string();
            if (!name.starts_with("launch-") || path.extension() != ".list") {
                continue;
            }
            const descriptor journal{
                ::open(path.c_str(), O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            };
            struct stat metadata{};
            if (journal.get() < 0 || ::fstat(journal.get(), &metadata) != 0 ||
                !S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
                metadata.st_nlink != 1 || std::cmp_greater(metadata.st_size, max_journal_bytes)) {
                continue;
            }
            // A live launch holds the lock; only a dead one's journal is ours.
            if (::flock(journal.get(), LOCK_EX | LOCK_NB) != 0) {
                continue;
            }
            // A launch writes entries only once it holds the lock, so an
            // empty journal may be one being created right now. Leave it
            // unless it is old enough that its launch cannot still be
            // starting.
            if (metadata.st_size == 0) {
                if (::time(nullptr) - metadata.st_mtime > 3600) {
                    static_cast<void>(::unlink(path.c_str()));
                }
                continue;
            }
            std::string text(static_cast<std::size_t>(metadata.st_size), '\0');
            if (::read(journal.get(), text.data(), text.size()) !=
                static_cast<ssize_t>(text.size())) {
                continue;
            }
            for (const auto& [canary, decoy] : journal_entries(text)) {
                removed += remove_if_ours(decoy, canary) ? 1U : 0U;
            }
            static_cast<void>(::unlink(path.c_str()));
        }
    } catch (...) {
        return removed;
    }
    return removed;
}

auto decoy_journal_directory() -> std::expected<std::filesystem::path, std::string> {
    auto directories = glove::host::resolve_directories(glove::host::current_environment());
    if (!directories) {
        return std::unexpected(directories.error());
    }
    std::error_code ec;
    const auto state = std::filesystem::weakly_canonical(directories->state, ec);
    if (ec) {
        return std::unexpected("cannot resolve " + directories->state.string());
    }
    auto directory = (state / "decoys").lexically_normal();
    if (auto ok = glove::host::snapshot::ensure_protected_directory(directory, true); !ok) {
        return std::unexpected(directory.string() + ": " + ok.error());
    }
    return directory;
}

} // namespace glove::run::detail
