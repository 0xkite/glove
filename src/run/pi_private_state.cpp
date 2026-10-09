#include "pi_private_state.hpp"

#include "glove/detail/descriptor_acl.hpp"

#include "../host/snapshot_cleanup.hpp"
#include "pi_private_cleanup.hpp"
#include "pi_private_files.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace {

template<typename T> using result = std::expected<T, std::string>;
constexpr std::size_t config_budget = 32U * 1024U;
constexpr const char* marker_name = ".glove-pi-lease";
enum class phase { constructing, launching, quiescent, uncertain };

using private_files::check_file;
using private_files::descriptor;
using private_files::directory_flags;
using private_files::edge;
using private_files::failure;
using private_files::pin_parent;
using private_files::pinned_parent;
using private_files::private_file;
using private_files::safe_directory;
using private_files::same;
using private_files::stable_bytes;
using private_files::write_bytes;

auto marker_bytes(const struct stat& root, phase value) -> std::string {
    const char* label = value == phase::constructing ? "constructing"
                        : value == phase::launching  ? "launching"
                                                     : "quiescent";
    return "glove-pi-private-v1\n" + std::to_string(static_cast<std::uintmax_t>(root.st_dev)) +
           "\n" + std::to_string(static_cast<std::uintmax_t>(root.st_ino)) + "\n" + label + "\n";
}

auto read_marker(int fd, const struct stat& root) -> result<phase> {
    struct stat before{};
    if (::fstat(fd, &before) != 0) {
        return failure("inspect Pi lease bytes");
    }
    if (!private_file(before, 0600) || before.st_size <= 0 || before.st_size > 128) {
        return std::unexpected("unsafe or malformed Pi lease");
    }
    std::array<char, 129> buffer{};
    std::size_t offset = 0;
    const auto size = static_cast<std::size_t>(before.st_size);
    while (offset < size) {
        const auto count =
            ::pread(fd, buffer.data() + offset, size - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return failure("read Pi lease bytes");
        }
        offset += static_cast<std::size_t>(count);
    }
    struct stat after{};
    if (::fstat(fd, &after) != 0) {
        return failure("reinspect Pi lease bytes");
    }
    if (!stable_bytes(before, after) || after.st_nlink != 1) {
        return std::unexpected("Pi lease changed while reading");
    }
    const std::string_view bytes{buffer.data(), size};
    for (const auto value : {phase::constructing, phase::launching, phase::quiescent}) {
        if (bytes == marker_bytes(root, value)) {
            return value;
        }
    }
    return std::unexpected("malformed or root-unbound Pi lease");
}

auto valid_run_name(std::string_view name) -> bool {
    if (name.size() != 52 || !name.starts_with("run-")) {
        return false;
    }
    for (const auto value : name.substr(4)) {
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
            return false;
        }
    }
    return true;
}

using private_cleanup::directory_stream;
using private_cleanup::inspect_tree;
using private_cleanup::recovery_entries;

} // namespace

struct pi_private_state::implementation {
    pinned_parent parent;
    descriptor root_fd;
    descriptor lease_fd;
    struct stat root_identity{};
    struct stat lease_identity{};
    std::vector<edge> children;
    std::vector<edge> configs;
    std::string name;
    phase current = phase::constructing;
    bool removed = false;
    std::filesystem::path root_path;
    std::filesystem::path home_path;
    std::filesystem::path tmp_path;
    std::filesystem::path agent_path;
    std::filesystem::path sessions_path;
    std::filesystem::path models_path;
    std::filesystem::path settings_path;
    std::filesystem::path auth_path;

    auto attached() const -> result<void> {
        if (auto checked = parent.check(); !checked) {
            return checked;
        }
        struct stat actual{};
        struct stat named{};
        if (::fstat(root_fd.get(), &actual) != 0 ||
            ::fstatat(parent.fd(), name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("reinspect Pi private root");
        }
        if (!same(root_identity, actual) || !same(actual, named) || !safe_directory(actual, true) ||
            !safe_directory(named, true) || actual.st_dev != parent.chain.back().identity.st_dev) {
            return std::unexpected("Pi private root changed or is unsafe");
        }
        return glove::detail::check_descriptor_acl(
            root_fd.get(), glove::detail::acl_scope::owner_private
        );
    }

    auto payload() const -> result<void> {
        for (const auto& child : children) {
            struct stat actual{};
            struct stat named{};
            if (::fstat(child.fd.get(), &actual) != 0 ||
                ::fstatat(root_fd.get(), child.name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
                return failure("reinspect Pi fixed child");
            }
            if (!same(child.identity, actual) || !same(actual, named) ||
                !safe_directory(actual, true)) {
                return std::unexpected("Pi fixed child changed");
            }
            if (auto acl = glove::detail::check_descriptor_acl(
                    child.fd.get(), glove::detail::acl_scope::owner_private
                );
                !acl) {
                return acl;
            }
        }
        for (const auto& file : configs) {
            // agent is the third fixed child, never a caller-supplied grant.
            auto checked = check_file(
                children[2].fd.get(), file.name.c_str(), file.fd.get(), file.identity, 0400
            );
            if (!checked) {
                return checked;
            }
            struct stat actual{};
            if (::fstat(file.fd.get(), &actual) != 0) {
                return failure("reinspect Pi immutable config size");
            }
            if (!stable_bytes(actual, file.identity)) {
                return std::unexpected("Pi immutable config metadata changed");
            }
        }
        return {};
    }

    auto checked_phase() const -> result<phase> {
        if (auto checked = attached(); !checked) {
            return std::unexpected(checked.error());
        }
        if (auto checked =
                check_file(root_fd.get(), marker_name, lease_fd.get(), lease_identity, 0600);
            !checked) {
            return std::unexpected(checked.error());
        }
        if (::flock(lease_fd.get(), LOCK_EX | LOCK_NB) != 0) {
            return failure("recheck exclusive Pi lease");
        }
        auto value = read_marker(lease_fd.get(), root_identity);
        if (!value) {
            return value;
        }
        if (auto checked = attached(); !checked) {
            return std::unexpected(checked.error());
        }
        if (auto checked =
                check_file(root_fd.get(), marker_name, lease_fd.get(), lease_identity, 0600);
            !checked) {
            return std::unexpected(checked.error());
        }
        return value;
    }

    auto transition(phase target) -> result<void> {
        auto recorded = checked_phase();
        if (!recorded || *recorded != current) {
            current = phase::uncertain;
            return std::unexpected(recorded ? "Pi phase changed externally" : recorded.error());
        }
        if (auto checked = payload(); !checked) {
            current = phase::uncertain;
            return checked;
        }
        // Torn writes or durability failures must never enable destructor cleanup.
        current = phase::uncertain;
        if (auto written = write_bytes(lease_fd.get(), marker_bytes(root_identity, target));
            !written) {
            return written;
        }
        if (::fsync(root_fd.get()) != 0 || ::fsync(parent.fd()) != 0) {
            return failure("persist Pi phase namespace");
        }
        auto checked = checked_phase();
        if (!checked || *checked != target) {
            return std::unexpected(checked ? "Pi durable phase mismatch" : checked.error());
        }
        if (auto payload_checked = payload(); !payload_checked) {
            return payload_checked;
        }
        current = target;
        return {};
    }

    auto remove() -> result<void> {
        if (removed) {
            return {};
        }
        if (current == phase::launching || current == phase::uncertain) {
            return std::unexpected(
                "Pi launching or unresolved state retained: " + root_path.string()
            );
        }
        auto recorded = checked_phase();
        if (!recorded || *recorded != current) {
            current = phase::uncertain;
            return std::unexpected(recorded ? "Pi cleanup phase mismatch" : recorded.error());
        }
        if (auto checked = payload(); !checked) {
            return std::unexpected(checked.error() + "; retained: " + root_path.string());
        }
        std::size_t entries = 0;
        if (auto checked = inspect_tree(root_fd.get(), root_identity.st_dev, entries, 0, false);
            !checked) {
            return std::unexpected(checked.error() + "; retained: " + root_path.string());
        }
        if (auto checked = attached(); !checked) {
            current = phase::uncertain;
            return checked;
        }
        auto fresh_phase = checked_phase();
        if (!fresh_phase || *fresh_phase != current) {
            current = phase::uncertain;
            return std::unexpected(
                fresh_phase ? "Pi cleanup phase changed after preflight" : fresh_phase.error()
            );
        }
        if (auto checked = payload(); !checked) {
            return std::unexpected(checked.error() + "; retained: " + root_path.string());
        }
        entries = 0;
        if (auto checked = inspect_tree(root_fd.get(), root_identity.st_dev, entries, 0, true);
            !checked) {
            return std::unexpected(checked.error() + "; retained: " + root_path.string());
        }
        auto cleaned = host::snapshot::remove_owned_staging_tree(parent.fd(), name, root_fd.get());
        if (!cleaned) {
            current = phase::uncertain;
            return std::unexpected(
                "Pi cleanup retained unresolved root " + root_path.string() + ": " + cleaned.error()
            );
        }
        removed = true;
        if (::fsync(parent.fd()) != 0) {
            return failure("persist Pi root removal");
        }
        return {};
    }
};

pi_private_state::pi_private_state(std::unique_ptr<implementation> state) noexcept
    : state_{std::move(state)} {}

pi_private_state::pi_private_state(pi_private_state&&) noexcept = default;

auto pi_private_state::operator=(pi_private_state&& other) noexcept -> pi_private_state& {
    if (this != &other) {
        pi_private_state previous{std::move(*this)};
        state_ = std::move(other.state_);
    }
    return *this;
}

pi_private_state::~pi_private_state() {
    if (state_ && !state_->removed &&
        (state_->current == phase::constructing || state_->current == phase::quiescent)) {
        try {
            (void)state_->remove();
        } catch (...) {
            // Best effort includes allocation failure. Closing host descriptors
            // leaves the unresolved namespace for conservative recovery.
        }
    }
}

auto pi_private_state::create(
    const std::filesystem::path& parent_path,
    const pi_guest_config& config,
    pi_creation_rollback_barrier rollback_barrier
) -> result<pi_private_state> {
    // Subtraction avoids overflow; argument/environment bytes are not materialized.
    if (config.models_json.size() > config_budget - 2 ||
        config.settings_json.size() > config_budget - 2 - config.models_json.size()) {
        return std::unexpected("Pi generated configuration exceeds 32 KiB logical budget");
    }
    auto parent = pin_parent(parent_path);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    auto state = std::make_unique<implementation>();
    state->parent = std::move(*parent);
    std::array<unsigned char, 24> random{};
    if (::getentropy(random.data(), random.size()) != 0) {
        return failure("generate Pi private root name");
    }
    constexpr std::string_view hex = "0123456789abcdef";
    state->name = "run-";
    for (const auto byte : random) {
        state->name += hex[byte >> 4U];
        state->name += hex[byte & 15U];
    }
    state->root_path = parent_path / state->name;
    state->home_path = state->root_path / "home";
    state->tmp_path = state->root_path / "tmp";
    state->agent_path = state->root_path / "agent";
    state->sessions_path = state->root_path / "sessions";
    state->models_path = state->agent_path / "models.json";
    state->settings_path = state->agent_path / "settings.json";
    state->auth_path = state->agent_path / "auth.json";
    if (auto checked = state->parent.check(); !checked) {
        return std::unexpected(checked.error());
    }
    if (::mkdirat(state->parent.fd(), state->name.c_str(), 0700) != 0) {
        return failure("exclusively create Pi private root");
    }
    struct stat named{};
    state->root_fd = descriptor{::openat(state->parent.fd(), state->name.c_str(), directory_flags)};
    if (state->root_fd.get() < 0 || ::fstat(state->root_fd.get(), &state->root_identity) != 0 ||
        ::fstatat(state->parent.fd(), state->name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same(state->root_identity, named) || !safe_directory(named, true)) {
        return std::unexpected(
            "Pi root created but ownership unresolved; retained: " + state->root_path.string()
        );
    }
    // From here rollback has descriptor-proven ownership, including partial trees.
    const auto rollback = [&](std::string original) -> result<pi_private_state> {
        if (rollback_barrier.before_cleanup != nullptr) {
            rollback_barrier.before_cleanup(rollback_barrier.context);
        }
        auto attached = state->attached();
        auto cleaned = attached ? host::snapshot::remove_owned_staging_tree(
                                      state->parent.fd(), state->name, state->root_fd.get()
                                  )
                                : result<void>{std::unexpected(attached.error())};
        if (!cleaned) {
            original += "; rollback retained " + state->root_path.string() + ": " + cleaned.error();
        } else if (::fsync(state->parent.fd()) != 0) {
            original += "; " + failure("persist Pi rollback").error();
        }
        return std::unexpected(std::move(original));
    };
    if (auto cleared = glove::detail::clear_created_descriptor_acl(state->root_fd.get());
        !cleared) {
        return rollback(cleared.error());
    }
    state->lease_fd = descriptor{::openat(
        state->root_fd.get(),
        marker_name,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        0600
    )};
    if (state->lease_fd.get() < 0 || ::fchmod(state->lease_fd.get(), 0600) != 0 ||
        ::fstat(state->lease_fd.get(), &state->lease_identity) != 0 ||
        ::flock(state->lease_fd.get(), LOCK_EX | LOCK_NB) != 0) {
        return rollback(failure("create and lock Pi lease").error());
    }
    if (auto checked = check_file(
            state->root_fd.get(), marker_name, state->lease_fd.get(), state->lease_identity, 0600
        );
        !checked) {
        return rollback(checked.error());
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(state->lease_fd.get());
        !cleared) {
        return rollback(cleared.error());
    }
    if (auto written = write_bytes(
            state->lease_fd.get(), marker_bytes(state->root_identity, phase::constructing)
        );
        !written) {
        return rollback(written.error());
    }
    // Persist the locked constructing marker before any subsequent materialization.
    if (::fsync(state->root_fd.get()) != 0 || ::fsync(state->parent.fd()) != 0) {
        return rollback(failure("persist Pi constructing lease").error());
    }
    for (const auto* child : {"home", "tmp", "agent", "sessions"}) {
        if (auto checked = state->attached(); !checked) {
            return rollback(checked.error());
        }
        if (::mkdirat(state->root_fd.get(), child, 0700) != 0) {
            return rollback(failure("create Pi private child").error());
        }
        descriptor fd{::openat(state->root_fd.get(), child, directory_flags)};
        struct stat info{};
        struct stat entry{};
        if (fd.get() < 0 || ::fstat(fd.get(), &info) != 0 ||
            ::fstatat(state->root_fd.get(), child, &entry, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same(info, entry) || !safe_directory(info, true) ||
            info.st_dev != state->root_identity.st_dev || ::fsync(fd.get()) != 0) {
            return rollback("Pi private child is unsafe or could not be persisted");
        }
        if (auto cleared = glove::detail::clear_created_descriptor_acl(fd.get()); !cleared) {
            return rollback(cleared.error());
        }
        if (::fsync(fd.get()) != 0) {
            return rollback(failure("persist Pi child ACL").error());
        }
        state->children.push_back({std::move(fd), child, info});
    }
    descriptor agent_fd{::openat(state->root_fd.get(), "agent", directory_flags)};
    struct stat agent_identity{};
    if (agent_fd.get() < 0 || ::fstat(agent_fd.get(), &agent_identity) != 0) {
        return rollback(failure("pin Pi agent directory").error());
    }
    const auto check_agent = [&]() -> result<void> {
        if (auto checked = state->attached(); !checked) {
            return checked;
        }
        struct stat actual{};
        struct stat entry{};
        if (::fstat(agent_fd.get(), &actual) != 0 ||
            ::fstatat(state->root_fd.get(), "agent", &entry, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("reinspect Pi agent directory");
        }
        if (!same(actual, agent_identity) || !same(actual, entry) ||
            !safe_directory(actual, true)) {
            return std::unexpected("Pi agent directory changed");
        }
        return glove::detail::check_descriptor_acl(
            agent_fd.get(), glove::detail::acl_scope::owner_private
        );
    };
    const std::array<std::pair<const char*, std::string_view>, 3> files{
        {{"models.json", config.models_json},
         {"settings.json", config.settings_json},
         {"auth.json", "{}"}}
    };
    for (const auto& [name, bytes] : files) {
        if (auto checked = check_agent(); !checked) {
            return rollback(checked.error());
        }
        descriptor file{::openat(
            agent_fd.get(),
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
            0600
        )};
        struct stat identity{};
        if (file.get() < 0 || ::fchmod(file.get(), 0600) != 0 ||
            ::fstat(file.get(), &identity) != 0) {
            return rollback(failure("create generated Pi configuration").error());
        }
        if (auto checked = check_file(agent_fd.get(), name, file.get(), identity, 0600); !checked) {
            return rollback(checked.error());
        }
        if (auto cleared = glove::detail::clear_created_descriptor_acl(file.get()); !cleared) {
            return rollback(cleared.error());
        }
        if (auto written = write_bytes(file.get(), bytes); !written) {
            return rollback(written.error());
        }
        if (::fchmod(file.get(), 0400) != 0 || ::fsync(file.get()) != 0) {
            return rollback(failure("seal generated Pi configuration").error());
        }
        identity.st_mode = (identity.st_mode & ~static_cast<mode_t>(07777U)) | 0400U;
        if (auto checked = check_file(agent_fd.get(), name, file.get(), identity, 0400); !checked) {
            return rollback(checked.error());
        }

        struct stat sealed{};
        if (::fstat(file.get(), &sealed) != 0 ||
            sealed.st_size != static_cast<off_t>(bytes.size())) {
            return rollback("generated Pi configuration size changed");
        }
        if (auto checked = check_agent(); !checked) {
            return rollback(checked.error());
        }
        state->configs.push_back({std::move(file), name, sealed});
    }
    if (::fsync(agent_fd.get()) != 0 || ::fsync(state->root_fd.get()) != 0 ||
        ::fsync(state->parent.fd()) != 0) {
        return rollback(failure("persist Pi private namespace").error());
    }
    if (auto checked = check_agent(); !checked) {
        return rollback(checked.error());
    }
    if (auto checked = state->payload(); !checked) {
        return rollback(checked.error());
    }
    auto recorded = state->checked_phase();
    if (!recorded || *recorded != phase::constructing) {
        return rollback(recorded ? "Pi constructing phase changed" : recorded.error());
    }
    return pi_private_state{std::move(state)};
}

auto pi_private_state::mark_launching() -> result<void> {
    if (!state_ || state_->removed || state_->current != phase::constructing) {
        return std::unexpected("Pi launch requires a constructing private state");
    }
    return state_->transition(phase::launching);
}

auto pi_private_state::mark_quiescent() -> result<void> {
    if (!state_ || state_->removed || state_->current != phase::launching) {
        return std::unexpected("Pi quiescence requires owned launch/reap success");
    }
    return state_->transition(phase::quiescent);
}

auto pi_private_state::cleanup() -> result<void> {
    return state_ ? state_->remove() : result<void>{};
}

auto pi_private_state::recover(const std::filesystem::path& parent_path) -> result<std::size_t> {
    auto parent = pin_parent(parent_path);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    descriptor enumeration{::openat(parent->fd(), ".", directory_flags)};
    if (enumeration.get() < 0) {
        return failure("open Pi recovery enumeration");
    }
    directory_stream stream{::fdopendir(enumeration.get())};
    if (!stream) {
        return failure("enumerate Pi recovery parent");
    }
    (void)enumeration.release();
    std::vector<std::string> names;
    std::size_t seen = 0;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(stream.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return failure("read Pi recovery parent");
            }
            break;
        }
        const auto length = ::strnlen(entry->d_name, sizeof(entry->d_name));
        if (length == sizeof(entry->d_name)) {
            return std::unexpected("unbounded Pi recovery entry name");
        }
        const std::string_view name{entry->d_name, length};
        if (name == "." || name == "..") {
            continue;
        }
        if (++seen > recovery_entries) {
            return std::unexpected("Pi recovery parent exceeds 4096 direct entries");
        }
        if (name.starts_with("run-")) {
            if (!valid_run_name(name)) {
                return std::unexpected("malformed Pi recovery name retained: " + std::string{name});
            }
            names.emplace_back(name);
        }
    }
    if (::closedir(stream.release()) != 0) {
        return failure("close Pi recovery enumeration");
    }
    std::size_t removed = 0;
    for (const auto& name : names) {
        auto state = std::make_unique<implementation>();
        // Repin every ancestor for each candidate; never canonicalize then open.
        auto pinned = pin_parent(parent_path);
        if (!pinned) {
            return std::unexpected(pinned.error());
        }
        if (auto checked = parent->check(); !checked) {
            return std::unexpected(checked.error());
        }
        if (!same(parent->chain.back().identity, pinned->chain.back().identity)) {
            return std::unexpected("Pi recovery parent replaced");
        }
        state->parent = std::move(*pinned);
        state->name = name;
        state->root_path = parent_path / name;
        struct stat before{};
        if (::fstatat(state->parent.fd(), name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect Pi recovery root");
        }
        if (!safe_directory(before, true)) {
            return std::unexpected("unsafe Pi recovery root retained: " + name);
        }
        state->root_fd = descriptor{::openat(state->parent.fd(), name.c_str(), directory_flags)};
        if (state->root_fd.get() < 0 || ::fstat(state->root_fd.get(), &state->root_identity) != 0) {
            return failure("pin Pi recovery root");
        }
        if (!same(before, state->root_identity)) {
            return std::unexpected("Pi recovery root replaced: " + name);
        }
        if (auto checked = state->attached(); !checked) {
            return std::unexpected(checked.error());
        }
        state->lease_fd = descriptor{::openat(
            state->root_fd.get(), marker_name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )};
        if (state->lease_fd.get() < 0 ||
            ::fstat(state->lease_fd.get(), &state->lease_identity) != 0) {
            return std::unexpected("missing or unreadable Pi recovery lease retained: " + name);
        }
        if (auto checked = check_file(
                state->root_fd.get(),
                marker_name,
                state->lease_fd.get(),
                state->lease_identity,
                0600
            );
            !checked) {
            return std::unexpected(checked.error() + "; retained: " + name);
        }
        if (::flock(state->lease_fd.get(), LOCK_EX | LOCK_NB) != 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            }
            return failure("lock Pi recovery lease");
        }
        auto recorded = state->checked_phase();
        if (!recorded) {
            return std::unexpected(recorded.error() + "; retained: " + name);
        }
        if (*recorded == phase::launching) {
            return std::unexpected(
                "Pi launching state retained despite absent host lease: " + name
            );
        }
        state->current = *recorded;
        if (auto cleaned = state->remove(); !cleaned) {
            return std::unexpected(cleaned.error());
        }
        ++removed;
    }
    return removed;
}

auto pi_private_state::root() const -> const std::filesystem::path& {
    return state_->root_path;
}

auto pi_private_state::home() const -> const std::filesystem::path& {
    return state_->home_path;
}

auto pi_private_state::tmp() const -> const std::filesystem::path& {
    return state_->tmp_path;
}

auto pi_private_state::agent() const -> const std::filesystem::path& {
    return state_->agent_path;
}

auto pi_private_state::sessions() const -> const std::filesystem::path& {
    return state_->sessions_path;
}

auto pi_private_state::models() const -> const std::filesystem::path& {
    return state_->models_path;
}

auto pi_private_state::settings() const -> const std::filesystem::path& {
    return state_->settings_path;
}

auto pi_private_state::auth() const -> const std::filesystem::path& {
    return state_->auth_path;
}

} // namespace glove::run::detail
