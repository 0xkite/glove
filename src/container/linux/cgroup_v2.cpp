#include "cgroup_v2.hpp"

#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container::linux_detail {

namespace {

constexpr std::size_t max_control_file_bytes = std::size_t{64} * 1024U;
constexpr std::string_view required_controllers = "+cpu +memory +pids";
constexpr std::string_view disabled_controllers = "-cpu -memory -pids";
constexpr std::string_view systemd_delegate_subgroup = "glove-host";

class unique_fd {
public:
    explicit unique_fd(int fd = -1) noexcept : fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(fd_, -1); }

    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

auto duplicate_fd(int fd) -> std::expected<int, std::string> {
    const int copy = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) {
        return std::unexpected(std::string{"duplicate cgroup fd: "} + std::strerror(errno));
    }
    return copy;
}

auto read_fd_bounded(int fd, std::string_view label) -> std::expected<std::string, std::string> {
    std::string value;
    std::array<char, 4096> chunk{};
    for (;;) {
        const ::ssize_t count = ::read(fd, chunk.data(), chunk.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                std::string{"read "} + std::string{label} + ": " + std::strerror(errno)
            );
        }
        if (count == 0) {
            return value;
        }
        const auto size = static_cast<std::size_t>(count);
        if (value.size() > max_control_file_bytes - size) {
            return std::unexpected(
                std::string{"cgroup control file exceeds bound: "} + std::string{label}
            );
        }
        value.append(chunk.data(), size);
    }
}

auto read_at(int directory_fd, const char* name, bool optional = false)
    -> std::expected<std::string, std::string> {
    unique_fd fd{::openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (fd.get() < 0) {
        if (optional && errno == ENOENT) {
            return std::string{};
        }
        return std::unexpected(std::string{"open "} + name + ": " + std::strerror(errno));
    }
    return read_fd_bounded(fd.get(), name);
}

auto write_all(int fd, std::string_view value, std::string_view label)
    -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ::ssize_t count = ::write(fd, value.data() + offset, value.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                std::string{"write "} + std::string{label} + ": " + std::strerror(errno)
            );
        }
        offset += static_cast<std::size_t>(count);
    }
    return {};
}

auto write_at(int directory_fd, const char* name, std::string_view value, bool optional = false)
    -> std::expected<void, std::string> {
    unique_fd fd{::openat(directory_fd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (fd.get() < 0) {
        if (optional && errno == ENOENT) {
            return {};
        }
        return std::unexpected(std::string{"open "} + name + ": " + std::strerror(errno));
    }
    return write_all(fd.get(), value, name);
}

auto parse_unsigned(std::string_view value, std::string_view label)
    -> std::expected<std::uint64_t, std::string> {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.remove_suffix(1);
    }
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        return std::unexpected(std::string{"invalid cgroup counter: "} + std::string{label});
    }
    return parsed;
}

auto keyed_counter(std::string_view content, std::string_view key)
    -> std::expected<std::uint64_t, std::string> {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto end = content.find('\n', offset);
        const auto line = content.substr(
            offset, end == std::string_view::npos ? content.size() - offset : end - offset
        );
        const auto space = line.find(' ');
        if (space != std::string_view::npos && line.substr(0, space) == key) {
            return parse_unsigned(line.substr(space + 1), key);
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1;
    }
    return std::unexpected(std::string{"missing cgroup counter: "} + std::string{key});
}

auto contains_word(std::string_view words, std::string_view expected) -> bool {
    std::size_t offset = 0;
    while (offset < words.size()) {
        const auto first = words.find_first_not_of(" \t\r\n", offset);
        if (first == std::string_view::npos) {
            return false;
        }
        const auto end = words.find_first_of(" \t\r\n", first);
        const auto word =
            words.substr(first, end == std::string_view::npos ? words.size() - first : end - first);
        if (word == expected) {
            return true;
        }
        if (end == std::string_view::npos) {
            return false;
        }
        offset = end + 1;
    }
    return false;
}

auto valid_session_id(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 64 &&
           std::all_of(value.begin(), value.end(), [](char character) {
               const auto byte = static_cast<unsigned char>(character);
               return std::isalnum(byte) || character == '-' || character == '_' ||
                      character == '.';
           });
}

auto current_cgroup_membership()
    -> std::expected<std::optional<std::filesystem::path>, std::string> {
    unique_fd fd{::open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (fd.get() < 0) {
        return std::unexpected(std::string{"open /proc/self/cgroup: "} + std::strerror(errno));
    }
    auto content = read_fd_bounded(fd.get(), "/proc/self/cgroup");
    if (!content) {
        return std::unexpected(content.error());
    }
    std::size_t offset = 0;
    while (offset < content->size()) {
        const auto end = content->find('\n', offset);
        const auto line = std::string_view{*content}.substr(
            offset, end == std::string::npos ? content->size() - offset : end - offset
        );
        if (line.starts_with("0::/")) {
            const auto relative = line.substr(4);
            std::filesystem::path path{"/sys/fs/cgroup"};
            if (!relative.empty()) {
                path /= relative;
            }
            return std::optional<std::filesystem::path>{path.lexically_normal()};
        }
        if (end == std::string::npos) {
            break;
        }
        offset = end + 1;
    }
    return std::optional<std::filesystem::path>{};
}

auto current_cgroup_path() -> std::expected<std::filesystem::path, std::string> {
    auto membership = current_cgroup_membership();
    if (!membership) {
        return std::unexpected(membership.error());
    }
    if (!*membership) {
        return std::unexpected(std::string{"unified cgroup v2 membership not found"});
    }
    return std::move(**membership);
}

auto probe_user_namespace() -> std::expected<bool, std::string> {
    std::array<int, 2> pipe_descriptors{-1, -1};
    if (::pipe(pipe_descriptors.data()) != 0) {
        return std::unexpected(std::string{"probe user namespace pipe: "} + std::strerror(errno));
    }
    unique_fd read_end{pipe_descriptors[0]};
    unique_fd write_end{pipe_descriptors[1]};
    const auto child = ::fork();
    if (child < 0) {
        return std::unexpected(std::string{"probe user namespace fork: "} + std::strerror(errno));
    }
    if (child == 0) {
        read_end.reset();
        if (::unshare(CLONE_NEWUSER) == 0) {
            ::_exit(0);
        }
        const int failure = errno;
        const auto* bytes = reinterpret_cast<const unsigned char*>(&failure);
        std::size_t written = 0;
        while (written < sizeof(failure)) {
            const auto amount =
                ::write(write_end.get(), bytes + written, sizeof(failure) - written);
            if (amount > 0) {
                written += static_cast<std::size_t>(amount);
            } else if (amount < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
        ::_exit(1);
    }
    write_end.reset();
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return std::unexpected(
                std::string{"probe user namespace wait: "} + std::strerror(errno)
            );
        }
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return true;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 1) {
        return std::unexpected(std::string{"probe user namespace child failed"});
    }
    int failure = 0;
    auto* bytes = reinterpret_cast<unsigned char*>(&failure);
    std::size_t received = 0;
    while (received < sizeof(failure)) {
        const auto amount = ::read(read_end.get(), bytes + received, sizeof(failure) - received);
        if (amount > 0) {
            received += static_cast<std::size_t>(amount);
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    if (received != sizeof(failure)) {
        return std::unexpected(std::string{"probe user namespace result is incomplete"});
    }
    switch (failure) {
    case EACCES:
    case EINVAL:
    case ENOSPC:
    case ENOSYS:
    case EPERM:
    case EUSERS:
        return false;
    default:
        return std::unexpected(
            std::string{"probe user namespace creation: "} + std::strerror(failure)
        );
    }
}

auto current_cgroup_is_exclusive(int directory_fd) -> std::expected<bool, std::string> {
    auto processes = read_at(directory_fd, "cgroup.procs");
    if (!processes) {
        return std::unexpected(processes.error());
    }
    const auto current = static_cast<std::uint64_t>(::getpid());
    bool found_current = false;
    std::size_t offset = 0;
    while (offset < processes->size()) {
        while (offset < processes->size() &&
               std::isspace(static_cast<unsigned char>((*processes)[offset])) != 0) {
            ++offset;
        }
        if (offset == processes->size()) {
            break;
        }
        const auto end = processes->find_first_of(" \t\r\n", offset);
        const auto field = std::string_view{*processes}.substr(
            offset, end == std::string::npos ? processes->size() - offset : end - offset
        );
        std::uint64_t process = 0;
        const auto parsed = std::from_chars(field.data(), field.data() + field.size(), process);
        if (parsed.ec != std::errc{} || parsed.ptr != field.data() + field.size()) {
            return std::unexpected(std::string{"parse delegated cgroup membership"});
        }
        if (process != current) {
            return false;
        }
        found_current = true;
        if (end == std::string::npos) {
            break;
        }
        offset = end + 1U;
    }
    if (!found_current) {
        return std::unexpected(std::string{"current process is absent from delegated cgroup"});
    }
    return true;
}

auto create_unique_host_leaf(int root_fd) -> std::expected<std::string, std::string> {
    const auto base = std::string{"glove-host-"} + std::to_string(::getpid()) + "-" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    for (unsigned int attempt = 0; attempt < 16; ++attempt) {
        auto name = base + "-" + std::to_string(attempt);
        if (::mkdirat(root_fd, name.c_str(), 0700) == 0) {
            return name;
        }
        if (errno != EEXIST) {
            return std::unexpected(std::string{"create cgroup host leaf: "} + std::strerror(errno));
        }
    }
    return std::unexpected(std::string{"cannot allocate unique cgroup host leaf"});
}

struct systemd_delegated_parent {
    unique_fd directory;
    std::filesystem::path path;
    bool enabled_controllers = false;
};

auto prepare_systemd_delegated_parent(const std::filesystem::path& current_path)
    -> std::expected<std::optional<systemd_delegated_parent>, std::string> {
    if (current_path.filename() != std::filesystem::path{systemd_delegate_subgroup}) {
        return std::optional<systemd_delegated_parent>{};
    }
    const auto parent_path = current_path.parent_path();
    if (parent_path.empty() || parent_path == current_path ||
        parent_path == std::filesystem::path{"/sys/fs/cgroup"}) {
        return std::unexpected(std::string{"systemd delegate subgroup parent is invalid"});
    }
    unique_fd current_fd{
        ::open(current_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    unique_fd parent_fd{
        ::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (current_fd.get() < 0 || parent_fd.get() < 0) {
        return std::unexpected(
            std::string{"open systemd delegated cgroup: "} + std::strerror(errno)
        );
    }
    struct stat current_status{};
    struct stat parent_status{};
    struct stat linked_status{};
    if (::fstat(current_fd.get(), &current_status) != 0 ||
        ::fstat(parent_fd.get(), &parent_status) != 0 ||
        ::fstatat(
            parent_fd.get(),
            std::string{systemd_delegate_subgroup}.c_str(),
            &linked_status,
            AT_SYMLINK_NOFOLLOW
        ) != 0) {
        return std::unexpected(
            std::string{"inspect systemd delegated cgroup: "} + std::strerror(errno)
        );
    }
    const auto protected_directory = [](const struct stat& status) {
        return S_ISDIR(status.st_mode) && status.st_uid == ::geteuid() &&
               (static_cast<unsigned int>(status.st_mode) & 0022U) == 0U;
    };
    if (!protected_directory(current_status) || !protected_directory(parent_status) ||
        current_status.st_dev != linked_status.st_dev ||
        current_status.st_ino != linked_status.st_ino) {
        return std::unexpected(std::string{"systemd delegate subgroup identity is invalid"});
    }
    auto exclusive = current_cgroup_is_exclusive(current_fd.get());
    if (!exclusive) {
        return std::unexpected(exclusive.error());
    }
    if (!*exclusive) {
        return std::unexpected(std::string{"systemd delegate subgroup is not process-exclusive"});
    }
    auto parent_processes = read_at(parent_fd.get(), "cgroup.procs");
    if (!parent_processes) {
        return std::unexpected(parent_processes.error());
    }
    if (!parent_processes->empty()) {
        return std::unexpected(std::string{"systemd delegated cgroup contains internal processes"});
    }
    auto controllers = read_at(parent_fd.get(), "cgroup.controllers");
    if (!controllers) {
        return std::unexpected(controllers.error());
    }
    for (const auto required : {"cpu", "memory", "pids"}) {
        if (!contains_word(*controllers, required)) {
            return std::unexpected(
                std::string{"systemd delegated cgroup is missing controller: "} + required
            );
        }
    }
    auto subtree = read_at(parent_fd.get(), "cgroup.subtree_control");
    if (!subtree) {
        return std::unexpected(subtree.error());
    }
    const bool cpu = contains_word(*subtree, "cpu");
    const bool memory = contains_word(*subtree, "memory");
    const bool pids = contains_word(*subtree, "pids");
    if ((cpu || memory || pids) && !(cpu && memory && pids)) {
        return std::unexpected(std::string{"systemd delegated controllers are partially enabled"});
    }
    bool enabled_controllers = false;
    if (!(cpu && memory && pids)) {
        auto enabled = write_at(parent_fd.get(), "cgroup.subtree_control", required_controllers);
        if (!enabled) {
            return std::unexpected(enabled.error());
        }
        enabled_controllers = true;
        subtree = read_at(parent_fd.get(), "cgroup.subtree_control");
        if (!subtree || !contains_word(*subtree, "cpu") || !contains_word(*subtree, "memory") ||
            !contains_word(*subtree, "pids")) {
            (void)write_at(parent_fd.get(), "cgroup.subtree_control", disabled_controllers);
            return std::unexpected(
                subtree ? std::string{"systemd delegated controllers were not enabled"}
                        : subtree.error()
            );
        }
    }
    return std::optional<systemd_delegated_parent>{systemd_delegated_parent{
        .directory = std::move(parent_fd),
        .path = parent_path,
        .enabled_controllers = enabled_controllers,
    }};
}

auto remove_directory_at(int parent_fd, const std::string& name) noexcept -> bool {
    return ::unlinkat(parent_fd, name.c_str(), AT_REMOVEDIR) == 0;
}

} // namespace

auto probe_linux_session_prerequisite() -> std::expected<linux_session_prerequisite, std::string> {
    auto user_namespace = probe_user_namespace();
    if (!user_namespace) {
        return std::unexpected(user_namespace.error());
    }
    if (!*user_namespace) {
        return linux_session_prerequisite::user_namespace_unavailable;
    }

    struct statfs cgroup_filesystem{};
    if (::statfs("/sys/fs/cgroup", &cgroup_filesystem) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return linux_session_prerequisite::cgroup_v2_unavailable;
        }
        return std::unexpected(std::string{"probe cgroup v2 filesystem: "} + std::strerror(errno));
    }
    if (static_cast<unsigned long>(cgroup_filesystem.f_type) !=
        static_cast<unsigned long>(CGROUP2_SUPER_MAGIC)) {
        return linux_session_prerequisite::cgroup_v2_unavailable;
    }

    auto membership = current_cgroup_membership();
    if (!membership) {
        return std::unexpected(membership.error());
    }
    if (!*membership) {
        // The cgroup filesystem above was positively identified as cgroup v2.
        // Missing unified membership is therefore inconsistent or malformed
        // process state, not an environmental absence that acceptance tests
        // may skip.
        return std::unexpected(std::string{"unified cgroup v2 membership not found"});
    }
    unique_fd root_fd{
        ::open((*membership)->c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (root_fd.get() < 0) {
        if (errno == EACCES || errno == ENOENT || errno == ENOTDIR) {
            return linux_session_prerequisite::cgroup_delegation_unavailable;
        }
        return std::unexpected(std::string{"probe delegated cgroup: "} + std::strerror(errno));
    }

    const auto file_exists = [&](const char* name) -> std::expected<bool, std::string> {
        struct stat status{};
        if (::fstatat(root_fd.get(), name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
            return S_ISREG(status.st_mode);
        }
        if (errno == ENOENT) {
            return false;
        }
        return std::unexpected(
            std::string{"probe delegated cgroup control file: "} + std::strerror(errno)
        );
    };
    auto controllers_file = file_exists("cgroup.controllers");
    if (!controllers_file) {
        return std::unexpected(controllers_file.error());
    }
    if (!*controllers_file) {
        return linux_session_prerequisite::cgroup_controllers_unavailable;
    }
    for (const auto* name : {"cgroup.procs", "cgroup.subtree_control"}) {
        auto present = file_exists(name);
        if (!present) {
            return std::unexpected(present.error());
        }
        if (!*present) {
            return linux_session_prerequisite::cgroup_delegation_unavailable;
        }
    }

    auto controllers = read_at(root_fd.get(), "cgroup.controllers");
    if (!controllers) {
        return std::unexpected(controllers.error());
    }
    for (const auto required : {"cpu", "memory", "pids"}) {
        if (!contains_word(*controllers, required)) {
            return linux_session_prerequisite::cgroup_controllers_unavailable;
        }
    }
    auto subtree = read_at(root_fd.get(), "cgroup.subtree_control");
    if (!subtree) {
        return std::unexpected(subtree.error());
    }
    if (contains_word(*subtree, "cpu") || contains_word(*subtree, "memory") ||
        contains_word(*subtree, "pids")) {
        return linux_session_prerequisite::cgroup_delegation_unavailable;
    }

    struct statvfs mount_status{};
    if (::fstatvfs(root_fd.get(), &mount_status) != 0) {
        return std::unexpected(
            std::string{"probe delegated cgroup mount: "} + std::strerror(errno)
        );
    }
    if ((mount_status.f_flag & ST_RDONLY) != 0U) {
        return linux_session_prerequisite::cgroup_delegation_unavailable;
    }
    for (const auto* name : {".", "cgroup.procs", "cgroup.subtree_control"}) {
        if (::faccessat(root_fd.get(), name, W_OK, AT_EACCESS) != 0) {
            if (errno == EACCES || errno == EPERM || errno == EROFS) {
                return linux_session_prerequisite::cgroup_delegation_unavailable;
            }
            return std::unexpected(
                std::string{"probe delegated cgroup write access: "} + std::strerror(errno)
            );
        }
    }
    auto exclusive = current_cgroup_is_exclusive(root_fd.get());
    if (!exclusive) {
        return std::unexpected(exclusive.error());
    }
    if (!*exclusive) {
        return linux_session_prerequisite::cgroup_delegation_unavailable;
    }
    return linux_session_prerequisite::available;
}

cgroup_v2_session::cgroup_v2_session(
    int parent_fd, int directory_fd, std::filesystem::path path, std::string directory_name
)
    : parent_fd_{parent_fd},
      directory_fd_{directory_fd},
      path_{std::move(path)},
      directory_name_{std::move(directory_name)} {}

cgroup_v2_session::cgroup_v2_session(cgroup_v2_session&& other) noexcept
    : parent_fd_{std::exchange(other.parent_fd_, -1)},
      directory_fd_{std::exchange(other.directory_fd_, -1)},
      path_{std::move(other.path_)},
      directory_name_{std::move(other.directory_name_)} {}

cgroup_v2_session::~cgroup_v2_session() {
    try {
        (void)cleanup();
    } catch (...) {
        // Destruction remains best-effort; explicit cleanup reports failures.
    }
    close_descriptors();
}

void cgroup_v2_session::close_descriptors() noexcept {
    if (directory_fd_ >= 0) {
        ::close(directory_fd_);
        directory_fd_ = -1;
    }
    if (parent_fd_ >= 0) {
        ::close(parent_fd_);
        parent_fd_ = -1;
    }
}

auto cgroup_v2_session::attach(::pid_t pid) const -> std::expected<void, std::string> {
    if (directory_fd_ < 0 || pid <= 0) {
        return std::unexpected(std::string{"invalid cgroup session or pid"});
    }
    return write_at(directory_fd_, "cgroup.procs", std::to_string(pid));
}

auto cgroup_v2_session::observe() const -> std::expected<cgroup_observation, std::string> {
    if (directory_fd_ < 0) {
        return std::unexpected(std::string{"cgroup session is closed"});
    }
    auto cpu = read_at(directory_fd_, "cpu.stat");
    auto memory_peak = read_at(directory_fd_, "memory.peak");
    auto pids_peak = read_at(directory_fd_, "pids.peak");
    auto memory_events = read_at(directory_fd_, "memory.events.local");
    auto pid_events = read_at(directory_fd_, "pids.events");
    if (!cpu || !memory_peak || !pids_peak || !memory_events || !pid_events) {
        const std::array results = {&cpu, &memory_peak, &pids_peak, &memory_events, &pid_events};
        for (const auto* result : results) {
            if (!*result) {
                return std::unexpected(result->error());
            }
        }
    }
    auto usage_usec = keyed_counter(*cpu, "usage_usec");
    auto memory = parse_unsigned(*memory_peak, "memory.peak");
    auto pids = parse_unsigned(*pids_peak, "pids.peak");
    auto memory_max = keyed_counter(*memory_events, "max");
    auto oom_kill = keyed_counter(*memory_events, "oom_kill");
    auto pid_max = keyed_counter(*pid_events, "max");
    if (!usage_usec || !memory || !pids || !memory_max || !oom_kill || !pid_max) {
        const std::array results = {&usage_usec, &memory, &pids, &memory_max, &oom_kill, &pid_max};
        for (const auto* result : results) {
            if (!*result) {
                return std::unexpected(result->error());
            }
        }
    }
    if (*pids > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"pids.peak exceeds receipt representation"});
    }
    return cgroup_observation{
        .cpu_time_ms = *usage_usec / 1000,
        .peak_memory_bytes = *memory,
        .peak_pids = static_cast<std::uint32_t>(*pids),
        .memory_limit_hit = *memory_max > 0 || *oom_kill > 0,
        .pid_limit_hit = *pid_max > 0,
    };
}

cgroup_limit_result cgroup_v2_session::triggered_limit(const resource_limits& limits) const {
    auto observation = observe();
    if (!observation) {
        return std::unexpected(observation.error());
    }
    if (observation->memory_limit_hit) {
        return cgroup_limit_event::memory;
    }
    if (observation->pid_limit_hit) {
        return cgroup_limit_event::pids;
    }
    if (observation->cpu_time_ms >= limits.cpu_time_ms) {
        return cgroup_limit_event::cpu_time;
    }
    return std::nullopt;
}

auto cgroup_v2_session::kill_all() const -> std::expected<void, std::string> {
    if (directory_fd_ < 0) {
        return std::unexpected(std::string{"cgroup session is closed"});
    }
    unique_fd kill_fd{::openat(directory_fd_, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (kill_fd.get() >= 0) {
        return write_all(kill_fd.get(), "1", "cgroup.kill");
    }
    if (errno != ENOENT) {
        return std::unexpected(std::string{"open cgroup.kill: "} + std::strerror(errno));
    }
    auto processes = read_at(directory_fd_, "cgroup.procs");
    if (!processes) {
        return std::unexpected(processes.error());
    }
    std::size_t offset = 0;
    while (offset < processes->size()) {
        const auto end = processes->find('\n', offset);
        const auto line = std::string_view{*processes}.substr(
            offset, end == std::string::npos ? processes->size() - offset : end - offset
        );
        if (!line.empty()) {
            auto parsed = parse_unsigned(line, "cgroup.procs");
            if (!parsed ||
                *parsed > static_cast<std::uint64_t>(std::numeric_limits<::pid_t>::max())) {
                return std::unexpected(
                    parsed ? std::string{"cgroup pid exceeds pid_t"} : parsed.error()
                );
            }
            if (::kill(static_cast<::pid_t>(*parsed), SIGKILL) < 0 && errno != ESRCH) {
                return std::unexpected(std::string{"kill cgroup member: "} + std::strerror(errno));
            }
        }
        if (end == std::string::npos) {
            break;
        }
        offset = end + 1;
    }
    return {};
}

auto cgroup_v2_session::cleanup() -> std::expected<void, std::string> {
    if (directory_fd_ < 0 || parent_fd_ < 0 || directory_name_.empty()) {
        return {};
    }
    auto processes = read_at(directory_fd_, "cgroup.procs");
    if (!processes) {
        return std::unexpected(processes.error());
    }
    if (!processes->empty()) {
        if (auto killed = kill_all(); !killed) {
            return killed;
        }
        for (unsigned int attempt = 0; attempt < 100; ++attempt) {
            ::usleep(10U * 1000U);
            processes = read_at(directory_fd_, "cgroup.procs");
            if (!processes) {
                return std::unexpected(processes.error());
            }
            if (processes->empty()) {
                break;
            }
        }
        if (!processes->empty()) {
            return std::unexpected(std::string{"cgroup still populated after kill request"});
        }
    }
    ::close(directory_fd_);
    directory_fd_ = -1;
    if (!remove_directory_at(parent_fd_, directory_name_)) {
        return std::unexpected(std::string{"remove cgroup session: "} + std::strerror(errno));
    }
    directory_name_.clear();
    path_.clear();
    return {};
}

cgroup_v2_root::cgroup_v2_root(
    int directory_fd,
    std::filesystem::path path,
    std::string host_leaf_name,
    bool enabled_controllers,
    bool owns_host_leaf
)
    : directory_fd_{directory_fd},
      path_{std::move(path)},
      host_leaf_name_{std::move(host_leaf_name)},
      enabled_controllers_{enabled_controllers},
      owns_host_leaf_{owns_host_leaf} {}

cgroup_v2_root::cgroup_v2_root(cgroup_v2_root&& other) noexcept
    : directory_fd_{std::exchange(other.directory_fd_, -1)},
      path_{std::move(other.path_)},
      host_leaf_name_{std::move(other.host_leaf_name_)},
      enabled_controllers_{std::exchange(other.enabled_controllers_, false)},
      owns_host_leaf_{std::exchange(other.owns_host_leaf_, false)} {}

cgroup_v2_root::~cgroup_v2_root() {
    try {
        release();
    } catch (...) {
        // Destruction remains best-effort; the descriptor still must close.
    }
    if (directory_fd_ >= 0) {
        ::close(directory_fd_);
        directory_fd_ = -1;
    }
}

auto cgroup_v2_root::prepare_for_current_process() -> std::expected<cgroup_v2_root, std::string> {
    auto path = current_cgroup_path();
    if (!path) {
        return std::unexpected(path.error());
    }
    auto systemd_parent = prepare_systemd_delegated_parent(*path);
    if (!systemd_parent) {
        return std::unexpected(systemd_parent.error());
    }
    if (*systemd_parent) {
        auto prepared = std::move(**systemd_parent);
        return cgroup_v2_root{
            prepared.directory.release(),
            std::move(prepared.path),
            std::string{systemd_delegate_subgroup},
            prepared.enabled_controllers,
            false,
        };
    }
    unique_fd root_fd{::open(path->c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (root_fd.get() < 0) {
        return std::unexpected(std::string{"open delegated cgroup: "} + std::strerror(errno));
    }
    auto controllers = read_at(root_fd.get(), "cgroup.controllers");
    if (!controllers) {
        return std::unexpected(controllers.error());
    }
    for (const auto required : {"cpu", "memory", "pids"}) {
        if (!contains_word(*controllers, required)) {
            return std::unexpected(
                std::string{"delegated cgroup is missing controller: "} + required
            );
        }
    }
    auto subtree = read_at(root_fd.get(), "cgroup.subtree_control");
    if (!subtree) {
        return std::unexpected(subtree.error());
    }
    const bool already_enabled = contains_word(*subtree, "cpu") &&
                                 contains_word(*subtree, "memory") &&
                                 contains_word(*subtree, "pids");
    if (already_enabled) {
        return std::unexpected(
            std::string{"current cgroup already delegates controllers and may not host glove"}
        );
    }

    auto host_name = create_unique_host_leaf(root_fd.get());
    if (!host_name) {
        return std::unexpected(host_name.error());
    }
    unique_fd host_fd{
        ::openat(root_fd.get(), host_name->c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (host_fd.get() < 0) {
        const int saved = errno;
        remove_directory_at(root_fd.get(), *host_name);
        return std::unexpected(std::string{"open cgroup host leaf: "} + std::strerror(saved));
    }
    if (auto moved = write_at(host_fd.get(), "cgroup.procs", std::to_string(::getpid())); !moved) {
        remove_directory_at(root_fd.get(), *host_name);
        return std::unexpected(moved.error());
    }
    if (auto enabled = write_at(root_fd.get(), "cgroup.subtree_control", required_controllers);
        !enabled) {
        (void)write_at(root_fd.get(), "cgroup.procs", std::to_string(::getpid()));
        remove_directory_at(root_fd.get(), *host_name);
        return std::unexpected(enabled.error());
    }
    return cgroup_v2_root{root_fd.release(), *path, std::move(*host_name), true, true};
}

cgroup_session_result
cgroup_v2_root::create_session(std::string_view session_id, const resource_limits& limits) const {
    if (directory_fd_ < 0) {
        return std::unexpected(std::string{"cgroup root is closed"});
    }
    if (!valid_session_id(session_id)) {
        return std::unexpected(std::string{"invalid bounded cgroup session id"});
    }
    if (limits.cpu_time_ms == 0 || limits.memory_bytes == 0 || limits.pids == 0) {
        return std::unexpected(std::string{"cgroup resource limits must be non-zero"});
    }
    std::string name = "glove-session-" + std::string{session_id};
    if (::mkdirat(directory_fd_, name.c_str(), 0700) < 0) {
        return std::unexpected(std::string{"create cgroup session: "} + std::strerror(errno));
    }
    unique_fd session_fd{
        ::openat(directory_fd_, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (session_fd.get() < 0) {
        const int saved = errno;
        remove_directory_at(directory_fd_, name);
        return std::unexpected(std::string{"open cgroup session: "} + std::strerror(saved));
    }
    auto fail = [&](std::string message) -> cgroup_session_result {
        session_fd.reset();
        remove_directory_at(directory_fd_, name);
        return std::unexpected(std::move(message));
    };
    if (auto memory = write_at(session_fd.get(), "memory.max", std::to_string(limits.memory_bytes));
        !memory) {
        return fail(memory.error());
    }
    if (auto swap = write_at(session_fd.get(), "memory.swap.max", "0", true); !swap) {
        return fail(swap.error());
    }
    if (auto oom_group = write_at(session_fd.get(), "memory.oom.group", "1", true); !oom_group) {
        return fail(oom_group.error());
    }
    if (auto pids = write_at(session_fd.get(), "pids.max", std::to_string(limits.pids)); !pids) {
        return fail(pids.error());
    }
    auto parent_copy = duplicate_fd(directory_fd_);
    if (!parent_copy) {
        return fail(parent_copy.error());
    }
    return cgroup_v2_session{*parent_copy, session_fd.release(), path_ / name, std::move(name)};
}

cgroup_session_result cgroup_v2_root::adopt_session(
    std::string_view session_id, std::uint64_t expected_device, std::uint64_t expected_inode
) const {
    if (directory_fd_ < 0) {
        return std::unexpected(std::string{"cgroup root is closed"});
    }
    if (!valid_session_id(session_id) || expected_device == 0 || expected_inode == 0) {
        return std::unexpected(std::string{"invalid cgroup adoption identity"});
    }
    std::string name = "glove-session-" + std::string{session_id};
    unique_fd session_fd{
        ::openat(directory_fd_, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (session_fd.get() < 0) {
        return std::unexpected(
            std::string{"open cgroup session for adoption: "} + std::strerror(errno)
        );
    }

    struct stat status{};

    if (::fstat(session_fd.get(), &status) < 0) {
        return std::unexpected(
            std::string{"inspect cgroup session for adoption: "} + std::strerror(errno)
        );
    }
    if (!S_ISDIR(status.st_mode) || static_cast<std::uint64_t>(status.st_dev) != expected_device ||
        static_cast<std::uint64_t>(status.st_ino) != expected_inode) {
        return std::unexpected(std::string{"cgroup session adoption identity mismatch"});
    }
    auto parent_copy = duplicate_fd(directory_fd_);
    if (!parent_copy) {
        return std::unexpected(parent_copy.error());
    }
    return cgroup_v2_session{*parent_copy, session_fd.release(), path_ / name, std::move(name)};
}

auto cgroup_v2_root::cleanup_session_if_matches(
    std::string_view session_id, std::uint64_t expected_device, std::uint64_t expected_inode
) const -> std::expected<void, std::string> {
    if (directory_fd_ < 0 || !valid_session_id(session_id) || expected_device == 0 ||
        expected_inode == 0) {
        return std::unexpected(std::string{"invalid cgroup cleanup identity"});
    }
    std::string name = "glove-session-" + std::string{session_id};
    unique_fd session_fd{
        ::openat(directory_fd_, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (session_fd.get() < 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(
            std::string{"open cgroup session for cleanup: "} + std::strerror(errno)
        );
    }

    struct stat status{};

    if (::fstat(session_fd.get(), &status) < 0) {
        return std::unexpected(
            std::string{"inspect cgroup session for cleanup: "} + std::strerror(errno)
        );
    }
    if (!S_ISDIR(status.st_mode) || static_cast<std::uint64_t>(status.st_dev) != expected_device ||
        static_cast<std::uint64_t>(status.st_ino) != expected_inode) {
        return std::unexpected(std::string{"cgroup session cleanup identity mismatch"});
    }
    auto parent_copy = duplicate_fd(directory_fd_);
    if (!parent_copy) {
        return std::unexpected(parent_copy.error());
    }
    cgroup_v2_session adopted{*parent_copy, session_fd.release(), path_ / name, std::move(name)};
    return adopted.cleanup();
}

void cgroup_v2_root::release() {
    if (directory_fd_ < 0) {
        return;
    }
    if (enabled_controllers_) {
        if (write_at(directory_fd_, "cgroup.subtree_control", disabled_controllers) &&
            owns_host_leaf_) {
            (void)write_at(directory_fd_, "cgroup.procs", std::to_string(::getpid()));
            (void)remove_directory_at(directory_fd_, host_leaf_name_);
        }
    }
    ::close(directory_fd_);
    directory_fd_ = -1;
    path_.clear();
    host_leaf_name_.clear();
    enabled_controllers_ = false;
    owns_host_leaf_ = false;
}

} // namespace glove::container::linux_detail
