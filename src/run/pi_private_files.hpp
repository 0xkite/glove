#pragma once

#include "glove/detail/descriptor_acl.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::run::detail::private_files {

template<typename T> using result = std::expected<T, std::string>;
inline constexpr int directory_flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

class descriptor {
public:
    explicit descriptor(int value = -1) noexcept : value_{value} {}

    descriptor(const descriptor&) = delete;
    auto operator=(const descriptor&) -> descriptor& = delete;

    descriptor(descriptor&& other) noexcept : value_{std::exchange(other.value_, -1)} {}

    auto operator=(descriptor&& other) noexcept -> descriptor& {
        if (this != &other) {
            descriptor previous{std::exchange(value_, std::exchange(other.value_, -1))};
        }
        return *this;
    }

    ~descriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return value_; }

    auto release() noexcept -> int { return std::exchange(value_, -1); }

private:
    int value_;
};

inline auto failure(std::string_view operation) -> std::unexpected<std::string> {
    const int saved = errno;
    return std::unexpected(
        std::string{operation} + ": " + std::error_code{saved, std::generic_category()}.message()
    );
}

inline auto same(const struct stat& left, const struct stat& right) -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_uid == right.st_uid && left.st_gid == right.st_gid &&
           left.st_mode == right.st_mode;
}

inline auto stable_bytes(const struct stat& left, const struct stat& right) -> bool {
    if (!same(left, right) || left.st_size != right.st_size || left.st_nlink != right.st_nlink) {
        return false;
    }
#if defined(__APPLE__)
    return left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
           left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
           left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
#else
    return left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
           left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
#endif
}

inline auto safe_directory(const struct stat& info, bool parent) -> bool {
    if (!S_ISDIR(info.st_mode) || info.st_nlink == 0) {
        return false;
    }
    const auto mode = info.st_mode & 07777U;
    if (parent) {
        return info.st_uid == ::geteuid() && mode == 0700U;
    }
    // The only writable-ancestor exception is a root-owned sticky temp fixture
    // namespace. No symlink exception (not even /var -> /private/var on Darwin).
    return (info.st_uid == 0 || info.st_uid == ::geteuid()) &&
           (((mode & 0022U) == 0 && (mode & 07000U) == 0) || (info.st_uid == 0 && mode == 01777U));
}

struct edge {
    descriptor fd;
    std::string name;
    struct stat identity{};
};

struct pinned_parent {
    std::vector<edge> chain;

    auto fd() const -> int { return chain.back().fd.get(); }

    auto check() const -> result<void> {
        for (std::size_t index = 0; index < chain.size(); ++index) {
            const auto& item = chain[index];
            struct stat opened{};
            struct stat named{};
            if (::fstat(item.fd.get(), &opened) != 0 ||
                (index != 0 &&
                 ::fstatat(
                     chain[index - 1].fd.get(), item.name.c_str(), &named, AT_SYMLINK_NOFOLLOW
                 ) != 0)) {
                return failure("reinspect Pi parent ancestry");
            }
            if (!same(opened, item.identity) ||
                !safe_directory(opened, index + 1 == chain.size()) ||
                (index != 0 && !same(opened, named))) {
                return std::unexpected("Pi parent ancestry changed or is unsafe");
            }
            if (auto acl = glove::detail::check_descriptor_acl(
                    item.fd.get(),
                    index + 1 == chain.size() ? glove::detail::acl_scope::owner_private
                                              : glove::detail::acl_scope::integrity
                );
                !acl) {
                return acl;
            }
        }
        return {};
    }
};

inline auto pin_parent(const std::filesystem::path& path) -> result<pinned_parent> {
    const auto text = path.native();
    if (text.size() < 2 || text.size() > 4096 || text.front() != '/' || text.back() == '/' ||
        text.find('\0') != std::string::npos) {
        return std::unexpected("Pi parent must be a bounded canonical absolute path");
    }
    pinned_parent pinned;
    descriptor root{::open("/", directory_flags)};
    struct stat root_info{};
    if (root.get() < 0 || ::fstat(root.get(), &root_info) != 0) {
        return failure("pin Pi filesystem root");
    }
    if (!safe_directory(root_info, false)) {
        return std::unexpected("unsafe Pi filesystem root");
    }
    pinned.chain.push_back({std::move(root), {}, root_info});
    std::size_t begin = 1;
    while (begin < text.size()) {
        const auto end = text.find('/', begin);
        const auto name = text.substr(begin, end == std::string::npos ? end : end - begin);
        if (name.empty() || name == "." || name == ".." || name.size() > 255 ||
            pinned.chain.size() >= 64) {
            return std::unexpected("noncanonical or overly deep Pi parent path");
        }
        const int parent_fd = pinned.fd();
        struct stat before{};
        if (::fstatat(parent_fd, name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("inspect Pi parent component");
        }
        const bool final = end == std::string::npos;
        if (!safe_directory(before, final)) {
            return std::unexpected("unsafe Pi parent component: " + name);
        }
        descriptor opened{::openat(parent_fd, name.c_str(), directory_flags)};
        struct stat actual{};
        struct stat named{};
        if (opened.get() < 0 || ::fstat(opened.get(), &actual) != 0 ||
            ::fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("pin Pi parent component");
        }
        if (!same(before, actual) || !same(actual, named) || !safe_directory(actual, final)) {
            return std::unexpected("Pi parent component changed on open");
        }
        pinned.chain.push_back({std::move(opened), name, actual});
        if (final) {
            break;
        }
        begin = end + 1;
    }
    if (auto checked = pinned.check(); !checked) {
        return std::unexpected(checked.error());
    }
    return pinned;
}

inline auto private_file(const struct stat& info, mode_t mode) -> bool {
    return S_ISREG(info.st_mode) && info.st_uid == ::geteuid() && (info.st_mode & 07777U) == mode &&
           info.st_nlink == 1;
}

inline auto
check_file(int parent, const char* name, int fd, const struct stat& identity, mode_t mode)
    -> result<void> {
    struct stat actual{};
    struct stat named{};
    if (::fstat(fd, &actual) != 0 || ::fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("reinspect Pi private file");
    }
    if (!same(identity, actual) || !same(actual, named) || !private_file(actual, mode) ||
        !private_file(named, mode) || !stable_bytes(actual, named)) {
        return std::unexpected("Pi private file changed or is unsafe");
    }
    return glove::detail::check_descriptor_acl(fd, glove::detail::acl_scope::owner_private);
}

inline auto write_bytes(int fd, std::string_view bytes) -> result<void> {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count =
            ::pwrite(fd, bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return failure("write Pi private file");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::ftruncate(fd, static_cast<off_t>(bytes.size())) != 0 || ::fsync(fd) != 0) {
        return failure("persist Pi private file");
    }
    return {};
}

} // namespace glove::run::detail::private_files
