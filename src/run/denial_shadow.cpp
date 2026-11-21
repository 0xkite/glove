#include "denial_shadow.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <system_error>
#include <utility>

namespace glove::run::detail {

namespace {

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

auto refuse(std::string_view why) -> std::unexpected<std::string> {
    return std::unexpected("denial model: " + std::string{why});
}

// True when PATH is ROOT or lies under it on a component boundary.
auto within(const std::filesystem::path& path, const std::filesystem::path& root) -> bool {
    return !root.empty() &&
           std::mismatch(root.begin(), root.end(), path.begin(), path.end()).first == root.end();
}

} // namespace

auto load_shadow_decider(const std::filesystem::path& path, std::span<const std::string> exposed)
    -> std::expected<std::shared_ptr<const glove::container::denial_decider>, std::string> {
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(path, ec).lexically_normal();
    if (ec || !absolute.has_filename()) {
        return refuse("path is not a file path");
    }
    const auto resolved = std::filesystem::weakly_canonical(absolute, ec);
    if (ec) {
        return refuse("path cannot be resolved");
    }
    for (const auto& grant : exposed) {
        const std::filesystem::path root{grant};
        auto canonical_root = std::filesystem::weakly_canonical(root, ec);
        if (ec) {
            canonical_root = root;
        }
        if (within(resolved, root) || within(resolved, canonical_root) || within(absolute, root)) {
            return refuse("the sandbox can reach the file");
        }
    }

    const descriptor file{::open(absolute.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
    if (file.get() < 0) {
        return refuse(errno == ENOENT ? "no such file" : "cannot open the file");
    }
    struct stat metadata{};
    if (::fstat(file.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_nlink != 1) {
        return refuse("not one regular file");
    }
    if ((metadata.st_uid != ::geteuid() && metadata.st_uid != 0) ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return refuse("another user could have written the file");
    }
    if (metadata.st_size <= 0 ||
        std::cmp_greater(metadata.st_size, glove::container::max_denial_model_bytes)) {
        return refuse("file is empty or too large");
    }
    std::string text(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t filled = 0;
    while (filled < text.size()) {
        const auto got = ::read(file.get(), text.data() + filled, text.size() - filled);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return refuse("cannot read the file");
        }
        filled += static_cast<std::size_t>(got);
    }
    auto loaded = glove::container::load_denial_model(text);
    if (!loaded) {
        return refuse("file is not a valid model for this feature schema");
    }
    return std::shared_ptr<const glove::container::denial_decider>{std::move(*loaded)};
}

} // namespace glove::run::detail
