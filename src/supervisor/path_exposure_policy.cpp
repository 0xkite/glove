#include "glove/supervisor/path_exposure.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace exposure_policy_wire {

struct mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct root {
    std::string root_id;
    std::string host_root;
    std::vector<mode> allowed_modes;
    std::uint64_t max_ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

struct policy {
    std::uint8_t schema_version = 0;
    std::vector<root> roots;
};

} // namespace exposure_policy_wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::uint64_t max_policy_bytes = std::uint64_t{1024} * 1024U;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;
    unique_fd(unique_fd&&) = delete;
    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto modification_time_matches(const struct stat& left, const struct stat& right) -> bool {
#if defined(__APPLE__)
    return left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
           left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec;
#else
    return left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec;
#endif
}

auto same_file(const struct stat& left, const struct stat& right) -> bool {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_mode == right.st_mode && left.st_uid == right.st_uid &&
           left.st_nlink == right.st_nlink && left.st_size == right.st_size &&
           modification_time_matches(left, right);
}

auto load_policy_contents(const std::filesystem::path& path) -> result<std::string> {
    if (!path.is_absolute()) {
        return std::unexpected(std::string{"path exposure policy path must be absolute"});
    }
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(error_message("open path exposure policy"));
    }
    struct stat before{};
    if (::fstat(descriptor.get(), &before) != 0) {
        return std::unexpected(error_message("inspect path exposure policy"));
    }
    const auto permissions = static_cast<unsigned int>(before.st_mode) & 0777U;
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        permissions != 0600U || before.st_size <= 0 ||
        static_cast<std::uint64_t>(before.st_size) > max_policy_bytes ||
        static_cast<std::uint64_t>(before.st_size) >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::unexpected(
            std::string{"path exposure policy must be a bounded owner-only single-link file"}
        );
    }
    std::string contents(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto read = ::pread(
            descriptor.get(),
            contents.data() + consumed,
            contents.size() - consumed,
            static_cast<off_t>(consumed)
        );
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(
                read < 0 ? error_message("read path exposure policy")
                         : std::string{"path exposure policy ended unexpectedly"}
            );
        }
        consumed += static_cast<std::size_t>(read);
    }
    struct stat after{};
    if (::fstat(descriptor.get(), &after) != 0 || !same_file(before, after)) {
        return std::unexpected(std::string{"path exposure policy changed while loading"});
    }
    return contents;
}

auto parse_access(std::string_view value) -> result<path_access> {
    if (value == "read") {
        return path_access::read;
    }
    if (value == "ephemeral_write") {
        return path_access::ephemeral_write;
    }
    if (value == "retained_write") {
        return path_access::retained_write;
    }
    return std::unexpected(std::string{"path exposure policy access is invalid"});
}

auto parse_materialization(std::string_view value) -> result<path_materialization> {
    if (value == "bind") {
        return path_materialization::bind;
    }
    if (value == "git_worktree") {
        return path_materialization::git_worktree;
    }
    if (value == "copy") {
        return path_materialization::copy;
    }
    return std::unexpected(std::string{"path exposure policy materialization is invalid"});
}

auto parse_cleanup(std::string_view value) -> result<path_cleanup_policy> {
    if (value == "retain") {
        return path_cleanup_policy::retain;
    }
    if (value == "remove") {
        return path_cleanup_policy::remove;
    }
    return std::unexpected(std::string{"path exposure policy cleanup is invalid"});
}

auto parse_policy(const std::filesystem::path& policy_path)
    -> result<std::vector<path_exposure_root_policy>> {
    auto contents = load_policy_contents(policy_path);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    exposure_policy_wire::policy encoded;
    if (const auto error = glz::read<strict_read_options>(encoded, *contents);
        error || encoded.schema_version != 1) {
        return std::unexpected(std::string{"path exposure policy schema is invalid"});
    }
    std::vector<path_exposure_root_policy> roots;
    roots.reserve(encoded.roots.size());
    for (auto& encoded_root : encoded.roots) {
        std::vector<path_exposure_mode> modes;
        modes.reserve(encoded_root.allowed_modes.size());
        for (const auto& encoded_mode : encoded_root.allowed_modes) {
            auto access = parse_access(encoded_mode.access);
            auto materialization = parse_materialization(encoded_mode.materialization);
            auto cleanup = parse_cleanup(encoded_mode.cleanup_policy);
            if (!access || !materialization || !cleanup) {
                return std::unexpected(std::string{"path exposure policy mode is invalid"});
            }
            modes.push_back({
                .access = *access,
                .materialization = *materialization,
                .max_bytes = encoded_mode.max_bytes,
                .cleanup_policy = *cleanup,
            });
        }
        roots.push_back({
            .root_id = std::move(encoded_root.root_id),
            .host_root = std::move(encoded_root.host_root),
            .allowed_modes = std::move(modes),
            .max_ttl_secs = encoded_root.max_ttl_secs,
            .allowed_runtime_template_ids = std::move(encoded_root.allowed_runtime_template_ids),
        });
    }
    return roots;
}

} // namespace

auto path_exposure_registry::inspect_policy(const std::filesystem::path& policy_path)
    -> result<path_exposure_registry> {
    auto roots = parse_policy(policy_path);
    if (!roots) {
        return std::unexpected(roots.error());
    }
    return build(std::move(*roots));
}

auto path_exposure_registry::load(
    const std::filesystem::path& policy_path,
    const std::filesystem::path& journal_path,
    std::uint64_t max_journal_bytes
) -> result<path_exposure_registry> {
    auto roots = parse_policy(policy_path);
    if (!roots) {
        return std::unexpected(roots.error());
    }
    return open(std::move(*roots), journal_path, max_journal_bytes);
}

} // namespace glove::supervisor
