#include "glove/run/pi_runtime.hpp"

#include "glove/detail/descriptor_acl.hpp"

#include "../host/runtime_snapshot.hpp"
#include "pi_runtime_internal.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#    include <linux/fs.h>
#    include <sys/syscall.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <map>
#include <system_error>
#include <utility>

namespace glove::run {
namespace pi_runtime_wire {

struct selection {
    std::string schema_id = "glove.pi-runtime.v1";
    std::uint8_t schema_version = 1;
    std::string provider;
    std::string model;
    std::string source_executable;
    std::string canonical_source_executable;
    std::string source_launch_executable;
    std::string protected_entry_point;
    std::string launch_executable;
    std::vector<std::string> launch_arguments;
    std::vector<std::string> read_only_paths;
    std::vector<std::string> source_read_only_paths;
    std::string snapshot_digest;
    std::string adoption_manifest_digest;
    std::uint64_t snapshot_logical_bytes = 0;
    std::uint64_t snapshot_entries = 0;
};

} // namespace pi_runtime_wire

namespace {

constexpr std::size_t max_record_bytes = std::size_t{512} * 1024U;

auto system_error(std::string_view operation, int code = errno) -> std::string {
    return std::string{operation} + ": " + std::error_code{code, std::generic_category()}.message();
}

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_;
};

auto same_identity(const struct stat& before, const struct stat& after) noexcept -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_uid == after.st_uid && before.st_mode == after.st_mode &&
           before.st_nlink == after.st_nlink && before.st_size == after.st_size
#if defined(__APPLE__)
           && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
#else
           && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec
#endif
        ;
}

auto valid_path(const std::filesystem::path& path) -> bool {
    return path.is_absolute() && path != path.root_path() && path.lexically_normal() == path &&
           path.native().size() <= 4096U && !path.native().contains('\0');
}

auto open_parent(const std::filesystem::path& path, bool& missing)
    -> std::expected<unique_fd, std::string> {
    if (!valid_path(path) || path.filename().native().size() > 128U || path.filename().empty()) {
        return std::unexpected(
            std::string{"Pi selection requires a bounded normalized absolute file path"}
        );
    }
    unique_fd root{::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (root.get() < 0) {
        return std::unexpected(system_error("open Pi selection root"));
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(root.get(), glove::detail::acl_scope::integrity);
        !acl) {
        return std::unexpected(acl.error());
    }
    // Walk through descriptors, not canonical() followed by a pathname open.
    // Root-owned sticky ancestors permit /private/tmp fixtures without trusting
    // arbitrary group-writable ancestors or following a home-directory alias.
    int parent = root.get();
    std::vector<unique_fd> ancestors;
    for (const auto& component : path.parent_path().relative_path()) {
        const int opened =
            ::openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (opened < 0) {
            missing = errno == ENOENT;
            return std::unexpected(system_error("open Pi selection ancestor"));
        }
        ancestors.emplace_back(opened);
        struct stat metadata{};
        if (::fstat(opened, &metadata) != 0) {
            return std::unexpected(system_error("inspect Pi selection ancestor"));
        }
        const bool root_sticky = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
        if (!S_ISDIR(metadata.st_mode) ||
            (metadata.st_uid != 0 && metadata.st_uid != ::geteuid()) ||
            ((metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 && !root_sticky)) {
            return std::unexpected(std::string{"unsafe Pi selection ancestor"});
        }
        if (auto acl =
                glove::detail::check_descriptor_acl(opened, glove::detail::acl_scope::integrity);
            !acl) {
            return std::unexpected(acl.error());
        }
        parent = opened;
    }
    struct stat metadata{};
    if (::fstat(parent, &metadata) != 0 || metadata.st_uid != ::geteuid() ||
        (metadata.st_mode & 07777U) != 0700U) {
        return std::unexpected(std::string{"Pi selection parent must be owner-0700"});
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(parent, glove::detail::acl_scope::owner_private);
        !acl) {
        return std::unexpected(acl.error());
    }
    const int duplicate = ::fcntl(parent, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        return std::unexpected(system_error("pin Pi selection parent"));
    }
    return unique_fd{duplicate};
}

auto parent_matches(int parent, const std::filesystem::path& path) -> bool {
    struct stat pinned{};
    struct stat named{};
    return ::fstat(parent, &pinned) == 0 && ::lstat(path.parent_path().c_str(), &named) == 0 &&
           pinned.st_dev == named.st_dev && pinned.st_ino == named.st_ino &&
           named.st_uid == ::geteuid() && (named.st_mode & 07777U) == 0700U &&
           glove::detail::check_descriptor_acl(parent, glove::detail::acl_scope::owner_private)
               .has_value();
}

auto owner_regular(
    const struct stat& metadata, bool allow_empty = false, std::size_t byte_limit = max_record_bytes
) -> bool {
    return S_ISREG(metadata.st_mode) && metadata.st_uid == ::geteuid() && metadata.st_nlink == 1 &&
           (metadata.st_mode & 07777U) == 0600U && metadata.st_size >= (allow_empty ? 0 : 1) &&
           static_cast<std::uint64_t>(metadata.st_size) <= byte_limit;
}

struct record_file {
    std::string bytes;
    struct stat identity{};
};

auto read_record(int parent, const std::string& name, std::size_t byte_limit = max_record_bytes)
    -> std::expected<std::optional<record_file>, std::string> {
    const unique_fd descriptor{
        ::openat(parent, name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    };
    if (descriptor.get() < 0) {
        if (errno == ENOENT) {
            return std::nullopt;
        }
        return std::unexpected(system_error("open Pi selection"));
    }
    struct stat before{};
    if (::fstat(descriptor.get(), &before) != 0 || !owner_regular(before, false, byte_limit)) {
        return std::unexpected(
            std::string{"Pi selection must be a bounded owner-0600 single-link regular file"}
        );
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            descriptor.get(), glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t consumed = 0;
    unsigned interruptions = 0;
    while (consumed < bytes.size()) {
        const auto count =
            ::read(descriptor.get(), bytes.data() + consumed, bytes.size() - consumed);
        if (count < 0 && errno == EINTR && ++interruptions < 8U) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(std::string{"Pi selection read failed or ended early"});
        }
        consumed += static_cast<std::size_t>(count);
    }
    struct stat after{};
    struct stat named{};
    if (::fstat(descriptor.get(), &after) != 0 ||
        ::fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_identity(before, after) || !same_identity(after, named) ||
        !glove::detail::check_descriptor_acl(
            descriptor.get(), glove::detail::acl_scope::owner_private
        )) {
        return std::unexpected(std::string{"Pi selection identity changed during read"});
    }
    return record_file{.bytes = std::move(bytes), .identity = after};
}

auto wire_selection(const pi_runtime_selection& value) -> pi_runtime_wire::selection {
    const auto paths = [](const auto& values) {
        std::vector<std::string> result;
        result.reserve(values.size());
        for (const auto& path : values) {
            result.push_back(path.string());
        }
        return result;
    };
    const auto& runtime = value.runtime;
    return {
        .schema_id = "glove.pi-runtime.v1",
        .schema_version = 1,
        .provider = std::string{pi_provider_name(value.model.provider)},
        .model = value.model.model,
        .source_executable = runtime.source_executable.string(),
        .canonical_source_executable = runtime.canonical_source_executable.string(),
        .source_launch_executable = runtime.source_launch_executable.string(),
        .protected_entry_point = runtime.protected_entry_point.string(),
        .launch_executable = runtime.launch_executable.string(),
        .launch_arguments = runtime.launch_arguments,
        .read_only_paths = paths(runtime.read_only_paths),
        .source_read_only_paths = paths(runtime.source_read_only_paths),
        .snapshot_digest = runtime.snapshot_digest,
        .adoption_manifest_digest = runtime.adoption_manifest_digest,
        .snapshot_logical_bytes = runtime.snapshot_logical_bytes,
        .snapshot_entries = runtime.snapshot_entries,
    };
}

auto encode_record(
    const pi_runtime_selection& value, std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::string, std::string> {
    if (auto model = select_pi_launch({}, value.model); !model) {
        return std::unexpected(model.error());
    }
    if (auto verified =
            host::detail::validate_pi_runtime_with_exclusions(value.runtime, source_exclusions);
        !verified) {
        return std::unexpected(verified.error());
    }
    std::string json;
    if (glz::write_json(wire_selection(value), json) || json.size() > max_record_bytes) {
        return std::unexpected(std::string{"Pi selection encoding exceeds bounds"});
    }
    return json;
}

auto decode_record(std::string_view json) -> std::expected<pi_runtime_selection, std::string> {
    if (json.empty() || json.size() > max_record_bytes) {
        return std::unexpected(std::string{"Pi selection exceeds bounds"});
    }
    pi_runtime_wire::selection wire;
    constexpr glz::opts strict{.error_on_unknown_keys = true, .error_on_missing_keys = true};
    if (glz::read<strict>(wire, json) || wire.schema_id != "glove.pi-runtime.v1" ||
        wire.schema_version != 1) {
        return std::unexpected(std::string{"malformed or unsupported Pi selection"});
    }
    auto model = select_pi_launch({.provider = wire.provider, .model = wire.model});
    if (!model) {
        return std::unexpected(model.error());
    }
    if (wire.launch_arguments.size() != 1U || wire.read_only_paths.size() != 1U ||
        wire.source_read_only_paths.empty() || wire.source_read_only_paths.size() > 64U) {
        return std::unexpected(std::string{"Pi selection closure exceeds bounds"});
    }
    const auto path_strings = {
        wire.source_executable,
        wire.canonical_source_executable,
        wire.source_launch_executable,
        wire.protected_entry_point,
        wire.launch_executable,
        wire.launch_arguments.front(),
        wire.read_only_paths.front()
    };
    if (!std::ranges::all_of(path_strings, [](const auto& path) { return valid_path(path); }) ||
        !std::ranges::all_of(wire.source_read_only_paths, [](const auto& path) {
            return valid_path(path);
        })) {
        return std::unexpected(std::string{"invalid Pi selection path"});
    }
    std::string canonical;
    if (glz::write_json(wire, canonical) || canonical != json) {
        return std::unexpected(std::string{"Pi selection is not canonical"});
    }
    std::vector<std::filesystem::path> roots;
    roots.reserve(wire.source_read_only_paths.size());
    for (const auto& path : wire.source_read_only_paths) {
        roots.emplace_back(path);
    }
    host::staged_runtime_harness runtime{
        .runtime_id = "pi",
        .executable_name = "pi",
        .source_executable = wire.source_executable,
        .protected_entry_point = wire.protected_entry_point,
        .launch_executable = wire.launch_executable,
        .launch_arguments = std::move(wire.launch_arguments),
        .read_only_paths = {wire.read_only_paths.front()},
        .snapshot_digest = std::move(wire.snapshot_digest),
        .adoption_manifest_digest = std::move(wire.adoption_manifest_digest),
        .snapshot_logical_bytes = wire.snapshot_logical_bytes,
        .snapshot_entries = wire.snapshot_entries,
        .changed = false,
    };
    runtime.canonical_source_executable = wire.canonical_source_executable;
    runtime.source_launch_executable = wire.source_launch_executable;
    runtime.source_read_only_paths = std::move(roots);
    return pi_runtime_selection{.model = std::move(model->model), .runtime = std::move(runtime)};
}

auto pin_lock(int parent, const std::string& name) -> std::expected<unique_fd, std::string> {
    int opened = ::openat(
        parent, name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600
    );
    const bool created = opened >= 0;
    if (opened < 0 && errno == EEXIST) {
        opened = ::openat(parent, name.c_str(), O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    }
    const unique_fd descriptor{opened};
    if (opened < 0 || (created && ::fchmod(opened, 0600) != 0)) {
        return std::unexpected(system_error("open protected Pi selection lock"));
    }
    struct stat metadata{};
    struct stat named{};
    if (::fstat(opened, &metadata) != 0 || !owner_regular(metadata, true) ||
        ::fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_identity(metadata, named)) {
        return std::unexpected(std::string{"unsafe Pi selection lock"});
    }
    if (created) {
        if (auto acl = glove::detail::clear_created_descriptor_acl(opened); !acl) {
            return std::unexpected(acl.error());
        }
    }
    if (auto acl =
            glove::detail::check_descriptor_acl(opened, glove::detail::acl_scope::owner_private);
        !acl) {
        return std::unexpected(acl.error());
    }
    if (::flock(opened, LOCK_EX | LOCK_NB) != 0) {
        return std::unexpected(system_error("Pi selection is busy; retry setup"));
    }
    const int duplicate = ::fcntl(opened, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        return std::unexpected(system_error("pin Pi selection lock"));
    }
    return unique_fd{duplicate};
}

class temporary_record {
public:
    temporary_record(int parent, std::string name, const struct stat& identity)
        : parent_{parent}, name_{std::move(name)}, identity_{identity} {}

    temporary_record(const temporary_record&) = delete;
    auto operator=(const temporary_record&) -> temporary_record& = delete;
    temporary_record(temporary_record&&) = delete;
    auto operator=(temporary_record&&) -> temporary_record& = delete;

    ~temporary_record() {
        if (active_) {
            (void)unlink_if_owned();
        }
    }

    auto remove() -> std::expected<void, std::string> {
        if (active_ && !unlink_if_owned()) {
            return std::unexpected(std::string{"Pi selection temporary-file cleanup failed"});
        }
        active_ = false;
        return {};
    }

    void renamed() noexcept { active_ = false; }

private:
    auto unlink_if_owned() noexcept -> bool {
        struct stat named{};
        return ::fstatat(parent_, name_.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
               named.st_dev == identity_.st_dev && named.st_ino == identity_.st_ino &&
               ::unlinkat(parent_, name_.c_str(), 0) == 0;
    }

    int parent_;
    std::string name_;
    struct stat identity_{};
    bool active_ = true;
};

auto load_selection_record(
    const std::filesystem::path& path,
    bool require_launch_authority,
    std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::optional<pi_runtime_selection>, std::string> {
    bool missing = false;
    auto parent = open_parent(path, missing);
    if (!parent) {
        if (missing) {
            return std::nullopt;
        }
        return std::unexpected(parent.error());
    }
    auto file = read_record(parent->get(), path.filename().string());
    if (!file) {
        return std::unexpected(file.error());
    }
    if (!*file) {
        return std::nullopt;
    }
    auto selection = decode_record((*file)->bytes);
    if (!selection) {
        return std::unexpected(selection.error());
    }
    if (require_launch_authority) {
        if (auto verified = host::detail::validate_pi_runtime_with_exclusions(
                selection->runtime, source_exclusions
            );
            !verified) {
            return std::unexpected(verified.error());
        }
    }
    auto checked_file = read_record(parent->get(), path.filename().string());
    if (!checked_file || !*checked_file ||
        !same_identity((*file)->identity, (*checked_file)->identity) ||
        (*checked_file)->bytes != (*file)->bytes || !parent_matches(parent->get(), path)) {
        return std::unexpected(std::string{"Pi selection changed during validation"});
    }
    return std::optional<pi_runtime_selection>{std::move(*selection)};
}

} // namespace

auto load_pi_runtime_selection(const std::filesystem::path& path)
    -> std::expected<std::optional<pi_runtime_selection>, std::string> {
    return load_selection_record(path, true, {});
}

namespace detail {

auto read_pi_operator_file(const std::filesystem::path& path)
    -> std::expected<std::optional<std::string>, std::string> {
    constexpr std::size_t max_operator_bytes = std::size_t{1024} * 1024U;
    if (std::distance(path.begin(), path.end()) > 128) {
        return std::unexpected(std::string{"protected operator file ancestry exceeds bounds"});
    }
    bool missing = false;
    auto parent = open_parent(path, missing);
    if (!parent) {
        if (missing) {
            return std::nullopt;
        }
        return std::unexpected(parent.error());
    }
    const auto name = path.filename().string();
    auto file = read_record(parent->get(), name, max_operator_bytes);
    if (!file) {
        return std::unexpected(file.error());
    }
    if (!*file) {
        return std::nullopt;
    }
    auto checked_file = read_record(parent->get(), name, max_operator_bytes);
    if (!checked_file || !*checked_file ||
        !same_identity((*file)->identity, (*checked_file)->identity) ||
        (*checked_file)->bytes != (*file)->bytes || !parent_matches(parent->get(), path)) {
        return std::unexpected(std::string{"protected operator file changed during admission"});
    }
    // Repeat the no-follow ancestry/ACL walk, not merely a pathname lstat that
    // could follow a replaced intermediate component. Unrelated sibling churn
    // is not a parent-binding change; same-UID atomic namespace is not claimed.
    bool now_missing = false;
    auto current_parent = open_parent(path, now_missing);
    struct stat pinned{};
    struct stat current{};
    if (!current_parent || ::fstat(parent->get(), &pinned) != 0 ||
        ::fstat(current_parent->get(), &current) != 0 || pinned.st_dev != current.st_dev ||
        pinned.st_ino != current.st_ino || pinned.st_uid != current.st_uid ||
        pinned.st_gid != current.st_gid || pinned.st_mode != current.st_mode ||
        !parent_matches(parent->get(), path)) {
        return std::unexpected(std::string{"protected operator file ancestry changed"});
    }
    return std::optional<std::string>{std::move((*file)->bytes)};
}

auto inspect_pi_operator_record(const std::filesystem::path& path)
    -> std::expected<std::optional<pi_runtime_selection>, std::string> {
    return load_selection_record(path, false, {});
}

} // namespace detail

auto detail::load_pi_runtime_with_exclusions(
    const std::filesystem::path& path, std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::optional<pi_runtime_selection>, std::string> {
    return load_selection_record(path, true, source_exclusions);
}

auto detail::store_pi_runtime_with_exclusions(
    const std::filesystem::path& path,
    const pi_runtime_selection& selection,
    bool approved,
    bool replace_existing,
    std::span<const std::filesystem::path> source_exclusions
) -> std::expected<bool, std::string> {
    if (!approved) {
        return std::unexpected(std::string{"approve Pi runtime setup before writing a selection"});
    }
    auto encoded = encode_record(selection, source_exclusions);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    bool missing = false;
    auto parent = open_parent(path, missing);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    const auto name = path.filename().string();
    auto lock = pin_lock(parent->get(), name + ".lock");
    if (!lock) {
        return std::unexpected(lock.error());
    }
    auto existing = read_record(parent->get(), name);
    if (!existing) {
        return std::unexpected(existing.error());
    }
    if (*existing) {
        if (!decode_record((*existing)->bytes)) {
            return std::unexpected(std::string{"refusing to overwrite malformed Pi selection"});
        }
        if ((*existing)->bytes == *encoded) {
            return false;
        }
        if (!replace_existing) {
            return std::unexpected(
                std::string{"Pi selection differs; explicit refresh consent required"}
            );
        }
    }
    std::array<unsigned char, 16> entropy{};
    if (::getentropy(entropy.data(), entropy.size()) != 0) {
        return std::unexpected(system_error("create Pi selection temporary identity"));
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string temporary = name + ".next-";
    for (unsigned char byte : entropy) {
        temporary.push_back(digits[byte >> 4U]);
        temporary.push_back(digits[byte & 15U]);
    }
    const unique_fd output{::openat(
        parent->get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600
    )};
    if (output.get() < 0) {
        return std::unexpected(system_error("create Pi selection temporary file"));
    }
    struct stat identity{};
    if (::fstat(output.get(), &identity) != 0) {
        return std::unexpected(system_error("pin Pi selection temporary file"));
    }
    temporary_record cleanup{parent->get(), temporary, identity};
    auto publish = [&]() -> std::expected<void, std::string> {
        if (::fchmod(output.get(), 0600) != 0) {
            return std::unexpected(system_error("protect Pi selection"));
        }
        struct stat owned{};
        struct stat bound{};
        if (::fstat(output.get(), &owned) != 0 || !owner_regular(owned, true) ||
            owned.st_dev != identity.st_dev || owned.st_ino != identity.st_ino ||
            ::fstatat(parent->get(), temporary.c_str(), &bound, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_identity(owned, bound)) {
            return std::unexpected(std::string{"unsafe newly created Pi selection"});
        }
        if (auto acl = glove::detail::clear_created_descriptor_acl(output.get()); !acl) {
            return std::unexpected(acl.error());
        }
        std::size_t consumed = 0;
        while (consumed < encoded->size()) {
            const auto count =
                ::write(output.get(), encoded->data() + consumed, encoded->size() - consumed);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                return std::unexpected(std::string{"write Pi selection failed"});
            }
            consumed += static_cast<std::size_t>(count);
        }
        if (::fsync(output.get()) != 0) {
            return std::unexpected(system_error("sync Pi selection"));
        }
        struct stat completed{};
        struct stat named{};
        if (::fstat(output.get(), &completed) != 0 || !owner_regular(completed) ||
            completed.st_dev != identity.st_dev || completed.st_ino != identity.st_ino ||
            ::fstatat(parent->get(), temporary.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same_identity(completed, named) ||
            !glove::detail::check_descriptor_acl(
                output.get(), glove::detail::acl_scope::owner_private
            )) {
            return std::unexpected(std::string{"Pi selection temporary identity changed"});
        }
        auto current = read_record(parent->get(), name);
        if (!current || static_cast<bool>(*current) != static_cast<bool>(*existing) ||
            (*current && !same_identity((*current)->identity, (*existing)->identity)) ||
            !parent_matches(parent->get(), path)) {
            return std::unexpected(std::string{"Pi selection changed before publication"});
        }
        if (*existing) {
            if (::renameat(parent->get(), temporary.c_str(), parent->get(), name.c_str()) != 0) {
                return std::unexpected(system_error("replace Pi selection"));
            }
            cleanup.renamed();
        } else {
            // An exclusive rename has no crash window exposing a two-link
            // record. A pre-publication collision must never be overwritten.
#if defined(__APPLE__)
            const int published = ::renameatx_np(
                parent->get(), temporary.c_str(), parent->get(), name.c_str(), RENAME_EXCL
            );
#elif defined(__linux__)
            const auto published = ::syscall(
                SYS_renameat2,
                parent->get(),
                temporary.c_str(),
                parent->get(),
                name.c_str(),
                RENAME_NOREPLACE
            );
#else
            return std::unexpected(
                std::string{"exclusive Pi selection publication is unsupported"}
            );
#endif
#if defined(__APPLE__) || defined(__linux__)
            if (published != 0) {
                return std::unexpected(system_error("publish exclusive Pi selection"));
            }
            cleanup.renamed();
#endif
        }
        return {};
    }();
    if (auto removed = cleanup.remove(); !removed) {
        return std::unexpected(removed.error());
    }
    if (!publish) {
        return std::unexpected(publish.error());
    }
    if (::fsync(parent->get()) != 0) {
        return std::unexpected(
            system_error("sync Pi selection parent; publication durability unknown")
        );
    }
    return true;
}

auto detail::pi_library_environment_with_exclusions(
    const pi_runtime_selection& selection, std::span<const std::filesystem::path> source_exclusions
) -> std::expected<std::vector<std::string>, std::string> {
    if (auto verified =
            host::detail::validate_pi_runtime_with_exclusions(selection.runtime, source_exclusions);
        !verified) {
        return std::unexpected(verified.error());
    }
    const auto& payload = selection.runtime.read_only_paths.front();
    std::string joined;
    std::map<std::string, std::filesystem::path> library_names;
    for (std::size_t index = 0; index < selection.runtime.source_read_only_paths.size(); ++index) {
        const auto library = payload / ("root-" + std::to_string(index)) / "lib";
        std::error_code error;
        if (!std::filesystem::is_directory(library, error)) {
            if (error && error != std::errc::no_such_file_or_directory) {
                return std::unexpected(error.message());
            }
            continue;
        }
        if (library.native().contains(':')) {
            return std::unexpected(
                std::string{"Pi snapshot library path contains an unsupported colon"}
            );
        }
        std::filesystem::directory_iterator iterator{library, error};
        if (error) {
            return std::unexpected(error.message());
        }
        for (const std::filesystem::directory_iterator end; iterator != end;
             iterator.increment(error)) {
            if (error) {
                return std::unexpected(error.message());
            }
            const auto name = iterator->path().filename().string();
            if (!name.ends_with(".dylib") && !name.ends_with(".so") && !name.contains(".so.")) {
                continue;
            }
            if (!library_names.emplace(name, iterator->path()).second) {
                return std::unexpected(
                    std::string{"ambiguous library name in Pi snapshot closure"}
                );
            }
        }
        if (error) {
            return std::unexpected(error.message());
        }
        if (!joined.empty()) {
            joined.push_back(':');
        }
        joined += library.string();
    }
    if (joined.empty()) {
        return std::vector<std::string>{};
    }
#if defined(__APPLE__)
    return std::vector<std::string>{"DYLD_LIBRARY_PATH=" + joined};
#else
    return std::vector<std::string>{"LD_LIBRARY_PATH=" + joined};
#endif
}

auto store_pi_runtime_selection(
    const std::filesystem::path& path,
    const pi_runtime_selection& selection,
    bool approved,
    bool replace_existing
) -> std::expected<bool, std::string> {
    return detail::store_pi_runtime_with_exclusions(
        path, selection, approved, replace_existing, {}
    );
}

auto pi_runtime_library_environment(const pi_runtime_selection& selection)
    -> std::expected<std::vector<std::string>, std::string> {
    return detail::pi_library_environment_with_exclusions(selection, {});
}

} // namespace glove::run
