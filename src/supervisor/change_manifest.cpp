#include "glove/supervisor/change_manifest.hpp"

#include "glove/container/digest.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace {

constexpr unsigned int max_depth = 64U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::size_t max_manifest_bytes = std::size_t{16} * 1024U * 1024U;
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

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

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

class unique_directory {
public:
    explicit unique_directory(DIR* directory) noexcept : directory_{directory} {}

    unique_directory(const unique_directory&) = delete;
    auto operator=(const unique_directory&) -> unique_directory& = delete;

    ~unique_directory() {
        if (directory_ != nullptr) {
            (void)::closedir(directory_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> DIR* { return directory_; }

private:
    DIR* directory_ = nullptr;
};

struct snapshot_state {
    std::uint64_t max_bytes = 0;
    std::uint64_t bytes = 0;
    std::size_t max_entries = 0;
    std::vector<path_snapshot_entry> entries;
};

} // namespace

struct wire_change {
    std::string kind;
    std::string path;
    std::string previous_path;
    std::string before_digest;
    std::string after_digest;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::uint32_t before_mode = 0;
    std::uint32_t after_mode = 0;
    bool directory = false;
};

struct wire_manifest {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::vector<wire_change> changes;
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
};

struct wire_manifest_envelope {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::vector<wire_change> changes;
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::string manifest_digest;
};

struct wire_snapshot_entry {
    std::string path;
    std::string content_digest;
    std::uint64_t bytes = 0;
    std::uint32_t mode = 0;
    bool directory = false;
};

namespace {

auto error_message(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
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

auto valid_component(std::string_view value) -> bool {
    return !value.empty() && value != "." && value != ".." && value.size() <= 255U &&
           value.find('/') == std::string_view::npos && value.find('\0') == std::string_view::npos;
}

auto valid_relative_path(std::string_view value) -> bool {
    if (value == ".") {
        return true;
    }
    const std::filesystem::path path{value};
    return !value.empty() && value.size() <= 4'096U && value.find('\0') == std::string_view::npos &&
           !path.is_absolute() && path.lexically_normal() == path &&
           std::ranges::none_of(path, [](const auto& component) {
               return component == "." || component == "..";
           });
}

auto checked_add(std::uint64_t& total, std::uint64_t value) -> bool {
    if (value > std::numeric_limits<std::uint64_t>::max() - total) {
        return false;
    }
    total += value;
    return true;
}

auto append_regular(
    int descriptor, std::string path, const struct stat& status, snapshot_state& state
) -> result<void> {
    if (status.st_size < 0 || status.st_nlink != 1) {
        return std::unexpected(std::string{"change snapshot contains an invalid regular file"});
    }
    const auto bytes = static_cast<std::uint64_t>(status.st_size);
    if (!checked_add(state.bytes, bytes) || state.bytes > state.max_bytes) {
        return std::unexpected(std::string{"change snapshot byte bound exceeded"});
    }
    auto digest = container::sha256_fd_hex(descriptor, bytes);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    state.entries.push_back({
        .path = std::move(path),
        .content_digest = std::move(*digest),
        .bytes = bytes,
        .mode = static_cast<std::uint32_t>(status.st_mode & 0777U),
        .directory = false,
    });
    return {};
}

auto snapshot_directory(
    int descriptor, std::string_view prefix, snapshot_state& state, unsigned int depth
) -> result<void> {
    if (depth > max_depth) {
        return std::unexpected(std::string{"change snapshot depth bound exceeded"});
    }
    const int duplicate =
        ::openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (duplicate < 0) {
        return std::unexpected(error_message("duplicate change snapshot directory"));
    }
    unique_fd iterator_descriptor{duplicate};
    DIR* raw = ::fdopendir(iterator_descriptor.get());
    if (raw == nullptr) {
        return std::unexpected(error_message("open change snapshot iterator"));
    }
    (void)iterator_descriptor.release();
    unique_directory directory{raw};
    std::vector<std::string> names;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                return std::unexpected(error_message("read change snapshot directory"));
            }
            break;
        }
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") {
            continue;
        }
        if (!valid_component(name)) {
            return std::unexpected(std::string{"change snapshot contains an invalid name"});
        }
        names.emplace_back(name);
    }
    std::ranges::sort(names);
    for (const auto& name : names) {
        if (state.entries.size() >= state.max_entries) {
            return std::unexpected(std::string{"change snapshot entry bound exceeded"});
        }
        struct stat status{};
        if (::fstatat(descriptor, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) {
            return std::unexpected(error_message("inspect change snapshot entry"));
        }
        const std::string path = prefix.empty() ? name : std::string{prefix} + "/" + name;
        if (S_ISREG(status.st_mode)) {
            unique_fd file{::openat(descriptor, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
            if (file.get() < 0) {
                return std::unexpected(error_message("open change snapshot file"));
            }
            struct stat opened{};
            if (::fstat(file.get(), &opened) != 0 || opened.st_dev != status.st_dev ||
                opened.st_ino != status.st_ino || opened.st_mode != status.st_mode ||
                opened.st_size != status.st_size) {
                return std::unexpected(std::string{"change snapshot file changed while opening"});
            }
            if (auto appended = append_regular(file.get(), path, opened, state); !appended) {
                return appended;
            }
            continue;
        }
        if (!S_ISDIR(status.st_mode)) {
            return std::unexpected(
                std::string{"change snapshot contains a symlink or special file"}
            );
        }
        unique_fd child{
            ::openat(descriptor, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (child.get() < 0) {
            return std::unexpected(error_message("open change snapshot directory"));
        }
        state.entries.push_back({
            .path = path,
            .content_digest = {},
            .bytes = 0,
            .mode = static_cast<std::uint32_t>(status.st_mode & 0777U),
            .directory = true,
        });
        if (auto nested = snapshot_directory(child.get(), path, state, depth + 1U); !nested) {
            return nested;
        }
    }
    return {};
}

auto change_kind_string(path_change_kind kind) -> std::string {
    switch (kind) {
    case path_change_kind::create:
        return "create";
    case path_change_kind::modify:
        return "modify";
    case path_change_kind::rename:
        return "rename";
    case path_change_kind::remove:
        return "remove";
    }
    return {};
}

auto parse_change_kind(std::string_view value) -> result<path_change_kind> {
    if (value == "create") {
        return path_change_kind::create;
    }
    if (value == "modify") {
        return path_change_kind::modify;
    }
    if (value == "rename") {
        return path_change_kind::rename;
    }
    if (value == "remove") {
        return path_change_kind::remove;
    }
    return std::unexpected(std::string{"retained change manifest has an unknown change kind"});
}

auto wire_entry(const path_change_entry& entry) -> wire_change {
    return {
        .kind = change_kind_string(entry.kind),
        .path = entry.path,
        .previous_path = entry.previous_path,
        .before_digest = entry.before_digest,
        .after_digest = entry.after_digest,
        .before_bytes = entry.before_bytes,
        .after_bytes = entry.after_bytes,
        .before_mode = entry.before_mode,
        .after_mode = entry.after_mode,
        .directory = entry.directory,
    };
}

auto open_owner_only_root(std::string_view raw) -> result<unique_fd> {
    const std::filesystem::path path{raw};
    if (!path.is_absolute() || path == path.root_path() || path.lexically_normal() != path) {
        return std::unexpected(std::string{"invalid retained stage root"});
    }
    unique_fd current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(error_message("open retained stage root"));
    }
    for (const auto& component : path.relative_path()) {
        const std::string name = component.string();
        unique_fd next{
            ::openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        };
        if (next.get() < 0) {
            return std::unexpected(error_message("resolve retained stage root"));
        }
        current = std::move(next);
    }
    struct stat status{};
    if (::fstat(current.get(), &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != ::geteuid() || (status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"retained stage root must be owner-only"});
    }
    return current;
}

auto read_bounded_file(int descriptor, std::size_t max_bytes) -> result<std::string> {
    struct stat status{};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_size <= 0 || static_cast<std::uint64_t>(status.st_size) > max_bytes) {
        return std::unexpected(std::string{"retained stage manifest file is invalid"});
    }
    std::string contents(static_cast<std::size_t>(status.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const auto count = ::pread(
            descriptor,
            contents.data() + offset,
            contents.size() - offset,
            static_cast<off_t>(offset)
        );
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(error_message("read retained stage manifest"));
        }
        offset += static_cast<std::size_t>(count);
    }
    return contents;
}

} // namespace

auto snapshot_path_tree(int descriptor, std::uint64_t max_bytes, std::size_t max_entries)
    -> result<std::vector<path_snapshot_entry>> {
    if (descriptor < 0 || max_bytes == 0 || max_entries == 0 || max_entries > 100'000U) {
        return std::unexpected(std::string{"change snapshot bounds are invalid"});
    }
    struct stat status{};
    if (::fstat(descriptor, &status) != 0) {
        return std::unexpected(error_message("inspect change snapshot root"));
    }
    snapshot_state state{.max_bytes = max_bytes, .max_entries = max_entries, .entries = {}};
    if (S_ISREG(status.st_mode)) {
        if (auto appended = append_regular(descriptor, ".", status, state); !appended) {
            return std::unexpected(appended.error());
        }
    } else if (S_ISDIR(status.st_mode)) {
        if (auto captured = snapshot_directory(descriptor, {}, state, 0); !captured) {
            return std::unexpected(captured.error());
        }
    } else {
        return std::unexpected(std::string{"change snapshot root has an unsupported type"});
    }
    return state.entries;
}

auto path_snapshot_digest(const std::vector<path_snapshot_entry>& snapshot) -> result<std::string> {
    if (snapshot.size() > 100'000U ||
        !std::ranges::is_sorted(snapshot, {}, &path_snapshot_entry::path) ||
        std::adjacent_find(
            snapshot.begin(), snapshot.end(), [](const auto& left, const auto& right) {
                return left.path == right.path;
            }
        ) != snapshot.end()) {
        return std::unexpected(std::string{"path snapshot is not canonical"});
    }
    std::vector<wire_snapshot_entry> encoded;
    encoded.reserve(snapshot.size());
    for (const auto& entry : snapshot) {
        if (!valid_relative_path(entry.path) || entry.mode > 0777U ||
            (!entry.directory && !valid_digest(entry.content_digest)) ||
            (entry.directory &&
             (entry.path == "." || !entry.content_digest.empty() || entry.bytes != 0))) {
            return std::unexpected(std::string{"path snapshot entry is invalid"});
        }
        encoded.push_back({
            .path = entry.path,
            .content_digest = entry.content_digest,
            .bytes = entry.bytes,
            .mode = entry.mode,
            .directory = entry.directory,
        });
    }
    auto json = glz::write_json(encoded);
    if (!json) {
        return std::unexpected(std::string{"encode path snapshot"});
    }
    return container::sha256_hex(
        std::span{reinterpret_cast<const unsigned char*>(json->data()), json->size()}
    );
}

auto build_retained_change_manifest(
    std::string session_id,
    std::string exposure_id,
    std::uint64_t generation,
    std::string scope_digest,
    std::string source_identity_digest,
    std::uint64_t max_bytes,
    const std::vector<path_snapshot_entry>& baseline,
    const std::vector<path_snapshot_entry>& current
) -> result<retained_change_manifest> {
    if (!valid_identifier(session_id) || !valid_identifier(exposure_id) || generation == 0 ||
        !valid_digest(scope_digest) || !valid_digest(source_identity_digest) || max_bytes == 0 ||
        baseline.size() > 100'000U || current.size() > 100'000U) {
        return std::unexpected(std::string{"retained change manifest identity is invalid"});
    }
    const auto canonical_snapshot = [](const auto& entries) {
        return std::ranges::is_sorted(entries, {}, &path_snapshot_entry::path) &&
               std::adjacent_find(
                   entries.begin(), entries.end(), [](const auto& left, const auto& right) {
                       return left.path == right.path;
                   }
               ) == entries.end();
    };
    if (!canonical_snapshot(baseline) || !canonical_snapshot(current)) {
        return std::unexpected(std::string{"retained change snapshots are not canonical"});
    }
    auto baseline_digest = path_snapshot_digest(baseline);
    auto staged_digest = path_snapshot_digest(current);
    if (!baseline_digest || !staged_digest) {
        return std::unexpected(!baseline_digest ? baseline_digest.error() : staged_digest.error());
    }

    std::map<std::string, path_snapshot_entry, std::less<>> before;
    std::map<std::string, path_snapshot_entry, std::less<>> after;
    for (const auto& entry : baseline) {
        before.emplace(entry.path, entry);
    }
    for (const auto& entry : current) {
        after.emplace(entry.path, entry);
    }
    std::vector<path_change_entry> removed;
    std::vector<path_change_entry> created;
    std::vector<path_change_entry> changes;
    for (const auto& [path, entry] : before) {
        const auto found = after.find(path);
        if (found == after.end()) {
            removed.push_back({
                .kind = path_change_kind::remove,
                .path = path,
                .previous_path = {},
                .before_digest = entry.content_digest,
                .after_digest = {},
                .before_bytes = entry.bytes,
                .after_bytes = 0,
                .before_mode = entry.mode,
                .after_mode = 0,
                .directory = entry.directory,
            });
        } else if (entry != found->second) {
            changes.push_back({
                .kind = path_change_kind::modify,
                .path = path,
                .previous_path = {},
                .before_digest = entry.content_digest,
                .after_digest = found->second.content_digest,
                .before_bytes = entry.bytes,
                .after_bytes = found->second.bytes,
                .before_mode = entry.mode,
                .after_mode = found->second.mode,
                .directory = found->second.directory,
            });
        }
    }
    for (const auto& [path, entry] : after) {
        if (!before.contains(path)) {
            created.push_back({
                .kind = path_change_kind::create,
                .path = path,
                .previous_path = {},
                .before_digest = {},
                .after_digest = entry.content_digest,
                .before_bytes = 0,
                .after_bytes = entry.bytes,
                .before_mode = 0,
                .after_mode = entry.mode,
                .directory = entry.directory,
            });
        }
    }

    std::set<std::size_t> renamed_removed;
    std::set<std::size_t> renamed_created;
    for (std::size_t removed_index = 0; removed_index < removed.size(); ++removed_index) {
        const auto& candidate = removed[removed_index];
        if (candidate.directory || candidate.before_digest.empty()) {
            continue;
        }
        std::vector<std::size_t> matches;
        for (std::size_t created_index = 0; created_index < created.size(); ++created_index) {
            const auto& target = created[created_index];
            if (!target.directory && target.after_digest == candidate.before_digest &&
                target.after_bytes == candidate.before_bytes) {
                matches.push_back(created_index);
            }
        }
        if (matches.size() != 1U) {
            continue;
        }
        const auto created_index = matches.front();
        const auto duplicate_source = std::ranges::count_if(removed, [&](const auto& source) {
            return !source.directory && source.before_digest == candidate.before_digest &&
                   source.before_bytes == candidate.before_bytes;
        });
        if (duplicate_source != 1 || renamed_created.contains(created_index)) {
            continue;
        }
        auto rename = created[created_index];
        rename.kind = path_change_kind::rename;
        rename.previous_path = candidate.path;
        rename.before_digest = candidate.before_digest;
        rename.before_bytes = candidate.before_bytes;
        rename.before_mode = candidate.before_mode;
        changes.push_back(std::move(rename));
        renamed_removed.insert(removed_index);
        renamed_created.insert(created_index);
    }
    for (std::size_t index = 0; index < removed.size(); ++index) {
        if (!renamed_removed.contains(index)) {
            changes.push_back(std::move(removed[index]));
        }
    }
    for (std::size_t index = 0; index < created.size(); ++index) {
        if (!renamed_created.contains(index)) {
            changes.push_back(std::move(created[index]));
        }
    }
    std::ranges::sort(changes, [](const auto& left, const auto& right) {
        return std::tie(left.path, left.kind, left.previous_path) <
               std::tie(right.path, right.kind, right.previous_path);
    });

    const bool directory = baseline.empty() || baseline.front().path != ".";
    if ((current.empty() || current.front().path != ".") != directory) {
        return std::unexpected(std::string{"retained change root type changed"});
    }
    retained_change_manifest manifest{
        .session_id = std::move(session_id),
        .exposure_id = std::move(exposure_id),
        .generation = generation,
        .scope_digest = std::move(scope_digest),
        .source_identity_digest = std::move(source_identity_digest),
        .max_bytes = max_bytes,
        .directory = directory,
        .baseline_tree_digest = std::move(*baseline_digest),
        .staged_tree_digest = std::move(*staged_digest),
        .changes = std::move(changes),
        .created = 0,
        .modified = 0,
        .renamed = 0,
        .removed = 0,
        .before_bytes = 0,
        .after_bytes = 0,
        .manifest_digest = {},
        .canonical_json = {},
    };
    std::vector<wire_change> encoded_changes;
    encoded_changes.reserve(manifest.changes.size());
    for (const auto& entry : manifest.changes) {
        encoded_changes.push_back(wire_entry(entry));
        manifest.before_bytes += entry.before_bytes;
        manifest.after_bytes += entry.after_bytes;
        switch (entry.kind) {
        case path_change_kind::create:
            ++manifest.created;
            break;
        case path_change_kind::modify:
            ++manifest.modified;
            break;
        case path_change_kind::rename:
            ++manifest.renamed;
            break;
        case path_change_kind::remove:
            ++manifest.removed;
            break;
        }
    }
    wire_manifest encoded{
        .schema_version = manifest.schema_version,
        .session_id = manifest.session_id,
        .exposure_id = manifest.exposure_id,
        .generation = manifest.generation,
        .scope_digest = manifest.scope_digest,
        .source_identity_digest = manifest.source_identity_digest,
        .max_bytes = manifest.max_bytes,
        .directory = manifest.directory,
        .baseline_tree_digest = manifest.baseline_tree_digest,
        .staged_tree_digest = manifest.staged_tree_digest,
        .changes = std::move(encoded_changes),
        .created = manifest.created,
        .modified = manifest.modified,
        .renamed = manifest.renamed,
        .removed = manifest.removed,
        .before_bytes = manifest.before_bytes,
        .after_bytes = manifest.after_bytes,
    };
    auto body = glz::write_json(encoded);
    if (!body) {
        return std::unexpected(std::string{"encode retained change manifest"});
    }
    auto digest = container::sha256_hex(
        std::span{reinterpret_cast<const unsigned char*>(body->data()), body->size()}
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    wire_manifest_envelope envelope{
        .schema_version = encoded.schema_version,
        .session_id = std::move(encoded.session_id),
        .exposure_id = std::move(encoded.exposure_id),
        .generation = encoded.generation,
        .scope_digest = std::move(encoded.scope_digest),
        .source_identity_digest = std::move(encoded.source_identity_digest),
        .max_bytes = encoded.max_bytes,
        .directory = encoded.directory,
        .baseline_tree_digest = std::move(encoded.baseline_tree_digest),
        .staged_tree_digest = std::move(encoded.staged_tree_digest),
        .changes = std::move(encoded.changes),
        .created = encoded.created,
        .modified = encoded.modified,
        .renamed = encoded.renamed,
        .removed = encoded.removed,
        .before_bytes = encoded.before_bytes,
        .after_bytes = encoded.after_bytes,
        .manifest_digest = *digest,
    };
    auto canonical = glz::write_json(envelope);
    if (!canonical || canonical->empty() || canonical->size() > max_manifest_bytes) {
        return std::unexpected(std::string{"encode retained change manifest envelope"});
    }
    manifest.manifest_digest = std::move(*digest);
    manifest.canonical_json = std::move(*canonical);
    return manifest;
}

auto decode_retained_change_manifest_json(std::string_view canonical_json)
    -> result<retained_change_manifest> {
    if (canonical_json.empty() || canonical_json.size() > max_manifest_bytes) {
        return std::unexpected(std::string{"retained change manifest exceeds its bound"});
    }
    // This public boundary accepts arbitrary byte spans. Give Glaze a mutable,
    // resizable buffer so padded parsing cannot read outside caller storage.
    std::string parse_buffer{canonical_json};
    wire_manifest_envelope envelope;
    if (const auto error = glz::read<strict_read_options>(envelope, parse_buffer);
        error || envelope.schema_version != 1 || !valid_identifier(envelope.session_id) ||
        !valid_identifier(envelope.exposure_id) || envelope.generation == 0 ||
        !valid_digest(envelope.scope_digest) || !valid_digest(envelope.source_identity_digest) ||
        envelope.max_bytes == 0 || !valid_digest(envelope.baseline_tree_digest) ||
        !valid_digest(envelope.staged_tree_digest) || !valid_digest(envelope.manifest_digest) ||
        envelope.changes.size() > 100'000U) {
        return std::unexpected(std::string{"retained change manifest schema is invalid"});
    }
    wire_manifest body{
        .schema_version = envelope.schema_version,
        .session_id = envelope.session_id,
        .exposure_id = envelope.exposure_id,
        .generation = envelope.generation,
        .scope_digest = envelope.scope_digest,
        .source_identity_digest = envelope.source_identity_digest,
        .max_bytes = envelope.max_bytes,
        .directory = envelope.directory,
        .baseline_tree_digest = envelope.baseline_tree_digest,
        .staged_tree_digest = envelope.staged_tree_digest,
        .changes = envelope.changes,
        .created = envelope.created,
        .modified = envelope.modified,
        .renamed = envelope.renamed,
        .removed = envelope.removed,
        .before_bytes = envelope.before_bytes,
        .after_bytes = envelope.after_bytes,
    };
    auto body_json = glz::write_json(body);
    if (!body_json) {
        return std::unexpected(std::string{"retained change manifest encoding failed"});
    }
    auto digest = container::sha256_hex(
        std::span{reinterpret_cast<const unsigned char*>(body_json->data()), body_json->size()}
    );
    if (!digest || *digest != envelope.manifest_digest) {
        return std::unexpected(std::string{"retained change manifest digest mismatch"});
    }
    auto reencoded = glz::write_json(envelope);
    if (!reencoded || *reencoded != canonical_json) {
        return std::unexpected(std::string{"retained change manifest is not canonical"});
    }

    retained_change_manifest manifest{
        .schema_version = envelope.schema_version,
        .session_id = std::move(envelope.session_id),
        .exposure_id = std::move(envelope.exposure_id),
        .generation = envelope.generation,
        .scope_digest = std::move(envelope.scope_digest),
        .source_identity_digest = std::move(envelope.source_identity_digest),
        .max_bytes = envelope.max_bytes,
        .directory = envelope.directory,
        .baseline_tree_digest = std::move(envelope.baseline_tree_digest),
        .staged_tree_digest = std::move(envelope.staged_tree_digest),
        .changes = {},
        .created = envelope.created,
        .modified = envelope.modified,
        .renamed = envelope.renamed,
        .removed = envelope.removed,
        .before_bytes = envelope.before_bytes,
        .after_bytes = envelope.after_bytes,
        .manifest_digest = std::move(envelope.manifest_digest),
        .canonical_json = std::string{canonical_json},
    };
    manifest.changes.reserve(envelope.changes.size());
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::string_view previous_path;
    for (auto& encoded : envelope.changes) {
        auto kind = parse_change_kind(encoded.kind);
        const bool before_file = !encoded.before_digest.empty();
        const bool after_file = !encoded.after_digest.empty();
        const bool valid_before =
            !before_file || (valid_digest(encoded.before_digest) && encoded.before_mode != 0);
        const bool valid_after =
            !after_file || (valid_digest(encoded.after_digest) && encoded.after_mode != 0);
        if (!kind || !valid_relative_path(encoded.path) ||
            (!encoded.previous_path.empty() && !valid_relative_path(encoded.previous_path)) ||
            !valid_before || !valid_after ||
            (!previous_path.empty() && previous_path >= encoded.path) ||
            !checked_add(before_bytes, encoded.before_bytes) ||
            !checked_add(after_bytes, encoded.after_bytes)) {
            return std::unexpected(std::string{"retained change manifest entries are invalid"});
        }
        const bool shape = [&] {
            switch (*kind) {
            case path_change_kind::create:
                return encoded.previous_path.empty() && encoded.before_digest.empty() &&
                       encoded.before_bytes == 0 && encoded.before_mode == 0;
            case path_change_kind::modify:
                return encoded.previous_path.empty();
            case path_change_kind::rename:
                return !encoded.previous_path.empty() && before_file && after_file &&
                       encoded.before_digest == encoded.after_digest &&
                       encoded.before_bytes == encoded.after_bytes;
            case path_change_kind::remove:
                return encoded.previous_path.empty() && encoded.after_digest.empty() &&
                       encoded.after_bytes == 0 && encoded.after_mode == 0;
            }
            return false;
        }();
        if (!shape) {
            return std::unexpected(std::string{"retained change manifest entry shape is invalid"});
        }
        previous_path = encoded.path;
        switch (*kind) {
        case path_change_kind::create:
            ++created;
            break;
        case path_change_kind::modify:
            ++modified;
            break;
        case path_change_kind::rename:
            ++renamed;
            break;
        case path_change_kind::remove:
            ++removed;
            break;
        }
        manifest.changes.push_back({
            .kind = *kind,
            .path = std::move(encoded.path),
            .previous_path = std::move(encoded.previous_path),
            .before_digest = std::move(encoded.before_digest),
            .after_digest = std::move(encoded.after_digest),
            .before_bytes = encoded.before_bytes,
            .after_bytes = encoded.after_bytes,
            .before_mode = encoded.before_mode,
            .after_mode = encoded.after_mode,
            .directory = encoded.directory,
        });
    }
    if (created != manifest.created || modified != manifest.modified ||
        renamed != manifest.renamed || removed != manifest.removed ||
        before_bytes != manifest.before_bytes || after_bytes != manifest.after_bytes) {
        return std::unexpected(std::string{"retained change manifest totals are invalid"});
    }
    return manifest;
}

auto inspect_retained_change_stage(
    std::string_view materialization_root, std::string_view session_id, std::string_view exposure_id
) -> result<retained_change_manifest> {
    if (!valid_identifier(session_id) || !valid_identifier(exposure_id)) {
        return std::unexpected(std::string{"invalid retained stage identity"});
    }
    auto root = open_owner_only_root(materialization_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    const std::string stage_name =
        "glove-retained-s" + std::to_string(session_id.size()) + "-" + std::string{session_id} +
        "-a" + std::to_string(exposure_id.size()) + "-" + std::string{exposure_id};
    unique_fd stage{
        ::openat(root->get(), stage_name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (stage.get() < 0) {
        return std::unexpected(error_message("open retained stage"));
    }
    struct stat stage_status{};
    if (::fstat(stage.get(), &stage_status) != 0 || !S_ISDIR(stage_status.st_mode) ||
        stage_status.st_uid != ::geteuid() || (stage_status.st_mode & 0077U) != 0) {
        return std::unexpected(std::string{"retained stage ownership is invalid"});
    }
    unique_fd manifest_fd{
        ::openat(stage.get(), "manifest.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (manifest_fd.get() < 0) {
        return std::unexpected(error_message("open retained stage manifest"));
    }
    auto json = read_bounded_file(manifest_fd.get(), std::size_t{16} * 1024U * 1024U);
    if (!json) {
        return std::unexpected(json.error());
    }
    auto manifest = decode_retained_change_manifest_json(*json);
    if (!manifest || manifest->session_id != session_id || manifest->exposure_id != exposure_id) {
        return std::unexpected(
            manifest ? std::string{"retained stage manifest identity mismatch"} : manifest.error()
        );
    }
    unique_fd content{
        ::openat(stage.get(), "content", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (content.get() < 0) {
        return std::unexpected(error_message("open retained stage content"));
    }
    unique_fd payload;
    int snapshot_descriptor = content.get();
    if (!manifest->directory) {
        payload =
            unique_fd{::openat(content.get(), ".glove-payload", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
        if (payload.get() < 0) {
            return std::unexpected(error_message("open retained stage payload"));
        }
        snapshot_descriptor = payload.get();
    }
    auto snapshot = snapshot_path_tree(snapshot_descriptor, manifest->max_bytes);
    auto digest = snapshot ? path_snapshot_digest(*snapshot)
                           : result<std::string>{std::unexpected(snapshot.error())};
    if (!digest || *digest != manifest->staged_tree_digest) {
        return std::unexpected(
            digest ? std::string{"retained stage content digest mismatch"} : digest.error()
        );
    }
    return manifest;
}

} // namespace glove::supervisor
