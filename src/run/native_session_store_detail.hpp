#pragma once

// Private shared detail of the native session store translation units. Not a
// public interface: the store owns every descriptor and invariant declared here.
#include "glove/detail/descriptor_acl.hpp"

#include "../container/sha256.hpp"
#include "native_session_store.hpp"
#include "pi_private_files.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <span>
#include <utility>

namespace glove::run::detail {
namespace native_session_wire {

struct metadata_wire {
    std::string schema_id;
    std::string session;
    std::string runtime_id;
    std::string harness_id;
    std::string runtime_digest;
    std::string history_format;
    std::string workspace;
    std::string policy_digest;
    std::string conversation_id;
};

struct record_wire {
    std::string schema_id;
    std::string session;
    std::string producing_epoch;
    std::string producing_generation;
    std::string harness_id;
    std::string runtime_digest;
    std::string history_format;
    std::string workspace;
    std::string policy_digest;
    std::string conversation_id;
    std::string history_digest;
    std::uint64_t history_bytes = 0;
    std::uint64_t history_entries = 0;
};

} // namespace native_session_wire

namespace native_session_detail {
using native_session_wire::metadata_wire;
using native_session_wire::record_wire;

template<typename T> using result = std::expected<T, std::string>;
using private_files::check_file;
using private_files::descriptor;
using private_files::directory_flags;
using private_files::failure;
using private_files::pin_parent;
using private_files::pinned_parent;
using private_files::private_file;
using private_files::safe_directory;
using private_files::same;
using private_files::stable_bytes;
using private_files::write_bytes;

inline constexpr std::string_view metadata_schema = "glove.native-session.v1";
inline constexpr std::string_view record_schema = "glove.native-checkpoint.v1";
inline constexpr int file_flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
inline constexpr int create_flags = O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

inline constexpr std::array journal_kinds{
    std::string_view{"session_created"},
    std::string_view{"epoch_started"},
    std::string_view{"intent"},
    std::string_view{"result"},
    std::string_view{"launched"},
    std::string_view{"prepare_cancelled"},
    std::string_view{"prepare_failed"},
    std::string_view{"outcome_known"},
    std::string_view{"outcome_uncertain"},
    std::string_view{"history_classified"},
    std::string_view{"checkpoint_published"},
    std::string_view{"checkpoint_failed"},
    std::string_view{"finalized"},
    std::string_view{"listener_recreated"},
    std::string_view{"note"}
};

inline auto random_hex(std::size_t bytes) -> result<std::string> {
    std::array<unsigned char, 32> random{};
    if (bytes > random.size() || ::getentropy(random.data(), bytes) != 0) {
        return std::unexpected("cannot obtain native session entropy");
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string text;
    for (std::size_t index = 0; index < bytes; ++index) {
        text.push_back(digits[random[index] >> 4U]);
        text.push_back(digits[random[index] & 15U]);
    }
    return text;
}

inline auto bounded_text(std::string_view value, std::size_t limit) -> bool {
    return value.size() <= limit && value.find('\0') == std::string_view::npos &&
           value.find('\n') == std::string_view::npos;
}

inline auto valid_metadata(const session_metadata& metadata) -> bool {
    return valid_session_id(metadata.session) && !metadata.runtime_id.empty() &&
           bounded_text(metadata.runtime_id, 64) && !metadata.harness_id.empty() &&
           bounded_text(metadata.harness_id, 64) && valid_checkpoint_id(metadata.runtime_digest) &&
           !metadata.history_format.empty() && bounded_text(metadata.history_format, 64) &&
           metadata.workspace.starts_with('/') && bounded_text(metadata.workspace, 4096) &&
           valid_checkpoint_id(metadata.policy_digest) && !metadata.conversation_id.empty() &&
           bounded_text(metadata.conversation_id, 128);
}

inline auto valid_event(const journal_event& event) -> bool {
    return std::ranges::find(journal_kinds, event.kind) != journal_kinds.end() &&
           (event.epoch.empty() || valid_epoch(event.epoch)) &&
           (event.request.empty() || valid_request_id(event.request)) &&
           (event.body_digest.empty() || valid_checkpoint_id(event.body_digest)) &&
           (event.checkpoint.empty() || valid_checkpoint_id(event.checkpoint)) &&
           bounded_text(event.op, 32) && bounded_text(event.code, 32) &&
           bounded_text(event.detail, 4096);
}

inline auto read_whole(int fd, std::size_t limit, std::string_view what) -> result<std::string> {
    struct stat before{};
    if (::fstat(fd, &before) != 0) {
        return failure("inspect " + std::string{what});
    }
    if (!S_ISREG(before.st_mode) || before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > limit) {
        return std::unexpected(std::string{what} + " is not a bounded regular file");
    }
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count =
            ::pread(fd, bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return failure("read " + std::string{what});
        }
        offset += static_cast<std::size_t>(count);
    }
    struct stat after{};
    if (::fstat(fd, &after) != 0 || !stable_bytes(before, after)) {
        return std::unexpected(std::string{what} + " changed while reading");
    }
    return bytes;
}

inline constexpr glz::opts strict_options{
    .error_on_unknown_keys = true, .error_on_missing_keys = true
};

inline auto encode_record(const checkpoint_record& record) -> result<std::string> {
    const record_wire wire{
        .schema_id = std::string{record_schema},
        .session = record.session,
        .producing_epoch = record.producing_epoch,
        .producing_generation = format_generation(record.producing_generation),
        .harness_id = record.harness_id,
        .runtime_digest = record.runtime_digest,
        .history_format = record.history_format,
        .workspace = record.workspace,
        .policy_digest = record.policy_digest,
        .conversation_id = record.conversation_id,
        .history_digest = record.history_digest,
        .history_bytes = record.history_bytes,
        .history_entries = record.history_entries
    };
    std::string json;
    if (glz::write_json(wire, json) || json.size() > 16U * 1024U) {
        return std::unexpected("cannot encode native checkpoint record");
    }
    json.push_back('\n');
    return json;
}

inline auto decode_record(std::string_view json) -> result<checkpoint_record> {
    record_wire wire;
    if (glz::read<strict_options>(wire, json) || wire.schema_id != record_schema) {
        return std::unexpected("malformed native checkpoint record");
    }
    auto generation = parse_generation(wire.producing_generation);
    if (!generation) {
        return std::unexpected("malformed native checkpoint generation");
    }
    return checkpoint_record{
        .session = wire.session,
        .producing_epoch = wire.producing_epoch,
        .producing_generation = *generation,
        .harness_id = wire.harness_id,
        .runtime_digest = wire.runtime_digest,
        .history_format = wire.history_format,
        .workspace = wire.workspace,
        .policy_digest = wire.policy_digest,
        .conversation_id = wire.conversation_id,
        .history_digest = wire.history_digest,
        .history_bytes = wire.history_bytes,
        .history_entries = wire.history_entries
    };
}

inline auto valid_record(const checkpoint_record& record, const session_metadata& metadata)
    -> bool {
    return record.session == metadata.session && valid_epoch(record.producing_epoch) &&
           record.producing_generation != 0 && record.harness_id == metadata.harness_id &&
           record.runtime_digest == metadata.runtime_digest &&
           record.history_format == metadata.history_format &&
           record.workspace == metadata.workspace &&
           record.policy_digest == metadata.policy_digest &&
           record.conversation_id == metadata.conversation_id &&
           valid_checkpoint_id(record.history_digest) && record.history_bytes > 0 &&
           record.history_bytes <= max_checkpoint_bytes && record.history_entries > 0 &&
           record.history_entries <= max_checkpoint_entries;
}

// Creates a sealed owner-only regular file below `parent`. The descriptor
// stays open so identity can be rechecked after sealing.
inline auto seal_file(int parent, const char* name, std::string_view bytes, bool fsync_fault)
    -> result<descriptor> {
    descriptor file{::openat(parent, name, O_WRONLY | create_flags, 0600)};
    struct stat identity{};
    if (file.get() < 0 || ::fchmod(file.get(), 0600) != 0 || ::fstat(file.get(), &identity) != 0) {
        return failure("create native session file");
    }
    if (auto checked = check_file(parent, name, file.get(), identity, 0600); !checked) {
        return std::unexpected(checked.error());
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(file.get()); !cleared) {
        return std::unexpected(cleared.error());
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::pwrite(
            file.get(), bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset)
        );
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return failure("write native session file");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (fsync_fault) {
        errno = EIO;
        return failure("persist native session file (injected)");
    }
    if (::fsync(file.get()) != 0 || ::fchmod(file.get(), 0400) != 0 || ::fsync(file.get()) != 0) {
        return failure("seal native session file");
    }
    struct stat sealed{};
    if (::fstat(file.get(), &sealed) != 0 || sealed.st_size != static_cast<off_t>(bytes.size())) {
        return std::unexpected("native session file size changed while sealing");
    }
    if (auto checked = check_file(parent, name, file.get(), sealed, 0400); !checked) {
        return std::unexpected(checked.error());
    }
    return file;
}

inline auto
open_regular(int parent, const char* name, mode_t mode, std::size_t limit, std::string_view what)
    -> result<std::pair<descriptor, std::string>> {
    descriptor file{::openat(parent, name, file_flags)};
    struct stat identity{};
    if (file.get() < 0 || ::fstat(file.get(), &identity) != 0) {
        return failure("open " + std::string{what});
    }
    if (!private_file(identity, mode)) {
        return std::unexpected(std::string{what} + " is not an owner-private single-link file");
    }
    if (auto checked = check_file(parent, name, file.get(), identity, mode); !checked) {
        return std::unexpected(checked.error());
    }
    auto bytes = read_whole(file.get(), limit, what);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return std::pair{std::move(file), std::move(*bytes)};
}

inline auto open_child_directory(int parent, const char* name, mode_t mode) -> result<descriptor> {
    struct stat before{};
    if (::fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        return failure("inspect native session directory");
    }
    descriptor opened{::openat(parent, name, directory_flags)};
    struct stat actual{};
    if (opened.get() < 0 || ::fstat(opened.get(), &actual) != 0) {
        return failure("open native session directory");
    }
    if (!same(before, actual) || !S_ISDIR(actual.st_mode) || actual.st_uid != ::geteuid() ||
        (actual.st_mode & 07777U) != mode || actual.st_nlink == 0) {
        return std::unexpected("native session directory is unsafe or changed");
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            opened.get(), glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    return opened;
}

inline auto create_child_directory(int parent, const char* name) -> result<descriptor> {
    if (::mkdirat(parent, name, 0700) != 0) {
        return failure("create native session directory");
    }
    auto opened = open_child_directory(parent, name, 0700);
    if (!opened) {
        return opened;
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(opened->get()); !cleared) {
        return std::unexpected(cleared.error());
    }
    if (::fsync(opened->get()) != 0) {
        return failure("persist native session directory");
    }
    return opened;
}

} // namespace native_session_detail

// Private header shared by the store translation units only.
using namespace native_session_detail; // NOLINT(google-build-using-namespace)

struct native_session_store::implementation {
    pinned_parent parent;
    descriptor root_fd;
    descriptor lease_fd;
    descriptor journal_fd;
    descriptor checkpoints_fd;
    struct stat root_identity{};
    std::string name;
    std::filesystem::path root_path;
    session_metadata metadata;
    std::vector<journal_event> events;
    std::size_t journal_bytes = 0;
    std::uint64_t checkpoint_aggregate = 0;
    std::size_t checkpoints = 0;

    auto attached() const -> result<void> {
        if (auto checked = parent.check(); !checked) {
            return checked;
        }
        struct stat actual{};
        struct stat named{};
        if (::fstat(root_fd.get(), &actual) != 0 ||
            ::fstatat(parent.fd(), name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
            return failure("reinspect native session root");
        }
        if (!same(root_identity, actual) || !same(actual, named) || !safe_directory(actual, true)) {
            return std::unexpected("native session root changed or is unsafe");
        }
        return glove::detail::check_descriptor_acl(
            root_fd.get(), glove::detail::acl_scope::owner_private
        );
    }

    auto load_journal() -> result<void> {
        struct stat info{};
        if (::fstat(journal_fd.get(), &info) != 0) {
            return failure("inspect native session journal");
        }
        if (!private_file(info, 0600) ||
            static_cast<std::uint64_t>(info.st_size) > max_journal_bytes) {
            return std::unexpected("native session journal is unsafe or exceeds its bound");
        }
        auto bytes = read_whole(journal_fd.get(), max_journal_bytes, "native session journal");
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        events.clear();
        journal_bytes = bytes->size();
        checkpoint_aggregate = 0;
        checkpoints = 0;
        std::string_view remaining{*bytes};
        std::uint64_t expected_seq = 1;
        while (!remaining.empty()) {
            const auto newline = remaining.find('\n');
            if (newline == std::string_view::npos) {
                return std::unexpected("native session journal has a truncated record");
            }
            const auto line = remaining.substr(0, newline);
            remaining.remove_prefix(newline + 1);
            if (line.empty() || line.size() > max_journal_event_bytes ||
                events.size() >= max_journal_events) {
                return std::unexpected("native session journal record exceeds bounds");
            }
            journal_event event;
            if (glz::read<strict_options>(event, line) || !valid_event(event) ||
                event.seq != expected_seq) {
                return std::unexpected("native session journal is corrupt or reordered");
            }
            ++expected_seq;
            if (event.kind == "checkpoint_published") {
                ++checkpoints;
            }
            events.push_back(std::move(event));
        }
        if (events.empty() || events.front().kind != "session_created") {
            return std::unexpected("native session journal lacks its creation record");
        }
        return {};
    }
};

} // namespace glove::run::detail
