// Checkpoint publication, admission and durable projection of the native
// session store. Shares the store's private detail header; see store.cpp.
#include "native_session_store_detail.hpp"

namespace glove::run::detail {
auto native_session_store::durable_projection() const -> session_projection {
    session_projection projection;
    for (const auto& event : state_->events) {
        if (event.kind == "intent" && (event.op == "start" || event.op == "resume")) {
            projection.generation = event.generation;
            projection.phase = session_phase::preparing;
            projection.history = history_status::absent;
            projection.effects = effects_status::unassessed;
        } else if (event.kind == "launched") {
            projection.phase = session_phase::running;
        } else if (event.kind == "intent" && event.op == "stop") {
            if (projection.phase == session_phase::preparing ||
                projection.phase == session_phase::running ||
                projection.phase == session_phase::interrupting) {
                projection.phase = session_phase::stopping;
            }
        } else if (event.kind == "prepare_cancelled" || event.kind == "prepare_failed") {
            projection.phase = session_phase::stopped;
        } else if (event.kind == "outcome_known") {
            projection.phase = session_phase::finalizing;
        } else if (event.kind == "outcome_uncertain") {
            projection.phase = session_phase::recovery_required;
            projection.effects = effects_status::incomplete;
        } else if (event.kind == "history_classified") {
            // The bare status is the `code` field; `detail` is diagnostic only.
            if (event.code == "available") {
                projection.history = history_status::available;
            } else if (event.code == "invalid") {
                projection.history = history_status::invalid;
            } else if (event.code == "failed" || event.code.empty()) {
                projection.history = history_status::failed;
            } else {
                projection.history = history_status::absent;
            }
        } else if (event.kind == "checkpoint_published") {
            projection.phase = session_phase::stopped;
            projection.history = history_status::published;
            projection.checkpoint = event.checkpoint;
        } else if (event.kind == "checkpoint_failed") {
            projection.phase = session_phase::recovery_required;
            projection.history = history_status::failed;
            projection.effects = effects_status::incomplete;
        } else if (event.kind == "finalized") {
            projection.phase = projection.history == history_status::failed
                                   ? session_phase::recovery_required
                                   : session_phase::stopped;
        }
    }
    return projection;
}

auto native_session_store::latest_checkpoint() const -> std::optional<std::string> {
    for (auto it = state_->events.rbegin(); it != state_->events.rend(); ++it) {
        if (it->kind == "checkpoint_published") {
            return it->checkpoint;
        }
    }
    return std::nullopt;
}

auto native_session_store::publish_checkpoint(
    checkpoint_record record,
    int source_directory_fd,
    std::string_view name,
    const history_validator& validate,
    store_fault fault
) -> std::expected<std::string, publish_failure> {
    const auto refuse = [](std::string message) -> std::expected<std::string, publish_failure> {
        return std::unexpected(
            publish_failure{.kind = publish_failure_kind::refused, .message = std::move(message)}
        );
    };
    const auto fail = [](std::string message) -> std::expected<std::string, publish_failure> {
        return std::unexpected(
            publish_failure{.kind = publish_failure_kind::failed, .message = std::move(message)}
        );
    };
    if (!validate || source_directory_fd < 0 || name.empty() || name.size() > 255 ||
        name.find('/') != std::string_view::npos || name.find('\0') != std::string_view::npos) {
        return refuse("native checkpoint publication requires a validator and leaf name");
    }
    // Capacity exhaustion is a persistence failure, not a verdict on the
    // history bytes: the generation stays retained and uncertain.
    if (state_->checkpoints >= max_checkpoints_per_session) {
        return fail("native session checkpoint count bound reached");
    }
    if (auto checked = state_->attached(); !checked) {
        return fail(checked.error());
    }
    const std::string leaf{name};
    // Two complete reads must agree byte-for-byte: a stable repeated read is
    // the strongest evidence available against a same-UID writer, not proof.
    descriptor source{::openat(source_directory_fd, leaf.c_str(), file_flags)};
    struct stat identity{};
    if (source.get() < 0) {
        if (errno == ENOENT) {
            return std::unexpected(
                publish_failure{
                    .kind = publish_failure_kind::missing, .message = "generation history is absent"
                }
            );
        }
        return fail(failure("open generation history").error());
    }
    if (::fstat(source.get(), &identity) != 0) {
        return fail(failure("inspect generation history").error());
    }
    if (!S_ISREG(identity.st_mode) || identity.st_uid != ::geteuid() || identity.st_nlink != 1 ||
        (identity.st_mode & 07077U) != 0) {
        return refuse("generation history is not an owner-only single-link regular file");
    }
    struct stat named{};
    if (::fstatat(source_directory_fd, leaf.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same(identity, named)) {
        return refuse("generation history name does not bind its descriptor");
    }
    if (fault == store_fault::copy) {
        errno = EIO;
        return fail(failure("copy generation history (injected)").error());
    }
    auto first = read_whole(source.get(), max_checkpoint_bytes, "generation history");
    if (!first) {
        return fail(first.error());
    }
    auto second = read_whole(source.get(), max_checkpoint_bytes, "generation history");
    if (!second || *first != *second) {
        return fail("generation history changed between reads");
    }
    if (first->empty()) {
        return refuse("generation history is empty");
    }
    auto summary = validate(*first);
    if (!summary) {
        return refuse("generation history refused: " + summary.error());
    }
    if (summary->entries == 0 || summary->entries > max_checkpoint_entries) {
        return refuse("generation history entry count outside bounds");
    }
    if (first->size() > max_checkpoint_aggregate_bytes - state_->checkpoint_aggregate) {
        return fail("native session checkpoint aggregate bound reached");
    }
    auto digest = sha256_of(*first);
    if (!digest) {
        return fail(digest.error());
    }
    record.history_digest = *digest;
    record.history_bytes = first->size();
    record.history_entries = summary->entries;
    if (!valid_record(record, state_->metadata)) {
        return refuse("native checkpoint record disagrees with session metadata");
    }
    auto encoded = encode_record(record);
    if (!encoded) {
        return fail(encoded.error());
    }
    auto id = sha256_of(*encoded);
    if (!id) {
        return fail(id.error());
    }
    struct stat existing{};
    if (::fstatat(state_->checkpoints_fd.get(), id->c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        return fail("native checkpoint identity already exists or is unresolved");
    }
    auto random = random_hex(8);
    if (!random) {
        return fail(random.error());
    }
    const std::string staging = ".publishing-" + *random;
    auto directory = create_child_directory(state_->checkpoints_fd.get(), staging.c_str());
    if (!directory) {
        return fail(directory.error());
    }
    const auto discard = [&](std::string error) -> std::expected<std::string, publish_failure> {
        // Best-effort removal of the exclusive staging tree; the previous
        // checkpoint and journal are untouched either way.
        (void)::fchmod(directory->get(), 0700);
        (void)::unlinkat(directory->get(), "history.jsonl", 0);
        (void)::unlinkat(directory->get(), "record.json", 0);
        (void)::unlinkat(state_->checkpoints_fd.get(), staging.c_str(), AT_REMOVEDIR);
        return fail(std::move(error));
    };
    auto history =
        seal_file(directory->get(), "history.jsonl", *first, fault == store_fault::history_fsync);
    if (!history) {
        return discard(history.error());
    }
    auto sealed_record =
        seal_file(directory->get(), "record.json", *encoded, fault == store_fault::record_fsync);
    if (!sealed_record) {
        return discard(sealed_record.error());
    }
    if (::fsync(directory->get()) != 0) {
        return discard(failure("persist native checkpoint staging").error());
    }
    if (fault == store_fault::publish_rename) {
        return discard("publish native checkpoint (injected rename failure)");
    }
    // macOS 15 refuses to rename a directory the caller cannot write (EACCES),
    // so the owner-only staging tree moves first and is sealed in place through
    // the retained descriptor. Nothing records the checkpoint until the journal
    // append below, and admission requires the sealed mode, so a crash between
    // the rename and the seal leaves an inert orphan rather than a checkpoint.
    if (::renameat(
            state_->checkpoints_fd.get(), staging.c_str(), state_->checkpoints_fd.get(), id->c_str()
        ) != 0) {
        return discard(failure("publish native checkpoint").error());
    }
    const auto discard_moved =
        [&](std::string error) -> std::expected<std::string, publish_failure> {
        (void)::fchmod(directory->get(), 0700);
        (void)::unlinkat(directory->get(), "history.jsonl", 0);
        (void)::unlinkat(directory->get(), "record.json", 0);
        (void)::unlinkat(state_->checkpoints_fd.get(), id->c_str(), AT_REMOVEDIR);
        return fail(std::move(error));
    };
    if (::fchmod(directory->get(), 0500) != 0 || ::fsync(directory->get()) != 0) {
        return discard_moved(failure("seal native checkpoint directory").error());
    }
    if (fault == store_fault::parent_sync) {
        errno = EIO;
        return fail(failure("persist native checkpoint namespace (injected)").error());
    }
    if (::fsync(state_->checkpoints_fd.get()) != 0) {
        return fail(failure("persist native checkpoint namespace").error());
    }
    if (auto appended = append(
            {.seq = 0,
             .kind = "checkpoint_published",
             .epoch = record.producing_epoch,
             .generation = record.producing_generation,
             .request = {},
             .body_digest = {},
             .op = {},
             .code = {},
             .checkpoint = *id,
             .detail = std::to_string(record.history_bytes)},
            fault
        );
        !appended) {
        // The directory exists but is not journaled: it is not a published
        // checkpoint. Resume admission only accepts journaled identities.
        return fail(appended.error());
    }
    state_->checkpoint_aggregate += record.history_bytes;
    return *id;
}

auto native_session_store::admit_checkpoint(
    std::string_view id, const history_validator& validate
) const -> result<admitted_checkpoint> {
    if (!valid_checkpoint_id(id) || !validate) {
        return std::unexpected("native checkpoint admission requires an exact identity");
    }
    const bool journaled = std::ranges::any_of(state_->events, [&](const journal_event& event) {
        return event.kind == "checkpoint_published" && event.checkpoint == id;
    });
    if (!journaled) {
        return std::unexpected("native checkpoint is not a journaled publication");
    }
    if (auto checked = state_->attached(); !checked) {
        return std::unexpected(checked.error());
    }
    const std::string name{id};
    auto directory = open_child_directory(state_->checkpoints_fd.get(), name.c_str(), 0500);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    auto record =
        open_regular(directory->get(), "record.json", 0400, 16U * 1024U, "checkpoint record");
    if (!record) {
        return std::unexpected(record.error());
    }
    auto record_digest = sha256_of(record->second);
    if (!record_digest || *record_digest != id) {
        return std::unexpected("native checkpoint record does not match its identity");
    }
    auto decoded = decode_record(record->second);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    if (!valid_record(*decoded, state_->metadata)) {
        return std::unexpected("native checkpoint binding is incompatible with this session");
    }
    auto history = open_regular(
        directory->get(), "history.jsonl", 0400, max_checkpoint_bytes, "checkpoint history"
    );
    if (!history) {
        return std::unexpected(history.error());
    }
    auto history_digest = sha256_of(history->second);
    if (!history_digest || *history_digest != decoded->history_digest ||
        history->second.size() != decoded->history_bytes) {
        return std::unexpected("native checkpoint history does not match its record");
    }
    auto summary = validate(history->second);
    if (!summary || summary->entries != decoded->history_entries) {
        return std::unexpected(
            "native checkpoint history refused: " +
            (summary ? "entry count drift" : summary.error())
        );
    }
    return admitted_checkpoint{
        .id = std::string{id}, .record = std::move(*decoded), .history = std::move(history->second)
    };
}

} // namespace glove::run::detail
