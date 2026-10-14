#include "native_session_store_detail.hpp"

namespace glove::run::detail {
native_session_store::native_session_store(std::unique_ptr<implementation> state) noexcept
    : state_{std::move(state)} {}

native_session_store::native_session_store(native_session_store&&) noexcept = default;

native_session_store::~native_session_store() = default;

auto native_session_store::create(
    const std::filesystem::path& parent_path, session_metadata metadata
) -> result<native_session_store> {
    if (!valid_metadata(metadata)) {
        return std::unexpected("invalid native session metadata");
    }
    auto parent = pin_parent(parent_path);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    auto state = std::make_unique<implementation>();
    state->parent = std::move(*parent);
    state->name = metadata.session;
    state->root_path = parent_path / state->name;
    state->metadata = std::move(metadata);
    if (::mkdirat(state->parent.fd(), state->name.c_str(), 0700) != 0) {
        return failure("exclusively create native session root");
    }
    struct stat named{};
    state->root_fd = descriptor{::openat(state->parent.fd(), state->name.c_str(), directory_flags)};
    if (state->root_fd.get() < 0 || ::fstat(state->root_fd.get(), &state->root_identity) != 0 ||
        ::fstatat(state->parent.fd(), state->name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same(state->root_identity, named) || !safe_directory(named, true)) {
        return std::unexpected(
            "native session root created but unresolved: " + state->root_path.string()
        );
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(state->root_fd.get());
        !cleared) {
        return std::unexpected(cleared.error());
    }
    state->lease_fd =
        descriptor{::openat(state->root_fd.get(), "lease", O_RDWR | create_flags, 0600)};
    if (state->lease_fd.get() < 0 || ::fchmod(state->lease_fd.get(), 0600) != 0 ||
        ::flock(state->lease_fd.get(), LOCK_EX | LOCK_NB) != 0) {
        return failure("create and lock native session lease");
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(state->lease_fd.get());
        !cleared) {
        return std::unexpected(cleared.error());
    }
    const metadata_wire wire{
        .schema_id = std::string{metadata_schema},
        .session = state->metadata.session,
        .runtime_id = state->metadata.runtime_id,
        .harness_id = state->metadata.harness_id,
        .runtime_digest = state->metadata.runtime_digest,
        .history_format = state->metadata.history_format,
        .workspace = state->metadata.workspace,
        .policy_digest = state->metadata.policy_digest,
        .conversation_id = state->metadata.conversation_id
    };
    std::string json;
    if (glz::write_json(wire, json) || json.size() > max_session_metadata_bytes) {
        return std::unexpected("cannot encode native session metadata");
    }
    json.push_back('\n');
    if (auto sealed = seal_file(state->root_fd.get(), "meta.json", json, false); !sealed) {
        return std::unexpected(sealed.error());
    }
    for (const auto* child : {"checkpoints", "control"}) {
        if (auto created = create_child_directory(state->root_fd.get(), child); !created) {
            return std::unexpected(created.error());
        }
    }
    auto checkpoints = open_child_directory(state->root_fd.get(), "checkpoints", 0700);
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    state->checkpoints_fd = std::move(*checkpoints);
    state->journal_fd =
        descriptor{::openat(state->root_fd.get(), "journal.log", O_RDWR | create_flags, 0600)};
    if (state->journal_fd.get() < 0 || ::fchmod(state->journal_fd.get(), 0600) != 0) {
        return failure("create native session journal");
    }
    if (auto cleared = glove::detail::clear_created_descriptor_acl(state->journal_fd.get());
        !cleared) {
        return std::unexpected(cleared.error());
    }
    if (::fsync(state->journal_fd.get()) != 0 || ::fsync(state->root_fd.get()) != 0 ||
        ::fsync(state->parent.fd()) != 0) {
        return failure("persist native session root");
    }
    native_session_store store{std::move(state)};
    if (auto appended = store.append(
            {.seq = 0,
             .kind = "session_created",
             .epoch = {},
             .generation = 0,
             .request = {},
             .body_digest = {},
             .op = {},
             .code = {},
             .checkpoint = {},
             .detail = {}}
        );
        !appended) {
        return std::unexpected(appended.error());
    }
    return store;
}

auto native_session_store::open(
    const std::filesystem::path& parent_path,
    std::string_view session,
    std::string_view expected_runtime_id
) -> result<native_session_store> {
    if (!valid_session_id(session)) {
        return std::unexpected("invalid native session identity");
    }
    auto parent = pin_parent(parent_path);
    if (!parent) {
        return std::unexpected(parent.error());
    }
    auto state = std::make_unique<implementation>();
    state->parent = std::move(*parent);
    state->name = std::string{session};
    state->root_path = parent_path / state->name;
    auto root = open_child_directory(state->parent.fd(), state->name.c_str(), 0700);
    if (!root) {
        return std::unexpected(root.error());
    }
    state->root_fd = std::move(*root);
    if (::fstat(state->root_fd.get(), &state->root_identity) != 0) {
        return failure("inspect native session root");
    }
    state->lease_fd = descriptor{
        ::openat(state->root_fd.get(), "lease", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    };
    struct stat lease{};
    if (state->lease_fd.get() < 0 || ::fstat(state->lease_fd.get(), &lease) != 0 ||
        !private_file(lease, 0600)) {
        return std::unexpected("native session lease is missing or unsafe");
    }
    if (auto checked =
            check_file(state->root_fd.get(), "lease", state->lease_fd.get(), lease, 0600);
        !checked) {
        return std::unexpected(checked.error());
    }
    if (::flock(state->lease_fd.get(), LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return std::unexpected("native session lease is held by a live owner");
        }
        return failure("lock native session lease");
    }
    auto meta = open_regular(
        state->root_fd.get(),
        "meta.json",
        0400,
        max_session_metadata_bytes,
        "native session metadata"
    );
    if (!meta) {
        return std::unexpected(meta.error());
    }
    metadata_wire wire;
    if (glz::read<strict_options>(wire, meta->second) || wire.schema_id != metadata_schema) {
        return std::unexpected("malformed native session metadata");
    }
    state->metadata = {
        .session = wire.session,
        .runtime_id = wire.runtime_id,
        .harness_id = wire.harness_id,
        .runtime_digest = wire.runtime_digest,
        .history_format = wire.history_format,
        .workspace = wire.workspace,
        .policy_digest = wire.policy_digest,
        .conversation_id = wire.conversation_id
    };
    if (!valid_metadata(state->metadata) || state->metadata.session != session ||
        state->metadata.runtime_id != expected_runtime_id) {
        return std::unexpected("native session metadata disagrees with its identity");
    }
    auto checkpoints = open_child_directory(state->root_fd.get(), "checkpoints", 0700);
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    state->checkpoints_fd = std::move(*checkpoints);
    if (auto control = open_child_directory(state->root_fd.get(), "control", 0700); !control) {
        return std::unexpected(control.error());
    }
    state->journal_fd = descriptor{
        ::openat(state->root_fd.get(), "journal.log", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    };
    struct stat journal{};
    if (state->journal_fd.get() < 0 || ::fstat(state->journal_fd.get(), &journal) != 0) {
        return failure("open native session journal");
    }
    if (auto checked =
            check_file(state->root_fd.get(), "journal.log", state->journal_fd.get(), journal, 0600);
        !checked) {
        return std::unexpected(checked.error());
    }
    if (auto loaded = state->load_journal(); !loaded) {
        return std::unexpected(loaded.error());
    }
    // Aggregate charge is reconstructed from published records.
    for (const auto& event : state->events) {
        if (event.kind != "checkpoint_published") {
            continue;
        }
        auto directory =
            open_child_directory(state->checkpoints_fd.get(), event.checkpoint.c_str(), 0500);
        if (!directory) {
            return std::unexpected("published native checkpoint is missing: " + directory.error());
        }
        auto record =
            open_regular(directory->get(), "record.json", 0400, 16U * 1024U, "checkpoint record");
        if (!record) {
            return std::unexpected(record.error());
        }
        auto decoded = decode_record(record->second);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        state->checkpoint_aggregate += decoded->history_bytes;
    }
    return native_session_store{std::move(state)};
}

auto native_session_store::root() const -> const std::filesystem::path& {
    return state_->root_path;
}

auto native_session_store::control_directory() const -> std::filesystem::path {
    return state_->root_path / "control";
}

auto native_session_store::metadata() const -> const session_metadata& {
    return state_->metadata;
}

auto native_session_store::events() const -> const std::vector<journal_event>& {
    return state_->events;
}

auto native_session_store::checkpoint_count() const -> std::size_t {
    return state_->checkpoints;
}

auto native_session_store::append(journal_event event, store_fault fault) -> result<void> {
    event.seq = state_->events.size() + 1;
    if (!valid_event(event)) {
        return std::unexpected("invalid native session journal event");
    }
    if (state_->events.size() >= max_journal_events) {
        return std::unexpected("native session journal is full");
    }
    std::string line;
    if (glz::write_json(event, line) || line.size() + 1 > max_journal_event_bytes) {
        return std::unexpected("cannot encode native session journal event");
    }
    line.push_back('\n');
    if (line.size() > max_journal_bytes - state_->journal_bytes) {
        return std::unexpected("native session journal exceeds its byte bound");
    }
    if (auto checked = state_->attached(); !checked) {
        return checked;
    }
    struct stat before{};
    if (::fstat(state_->journal_fd.get(), &before) != 0 ||
        static_cast<std::uint64_t>(before.st_size) != state_->journal_bytes) {
        return std::unexpected("native session journal changed externally");
    }
    if (fault == store_fault::journal_append) {
        errno = EIO;
        return failure("append native session journal (injected)");
    }
    std::size_t offset = 0;
    while (offset < line.size()) {
        const auto count = ::pwrite(
            state_->journal_fd.get(),
            line.data() + offset,
            line.size() - offset,
            static_cast<off_t>(state_->journal_bytes + offset)
        );
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return failure("append native session journal");
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::fsync(state_->journal_fd.get()) != 0) {
        return failure("persist native session journal");
    }
    state_->journal_bytes += line.size();
    if (event.kind == "checkpoint_published") {
        ++state_->checkpoints;
    }
    state_->events.push_back(std::move(event));
    return {};
}

auto mint_session_id() -> result<std::string> {
    auto hex = random_hex(16);
    if (!hex) {
        return std::unexpected(hex.error());
    }
    return "ns-" + *hex;
}

auto mint_epoch() -> result<std::string> {
    return random_hex(16);
}

auto mint_request_id() -> result<std::string> {
    return random_hex(16);
}

auto sha256_of(std::string_view bytes) -> result<std::string> {
    return container::detail::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()
        }
    );
}

} // namespace glove::run::detail
