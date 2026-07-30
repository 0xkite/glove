#include "glove/supervisor/path_exposure.hpp"

#include "glove/container/digest.hpp"
#include "glove/supervisor/path_exposure_journal.hpp"

#include <fcntl.h>
#if defined(__linux__)
#    include <linux/openat2.h>
#    include <sys/syscall.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace glove::supervisor {

namespace {

constexpr std::size_t max_roots = 64U;
constexpr std::size_t max_exposures = 1'024U;
constexpr std::size_t max_modes = 8U;
constexpr std::size_t max_runtimes = 64U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::size_t max_label_bytes = 256U;

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

private:
    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int descriptor_ = -1;
};

struct source_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t mode = 0;
    std::uint32_t owner = 0;
    std::uint32_t group = 0;

    auto operator==(const source_identity&) const -> bool = default;
};

struct root_record {
    path_exposure_root_policy policy;
    unique_fd descriptor;
    source_identity identity;
};

struct exposure_record {
    path_exposure_descriptor descriptor;
    std::string request_id;
    std::string request_digest;
    std::string host_path;
    std::string parent_identity_digest;
    unique_fd source_descriptor;
};

enum class request_kind : std::uint8_t {
    create,
    revoke,
};

struct request_record {
    request_kind kind = request_kind::create;
    std::string digest;
    std::pair<std::string, std::uint64_t> exposure;
};

class canonical_encoder {
public:
    void append_u8(std::uint8_t value) { bytes_.push_back(value); }

    void append_u32(std::uint32_t value) {
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_u64(std::uint64_t value) {
        for (const unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>(value >> shift));
        }
    }

    void append_string(std::string_view value) {
        append_u32(static_cast<std::uint32_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<const unsigned char> { return bytes_; }

private:
    std::vector<unsigned char> bytes_;
};

auto error_message(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_identifier_bytes &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == ':' ||
                      byte == '.';
           });
}

auto valid_path_component(std::string_view value) -> bool {
    return !value.empty() && value != "." && value != ".." && value.size() <= 255U &&
           value.find('/') == std::string_view::npos && value.find('\0') == std::string_view::npos;
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

auto valid_label(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_label_bytes &&
           std::ranges::none_of(value, [](unsigned char byte) {
               return byte < 0x20U || byte == 0x7fU || byte == '/' || byte == '\\';
           });
}

auto valid_absolute_path(std::string_view value) -> bool {
    const std::filesystem::path path{value};
    return !value.empty() && value.find('\0') == std::string_view::npos && path.is_absolute() &&
           path != path.root_path() && path.lexically_normal() == path;
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto mismatch =
        std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
    return mismatch.first == root.end();
}

auto reserved_host_path(const std::filesystem::path& candidate) -> bool {
    constexpr std::array<std::string_view, 4> kernel_roots = {"/dev", "/proc", "/run", "/sys"};
    if (std::ranges::any_of(kernel_roots, [&](std::string_view root) {
            return path_within(candidate, std::filesystem::path{root});
        })) {
        return true;
    }
    constexpr std::array<std::string_view, 6> secrets = {
        ".aws", ".azure", ".gnupg", ".kube", ".sage", ".ssh"
    };
    return std::ranges::any_of(candidate, [&](const auto& component) {
        const auto name = component.string();
        return std::ranges::find(secrets, name) != secrets.end();
    });
}

auto identity_for(int descriptor, std::string_view subject)
    -> std::expected<source_identity, std::string> {
    struct stat status{};
    if (::fstat(descriptor, &status) != 0) {
        return std::unexpected(error_message(std::string{"inspect "} + std::string{subject}));
    }
    if (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode)) {
        return std::unexpected(std::string{subject} + " must be a regular file or directory");
    }
    using unsigned_device = std::make_unsigned_t<decltype(status.st_dev)>;
    using unsigned_inode = std::make_unsigned_t<decltype(status.st_ino)>;
    static_assert(sizeof(unsigned_device) <= sizeof(std::uint64_t));
    static_assert(sizeof(unsigned_inode) <= sizeof(std::uint64_t));
    return source_identity{
        .device = static_cast<std::uint64_t>(static_cast<unsigned_device>(status.st_dev)),
        .inode = static_cast<std::uint64_t>(static_cast<unsigned_inode>(status.st_ino)),
        .mode = static_cast<std::uint32_t>(status.st_mode),
        .owner = static_cast<std::uint32_t>(status.st_uid),
        .group = static_cast<std::uint32_t>(status.st_gid),
    };
}

auto open_absolute_no_follow(const std::filesystem::path& path)
    -> std::expected<unique_fd, std::string> {
    unique_fd current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (current.get() < 0) {
        return std::unexpected(error_message("open filesystem root"));
    }
    const auto relative = path.relative_path();
    for (auto component = relative.begin(); component != relative.end(); ++component) {
        const bool final = std::next(component) == relative.end();
        int flags = O_CLOEXEC | O_NOFOLLOW;
#if defined(__linux__)
        flags |= O_PATH;
#else
        flags |= O_RDONLY | O_NONBLOCK;
#endif
        if (!final) {
            flags |= O_DIRECTORY;
        }
        unique_fd next{::openat(current.get(), component->c_str(), flags)};
        if (next.get() < 0) {
            return std::unexpected(error_message("resolve protected path"));
        }
        current = std::move(next);
    }
    return current;
}

auto open_beneath_root(const root_record& root, const std::filesystem::path& candidate)
    -> std::expected<unique_fd, std::string> {
    const std::filesystem::path root_path{root.policy.host_root};
    if (candidate == root_path || !path_within(candidate, root_path)) {
        return std::unexpected(
            std::string{"exposure path must be a strict protected-root descendant"}
        );
    }
    auto current_identity = identity_for(root.descriptor.get(), "protected root");
    if (!current_identity || *current_identity != root.identity) {
        return std::unexpected(std::string{"protected root identity changed"});
    }
    const auto relative = candidate.lexically_relative(root_path);
#if defined(__linux__)
    const open_how how{
        .flags = O_PATH | O_CLOEXEC,
        .mode = 0,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    const auto descriptor = static_cast<int>(
        ::syscall(SYS_openat2, root.descriptor.get(), relative.c_str(), &how, sizeof(how))
    );
    if (descriptor < 0) {
        return std::unexpected(error_message("resolve exposure with openat2"));
    }
    return unique_fd{descriptor};
#else
    const int duplicate = ::fcntl(root.descriptor.get(), F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) {
        return std::unexpected(error_message("duplicate protected root descriptor"));
    }
    unique_fd current{duplicate};
    for (auto component = relative.begin(); component != relative.end(); ++component) {
        if (*component == "." || *component == "..") {
            return std::unexpected(std::string{"exposure path traversal is invalid"});
        }
        const bool final = std::next(component) == relative.end();
        int flags = O_CLOEXEC | O_NOFOLLOW;
#    if defined(__linux__)
        flags |= O_PATH;
#    else
        flags |= O_RDONLY | O_NONBLOCK;
#    endif
        if (!final) {
            flags |= O_DIRECTORY;
        }
        unique_fd next{::openat(current.get(), component->c_str(), flags)};
        if (next.get() < 0) {
            return std::unexpected(error_message("resolve exposure beneath protected root"));
        }
        auto identity = identity_for(next.get(), "exposure source");
        if (!identity) {
            return std::unexpected(identity.error());
        }
        if (identity->device != root.identity.device) {
            return std::unexpected(std::string{"exposure may not cross a filesystem boundary"});
        }
        current = std::move(next);
    }
    return current;
#endif
}

auto mode_less(const path_exposure_mode& left, const path_exposure_mode& right) -> bool {
    return std::tie(left.access, left.materialization, left.max_bytes, left.cleanup_policy) <
           std::tie(right.access, right.materialization, right.max_bytes, right.cleanup_policy);
}

auto valid_mode(const path_exposure_mode& mode) -> bool {
    switch (mode.access) {
    case path_access::read:
        return mode.materialization == path_materialization::bind && mode.max_bytes == 0 &&
               mode.cleanup_policy == path_cleanup_policy::retain;
    case path_access::ephemeral_write:
        return mode.materialization == path_materialization::copy && mode.max_bytes != 0 &&
               mode.cleanup_policy == path_cleanup_policy::remove;
    case path_access::retained_write:
        return mode.materialization == path_materialization::copy &&
               mode.max_bytes >= minimum_retained_copy_bytes &&
               mode.cleanup_policy == path_cleanup_policy::retain;
    case path_access::direct_write:
        return false;
    }
    return false;
}

auto canonical_modes(std::vector<path_exposure_mode> modes)
    -> std::expected<std::vector<path_exposure_mode>, std::string> {
    if (modes.empty() || modes.size() > max_modes ||
        std::ranges::any_of(modes, [](const auto& mode) { return !valid_mode(mode); })) {
        return std::unexpected(std::string{"exposure modes are invalid"});
    }
    std::ranges::sort(modes, mode_less);
    if (std::adjacent_find(modes.begin(), modes.end()) != modes.end()) {
        return std::unexpected(std::string{"exposure modes contain duplicates"});
    }
    return modes;
}

auto canonical_runtimes(std::vector<std::string> runtimes)
    -> std::expected<std::vector<std::string>, std::string> {
    if (runtimes.empty() || runtimes.size() > max_runtimes ||
        std::ranges::any_of(runtimes, [](const auto& value) { return !valid_identifier(value); })) {
        return std::unexpected(std::string{"exposure runtime templates are invalid"});
    }
    std::ranges::sort(runtimes);
    if (std::adjacent_find(runtimes.begin(), runtimes.end()) != runtimes.end()) {
        return std::unexpected(std::string{"exposure runtime templates contain duplicates"});
    }
    return runtimes;
}

auto mode_is_subset(
    const path_exposure_mode& requested, const std::vector<path_exposure_mode>& allowed
) -> bool {
    return std::ranges::any_of(allowed, [&](const auto& candidate) {
        return candidate.access == requested.access &&
               candidate.materialization == requested.materialization &&
               candidate.cleanup_policy == requested.cleanup_policy &&
               requested.max_bytes <= candidate.max_bytes;
    });
}

auto encode_mode(canonical_encoder& encoder, const path_exposure_mode& mode) -> void {
    encoder.append_u8(static_cast<std::uint8_t>(mode.access));
    encoder.append_u8(static_cast<std::uint8_t>(mode.materialization));
    encoder.append_u64(mode.max_bytes);
    encoder.append_u8(static_cast<std::uint8_t>(mode.cleanup_policy));
}

auto identity_digest(const source_identity& identity) -> result<std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.path-exposure-source-identity");
    encoder.append_u8(1);
    encoder.append_u64(identity.device);
    encoder.append_u64(identity.inode);
    encoder.append_u32(identity.mode);
    encoder.append_u32(identity.owner);
    encoder.append_u32(identity.group);
    return container::sha256_hex(encoder.bytes());
}

auto recovery_parent_identity_digest(
    const root_record& root, const std::filesystem::path& host_path
) -> result<std::string> {
    const std::filesystem::path root_path{root.policy.host_root};
    const auto parent_path = host_path.parent_path();
    if (parent_path.empty() || (parent_path != root_path && !path_within(parent_path, root_path))) {
        return std::unexpected(std::string{"path exposure parent is outside its protected root"});
    }

    source_identity identity;
    if (parent_path == root_path) {
        auto inspected = identity_for(root.descriptor.get(), "protected root");
        if (!inspected || *inspected != root.identity) {
            return std::unexpected(
                !inspected ? inspected.error() : std::string{"protected root identity changed"}
            );
        }
        identity = *inspected;
    } else {
        auto parent = open_beneath_root(root, parent_path);
        if (!parent) {
            return std::unexpected(parent.error());
        }
        auto inspected = identity_for(parent->get(), "path exposure parent");
        if (!inspected || !S_ISDIR(inspected->mode)) {
            return std::unexpected(
                !inspected ? inspected.error()
                           : std::string{"path exposure parent is not a directory"}
            );
        }
        identity = *inspected;
    }
    return identity_digest(identity);
}

auto source_matches(const root_record& root, const exposure_record& exposure) -> bool {
    auto reopened = open_beneath_root(root, std::filesystem::path{exposure.host_path});
    if (!reopened) {
        return false;
    }
    auto identity = identity_for(reopened->get(), "exposure source");
    if (!identity) {
        return false;
    }
    auto digest = identity_digest(*identity);
    return digest && *digest == exposure.descriptor.source_identity_digest;
}

auto scope_digest(const path_exposure_descriptor& descriptor) -> result<std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.path-exposure-scope");
    encoder.append_u8(1);
    encoder.append_string(descriptor.exposure_id);
    encoder.append_u64(descriptor.generation);
    encoder.append_string(descriptor.root_id);
    encoder.append_string(descriptor.source_identity_digest);
    encoder.append_u32(static_cast<std::uint32_t>(descriptor.allowed_modes.size()));
    for (const auto& mode : descriptor.allowed_modes) {
        encode_mode(encoder, mode);
    }
    encoder.append_u64(descriptor.expires_at_ms);
    encoder.append_u32(static_cast<std::uint32_t>(descriptor.allowed_runtime_template_ids.size()));
    for (const auto& runtime : descriptor.allowed_runtime_template_ids) {
        encoder.append_string(runtime);
    }
    return container::sha256_hex(encoder.bytes());
}

auto request_digest(
    const path_exposure_create_request& request,
    const std::vector<path_exposure_mode>& modes,
    const std::vector<std::string>& runtimes
) -> result<std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.path-exposure-create-request");
    encoder.append_u8(1);
    for (const auto& value : {
             std::string_view{request.request_id},
             std::string_view{request.exposure_id},
             std::string_view{request.root_id},
             std::string_view{request.host_path},
             std::string_view{request.display_label},
         }) {
        encoder.append_string(value);
    }
    encoder.append_u32(static_cast<std::uint32_t>(modes.size()));
    for (const auto& mode : modes) {
        encode_mode(encoder, mode);
    }
    encoder.append_u64(request.ttl_secs);
    encoder.append_u32(static_cast<std::uint32_t>(runtimes.size()));
    for (const auto& runtime : runtimes) {
        encoder.append_string(runtime);
    }
    return container::sha256_hex(encoder.bytes());
}

auto revoke_request_digest(
    std::string_view request_id, std::string_view exposure_id, std::uint64_t generation
) -> result<std::string> {
    canonical_encoder encoder;
    encoder.append_string("glove.path-exposure-revoke-request");
    encoder.append_u8(1);
    encoder.append_string(request_id);
    encoder.append_string(exposure_id);
    encoder.append_u64(generation);
    return container::sha256_hex(encoder.bytes());
}

auto projected(const path_exposure_descriptor& descriptor, std::uint64_t now_ms)
    -> path_exposure_projection {
    auto state = descriptor.state;
    if (state == path_exposure_state::active && descriptor.expires_at_ms <= now_ms) {
        state = path_exposure_state::expired;
    }
    return {
        .schema_version = descriptor.schema_version,
        .exposure_id = descriptor.exposure_id,
        .generation = descriptor.generation,
        .scope_digest = descriptor.scope_digest,
        .display_label = descriptor.display_label,
        .allowed_modes = descriptor.allowed_modes,
        .expires_at_ms = descriptor.expires_at_ms,
        .allowed_runtime_template_ids = descriptor.allowed_runtime_template_ids,
        .state = state,
    };
}

} // namespace

struct path_exposure_registry::implementation {
    mutable std::mutex mutex;
    std::map<std::string, root_record> roots;
    std::map<std::pair<std::string, std::uint64_t>, exposure_record> exposures;
    std::map<std::string, std::uint64_t> last_generation;
    std::map<std::string, request_record> request_records;
    std::unique_ptr<path_exposure_journal> journal;
};

auto path_exposure_registry::validate_create_policy(
    const path_exposure_create_request& request
) const -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    const std::scoped_lock lock{state_->mutex};
    const auto root = state_->roots.find(request.root_id);
    if (root == state_->roots.end()) {
        std::string allowed;
        for (const auto& [root_id, record] : state_->roots) {
            (void)record;
            allowed += allowed.empty() ? root_id : ", " + root_id;
        }
        return std::unexpected(
            "root '" + request.root_id + "' is not configured; allowed roots: " + allowed
        );
    }
    if (request.ttl_secs > root->second.policy.max_ttl_secs) {
        return std::unexpected(
            "TTL " + std::to_string(request.ttl_secs) + " seconds exceeds root '" +
            request.root_id + "' maximum " + std::to_string(root->second.policy.max_ttl_secs) +
            " seconds"
        );
    }
    auto modes = canonical_modes(request.allowed_modes);
    if (!modes) {
        return std::unexpected(modes.error());
    }
    const auto rejected_mode = std::ranges::find_if(*modes, [&](const auto& mode) {
        return !mode_is_subset(mode, root->second.policy.allowed_modes);
    });
    if (rejected_mode != modes->end()) {
        const auto access_name = [](path_access access) -> std::string_view {
            switch (access) {
            case path_access::read:
                return "read";
            case path_access::ephemeral_write:
                return "ephemeral_write";
            case path_access::retained_write:
                return "retained_write";
            case path_access::direct_write:
                return "direct_write";
            }
            return "unknown";
        };
        std::string allowed;
        for (const auto& mode : root->second.policy.allowed_modes) {
            const auto tuple = std::string{access_name(mode.access)} +
                               "(max_bytes=" + std::to_string(mode.max_bytes) + ")";
            allowed += allowed.empty() ? tuple : ", " + tuple;
        }
        return std::unexpected(
            "mode " + std::string{access_name(rejected_mode->access)} +
            " with max_bytes=" + std::to_string(rejected_mode->max_bytes) +
            " is not allowed; allowed mode quotas: " + allowed
        );
    }
    auto runtimes = canonical_runtimes(request.allowed_runtime_template_ids);
    if (!runtimes) {
        return std::unexpected(runtimes.error());
    }
    std::vector<std::string> rejected_runtimes;
    for (const auto& runtime : *runtimes) {
        if (!std::ranges::binary_search(
                root->second.policy.allowed_runtime_template_ids, runtime
            )) {
            rejected_runtimes.push_back(runtime);
        }
    }
    if (!rejected_runtimes.empty()) {
        std::string rejected;
        for (const auto& runtime : rejected_runtimes) {
            rejected += rejected.empty() ? runtime : ", " + runtime;
        }
        std::string allowed;
        for (const auto& runtime : root->second.policy.allowed_runtime_template_ids) {
            allowed += allowed.empty() ? runtime : ", " + runtime;
        }
        return std::unexpected(
            "runtime templates not allowed: " + rejected + "; allowed runtimes: " + allowed
        );
    }
    return {};
}

path_exposure_recovery_target::path_exposure_recovery_target(
    int parent_descriptor_fd, std::string basename, std::string source_identity_digest
)
    : parent_descriptor_fd_{parent_descriptor_fd},
      basename_{std::move(basename)},
      source_identity_digest_{std::move(source_identity_digest)} {}

path_exposure_recovery_target::path_exposure_recovery_target(
    path_exposure_recovery_target&& other
) noexcept
    : parent_descriptor_fd_{std::exchange(other.parent_descriptor_fd_, -1)},
      basename_{std::move(other.basename_)},
      source_identity_digest_{std::move(other.source_identity_digest_)} {}

auto path_exposure_recovery_target::operator=(path_exposure_recovery_target&& other) noexcept
    -> path_exposure_recovery_target& {
    if (this != &other) {
        close_descriptor();
        parent_descriptor_fd_ = std::exchange(other.parent_descriptor_fd_, -1);
        basename_ = std::move(other.basename_);
        source_identity_digest_ = std::move(other.source_identity_digest_);
    }
    return *this;
}

path_exposure_recovery_target::~path_exposure_recovery_target() {
    close_descriptor();
}

auto path_exposure_recovery_target::current_source_identity_digest() const -> result<std::string> {
    if (parent_descriptor_fd_ < 0 || !valid_path_component(basename_)) {
        return std::unexpected(std::string{"path exposure recovery target is unavailable"});
    }
    int flags = O_CLOEXEC | O_NOFOLLOW;
#if defined(__linux__)
    flags |= O_PATH;
#else
    flags |= O_RDONLY | O_NONBLOCK;
#endif
    unique_fd source{::openat(parent_descriptor_fd_, basename_.c_str(), flags)};
    if (source.get() < 0) {
        return std::unexpected(error_message("open path exposure recovery source"));
    }
    auto identity = identity_for(source.get(), "path exposure recovery source");
    if (!identity) {
        return std::unexpected(identity.error());
    }
    return identity_digest(*identity);
}

void path_exposure_recovery_target::close_descriptor() noexcept {
    if (parent_descriptor_fd_ >= 0) {
        (void)::close(parent_descriptor_fd_);
        parent_descriptor_fd_ = -1;
    }
}

path_exposure_registry::path_exposure_registry(
    construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {
    (void)token;
}

path_exposure_registry::path_exposure_registry(path_exposure_registry&&) noexcept = default;

auto path_exposure_registry::operator=(path_exposure_registry&&) noexcept
    -> path_exposure_registry& = default;

path_exposure_registry::~path_exposure_registry() = default;

auto path_exposure_registry::build(std::vector<path_exposure_root_policy> roots)
    -> result<path_exposure_registry> {
    if (roots.empty() || roots.size() > max_roots) {
        return std::unexpected(std::string{"exposure root collection is invalid"});
    }
    auto state = std::make_unique<implementation>();
    std::vector<std::filesystem::path> paths;
    paths.reserve(roots.size());
    for (auto& root : roots) {
        if (!valid_identifier(root.root_id) || !valid_absolute_path(root.host_root) ||
            reserved_host_path(std::filesystem::path{root.host_root}) || root.max_ttl_secs == 0) {
            return std::unexpected(std::string{"protected exposure root is invalid"});
        }
        auto modes = canonical_modes(std::move(root.allowed_modes));
        auto runtimes = canonical_runtimes(std::move(root.allowed_runtime_template_ids));
        if (!modes || !runtimes) {
            return std::unexpected(!modes ? modes.error() : runtimes.error());
        }
        root.allowed_modes = std::move(*modes);
        root.allowed_runtime_template_ids = std::move(*runtimes);
        const std::filesystem::path root_path{root.host_root};
        if (std::ranges::any_of(paths, [&](const auto& existing) {
                return path_within(root_path, existing) || path_within(existing, root_path);
            })) {
            return std::unexpected(std::string{"protected exposure roots overlap"});
        }
        auto descriptor = open_absolute_no_follow(root_path);
        if (!descriptor) {
            return std::unexpected(descriptor.error());
        }
        auto identity = identity_for(descriptor->get(), "protected exposure root");
        if (!identity || !S_ISDIR(identity->mode)) {
            return std::unexpected(
                !identity ? identity.error()
                          : std::string{"protected exposure root is not a directory"}
            );
        }
        const auto root_id = root.root_id;
        if (!state->roots
                 .emplace(
                     root_id,
                     root_record{
                         .policy = std::move(root),
                         .descriptor = std::move(*descriptor),
                         .identity = *identity,
                     }
                 )
                 .second) {
            return std::unexpected(std::string{"protected exposure root identifier is duplicated"});
        }
        paths.push_back(root_path);
    }
    return path_exposure_registry{construction_token{}, std::move(state)};
}

auto path_exposure_registry::open(
    std::vector<path_exposure_root_policy> roots,
    const std::filesystem::path& journal_path,
    std::uint64_t max_journal_bytes
) -> result<path_exposure_registry> {
    auto registry = build(std::move(roots));
    if (!registry) {
        return std::unexpected(registry.error());
    }
    auto journal = path_exposure_journal::open(journal_path, max_journal_bytes);
    if (!journal) {
        return std::unexpected(journal.error());
    }
    auto& state = *registry->state_;
    for (const auto& event : journal->records()) {
        if (const auto* create = std::get_if<path_exposure_create_record>(&event)) {
            const auto& descriptor = create->descriptor;
            auto modes = canonical_modes(descriptor.allowed_modes);
            auto runtimes = canonical_runtimes(descriptor.allowed_runtime_template_ids);
            const auto root = state.roots.find(descriptor.root_id);
            if (descriptor.schema_version != 1 || !valid_identifier(descriptor.exposure_id) ||
                descriptor.generation == 0 || !valid_digest(descriptor.source_identity_digest) ||
                !valid_digest(descriptor.scope_digest) || !valid_label(descriptor.display_label) ||
                descriptor.expires_at_ms == 0 || descriptor.state != path_exposure_state::active ||
                !valid_identifier(create->request_id) || !valid_digest(create->request_digest) ||
                !valid_absolute_path(create->host_path) || reserved_host_path(create->host_path) ||
                !valid_digest(create->parent_identity_digest) || !modes || !runtimes ||
                *modes != descriptor.allowed_modes ||
                *runtimes != descriptor.allowed_runtime_template_ids || root == state.roots.end() ||
                state.last_generation[descriptor.exposure_id] ==
                    std::numeric_limits<std::uint64_t>::max() ||
                descriptor.generation != state.last_generation[descriptor.exposure_id] + 1U ||
                state.exposures.size() >= max_exposures ||
                state.request_records.contains(create->request_id) ||
                create->host_path == root->second.policy.host_root ||
                !path_within(create->host_path, root->second.policy.host_root) ||
                std::ranges::any_of(
                    descriptor.allowed_modes,
                    [&](const auto& mode) {
                        return !mode_is_subset(mode, root->second.policy.allowed_modes);
                    }
                ) ||
                std::ranges::any_of(
                    descriptor.allowed_runtime_template_ids, [&](const auto& runtime) {
                        return !std::ranges::binary_search(
                            root->second.policy.allowed_runtime_template_ids, runtime
                        );
                    }
                )) {
                return std::unexpected(
                    std::string{"path exposure journal create replay is invalid"}
                );
            }
            auto expected_scope = scope_digest(descriptor);
            if (!expected_scope || *expected_scope != descriptor.scope_digest) {
                return std::unexpected(
                    std::string{"path exposure journal scope binding is invalid"}
                );
            }
            unique_fd source_descriptor;
            if (auto source =
                    open_beneath_root(root->second, std::filesystem::path{create->host_path})) {
                source_descriptor = std::move(*source);
            }
            const auto key = std::pair{descriptor.exposure_id, descriptor.generation};
            state.last_generation[descriptor.exposure_id] = descriptor.generation;
            state.request_records.emplace(
                create->request_id,
                request_record{
                    .kind = request_kind::create,
                    .digest = create->request_digest,
                    .exposure = key,
                }
            );
            state.exposures.emplace(
                key,
                exposure_record{
                    .descriptor = descriptor,
                    .request_id = create->request_id,
                    .request_digest = create->request_digest,
                    .host_path = create->host_path,
                    .parent_identity_digest = create->parent_identity_digest,
                    .source_descriptor = std::move(source_descriptor),
                }
            );
            continue;
        }
        const auto& revoke = std::get<path_exposure_revoke_record>(event);
        const auto record = state.exposures.find({revoke.exposure_id, revoke.generation});
        if (record == state.exposures.end() ||
            record->second.descriptor.state != path_exposure_state::active ||
            revoke.state == path_exposure_state::active || revoke.revoked_at_ms == 0 ||
            !valid_identifier(revoke.request_id) || !valid_digest(revoke.request_digest) ||
            state.request_records.contains(revoke.request_id)) {
            return std::unexpected(std::string{"path exposure journal revoke replay is invalid"});
        }
        auto expected_digest =
            revoke_request_digest(revoke.request_id, revoke.exposure_id, revoke.generation);
        if (!expected_digest || *expected_digest != revoke.request_digest) {
            return std::unexpected(std::string{"path exposure journal revoke binding is invalid"});
        }
        state.request_records.emplace(
            revoke.request_id,
            request_record{
                .kind = request_kind::revoke,
                .digest = revoke.request_digest,
                .exposure = {revoke.exposure_id, revoke.generation},
            }
        );
        record->second.descriptor.state = revoke.state;
    }
    state.journal = std::make_unique<path_exposure_journal>(std::move(*journal));
    return registry;
}

auto path_exposure_registry::create(
    const path_exposure_create_request& request, std::uint64_t now_ms
) -> result<path_exposure_descriptor> {
    if (!state_) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (now_ms == 0 || !valid_identifier(request.request_id) ||
        !valid_identifier(request.exposure_id) || !valid_identifier(request.root_id) ||
        !valid_absolute_path(request.host_path) || !valid_label(request.display_label) ||
        request.ttl_secs == 0) {
        return std::unexpected(std::string{"path exposure create request is invalid"});
    }
    auto modes = canonical_modes(request.allowed_modes);
    auto runtimes = canonical_runtimes(request.allowed_runtime_template_ids);
    if (!modes || !runtimes) {
        return std::unexpected(!modes ? modes.error() : runtimes.error());
    }
    auto digest = request_digest(request, *modes, *runtimes);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (const auto replay = state_->request_records.find(request.request_id);
        replay != state_->request_records.end()) {
        const auto record = state_->exposures.find(replay->second.exposure);
        if (replay->second.kind != request_kind::create || replay->second.digest != *digest ||
            record == state_->exposures.end() || record->second.request_digest != *digest) {
            return std::unexpected(std::string{"path exposure request identifier conflict"});
        }
        return record->second.descriptor;
    }
    const auto root = state_->roots.find(request.root_id);
    if (root == state_->roots.end() || request.ttl_secs > root->second.policy.max_ttl_secs ||
        std::ranges::any_of(
            *modes,
            [&](const auto& mode) {
                return !mode_is_subset(mode, root->second.policy.allowed_modes);
            }
        ) ||
        std::ranges::any_of(*runtimes, [&](const auto& runtime) {
            return !std::ranges::binary_search(
                root->second.policy.allowed_runtime_template_ids, runtime
            );
        })) {
        return std::unexpected(std::string{"path exposure exceeds protected-root policy"});
    }
    const std::filesystem::path host_path{request.host_path};
    if (reserved_host_path(host_path)) {
        return std::unexpected(std::string{"path exposure source is reserved"});
    }
    auto source = open_beneath_root(root->second, host_path);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto identity = identity_for(source->get(), "exposure source");
    if (!identity) {
        return std::unexpected(identity.error());
    }
    auto source_digest = identity_digest(*identity);
    if (!source_digest) {
        return std::unexpected(source_digest.error());
    }
    auto parent_digest = recovery_parent_identity_digest(root->second, host_path);
    if (!parent_digest) {
        return std::unexpected(parent_digest.error());
    }
    if (state_->exposures.size() >= max_exposures) {
        return std::unexpected(std::string{"path exposure registry capacity exceeded"});
    }
    const auto previous = state_->last_generation[request.exposure_id];
    if (previous == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(std::string{"path exposure generation exhausted"});
    }
    if (previous != 0) {
        const auto prior = state_->exposures.find({request.exposure_id, previous});
        if (prior == state_->exposures.end()) {
            return std::unexpected(std::string{"path exposure generation state is corrupt"});
        }
        if (prior->second.descriptor.state == path_exposure_state::active &&
            prior->second.descriptor.expires_at_ms > now_ms) {
            return std::unexpected(
                std::string{"active path exposure generation must be revoked before replacement"}
            );
        }
    }
    const auto generation = previous + 1U;
    if (request.ttl_secs > (std::numeric_limits<std::uint64_t>::max() - now_ms) / 1'000U) {
        return std::unexpected(std::string{"path exposure expiry overflows"});
    }
    path_exposure_descriptor descriptor{
        .schema_version = 1,
        .exposure_id = request.exposure_id,
        .generation = generation,
        .root_id = request.root_id,
        .source_identity_digest = std::move(*source_digest),
        .scope_digest = {},
        .display_label = request.display_label,
        .allowed_modes = std::move(*modes),
        .expires_at_ms = now_ms + request.ttl_secs * 1'000U,
        .allowed_runtime_template_ids = std::move(*runtimes),
        .state = path_exposure_state::active,
    };
    auto scope = scope_digest(descriptor);
    if (!scope) {
        return std::unexpected(scope.error());
    }
    descriptor.scope_digest = std::move(*scope);
    if (state_->journal) {
        auto appended = state_->journal->append(
            path_exposure_create_record{
                .descriptor = descriptor,
                .request_id = request.request_id,
                .request_digest = *digest,
                .host_path = request.host_path,
                .parent_identity_digest = *parent_digest,
            }
        );
        if (!appended) {
            return std::unexpected(appended.error());
        }
    }
    const auto key = std::pair{descriptor.exposure_id, descriptor.generation};
    state_->last_generation[descriptor.exposure_id] = descriptor.generation;
    state_->request_records.emplace(
        request.request_id,
        request_record{
            .kind = request_kind::create,
            .digest = *digest,
            .exposure = key,
        }
    );
    state_->exposures.emplace(
        key,
        exposure_record{
            .descriptor = descriptor,
            .request_id = request.request_id,
            .request_digest = std::move(*digest),
            .host_path = request.host_path,
            .parent_identity_digest = std::move(*parent_digest),
            .source_descriptor = std::move(*source),
        }
    );
    return descriptor;
}

auto path_exposure_registry::revoke(
    std::string_view request_id,
    std::string_view exposure_id,
    std::uint64_t generation,
    std::uint64_t now_ms
) -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (!valid_identifier(request_id) || !valid_identifier(exposure_id) || generation == 0 ||
        now_ms == 0) {
        return std::unexpected(std::string{"path exposure revoke request is invalid"});
    }
    auto digest = revoke_request_digest(request_id, exposure_id, generation);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (const auto replay = state_->request_records.find(std::string{request_id});
        replay != state_->request_records.end()) {
        if (replay->second.kind != request_kind::revoke || replay->second.digest != *digest) {
            return std::unexpected(std::string{"path exposure request identifier conflict"});
        }
        return {};
    }
    const auto record = state_->exposures.find({std::string{exposure_id}, generation});
    if (record == state_->exposures.end()) {
        return std::unexpected(std::string{"path exposure generation was not found"});
    }
    if (record->second.descriptor.state != path_exposure_state::active) {
        return std::unexpected(std::string{"path exposure generation is no longer active"});
    }
    const auto next_state = record->second.descriptor.expires_at_ms <= now_ms
                                ? path_exposure_state::expired
                                : path_exposure_state::revoked;
    if (state_->journal) {
        auto appended = state_->journal->append(
            path_exposure_revoke_record{
                .request_id = std::string{request_id},
                .request_digest = *digest,
                .exposure_id = std::string{exposure_id},
                .generation = generation,
                .state = next_state,
                .revoked_at_ms = now_ms,
            }
        );
        if (!appended) {
            return std::unexpected(appended.error());
        }
    }
    state_->request_records.emplace(
        std::string{request_id},
        request_record{
            .kind = request_kind::revoke,
            .digest = *digest,
            .exposure = {std::string{exposure_id}, generation},
        }
    );
    record->second.descriptor.state = next_state;
    return {};
}

auto path_exposure_registry::list(std::uint64_t now_ms) const
    -> std::vector<path_exposure_projection> {
    std::vector<path_exposure_projection> output;
    if (!state_) {
        return output;
    }
    const std::scoped_lock lock{state_->mutex};
    output.reserve(state_->exposures.size());
    for (const auto& [key, record] : state_->exposures) {
        (void)key;
        auto projection = projected(record.descriptor, now_ms);
        if (projection.state == path_exposure_state::active) {
            const auto root = state_->roots.find(record.descriptor.root_id);
            if (root == state_->roots.end() || !source_matches(root->second, record)) {
                projection.state = path_exposure_state::revoked;
            }
        }
        output.push_back(std::move(projection));
    }
    return output;
}

auto path_exposure_registry::validate_grant(
    const path_exposure_grant& grant, std::string_view runtime_template_id, std::uint64_t now_ms
) const -> std::expected<void, std::string> {
    if (!state_) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    const std::scoped_lock lock{state_->mutex};
    if (!valid_identifier(grant.exposure_id) || grant.generation == 0 ||
        !valid_digest(grant.scope_digest) || !valid_identifier(runtime_template_id) ||
        grant.ttl_secs == 0 ||
        !valid_mode(
            path_exposure_mode{
                .access = grant.access,
                .materialization = grant.materialization,
                .max_bytes = grant.max_bytes,
                .cleanup_policy = grant.cleanup_policy,
            }
        )) {
        return std::unexpected(std::string{"path exposure grant is invalid"});
    }
    const auto record = state_->exposures.find({grant.exposure_id, grant.generation});
    if (record == state_->exposures.end()) {
        return std::unexpected(std::string{"path exposure generation is unavailable"});
    }
    const auto& descriptor = record->second.descriptor;
    if (descriptor.state != path_exposure_state::active || descriptor.expires_at_ms <= now_ms ||
        descriptor.scope_digest != grant.scope_digest ||
        grant.ttl_secs > (descriptor.expires_at_ms - now_ms) / 1'000U ||
        !std::ranges::binary_search(
            descriptor.allowed_runtime_template_ids, std::string{runtime_template_id}
        ) ||
        !mode_is_subset(
            path_exposure_mode{
                .access = grant.access,
                .materialization = grant.materialization,
                .max_bytes = grant.max_bytes,
                .cleanup_policy = grant.cleanup_policy,
            },
            descriptor.allowed_modes
        )) {
        return std::unexpected(std::string{"path exposure grant is stale or unauthorized"});
    }
    const auto root = state_->roots.find(descriptor.root_id);
    if (root == state_->roots.end()) {
        return std::unexpected(std::string{"path exposure protected root is unavailable"});
    }
    if (!source_matches(root->second, record->second)) {
        return std::unexpected(std::string{"path exposure source identity changed"});
    }
    return {};
}

auto path_exposure_registry::resolve_grant(
    const path_exposure_grant& grant, std::string_view runtime_template_id, std::uint64_t now_ms
) const -> result<resolved_path_grant> {
    if (auto valid = validate_grant(grant, runtime_template_id, now_ms); !valid) {
        return std::unexpected(valid.error());
    }

    const std::scoped_lock lock{state_->mutex};
    const auto record = state_->exposures.find({grant.exposure_id, grant.generation});
    if (record == state_->exposures.end()) {
        return std::unexpected(std::string{"path exposure generation is unavailable"});
    }
    const auto& descriptor = record->second.descriptor;
    const auto root = state_->roots.find(descriptor.root_id);
    if (descriptor.state != path_exposure_state::active || descriptor.expires_at_ms <= now_ms ||
        descriptor.scope_digest != grant.scope_digest || root == state_->roots.end()) {
        return std::unexpected(std::string{"path exposure grant changed while resolving"});
    }
    auto source = open_beneath_root(root->second, std::filesystem::path{record->second.host_path});
    if (!source) {
        return std::unexpected(source.error());
    }
    auto identity = identity_for(source->get(), "path exposure source");
    if (!identity) {
        return std::unexpected(identity.error());
    }
    auto digest = identity_digest(*identity);
    if (!digest || *digest != descriptor.source_identity_digest) {
        return std::unexpected(std::string{"path exposure source identity changed"});
    }
    const int duplicated = ::fcntl(source->get(), F_DUPFD_CLOEXEC, 0);
    if (duplicated < 0) {
        return std::unexpected(error_message("duplicate path exposure descriptor"));
    }
    const path_access_policy policy{
        .access = grant.access,
        .materialization = grant.materialization,
        .create_policy = grant.materialization == path_materialization::git_worktree
                             ? path_create_policy::git_worktree
                             : (grant.materialization == path_materialization::bind
                                    ? path_create_policy::never
                                    : path_create_policy::empty_directory),
        .cleanup_policy = grant.cleanup_policy,
        .max_bytes = grant.max_bytes,
    };
    return resolved_path_grant{
        duplicated,
        grant.exposure_id,
        record->second.host_path,
        "/workspace/exposures/" + grant.exposure_id,
        policy,
        path_grant_request{
            .alias = grant.exposure_id,
            .access = grant.access,
            .ttl_secs = grant.ttl_secs,
            .max_bytes = grant.max_bytes,
        },
        path_identity{
            .device = identity->device,
            .inode = identity->inode,
            .mode = identity->mode,
        },
        descriptor.generation,
        descriptor.scope_digest,
        descriptor.source_identity_digest,
    };
}

auto path_exposure_registry::resolve_recovery_target(
    std::string_view exposure_id,
    std::uint64_t generation,
    std::string_view scope_digest_value,
    std::string_view source_identity_digest_value
) const -> result<path_exposure_recovery_target> {
    if (!state_) {
        return std::unexpected(std::string{"path exposure registry is unavailable"});
    }
    if (!valid_identifier(exposure_id) || generation == 0 || !valid_digest(scope_digest_value) ||
        !valid_digest(source_identity_digest_value)) {
        return std::unexpected(std::string{"path exposure recovery binding is invalid"});
    }

    const std::scoped_lock lock{state_->mutex};
    const auto record = state_->exposures.find({std::string{exposure_id}, generation});
    if (record == state_->exposures.end()) {
        return std::unexpected(std::string{"path exposure recovery generation is unavailable"});
    }
    const auto& descriptor = record->second.descriptor;
    if (descriptor.scope_digest != scope_digest_value ||
        descriptor.source_identity_digest != source_identity_digest_value) {
        return std::unexpected(std::string{"path exposure recovery binding is stale"});
    }
    const auto root = state_->roots.find(descriptor.root_id);
    if (root == state_->roots.end()) {
        return std::unexpected(std::string{"path exposure protected root is unavailable"});
    }

    const std::filesystem::path host_path{record->second.host_path};
    const std::filesystem::path parent_path = host_path.parent_path();
    const std::filesystem::path root_path{root->second.policy.host_root};
    if (host_path.filename().empty() || parent_path.empty() ||
        (parent_path != root_path && !path_within(parent_path, root_path))) {
        return std::unexpected(std::string{"path exposure recovery locator is invalid"});
    }
    auto parent_identity = recovery_parent_identity_digest(root->second, host_path);
    if (!parent_identity || *parent_identity != record->second.parent_identity_digest) {
        return std::unexpected(
            !parent_identity ? parent_identity.error()
                             : std::string{"path exposure recovery parent identity changed"}
        );
    }

    int parent_descriptor = -1;
    if (parent_path == root_path) {
        auto root_identity = identity_for(root->second.descriptor.get(), "protected root");
        if (!root_identity || *root_identity != root->second.identity) {
            return std::unexpected(std::string{"protected root identity changed"});
        }
        parent_descriptor = ::openat(
            root->second.descriptor.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        );
    } else {
        auto parent = open_beneath_root(root->second, parent_path);
        if (!parent) {
            return std::unexpected(parent.error());
        }
        auto opened_parent_identity = identity_for(parent->get(), "path exposure recovery parent");
        if (!opened_parent_identity || !S_ISDIR(opened_parent_identity->mode)) {
            return std::unexpected(
                !opened_parent_identity
                    ? opened_parent_identity.error()
                    : std::string{"path exposure recovery parent is not a directory"}
            );
        }
        parent_descriptor =
            ::openat(parent->get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (parent_descriptor < 0) {
        return std::unexpected(error_message("duplicate path exposure recovery parent"));
    }
    return path_exposure_recovery_target{
        parent_descriptor,
        host_path.filename().string(),
        descriptor.source_identity_digest,
    };
}

} // namespace glove::supervisor
