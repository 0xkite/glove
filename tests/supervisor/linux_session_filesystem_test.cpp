#include "glove/container/digest.hpp"
#include "glove/supervisor/linux_session_filesystem.hpp"
#include "glove/supervisor/path_alias.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view canonical_library_bundle =
    R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_tree {
public:
    temporary_tree() {
        std::string pattern = "/tmp/glove-session-filesystem-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;

    ~temporary_tree() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto policy_for(
    std::string alias,
    const std::filesystem::path& source,
    std::string target,
    std::uint64_t max_bytes
) -> glove::supervisor::path_alias_policy {
    return {
        .alias = std::move(alias),
        .host_path = source.string(),
        .target_path = std::move(target),
        .max_ttl_secs = 3600,
        .access = {{
            .access = glove::supervisor::path_access::ephemeral_write,
            .materialization = glove::supervisor::path_materialization::copy,
            .create_policy = glove::supervisor::path_create_policy::empty_directory,
            .cleanup_policy = glove::supervisor::path_cleanup_policy::remove,
            .max_bytes = max_bytes,
        }},
    };
}

auto read_policy_for(std::string alias, const std::filesystem::path& source, std::string target)
    -> glove::supervisor::path_alias_policy {
    return {
        .alias = std::move(alias),
        .host_path = source.string(),
        .target_path = std::move(target),
        .max_ttl_secs = 3600,
        .access = {{
            .access = glove::supervisor::path_access::read,
            .materialization = glove::supervisor::path_materialization::bind,
            .create_policy = glove::supervisor::path_create_policy::never,
            .cleanup_policy = glove::supervisor::path_cleanup_policy::retain,
            .max_bytes = 0,
        }},
    };
}

auto resolve(
    const glove::supervisor::path_alias_registry& registry,
    std::string alias,
    std::uint64_t max_bytes
) -> glove::supervisor::result<glove::supervisor::resolved_path_grant> {
    return registry.resolve({
        .alias = std::move(alias),
        .access = glove::supervisor::path_access::ephemeral_write,
        .ttl_secs = 300,
        .max_bytes = max_bytes,
    });
}

auto resolve_read(const glove::supervisor::path_alias_registry& registry, std::string alias)
    -> glove::supervisor::result<glove::supervisor::resolved_path_grant> {
    return registry.resolve({
        .alias = std::move(alias),
        .access = glove::supervisor::path_access::read,
        .ttl_secs = 300,
        .max_bytes = 0,
    });
}

auto read_at(int directory_fd, const char* name) -> std::string {
    const int fd = ::openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return {};
    }
    std::array<char, 128> bytes{};
    const ::ssize_t count = ::read(fd, bytes.data(), bytes.size());
    ::close(fd);
    return count > 0 ? std::string{bytes.data(), static_cast<std::size_t>(count)} : std::string{};
}

auto digest_for(std::string_view value) -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    return glove::container::sha256_hex(std::span{bytes, value.size()}).value_or("");
}

auto fill_until_quota(int directory_fd, std::uint64_t quota_bytes) -> bool {
    const int fd = ::openat(
        directory_fd, "pressure", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    );
    if (fd < 0) {
        return errno == ENOSPC || errno == EDQUOT;
    }
    std::array<char, 4096> block{};
    bool denied = false;
    for (std::uint64_t attempt = 0; attempt < quota_bytes / block.size() + 32; ++attempt) {
        if (::write(fd, block.data(), block.size()) < 0) {
            denied = errno == ENOSPC || errno == EDQUOT;
            break;
        }
    }
    ::close(fd);
    return denied;
}

auto run() -> int {
    temporary_tree tree;
    REQUIRE(!tree.root().empty());
    const auto materialization_root = tree.root() / "materializations";
    const auto first_source = tree.root() / "first";
    const auto second_source = tree.root() / "second";
    const auto reference_source = tree.root() / "reference";
    const auto library_root = tree.root() / "library-bundles";
    REQUIRE(std::filesystem::create_directory(materialization_root));
    REQUIRE(::chmod(materialization_root.c_str(), 0700) == 0);
    REQUIRE(std::filesystem::create_directory(first_source));
    REQUIRE(std::filesystem::create_directory(second_source));
    REQUIRE(std::filesystem::create_directory(reference_source));
    REQUIRE(std::filesystem::create_directory(library_root));
    REQUIRE(::chmod(library_root.c_str(), 0700) == 0);
    {
        std::ofstream first{first_source / "first.txt"};
        first << "first";
        std::ofstream second{second_source / "second.txt"};
        second << "second";
        std::ofstream reference{reference_source / "reference.txt"};
        reference << "reference";
    }
    const auto library_digest = digest_for(canonical_library_bundle);
    const auto library_path = library_root / (library_digest + ".json");
    {
        std::ofstream library{library_path, std::ios::binary | std::ios::trunc};
        library << canonical_library_bundle;
    }
    REQUIRE(::chmod(library_path.c_str(), 0600) == 0);
    auto library_store = glove::supervisor::library_bundle_store::open(library_root);
    REQUIRE(library_store.has_value());
    std::vector<glove::supervisor::resolved_library_projection_target> projection_targets;
    projection_targets.push_back({
        .projection =
            {
                .projection_id = "sage-core",
                .content_digest = library_digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto library_projections = library_store->resolve_projections(projection_targets);
    REQUIRE(library_projections.has_value());

    const long page_size = ::sysconf(_SC_PAGESIZE);
    REQUIRE(page_size > 0);
    const auto page = static_cast<std::uint64_t>(page_size);
    const auto alias_quota = page * 16U;
    const auto session_quota = page * 64U;
    auto registry = glove::supervisor::path_alias_registry::build({
        policy_for("first", first_source, "/workspace/first", alias_quota),
        policy_for("second", second_source, "/workspace/second", alias_quota),
        read_policy_for("reference", reference_source, "/workspace/reference"),
    });
    REQUIRE(registry.has_value());
    auto first = resolve(*registry, "first", alias_quota);
    auto second = resolve(*registry, "second", alias_quota);
    auto reference = resolve_read(*registry, "reference");
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE(reference.has_value());
    const auto reference_identity = reference->identity();
    std::vector<glove::supervisor::resolved_path_grant> grants;
    grants.push_back(std::move(*first));
    grants.push_back(std::move(*second));
    grants.push_back(std::move(*reference));

    auto filesystem = glove::supervisor::linux_detail::linux_session_filesystem::create(
        materialization_root.string(),
        "session-1",
        session_quota,
        std::move(grants),
        std::move(*library_projections)
    );
    if (!filesystem && filesystem.error().find("tmpfs mount unavailable") != std::string::npos) {
        std::fprintf(stderr, "%s\n", filesystem.error().c_str());
        return 77;
    }
    REQUIRE(filesystem.has_value());
    auto mounts = filesystem->mounts();
    REQUIRE(mounts.size() == 6);
    const auto find_mount = [&](std::string_view target) {
        return std::ranges::find(
            mounts, target, &glove::supervisor::linux_detail::session_mount::target_path
        );
    };
    const auto first_mount = find_mount("/workspace/first");
    const auto second_mount = find_mount("/workspace/second");
    const auto reference_mount = find_mount("/workspace/reference");
    const auto tmp_mount = find_mount("/tmp");
    const auto var_tmp_mount = find_mount("/var/tmp");
    const auto library_mount = find_mount("/opt/sage/library-bundles/" + library_digest + ".json");
    REQUIRE(first_mount != mounts.end());
    REQUIRE(second_mount != mounts.end());
    REQUIRE(reference_mount != mounts.end());
    REQUIRE(tmp_mount != mounts.end());
    REQUIRE(var_tmp_mount != mounts.end());
    REQUIRE(library_mount != mounts.end());
    REQUIRE(first_mount->writable);
    REQUIRE(first_mount->directory);
    REQUIRE(!reference_mount->writable);
    REQUIRE(reference_mount->quota_partition.empty());
    REQUIRE(reference_mount->quota_bytes == 0);
    REQUIRE(reference_mount->source_identity == reference_identity);
    REQUIRE(!library_mount->writable);
    REQUIRE(!library_mount->directory);
    REQUIRE(library_mount->alias == "library:sage-core");
    REQUIRE(library_mount->source_content_digest == library_digest);
    REQUIRE(library_mount->source_identity.has_value());
    REQUIRE(S_ISREG(static_cast<mode_t>(library_mount->source_identity->mode)));
    REQUIRE(read_at(first_mount->descriptor_fd, "first.txt") == "first");
    REQUIRE(read_at(second_mount->descriptor_fd, "second.txt") == "second");
    REQUIRE(read_at(reference_mount->descriptor_fd, "reference.txt") == "reference");
    REQUIRE(tmp_mount->descriptor_fd != var_tmp_mount->descriptor_fd);

    auto usage = filesystem->observe();
    REQUIRE(usage.has_value());
    REQUIRE(usage->quota_bytes == session_quota);
    REQUIRE(usage->materializations == 2);
    REQUIRE(!usage->limit_hit);
    REQUIRE(filesystem->disk_limit_bytes() == session_quota);
    const std::vector<glove::supervisor::linux_detail::recovered_quota_partition>
        expected_partitions = {
            {.alias = "first", .quota_bytes = alias_quota},
            {.alias = "second", .quota_bytes = alias_quota},
    };
    REQUIRE(filesystem->recovery_partitions() == expected_partitions);
    REQUIRE(fill_until_quota(tmp_mount->descriptor_fd, session_quota));
    usage = filesystem->observe();
    REQUIRE(usage.has_value());
    REQUIRE(usage->limit_hit);
    REQUIRE(usage->filesystem_bytes <= usage->quota_bytes);

    REQUIRE(filesystem->cleanup().has_value());
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto overcommitted_registry = glove::supervisor::path_alias_registry::build({
        policy_for("too-large", first_source, "/workspace/too-large", session_quota),
    });
    REQUIRE(overcommitted_registry.has_value());
    auto too_large = resolve(*overcommitted_registry, "too-large", session_quota);
    REQUIRE(too_large.has_value());
    std::vector<glove::supervisor::resolved_path_grant> overcommitted;
    overcommitted.push_back(std::move(*too_large));
    auto rejected = glove::supervisor::linux_detail::linux_session_filesystem::create(
        materialization_root.string(),
        "session-overcommitted",
        session_quota,
        std::move(overcommitted)
    );
    REQUIRE(!rejected.has_value());
    REQUIRE(rejected.error().find("scratch quota") != std::string::npos);
    REQUIRE(std::filesystem::is_empty(materialization_root));

    const ::pid_t crashed_owner = ::fork();
    REQUIRE(crashed_owner >= 0);
    if (crashed_owner == 0) {
        auto recovery_registry = glove::supervisor::path_alias_registry::build({
            policy_for("first", first_source, "/workspace/first", alias_quota),
            policy_for("second", second_source, "/workspace/second", alias_quota),
        });
        if (!recovery_registry) {
            std::_Exit(40);
        }
        auto recovery_first = resolve(*recovery_registry, "first", alias_quota);
        auto recovery_second = resolve(*recovery_registry, "second", alias_quota);
        if (!recovery_first || !recovery_second) {
            std::_Exit(41);
        }
        std::vector<glove::supervisor::resolved_path_grant> recovery_grants;
        recovery_grants.push_back(std::move(*recovery_first));
        recovery_grants.push_back(std::move(*recovery_second));
        auto abandoned = glove::supervisor::linux_detail::linux_session_filesystem::create(
            materialization_root.string(),
            "session-recovered",
            session_quota,
            std::move(recovery_grants)
        );
        if (!abandoned) {
            std::_Exit(42);
        }
        std::_Exit(0);
    }
    int crashed_status = 0;
    REQUIRE(::waitpid(crashed_owner, &crashed_status, 0) == crashed_owner);
    REQUIRE(WIFEXITED(crashed_status));
    REQUIRE(WEXITSTATUS(crashed_status) == 0);
    REQUIRE(!std::filesystem::is_empty(materialization_root));
    const std::vector<glove::supervisor::linux_detail::recovered_quota_partition> wrong_partitions =
        {
            {.alias = "first", .quota_bytes = alias_quota + page},
            {.alias = "second", .quota_bytes = alias_quota},
    };
    REQUIRE(!glove::supervisor::linux_detail::linux_session_filesystem::cleanup_recovered(
                 materialization_root.string(), "session-recovered", session_quota, wrong_partitions
    )
                 .has_value());
    REQUIRE(!std::filesystem::is_empty(materialization_root));
    const std::vector<glove::supervisor::linux_detail::recovered_quota_partition> partitions = {
        {.alias = "first", .quota_bytes = alias_quota},
        {.alias = "second", .quota_bytes = alias_quota},
    };
    REQUIRE(
        glove::supervisor::linux_detail::linux_session_filesystem::cleanup_recovered(
            materialization_root.string(), "session-recovered", session_quota, partitions
        )
            .has_value()
    );
    REQUIRE(std::filesystem::is_empty(materialization_root));

    auto reserved_ancestor_registry = glove::supervisor::path_alias_registry::build({
        policy_for("reserved-ancestor", first_source, "/var", alias_quota),
    });
    REQUIRE(reserved_ancestor_registry.has_value());
    auto reserved_ancestor = resolve(*reserved_ancestor_registry, "reserved-ancestor", alias_quota);
    REQUIRE(reserved_ancestor.has_value());
    std::vector<glove::supervisor::resolved_path_grant> reserved_ancestor_grants;
    reserved_ancestor_grants.push_back(std::move(*reserved_ancestor));
    auto reserved_ancestor_result =
        glove::supervisor::linux_detail::linux_session_filesystem::create(
            materialization_root.string(),
            "session-reserved-ancestor",
            session_quota,
            std::move(reserved_ancestor_grants)
        );
    REQUIRE(!reserved_ancestor_result.has_value());
    REQUIRE(
        reserved_ancestor_result.error().find("invalid session filesystem grant") !=
        std::string::npos
    );
    REQUIRE(std::filesystem::is_empty(materialization_root));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
