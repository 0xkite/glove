#include "glove/host/runtime_policy.hpp"
#include "glove/supervisor/harness_adoption.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-harness-adoption-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::vector<std::filesystem::path> entries;
        for (std::filesystem::recursive_directory_iterator
                 iterator{root_, std::filesystem::directory_options::none, error},
             end;
             !error && iterator != end;
             iterator.increment(error)) {
            entries.push_back(iterator->path());
        }
        for (auto iterator = entries.rbegin(); iterator != entries.rend(); ++iterator) {
            const auto status = std::filesystem::symlink_status(*iterator, error);
            if (!error && !std::filesystem::is_symlink(status)) {
                std::filesystem::permissions(
                    *iterator,
                    std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::replace,
                    error
                );
            }
            error.clear();
        }
        std::filesystem::permissions(
            root_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, error
        );
        error.clear();
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto write_file(const std::filesystem::path& path, std::string_view contents, mode_t mode) -> bool {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (descriptor < 0) {
        return false;
    }
    std::size_t offset = 0;
    bool success = true;
    while (offset < contents.size()) {
        const auto written =
            ::write(descriptor, contents.data() + offset, contents.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            success = false;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    success = success && ::fsync(descriptor) == 0;
    success = ::close(descriptor) == 0 && success;
    return success && ::chmod(path.c_str(), mode) == 0;
}

auto overwrite_file(const std::filesystem::path& path, std::string_view contents, mode_t mode)
    -> bool {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    std::size_t offset = 0;
    bool success = true;
    while (offset < contents.size()) {
        const auto written =
            ::write(descriptor, contents.data() + offset, contents.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            success = false;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    success = success && ::fsync(descriptor) == 0;
    success = ::close(descriptor) == 0 && success;
    return success && ::chmod(path.c_str(), mode) == 0;
}

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{},
    };
}

struct adoption_fixture {
    std::filesystem::path root;
    std::filesystem::path manifest_path;
    std::filesystem::path payload_file;
    glove::supervisor::native_harness_adoption_policy policy;
};

auto make_fixture(const std::filesystem::path& parent, std::string_view name)
    -> std::optional<adoption_fixture> {
    const auto fixture_root = parent / std::string{name};
    const auto settings_path = fixture_root / "source/settings.json";
    const auto package = fixture_root / "store/example-extension";
    if (!std::filesystem::create_directories(settings_path.parent_path()) ||
        !std::filesystem::create_directories(package) || ::chmod(fixture_root.c_str(), 0700) != 0) {
        return std::nullopt;
    }
    if (!write_file(settings_path, R"({"packages":["npm:example-extension"]})", 0600) ||
        !write_file(
            package / "package.json", R"({"name":"example-extension","dependencies":{}})", 0600
        ) ||
        !write_file(package / "index.js", "export default {};\n", 0600)) {
        return std::nullopt;
    }

    const auto protected_directory = fixture_root / "protected";
    auto generated = glove::host::generate_pi_adoption_manifest({
        .settings_path = settings_path,
        .package_store_root = fixture_root / "store",
        .protected_directory = protected_directory,
        .dry_run = false,
    });
    if (!generated) {
        std::fprintf(stderr, "generate Pi adoption fixture: %s\n", generated.error().c_str());
        return std::nullopt;
    }
    std::error_code error;
    const auto canonical_root = std::filesystem::canonical(protected_directory, error);
    if (error) {
        return std::nullopt;
    }
    return adoption_fixture{
        .root = canonical_root,
        .manifest_path = canonical_root / "manifests" / generated->manifest_path.filename(),
        .payload_file =
            canonical_root / "snapshots" / generated->snapshot_digest / "payload/root-0/index.js",
        .policy = {
            .manifest_root = canonical_root.string(),
            .manifest_digest = generated->manifest_digest,
            .snapshot_digest = generated->snapshot_digest,
        },
    };
}

auto mutate_digest_field(std::string contents, std::string_view field)
    -> std::optional<std::string> {
    const std::string prefix = "\"" + std::string{field} + "\":\"";
    const auto position = contents.find(prefix);
    if (position == std::string::npos || position + prefix.size() >= contents.size()) {
        return std::nullopt;
    }
    auto& byte = contents[position + prefix.size()];
    byte = byte == '0' ? '1' : '0';
    return contents;
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());

    auto fixture = make_fixture(temporary.root(), "valid");
    REQUIRE(fixture.has_value());
    REQUIRE(
        glove::supervisor::validate_native_harness_adoption_policy(fixture->policy).has_value()
    );

    auto resolved = glove::supervisor::resolve_native_harness_adoption(fixture->policy, "pi");
    if (!resolved) {
        std::fprintf(stderr, "resolve valid adoption fixture: %s\n", resolved.error().c_str());
    }
    REQUIRE(resolved.has_value());
    const auto identity = resolved->identity();
    REQUIRE(identity.manifest_digest == fixture->policy.manifest_digest);
    REQUIRE(identity.snapshot_digest == fixture->policy.snapshot_digest);
    REQUIRE(resolved->runtime_id() == "pi");
    REQUIRE(resolved->payload_count() == 1U);
    REQUIRE(
        resolved->generated_settings_json() ==
        "{\"packages\":[\"./extensions/0\"],\"enableSkillCommands\":true}\n"
    );
    auto verified = resolved->verify_identity();
    if (!verified) {
        std::fprintf(stderr, "verify valid adoption fixture: %s\n", verified.error().c_str());
    }
    REQUIRE(verified.has_value());

    const auto private_home = temporary.root() / "private-home";
    REQUIRE(std::filesystem::create_directory(private_home));
    REQUIRE(::chmod(private_home.c_str(), 0700) == 0);
    const int private_home_fd =
        ::open(private_home.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(private_home_fd >= 0);
    const auto adapter = glove::supervisor::native_skill_runtime_adapter_for("pi");
    REQUIRE(adapter.has_value());
    auto projection = glove::supervisor::resolve_native_skill_runtime_projection(*adapter, {});
    REQUIRE(projection.has_value());
    const auto unbound_projection_digest =
        glove::supervisor::native_skill_runtime_projection_digest(*adapter, *projection);
    const auto bound_projection_digest =
        glove::supervisor::native_skill_runtime_projection_digest(*adapter, *projection, &identity);
    REQUIRE(unbound_projection_digest.has_value());
    REQUIRE(bound_projection_digest.has_value());
    REQUIRE(*bound_projection_digest != *unbound_projection_digest);
    auto materialized = glove::supervisor::materialize_native_skill_runtime_projection(
        private_home_fd, *adapter, *projection, &*resolved
    );
    ::close(private_home_fd);
    if (!materialized) {
        std::fprintf(stderr, "materialize adoption fixture: %s\n", materialized.error().c_str());
    }
    REQUIRE(materialized.has_value());
    REQUIRE(
        read_file(private_home / ".pi/agent/settings.json") ==
        "{\"packages\":[\"./extensions/0\"],\"enableSkillCommands\":true}\n"
    );
    REQUIRE(std::filesystem::exists(private_home / ".pi/agent/extensions/0/package.json"));
    REQUIRE(std::filesystem::exists(private_home / ".pi/agent/extensions/0/index.js"));
    REQUIRE(!std::filesystem::exists(private_home / ".pi/agent/auth.json"));
    REQUIRE(!std::filesystem::exists(private_home / ".pi/agent/sessions"));

    auto invalid_policy = fixture->policy;
    invalid_policy.manifest_root = "relative";
    REQUIRE(
        !glove::supervisor::validate_native_harness_adoption_policy(invalid_policy).has_value()
    );
    invalid_policy = fixture->policy;
    invalid_policy.manifest_root = "/";
    REQUIRE(
        !glove::supervisor::validate_native_harness_adoption_policy(invalid_policy).has_value()
    );
    invalid_policy = fixture->policy;
    invalid_policy.snapshot_digest.front() = 'A';
    REQUIRE(
        !glove::supervisor::validate_native_harness_adoption_policy(invalid_policy).has_value()
    );

    auto unsafe_root = make_fixture(temporary.root(), "unsafe-root");
    REQUIRE(unsafe_root.has_value());
    REQUIRE(::chmod(unsafe_root->root.c_str(), 0755) == 0);
    REQUIRE(
        !glove::supervisor::resolve_native_harness_adoption(unsafe_root->policy, "pi").has_value()
    );

    auto linked_root = make_fixture(temporary.root(), "linked-root");
    REQUIRE(linked_root.has_value());
    const auto root_target = linked_root->root.string() + "-target";
    std::error_code rename_error;
    std::filesystem::rename(linked_root->root, root_target, rename_error);
    REQUIRE(!rename_error);
    REQUIRE(::symlink(root_target.c_str(), linked_root->root.c_str()) == 0);
    REQUIRE(
        !glove::supervisor::resolve_native_harness_adoption(linked_root->policy, "pi").has_value()
    );

    auto linked_manifest = make_fixture(temporary.root(), "linked-manifest");
    REQUIRE(linked_manifest.has_value());
    const auto manifest_target = temporary.root() / "manifest-target.json";
    rename_error.clear();
    std::filesystem::rename(linked_manifest->manifest_path, manifest_target, rename_error);
    REQUIRE(!rename_error);
    REQUIRE(::symlink(manifest_target.c_str(), linked_manifest->manifest_path.c_str()) == 0);
    REQUIRE(!glove::supervisor::resolve_native_harness_adoption(linked_manifest->policy, "pi")
                 .has_value());

    auto hard_linked_manifest = make_fixture(temporary.root(), "hard-linked-manifest");
    REQUIRE(hard_linked_manifest.has_value());
    const auto extra_link = hard_linked_manifest->root / "manifests/extra.json";
    REQUIRE(::link(hard_linked_manifest->manifest_path.c_str(), extra_link.c_str()) == 0);
    REQUIRE(!glove::supervisor::resolve_native_harness_adoption(hard_linked_manifest->policy, "pi")
                 .has_value());

    auto malformed = make_fixture(temporary.root(), "malformed");
    REQUIRE(malformed.has_value());
    auto malformed_contents = read_file(malformed->manifest_path);
    REQUIRE(!malformed_contents.empty());
    malformed_contents.insert(malformed_contents.size() - 1U, ",\"unexpected\":true");
    REQUIRE(overwrite_file(malformed->manifest_path, malformed_contents, 0600));
    REQUIRE(
        !glove::supervisor::resolve_native_harness_adoption(malformed->policy, "pi").has_value()
    );

    auto duplicate = make_fixture(temporary.root(), "duplicate");
    REQUIRE(duplicate.has_value());
    auto duplicate_contents = read_file(duplicate->manifest_path);
    constexpr std::string_view runtime_id = "\"runtime_id\":\"pi\",";
    const auto runtime_id_position = duplicate_contents.find(runtime_id);
    REQUIRE(runtime_id_position != std::string::npos);
    duplicate_contents.insert(runtime_id_position, runtime_id);
    REQUIRE(overwrite_file(duplicate->manifest_path, duplicate_contents, 0600));
    REQUIRE(
        !glove::supervisor::resolve_native_harness_adoption(duplicate->policy, "pi").has_value()
    );

    auto mismatch = make_fixture(temporary.root(), "mismatch");
    REQUIRE(mismatch.has_value());
    auto mismatch_contents =
        mutate_digest_field(read_file(mismatch->manifest_path), "snapshot_digest");
    REQUIRE(mismatch_contents.has_value());
    REQUIRE(overwrite_file(mismatch->manifest_path, *mismatch_contents, 0600));
    REQUIRE(
        !glove::supervisor::resolve_native_harness_adoption(mismatch->policy, "pi").has_value()
    );

    auto manifest_mutation = make_fixture(temporary.root(), "manifest-mutation");
    REQUIRE(manifest_mutation.has_value());
    auto manifest_resolved =
        glove::supervisor::resolve_native_harness_adoption(manifest_mutation->policy, "pi");
    REQUIRE(manifest_resolved.has_value());
    auto changed_manifest = read_file(manifest_mutation->manifest_path);
    REQUIRE(!changed_manifest.empty());
    changed_manifest.front() = '[';
    REQUIRE(overwrite_file(manifest_mutation->manifest_path, changed_manifest, 0600));
    REQUIRE(!manifest_resolved->verify_identity().has_value());

    auto payload_mutation = make_fixture(temporary.root(), "payload-mutation");
    REQUIRE(payload_mutation.has_value());
    auto payload_resolved =
        glove::supervisor::resolve_native_harness_adoption(payload_mutation->policy, "pi");
    REQUIRE(payload_resolved.has_value());
    auto changed_payload = read_file(payload_mutation->payload_file);
    REQUIRE(!changed_payload.empty());
    changed_payload.front() = changed_payload.front() == 'x' ? 'y' : 'x';
    REQUIRE(::chmod(payload_mutation->payload_file.c_str(), 0600) == 0);
    REQUIRE(overwrite_file(payload_mutation->payload_file, changed_payload, 0400));
    REQUIRE(!payload_resolved->verify_identity().has_value());

    return 0;
}

} // namespace

int main() {
    return run();
}
