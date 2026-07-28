#include "glove/supervisor/native_skill_runtime_adapter.hpp"

#include "glove/container/digest.hpp"
#include "glove/supervisor/codex_runtime_adapter.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::supervisor {

namespace {

auto errno_message(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto write_all(int descriptor, std::string_view bytes) -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written <= 0) {
            return std::unexpected(errno_message("write native skill"));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto make_directory_at(int parent_fd, std::string_view name) -> std::expected<int, std::string> {
    if (name.empty() || name.size() > 128U || name.find('/') != std::string_view::npos ||
        name == "." || name == ".." || ::mkdirat(parent_fd, std::string{name}.c_str(), 0700) != 0) {
        return std::unexpected(errno_message("create native runtime directory"));
    }
    const int descriptor = ::openat(
        parent_fd, std::string{name}.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (descriptor < 0) {
        return std::unexpected(errno_message("open native runtime directory"));
    }
    return descriptor;
}

class canonical_encoder {
public:
    void append_u32(std::uint32_t value) {
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
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

} // namespace

auto native_skill_runtime_adapter_for(std::string_view runtime_id)
    -> std::optional<native_skill_runtime_adapter> {
    if (runtime_id == "codex") {
        return native_skill_runtime_adapter{
            .runtime_id = "codex",
            .executable_name = "codex",
            .home_mount_alias = "__runtime_home_codex",
            .skill_root_components = {".codex", "skills"},
            .managed_environment = {"CODEX_HOME=/home/agent/.codex"},
        };
    }
    if (runtime_id == "claude-code") {
        return native_skill_runtime_adapter{
            .runtime_id = "claude-code",
            .executable_name = "claude",
            .home_mount_alias = "__runtime_home_claude-code",
            .skill_root_components = {".claude", "skills"},
            .managed_environment = {},
        };
    }
    if (runtime_id == "pi") {
        return native_skill_runtime_adapter{
            .runtime_id = "pi",
            .executable_name = "pi",
            .home_mount_alias = "__runtime_home_pi",
            .skill_root_components = {".pi", "agent", "skills"},
            .managed_environment = {},
        };
    }
    if (runtime_id == "copilot") {
        return native_skill_runtime_adapter{
            .runtime_id = "copilot",
            .executable_name = "copilot",
            .home_mount_alias = "__runtime_home_copilot",
            .skill_root_components = {".copilot", "skills"},
            .managed_environment = {"COPILOT_HOME=/home/agent/.copilot"},
        };
    }
    if (runtime_id == "opencode") {
        return native_skill_runtime_adapter{
            .runtime_id = "opencode",
            .executable_name = "opencode",
            .home_mount_alias = "__runtime_home_opencode",
            .skill_root_components = {".config", "opencode", "skills"},
            .managed_environment = {"XDG_CONFIG_HOME=/home/agent/.config"},
        };
    }
    return std::nullopt;
}

auto is_builtin_adapter(const native_skill_runtime_adapter& adapter) -> bool {
    const auto builtin = native_skill_runtime_adapter_for(adapter.runtime_id);
    return builtin && *builtin == adapter;
}

auto resolve_native_skill_runtime_projection(
    const native_skill_runtime_adapter& adapter,
    const std::vector<resolved_library_projection>& bundles
) -> std::expected<native_skill_runtime_projection, std::string> {
    if (!is_builtin_adapter(adapter) || adapter.skill_root_components.empty()) {
        return std::unexpected(std::string{"native skill runtime adapter is unsupported"});
    }
    auto codex_projection = resolve_codex_runtime_projection(bundles);
    if (!codex_projection) {
        return std::unexpected(codex_projection.error());
    }
    native_skill_runtime_projection projection;
    projection.skills.reserve(codex_projection->skills.size());
    for (const auto& skill : codex_projection->skills) {
        projection.skills.push_back({
            .projection_id = skill.projection_id,
            .bundle_content_digest = skill.bundle_content_digest,
            .key = skill.key,
            .content_digest = skill.content_digest,
            .content = skill.content,
        });
    }
    return projection;
}

auto native_skill_runtime_projection_digest(
    const native_skill_runtime_adapter& adapter,
    const native_skill_runtime_projection& projection
) -> std::expected<std::string, std::string> {
    if (!is_builtin_adapter(adapter)) {
        return std::unexpected(std::string{"native skill runtime adapter is unsupported"});
    }
    codex_runtime_projection canonical;
    canonical.skills.reserve(projection.skills.size());
    for (const auto& skill : projection.skills) {
        canonical.skills.push_back({
            .projection_id = skill.projection_id,
            .bundle_content_digest = skill.bundle_content_digest,
            .key = skill.key,
            .content_digest = skill.content_digest,
            .content = skill.content,
        });
    }
    auto skill_digest = codex_runtime_projection_digest(canonical);
    if (!skill_digest) {
        return std::unexpected(skill_digest.error());
    }
    canonical_encoder encoder;
    encoder.append_string("glove.native-skill-runtime-projection");
    encoder.append_string(adapter.runtime_id);
    encoder.append_string(*skill_digest);
    auto digest = container::sha256_hex(encoder.bytes());
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return digest;
}

auto materialize_native_skill_runtime_projection(
    int private_home_fd,
    const native_skill_runtime_adapter& adapter,
    const native_skill_runtime_projection& projection
) -> std::expected<void, std::string> {
    if (private_home_fd < 0 || !is_builtin_adapter(adapter)) {
        return std::unexpected(std::string{"native skill runtime home is unavailable"});
    }
    int parent_fd = private_home_fd;
    std::vector<int> opened_directories;
    for (const auto& component : adapter.skill_root_components) {
        auto directory = make_directory_at(parent_fd, component);
        if (!directory) {
            for (const int descriptor : opened_directories) {
                ::close(descriptor);
            }
            return std::unexpected(directory.error());
        }
        opened_directories.push_back(*directory);
        parent_fd = *directory;
    }
    for (const auto& skill : projection.skills) {
        const auto directory = skill.projection_id + "-" + skill.key;
        auto skill_directory = make_directory_at(parent_fd, directory);
        if (!skill_directory) {
            for (const int descriptor : opened_directories) {
                ::close(descriptor);
            }
            return std::unexpected(skill_directory.error());
        }
        const int file_fd = ::openat(
            *skill_directory, "SKILL.md", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        );
        ::close(*skill_directory);
        if (file_fd < 0) {
            for (const int descriptor : opened_directories) {
                ::close(descriptor);
            }
            return std::unexpected(errno_message("create native skill"));
        }
        auto wrote = write_all(file_fd, skill.content);
        const int sync_status = ::fsync(file_fd);
        ::close(file_fd);
        if (!wrote || sync_status != 0) {
            for (const int descriptor : opened_directories) {
                ::close(descriptor);
            }
            return std::unexpected(wrote ? errno_message("sync native skill") : wrote.error());
        }
    }
    if (::fsync(parent_fd) != 0) {
        for (const int descriptor : opened_directories) {
            ::close(descriptor);
        }
        return std::unexpected(errno_message("sync native skills directory"));
    }
    for (const int descriptor : opened_directories) {
        ::close(descriptor);
    }
    return {};
}

} // namespace glove::supervisor
