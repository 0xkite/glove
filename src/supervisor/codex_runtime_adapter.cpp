#include "glove/supervisor/codex_runtime_adapter.hpp"

#include "glove/container/digest.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cerrno>
#include <fcntl.h>
#include <set>
#include <span>
#include <sys/stat.h>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unistd.h>
#include <utility>

namespace glove::supervisor {

namespace wire {

struct bundle_entry {
    std::string key;
    std::string kind;
    std::string content_digest;
    std::string content;
};

struct bundle_document {
    std::uint8_t schema_version = 0;
    std::string source_library_ref;
    std::string source_manifest_digest;
    std::vector<bundle_entry> entries;
};

} // namespace wire

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};
constexpr std::size_t max_bundle_entries = 4'096U;
constexpr std::size_t max_entry_bytes = 1024U * 1024U;
constexpr std::size_t max_projection_bytes = 16U * 1024U * 1024U;

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

auto valid_skill_key(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_';
    });
}

auto valid_projection_id(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && std::ranges::all_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '-' || character == '_' ||
               character == ':' || character == '.';
    });
}

auto read_bundle(const resolved_library_bundle& bundle) -> std::expected<std::string, std::string> {
    if (auto verified = bundle.verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    if (bundle.size_bytes() == 0 || bundle.size_bytes() > max_library_bundle_bytes) {
        return std::unexpected(std::string{"Codex bundle size is invalid"});
    }
    std::string bytes(static_cast<std::size_t>(bundle.size_bytes()), '\0');
    const auto count = ::pread(bundle.descriptor_fd(), bytes.data(), bytes.size(), 0);
    if (count != static_cast<ssize_t>(bytes.size())) {
        return std::unexpected(std::string{"read verified Codex bundle"});
    }
    const auto* raw = reinterpret_cast<const unsigned char*>(bytes.data());
    const auto digest = glove::container::sha256_hex(std::span{raw, bytes.size()});
    if (!digest || *digest != bundle.content_digest()) {
        return std::unexpected(std::string{"Codex bundle digest changed while reading"});
    }
    if (auto verified = bundle.verify_identity(); !verified) {
        return std::unexpected(verified.error());
    }
    return bytes;
}

auto decode_bundle(const resolved_library_bundle& bundle)
    -> std::expected<wire::bundle_document, std::string> {
    auto bytes = read_bundle(bundle);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    wire::bundle_document document;
    std::string parse_buffer{*bytes};
    if (const auto error = glz::read<strict_read_options>(document, parse_buffer); error) {
        return std::unexpected(std::string{"Codex bundle JSON is invalid"});
    }
    if (document.schema_version != 1 || document.source_library_ref.empty() ||
        document.source_library_ref.size() > 512U || !valid_digest(document.source_manifest_digest) ||
        document.entries.size() > max_bundle_entries) {
        return std::unexpected(std::string{"Codex bundle schema is invalid"});
    }
    return document;
}

auto errno_message(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto write_all(int descriptor, std::string_view bytes) -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written <= 0) {
            return std::unexpected(errno_message("write Codex skill"));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

auto make_directory_at(int parent_fd, const char* name) -> std::expected<void, std::string> {
#if defined(__linux__)
    if (::mkdirat(parent_fd, name, 0700) != 0) {
        return std::unexpected(errno_message("create Codex private directory"));
    }
    return {};
#else
    static_cast<void>(parent_fd);
    static_cast<void>(name);
    return std::unexpected(std::string{"Codex private-home materialization requires Linux"});
#endif
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

auto resolve_codex_runtime_projection(const std::vector<resolved_library_projection>& bundles)
    -> std::expected<codex_runtime_projection, std::string> {
    codex_runtime_projection projection;
    std::set<std::pair<std::string, std::string>> identities;
    std::size_t total_bytes = 0;
    for (const auto& bundle_projection : bundles) {
        if (bundle_projection.projection_id.empty() || !valid_digest(bundle_projection.bundle.content_digest())) {
            return std::unexpected(std::string{"Codex library projection identity is invalid"});
        }
        auto document = decode_bundle(bundle_projection.bundle);
        if (!document) {
            return std::unexpected(document.error());
        }
        for (const auto& entry : document->entries) {
            if (entry.kind != "skill" || !valid_skill_key(entry.key) || !valid_digest(entry.content_digest) ||
                entry.content.empty() || entry.content.size() > max_entry_bytes || entry.content.find('\0') != std::string::npos ||
                !identities.insert({bundle_projection.projection_id, entry.key}).second) {
                return std::unexpected(std::string{"Codex bundle entry is unsafe or unsupported"});
            }
            const auto* raw = reinterpret_cast<const unsigned char*>(entry.content.data());
            const auto digest = glove::container::sha256_hex(std::span{raw, entry.content.size()});
            if (!digest || *digest != entry.content_digest || entry.content.size() > max_projection_bytes - total_bytes) {
                return std::unexpected(std::string{"Codex bundle entry digest or size is invalid"});
            }
            total_bytes += entry.content.size();
            projection.skills.push_back({
                .projection_id = bundle_projection.projection_id,
                .bundle_content_digest = std::string{bundle_projection.bundle.content_digest()},
                .key = entry.key,
                .content_digest = entry.content_digest,
                .content = entry.content,
            });
        }
    }
    std::ranges::sort(projection.skills, [](const auto& left, const auto& right) {
        return std::tie(left.projection_id, left.key) < std::tie(right.projection_id, right.key);
    });
    return projection;
}

auto codex_runtime_projection_digest(const codex_runtime_projection& projection)
    -> std::expected<std::string, std::string> {
    if (projection.skills.size() > max_bundle_entries) {
        return std::unexpected(std::string{"Codex projection exceeds its skill bound"});
    }
    canonical_encoder encoder;
    encoder.append_string("glove.codex-runtime-projection");
    encoder.append_u32(static_cast<std::uint32_t>(projection.skills.size()));
    std::pair<std::string, std::string> previous;
    bool have_previous = false;
    for (const auto& skill : projection.skills) {
        if (!valid_projection_id(skill.projection_id) || !valid_digest(skill.bundle_content_digest) ||
            !valid_skill_key(skill.key) || !valid_digest(skill.content_digest) ||
            skill.content.empty() || skill.content.size() > max_entry_bytes) {
            return std::unexpected(std::string{"Codex projection is invalid"});
        }
        const auto identity = std::pair{skill.projection_id, skill.key};
        if (have_previous && identity <= previous) {
            return std::unexpected(std::string{"Codex projection is not canonically ordered"});
        }
        const auto* raw = reinterpret_cast<const unsigned char*>(skill.content.data());
        const auto content_digest = glove::container::sha256_hex(std::span{raw, skill.content.size()});
        if (!content_digest || *content_digest != skill.content_digest) {
            return std::unexpected(std::string{"Codex projection content digest is invalid"});
        }
        encoder.append_string(skill.projection_id);
        encoder.append_string(skill.bundle_content_digest);
        encoder.append_string(skill.key);
        encoder.append_string(skill.content_digest);
        previous = identity;
        have_previous = true;
    }
    return glove::container::sha256_hex(encoder.bytes());
}

auto materialize_codex_runtime_projection(
    int private_home_fd, const codex_runtime_projection& projection
) -> std::expected<void, std::string> {
    if (private_home_fd < 0) {
        return std::unexpected(std::string{"Codex private home descriptor is unavailable"});
    }
    if (auto created = make_directory_at(private_home_fd, ".codex"); !created) {
        return std::unexpected(created.error());
    }
    const int codex_fd = ::openat(
        private_home_fd, ".codex", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (codex_fd < 0) {
        return std::unexpected(errno_message("open private CODEX_HOME"));
    }
    const auto close_codex = [&] { ::close(codex_fd); };
    if (auto created = make_directory_at(codex_fd, "skills"); !created) {
        close_codex();
        return std::unexpected(errno_message("create Codex skills directory"));
    }
    const int skills_fd = ::openat(codex_fd, "skills", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close_codex();
    if (skills_fd < 0) {
        return std::unexpected(errno_message("open Codex skills directory"));
    }
    for (const auto& skill : projection.skills) {
        const auto directory = skill.projection_id + "-" + skill.key;
        if (!valid_skill_key(skill.key) || directory.size() > 255U ||
            !make_directory_at(skills_fd, directory.c_str())) {
            ::close(skills_fd);
            return std::unexpected(std::string{"create Codex skill directory"});
        }
        const int skill_fd = ::openat(
            skills_fd, directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        );
        if (skill_fd < 0) {
            ::close(skills_fd);
            return std::unexpected(errno_message("open Codex skill directory"));
        }
        const int file_fd = ::openat(
            skill_fd, "SKILL.md", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        );
        ::close(skill_fd);
        if (file_fd < 0) {
            ::close(skills_fd);
            return std::unexpected(errno_message("create Codex skill"));
        }
        auto wrote = write_all(file_fd, skill.content);
        const int sync_status = ::fsync(file_fd);
        ::close(file_fd);
        if (!wrote || sync_status != 0) {
            ::close(skills_fd);
            return std::unexpected(wrote ? errno_message("sync Codex skill") : wrote.error());
        }
    }
    if (::fsync(skills_fd) != 0) {
        ::close(skills_fd);
        return std::unexpected(errno_message("sync Codex skill directory"));
    }
    ::close(skills_fd);
    return {};
}

} // namespace glove::supervisor
