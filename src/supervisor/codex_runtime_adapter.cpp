#include "glove/supervisor/codex_runtime_adapter.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
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
constexpr std::size_t max_skill_directory_bytes = 255U;
constexpr std::size_t max_json_nesting = 64U;

class unique_member_json_parser {
public:
    explicit unique_member_json_parser(std::string_view input) : input_(input) {}

    [[nodiscard]] auto parse() -> bool {
        skip_whitespace();
        if (!parse_value(0U)) {
            return false;
        }
        skip_whitespace();
        return position_ == input_.size();
    }

private:
    auto skip_whitespace() -> void {
        while (position_ < input_.size()) {
            const auto byte = input_.at(position_);
            if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r') {
                return;
            }
            ++position_;
        }
    }

    [[nodiscard]] auto consume(char expected) -> bool {
        const auto matches = position_ < input_.size() && input_.at(position_) == expected;
        if (matches) {
            ++position_;
        }
        return matches;
    }

    [[nodiscard]] auto consume_literal(std::string_view literal) -> bool {
        const auto matches = input_.substr(position_, literal.size()) == literal;
        if (matches) {
            position_ += literal.size();
        }
        return matches;
    }

    [[nodiscard]] auto parse_string() -> std::optional<std::string_view> {
        if (!consume('"')) {
            return std::nullopt;
        }
        const auto start = position_ - 1U;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_.at(position_++));
            if (byte == static_cast<unsigned char>('"')) {
                return input_.substr(start, position_ - start);
            }
            if (byte < 0x20U) {
                return std::nullopt;
            }
            if (byte == static_cast<unsigned char>('\\')) {
                if (position_ >= input_.size()) {
                    return std::nullopt;
                }
                ++position_;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] static auto is_digit(char byte) -> bool { return byte >= '0' && byte <= '9'; }

    [[nodiscard]] auto consume_digits() -> bool {
        const auto start = position_;
        while (position_ < input_.size() && is_digit(input_.at(position_))) {
            ++position_;
        }
        return position_ != start;
    }

    [[nodiscard]] auto parse_integer_part() -> bool {
        if (position_ >= input_.size()) {
            return false;
        }
        if (input_.at(position_) == '0') {
            ++position_;
            return position_ >= input_.size() || !is_digit(input_.at(position_));
        }
        const auto first = input_.at(position_);
        return first >= '1' && first <= '9' && consume_digits();
    }

    [[nodiscard]] auto parse_fraction() -> bool {
        if (position_ >= input_.size() || input_.at(position_) != '.') {
            return true;
        }
        ++position_;
        return consume_digits();
    }

    [[nodiscard]] auto parse_exponent() -> bool {
        if (position_ >= input_.size()) {
            return true;
        }
        const auto marker = input_.at(position_);
        if (marker != 'e' && marker != 'E') {
            return true;
        }
        ++position_;
        if (position_ < input_.size()) {
            const auto sign = input_.at(position_);
            if (sign == '+' || sign == '-') {
                ++position_;
            }
        }
        return consume_digits();
    }

    [[nodiscard]] auto parse_number() -> bool {
        if (position_ < input_.size() && input_.at(position_) == '-') {
            ++position_;
        }
        return parse_integer_part() && parse_fraction() && parse_exponent();
    }

    [[nodiscard]] auto parse_object(std::size_t depth) -> bool {
        if (depth >= max_json_nesting || !consume('{')) {
            return false;
        }
        skip_whitespace();
        if (consume('}')) {
            return true;
        }

        std::set<std::string, std::less<>> keys;
        while (true) {
            const auto raw_key = parse_string();
            if (!raw_key) {
                return false;
            }
            auto key = glz::read_json<std::string>(*raw_key);
            if (!key || !keys.emplace(std::move(*key)).second) {
                return false;
            }
            skip_whitespace();
            if (!consume(':')) {
                return false;
            }
            skip_whitespace();
            if (!parse_value(depth + 1U)) {
                return false;
            }
            skip_whitespace();
            if (consume('}')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }
    }

    [[nodiscard]] auto parse_array(std::size_t depth) -> bool {
        if (depth >= max_json_nesting || !consume('[')) {
            return false;
        }
        skip_whitespace();
        if (consume(']')) {
            return true;
        }
        while (true) {
            if (!parse_value(depth + 1U)) {
                return false;
            }
            skip_whitespace();
            if (consume(']')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }
    }

    [[nodiscard]] auto parse_value(std::size_t depth) -> bool {
        if (position_ >= input_.size()) {
            return false;
        }
        switch (input_.at(position_)) {
        case '{':
            return parse_object(depth);
        case '[':
            return parse_array(depth);
        case '"':
            return parse_string().has_value();
        case 't':
            return consume_literal("true");
        case 'f':
            return consume_literal("false");
        case 'n':
            return consume_literal("null");
        default:
            return parse_number();
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
};

[[nodiscard]] auto has_unique_json_object_members(std::string_view input) noexcept -> bool {
    if (input.empty() || input.size() > max_library_bundle_bytes) {
        return false;
    }
    try {
        return unique_member_json_parser{input}.parse();
    } catch (...) {
        return false;
    }
}

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

auto valid_skill_directory_name(std::string_view projection_id, std::string_view key) -> bool {
    return projection_id.size() <= max_skill_directory_bytes &&
           key.size() < max_skill_directory_bytes &&
           projection_id.size() <= max_skill_directory_bytes - key.size() - 1U;
}

auto known_unmaterialized_bundle_kind(std::string_view kind) -> bool {
    return kind == "behavior" || kind == "prompt" || kind == "template" || kind == "workflow";
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
    if (!has_unique_json_object_members(*bytes)) {
        return std::unexpected(std::string{"Codex bundle JSON is invalid"});
    }
    wire::bundle_document document;
    std::string parse_buffer{*bytes};
    if (const auto error = glz::read<strict_read_options>(document, parse_buffer); error) {
        return std::unexpected(std::string{"Codex bundle JSON is invalid"});
    }
    if (document.schema_version != 1 || document.source_library_ref.empty() ||
        document.source_library_ref.size() > 512U ||
        document.source_library_ref.find('\0') != std::string::npos ||
        !valid_digest(document.source_manifest_digest) ||
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
    auto append_size(std::size_t value) -> std::expected<void, std::string> {
        if (value > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(std::string{"canonical value exceeds u32 encoding"});
        }
        for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes_.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
        }
        return {};
    }

    auto append_string(std::string_view value) -> std::expected<void, std::string> {
        if (auto appended = append_size(value.size()); !appended) {
            return std::unexpected(appended.error());
        }
        bytes_.insert(bytes_.end(), value.begin(), value.end());
        return {};
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
    std::size_t total_entries = 0;
    std::size_t total_bytes = 0;
    for (const auto& bundle_projection : bundles) {
        if (!valid_projection_id(bundle_projection.projection_id) ||
            !valid_digest(bundle_projection.bundle.content_digest())) {
            return std::unexpected(std::string{"Codex library projection identity is invalid"});
        }
        auto document = decode_bundle(bundle_projection.bundle);
        if (!document) {
            return std::unexpected(document.error());
        }
        for (const auto& entry : document->entries) {
            const bool materialize = entry.kind == "skill";
            if (total_entries == max_bundle_entries ||
                (!materialize && !known_unmaterialized_bundle_kind(entry.kind)) ||
                !valid_skill_key(entry.key) ||
                (materialize &&
                 !valid_skill_directory_name(bundle_projection.projection_id, entry.key)) ||
                !valid_digest(entry.content_digest) || entry.content.empty() ||
                entry.content.size() > max_entry_bytes ||
                entry.content.find('\0') != std::string::npos ||
                !identities.insert({bundle_projection.projection_id, entry.key}).second) {
                return std::unexpected(std::string{"Codex bundle entry is unsafe or unsupported"});
            }
            const auto* raw = reinterpret_cast<const unsigned char*>(entry.content.data());
            const auto digest = glove::container::sha256_hex(std::span{raw, entry.content.size()});
            if (!digest || *digest != entry.content_digest ||
                entry.content.size() > max_projection_bytes - total_bytes) {
                return std::unexpected(std::string{"Codex bundle entry digest or size is invalid"});
            }

            ++total_entries;
            total_bytes += entry.content.size();
            if (materialize) {
                projection.skills.push_back({
                    .projection_id = bundle_projection.projection_id,
                    .bundle_content_digest = std::string{bundle_projection.bundle.content_digest()},
                    .key = entry.key,
                    .content_digest = entry.content_digest,
                    .content = entry.content,
                });
            } else {
                projection.unmaterialized_entries.push_back({
                    .projection_id = bundle_projection.projection_id,
                    .bundle_content_digest = std::string{bundle_projection.bundle.content_digest()},
                    .key = entry.key,
                    .kind = entry.kind,
                    .content_digest = entry.content_digest,
                    .content_size = entry.content.size(),
                });
            }
        }
    }
    const auto by_identity = [](const auto& left, const auto& right) {
        return std::tie(left.projection_id, left.key) < std::tie(right.projection_id, right.key);
    };
    std::ranges::sort(projection.skills, by_identity);
    std::ranges::sort(projection.unmaterialized_entries, by_identity);
    return projection;
}

auto codex_runtime_projection_digest(const codex_runtime_projection& projection)
    -> std::expected<std::string, std::string> {
    if (projection.skills.size() > max_bundle_entries ||
        projection.unmaterialized_entries.size() > max_bundle_entries - projection.skills.size()) {
        return std::unexpected(std::string{"Codex projection exceeds its entry bound"});
    }
    canonical_encoder encoder;
    for (const std::string_view domain : {
             std::string_view{"glove.codex-runtime-projection.v2"},
             std::string_view{"materialized-skills.v1"},
         }) {
        if (auto appended = encoder.append_string(domain); !appended) {
            return std::unexpected(appended.error());
        }
    }
    if (auto appended = encoder.append_size(projection.skills.size()); !appended) {
        return std::unexpected(appended.error());
    }
    std::set<std::pair<std::string, std::string>> identities;
    std::pair<std::string, std::string> previous;
    bool have_previous = false;
    std::size_t total_bytes = 0;
    for (const auto& skill : projection.skills) {
        if (!valid_projection_id(skill.projection_id) ||
            !valid_digest(skill.bundle_content_digest) || !valid_skill_key(skill.key) ||
            !valid_digest(skill.content_digest) || skill.content.empty() ||
            !valid_skill_directory_name(skill.projection_id, skill.key) ||
            skill.content.size() > max_entry_bytes ||
            skill.content.find('\0') != std::string::npos ||
            skill.content.size() > max_projection_bytes - total_bytes) {
            return std::unexpected(std::string{"Codex projection is invalid"});
        }
        const auto identity = std::pair{skill.projection_id, skill.key};
        if ((have_previous && identity <= previous) || !identities.insert(identity).second) {
            return std::unexpected(std::string{"Codex projection is not canonically ordered"});
        }
        const auto* raw = reinterpret_cast<const unsigned char*>(skill.content.data());
        const auto content_digest =
            glove::container::sha256_hex(std::span{raw, skill.content.size()});
        if (!content_digest || *content_digest != skill.content_digest) {
            return std::unexpected(std::string{"Codex projection content digest is invalid"});
        }
        for (const std::string_view value : {
                 std::string_view{skill.projection_id},
                 std::string_view{skill.bundle_content_digest},
                 std::string_view{skill.key},
                 std::string_view{"skill"},
                 std::string_view{skill.content_digest},
             }) {
            if (auto appended = encoder.append_string(value); !appended) {
                return std::unexpected(appended.error());
            }
        }
        if (auto appended = encoder.append_size(skill.content.size()); !appended) {
            return std::unexpected(appended.error());
        }
        total_bytes += skill.content.size();
        previous = identity;
        have_previous = true;
    }

    if (auto appended = encoder.append_string("unmaterialized-known-entries.v1"); !appended) {
        return std::unexpected(appended.error());
    }
    if (auto appended = encoder.append_size(projection.unmaterialized_entries.size()); !appended) {
        return std::unexpected(appended.error());
    }
    previous = {};
    have_previous = false;
    for (const auto& entry : projection.unmaterialized_entries) {
        if (!valid_projection_id(entry.projection_id) ||
            !valid_digest(entry.bundle_content_digest) || !valid_skill_key(entry.key) ||
            !known_unmaterialized_bundle_kind(entry.kind) || !valid_digest(entry.content_digest) ||
            entry.content_size == 0U || entry.content_size > max_entry_bytes ||
            entry.content_size > max_projection_bytes - total_bytes) {
            return std::unexpected(std::string{"Codex unmaterialized entry is invalid"});
        }
        const auto identity = std::pair{entry.projection_id, entry.key};
        if ((have_previous && identity <= previous) || !identities.insert(identity).second) {
            return std::unexpected(std::string{"Codex projection contains a duplicate identity"});
        }
        for (const std::string_view value : {
                 std::string_view{entry.projection_id},
                 std::string_view{entry.bundle_content_digest},
                 std::string_view{entry.key},
                 std::string_view{entry.kind},
                 std::string_view{entry.content_digest},
             }) {
            if (auto appended = encoder.append_string(value); !appended) {
                return std::unexpected(appended.error());
            }
        }
        if (auto appended = encoder.append_size(entry.content_size); !appended) {
            return std::unexpected(appended.error());
        }
        total_bytes += entry.content_size;
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
    if (auto valid = codex_runtime_projection_digest(projection); !valid) {
        return std::unexpected(valid.error());
    }
    if (auto created = make_directory_at(private_home_fd, ".codex"); !created) {
        return std::unexpected(created.error());
    }
    const int codex_fd =
        ::openat(private_home_fd, ".codex", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (codex_fd < 0) {
        return std::unexpected(errno_message("open private CODEX_HOME"));
    }
    const auto close_codex = [&] { ::close(codex_fd); };
    if (auto created = make_directory_at(codex_fd, "skills"); !created) {
        close_codex();
        return std::unexpected(errno_message("create Codex skills directory"));
    }
    const int skills_fd =
        ::openat(codex_fd, "skills", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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
        const int skill_fd =
            ::openat(skills_fd, directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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
