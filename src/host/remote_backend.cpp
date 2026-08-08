#include "../../include/glove/host/remote_backend.hpp"

#include "../../include/glove/container/digest.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace glove::host {
namespace {

constexpr std::string_view ed25519_algorithm = "ssh-ed25519";
constexpr std::size_t ed25519_blob_bytes = 4U + 11U + 4U + 32U;
constexpr std::size_t max_identity_bytes = std::size_t{1024} * 1024U;

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

auto base64_value(unsigned char byte) -> std::optional<unsigned char> {
    if (byte >= 'A' && byte <= 'Z') {
        return static_cast<unsigned char>(byte - 'A');
    }
    if (byte >= 'a' && byte <= 'z') {
        return static_cast<unsigned char>(byte - 'a' + 26U);
    }
    if (byte >= '0' && byte <= '9') {
        return static_cast<unsigned char>(byte - '0' + 52U);
    }
    if (byte == '+') {
        return 62U;
    }
    if (byte == '/') {
        return 63U;
    }
    return std::nullopt;
}

auto decode_base64(std::string_view encoded) -> result<std::vector<unsigned char>> {
    if (encoded.empty() || encoded.size() % 4U != 0 || encoded.size() > 512U) {
        return std::unexpected(std::string{"invalid SSH public-key base64"});
    }
    std::vector<unsigned char> decoded;
    decoded.reserve((encoded.size() / 4U) * 3U);
    for (std::size_t offset = 0; offset < encoded.size(); offset += 4U) {
        std::array<unsigned char, 4> values{};
        std::size_t padding = 0;
        for (std::size_t index = 0; index < values.size(); ++index) {
            const auto byte = static_cast<unsigned char>(encoded[offset + index]);
            if (byte == '=') {
                if (offset + 4U != encoded.size() || index < 2U) {
                    return std::unexpected(std::string{"invalid SSH public-key padding"});
                }
                ++padding;
                values[index] = 0;
                continue;
            }
            if (padding != 0) {
                return std::unexpected(std::string{"invalid SSH public-key padding"});
            }
            auto value = base64_value(byte);
            if (!value) {
                return std::unexpected(std::string{"invalid SSH public-key base64"});
            }
            values[index] = *value;
        }
        const auto block = (static_cast<std::uint32_t>(values[0]) << 18U) |
                           (static_cast<std::uint32_t>(values[1]) << 12U) |
                           (static_cast<std::uint32_t>(values[2]) << 6U) |
                           static_cast<std::uint32_t>(values[3]);
        decoded.push_back(static_cast<unsigned char>((block >> 16U) & 0xffU));
        if (padding < 2U) {
            decoded.push_back(static_cast<unsigned char>((block >> 8U) & 0xffU));
        }
        if (padding == 0U) {
            decoded.push_back(static_cast<unsigned char>(block & 0xffU));
        }
    }
    return decoded;
}

auto encode_base64_unpadded(std::span<const unsigned char> bytes) -> std::string {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((bytes.size() + 2U) / 3U) * 4U);
    for (std::size_t offset = 0; offset < bytes.size(); offset += 3U) {
        const std::size_t remaining = bytes.size() - offset;
        const auto block =
            (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
            (remaining > 1U ? static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U : 0U) |
            (remaining > 2U ? static_cast<std::uint32_t>(bytes[offset + 2U]) : 0U);
        encoded.push_back(alphabet[(block >> 18U) & 0x3fU]);
        encoded.push_back(alphabet[(block >> 12U) & 0x3fU]);
        if (remaining > 1U) {
            encoded.push_back(alphabet[(block >> 6U) & 0x3fU]);
        }
        if (remaining > 2U) {
            encoded.push_back(alphabet[block & 0x3fU]);
        }
    }
    return encoded;
}

auto hex_nibble(char byte) -> std::optional<unsigned char> {
    if (byte >= '0' && byte <= '9') {
        return static_cast<unsigned char>(byte - '0');
    }
    if (byte >= 'a' && byte <= 'f') {
        return static_cast<unsigned char>(static_cast<unsigned int>(byte - 'a') + 10U);
    }
    return std::nullopt;
}

auto decode_sha256_hex(std::string_view value) -> result<std::array<unsigned char, 32>> {
    if (value.size() != 64U) {
        return std::unexpected(std::string{"invalid SHA-256 result"});
    }
    std::array<unsigned char, 32> decoded{};
    for (std::size_t index = 0; index < decoded.size(); ++index) {
        auto high = hex_nibble(value[index * 2U]);
        auto low = hex_nibble(value[(index * 2U) + 1U]);
        if (!high || !low) {
            return std::unexpected(std::string{"invalid SHA-256 result"});
        }
        decoded[index] = static_cast<unsigned char>((*high << 4U) | *low);
    }
    return decoded;
}

auto big_endian_u32(std::span<const unsigned char> bytes) -> std::uint32_t {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
}

auto parse_public_key(std::string_view public_key) -> result<std::vector<unsigned char>> {
    const auto separator = public_key.find(' ');
    if (separator == std::string_view::npos ||
        public_key.substr(0, separator) != ed25519_algorithm ||
        public_key.find(' ', separator + 1U) != std::string_view::npos ||
        public_key.find_first_of("\t\r\n") != std::string_view::npos) {
        return std::unexpected(std::string{"remote host key must be one ssh-ed25519 key"});
    }
    auto blob = decode_base64(public_key.substr(separator + 1U));
    if (!blob || blob->size() != ed25519_blob_bytes || big_endian_u32(*blob) != 11U ||
        std::string_view{reinterpret_cast<const char*>(blob->data() + 4U), 11U} !=
            ed25519_algorithm ||
        big_endian_u32(std::span<const unsigned char>{*blob}.subspan(15U, 4U)) != 32U) {
        return std::unexpected(std::string{"remote host key has an invalid Ed25519 blob"});
    }
    return blob;
}

auto safe_ssh_path(const std::filesystem::path& path) -> bool {
    const auto value = path.string();
    return path.is_absolute() && path.lexically_normal() == path &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '/' || byte == '.' || byte == '_' ||
                      byte == '-';
           });
}

auto verify_owner_directory(int descriptor) -> result<void> {
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0) {
        return std::unexpected(system_error("inspect remote SSH directory"));
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"remote SSH directory must be owner-only"});
    }
    return {};
}

auto verify_identity(const std::filesystem::path& path) -> result<void> {
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open remote identity"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U || metadata.st_size <= 0 ||
        static_cast<std::uint64_t>(metadata.st_size) > max_identity_bytes) {
        return std::unexpected(std::string{"remote identity must be an owner-only regular file"});
    }
    return {};
}

auto write_all(int descriptor, std::string_view contents) -> result<void> {
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto written =
            ::write(descriptor, contents.data() + consumed, contents.size() - consumed);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return std::unexpected(system_error("write remote SSH artifact"));
        }
        consumed += static_cast<std::size_t>(written);
    }
    return {};
}

auto replace_owner_file(int directory, std::string_view name, std::string_view contents)
    -> result<void> {
    const std::string temporary = "." + std::string{name} + ".tmp-" + std::to_string(::getpid());
    const unique_fd output{::openat(
        directory, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    )};
    if (output.get() < 0) {
        return std::unexpected(system_error("create remote SSH artifact"));
    }
    auto cleanup = [&] { (void)::unlinkat(directory, temporary.c_str(), 0); };
    if (auto wrote = write_all(output.get(), contents); !wrote) {
        cleanup();
        return std::unexpected(wrote.error());
    }
    if (::fsync(output.get()) != 0) {
        const auto error = system_error("sync remote SSH artifact");
        cleanup();
        return std::unexpected(error);
    }
    struct stat existing{};
    const auto inspected =
        ::fstatat(directory, std::string{name}.c_str(), &existing, AT_SYMLINK_NOFOLLOW);
    if (inspected == 0) {
        if (!S_ISREG(existing.st_mode) || existing.st_uid != ::geteuid() ||
            existing.st_nlink != 1 ||
            (static_cast<unsigned int>(existing.st_mode) & 0777U) != 0600U ||
            existing.st_size < 0 ||
            static_cast<std::uint64_t>(existing.st_size) != contents.size()) {
            cleanup();
            return std::unexpected(
                std::string{"existing remote SSH artifact is unsafe or differs"}
            );
        }
        const unique_fd current{
            ::openat(directory, std::string{name}.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        };
        std::string current_contents(contents.size(), '\0');
        std::size_t consumed = 0;
        while (current.get() >= 0 && consumed < current_contents.size()) {
            const auto count = ::read(
                current.get(),
                current_contents.data() + consumed,
                current_contents.size() - consumed
            );
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                break;
            }
            consumed += static_cast<std::size_t>(count);
        }
        cleanup();
        if (current.get() < 0 || consumed != current_contents.size() ||
            current_contents != contents) {
            return std::unexpected(
                std::string{"existing remote SSH artifact is unsafe or differs"}
            );
        }
        return {};
    }
    if (errno != ENOENT) {
        const auto error = system_error("inspect remote SSH artifact");
        cleanup();
        return std::unexpected(error);
    }
    if (::renameat(directory, temporary.c_str(), directory, std::string{name}.c_str()) != 0) {
        const auto error = system_error("install remote SSH artifact");
        cleanup();
        return std::unexpected(error);
    }
    if (::fsync(directory) != 0) {
        return std::unexpected(system_error("sync remote SSH directory"));
    }
    return {};
}

auto ssh_config_contents(
    const remote_backend_config& configured, const std::filesystem::path& known_hosts_path
) -> std::string {
    return "Host glove-remote\n"
           "  HostName " +
           configured.host + "\n  User " + configured.user + "\n  Port " +
           std::to_string(configured.port) + "\n  UserKnownHostsFile " + known_hosts_path.string() +
           "\n  GlobalKnownHostsFile none\n"
           "  StrictHostKeyChecking yes\n"
           "  HostKeyAlgorithms ssh-ed25519\n"
           "  UpdateHostKeys no\n"
           "  IdentityFile " +
           configured.identity_file.string() +
           "\n  IdentitiesOnly yes\n"
           "  BatchMode yes\n"
           "  PubkeyAuthentication yes\n"
           "  PreferredAuthentications publickey\n"
           "  PasswordAuthentication no\n"
           "  KbdInteractiveAuthentication no\n"
           "  ChallengeResponseAuthentication no\n"
           "  IdentityAgent none\n"
           "  ForwardAgent no\n"
           "  ForwardX11 no\n"
           "  ForwardX11Trusted no\n"
           "  ClearAllForwardings yes\n"
           "  PermitLocalCommand no\n"
           "  ProxyCommand none\n"
           "  ProxyJump none\n"
           "  RemoteCommand none\n"
           "  RequestTTY no\n"
           "  Tunnel no\n"
           "  ControlMaster no\n"
           "  ControlPath none\n"
           "  ControlPersist no\n";
}

} // namespace

auto openssh_host_key_fingerprint(std::string_view public_key) -> result<std::string> {
    auto blob = parse_public_key(public_key);
    if (!blob) {
        return std::unexpected(blob.error());
    }
    auto digest = container::sha256_hex(*blob);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    auto raw_digest = decode_sha256_hex(*digest);
    if (!raw_digest) {
        return std::unexpected(raw_digest.error());
    }
    return "SHA256:" + encode_base64_unpadded(*raw_digest);
}

auto prepare_remote_ssh_artifacts(
    const remote_backend_config& configured, const std::filesystem::path& runtime_directory
) -> result<remote_ssh_artifacts> {
    if (auto valid = validate(configured); !valid) {
        return std::unexpected(valid.error());
    }
    if (!safe_ssh_path(runtime_directory) || !safe_ssh_path(configured.identity_file)) {
        return std::unexpected(std::string{"remote SSH paths contain unsupported characters"});
    }
    if (auto identity = verify_identity(configured.identity_file); !identity) {
        return std::unexpected(identity.error());
    }
    const unique_fd runtime{
        ::open(runtime_directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (runtime.get() < 0) {
        return std::unexpected(system_error("open Glove runtime directory"));
    }
    if (auto owner = verify_owner_directory(runtime.get()); !owner) {
        return std::unexpected(owner.error());
    }
    constexpr std::string_view child_name = "remote-ssh";
    if (::mkdirat(runtime.get(), child_name.data(), 0700) != 0 && errno != EEXIST) {
        return std::unexpected(system_error("create remote SSH directory"));
    }
    const unique_fd directory{
        ::openat(runtime.get(), child_name.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (directory.get() < 0) {
        return std::unexpected(system_error("open remote SSH directory"));
    }
    if (auto owner = verify_owner_directory(directory.get()); !owner) {
        return std::unexpected(owner.error());
    }
    const auto artifact_root = runtime_directory / child_name;
    const auto config_path = artifact_root / "config";
    const auto known_hosts_path = artifact_root / "known_hosts";
    std::error_code canonical_error;
    const auto identity_path =
        std::filesystem::canonical(configured.identity_file, canonical_error);
    if (canonical_error) {
        return std::unexpected("canonicalize remote identity: " + canonical_error.message());
    }
    const auto canonical_config = std::filesystem::weakly_canonical(config_path, canonical_error);
    if (canonical_error) {
        return std::unexpected("canonicalize remote SSH config path: " + canonical_error.message());
    }
    const auto canonical_known_hosts =
        std::filesystem::weakly_canonical(known_hosts_path, canonical_error);
    if (canonical_error) {
        return std::unexpected(
            "canonicalize remote known-hosts path: " + canonical_error.message()
        );
    }
    if (identity_path == canonical_config || identity_path == canonical_known_hosts) {
        return std::unexpected(
            std::string{"remote identity must not overlap generated SSH artifacts"}
        );
    }
    const auto known_host = configured.port == 22U
                                ? configured.host
                                : "[" + configured.host + "]:" + std::to_string(configured.port);
    const auto known_hosts = known_host + " " + configured.host_public_key + "\n";
    if (auto wrote = replace_owner_file(directory.get(), "known_hosts", known_hosts); !wrote) {
        return std::unexpected(wrote.error());
    }
    if (auto wrote = replace_owner_file(
            directory.get(), "config", ssh_config_contents(configured, known_hosts_path)
        );
        !wrote) {
        return std::unexpected(wrote.error());
    }
    return remote_ssh_artifacts{
        .config_path = config_path,
        .known_hosts_path = known_hosts_path,
        .argv = {"/usr/bin/ssh", "-F", config_path.string(), "glove-remote"},
    };
}

} // namespace glove::host
