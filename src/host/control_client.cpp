#include "glove/host/control_client.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <sys/ucred.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <string_view>
#include <system_error>
#include <utility>

namespace glove::host {
namespace control_wire {

struct exposure_mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct create_exposure {
    std::string exposure_id;
    std::string root_id;
    std::string host_path;
    std::string display_label;
    std::vector<exposure_mode> allowed_modes;
    std::uint64_t ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

struct params {
    std::uint8_t schema_version = 1;
    std::string bootstrap_secret;
    std::uint64_t deadline_ms = 0;
    std::optional<std::string> idempotency_key;
    glz::raw_json payload;
};

struct request {
    std::string jsonrpc = "2.0";
    std::string id;
    std::string method;
    params params;
};

struct rpc_error {
    std::string code;
    std::string message;
};

struct response {
    std::string jsonrpc;
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<rpc_error> error;
};

struct exposure {
    std::uint8_t schema_version = 0;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string display_label;
    std::vector<exposure_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    std::string state;
};

struct exposure_result {
    std::uint8_t schema_version = 0;
    exposure exposure;
};

} // namespace control_wire

namespace {

constexpr std::size_t max_frame_bytes = std::size_t{1024} * 1024U;
constexpr std::chrono::seconds io_timeout{5};
constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

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

auto valid_identifier(std::string_view value) -> bool {
    return !value.empty() && value.size() <= 128U && value.front() != '-' && value.front() != '.' &&
           std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') || byte == '-' || byte == '_' || byte == '.';
           });
}

auto owner_only_contents(const std::filesystem::path& path, std::size_t expected_bytes)
    -> result<std::string> {
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open bootstrap secret"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0600U || metadata.st_size <= 0 ||
        static_cast<std::size_t>(metadata.st_size) > expected_bytes + 1U) {
        return std::unexpected(std::string{"bootstrap secret is not an owner-only file"});
    }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto read =
            ::read(descriptor.get(), contents.data() + consumed, contents.size() - consumed);
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(system_error("read bootstrap secret"));
        }
        consumed += static_cast<std::size_t>(read);
    }
    if (!contents.empty() && contents.back() == '\n') {
        contents.pop_back();
    }
    if (contents.size() != expected_bytes || !std::ranges::all_of(contents, [](unsigned char byte) {
            return std::isdigit(byte) != 0 || (byte >= 'a' && byte <= 'f');
        })) {
        return std::unexpected(std::string{"bootstrap secret must be 32-byte lowercase hex"});
    }
    return contents;
}

auto verify_socket(const std::filesystem::path& path) -> result<void> {
    struct stat metadata{};
    if (::lstat(path.c_str(), &metadata) != 0 || !S_ISSOCK(metadata.st_mode) ||
        metadata.st_uid != ::geteuid()) {
        return std::unexpected(std::string{"control socket is missing or not owned by this user"});
    }
    return {};
}

auto verify_peer(int descriptor) -> result<void> {
#if defined(__APPLE__)
    xucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, 0, LOCAL_PEERCRED, &credentials, &length) != 0 ||
        credentials.cr_uid != ::geteuid()) {
        return std::unexpected(std::string{"control peer ownership check failed"});
    }
#elif defined(__linux__)
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        credentials.uid != ::geteuid()) {
        return std::unexpected(std::string{"control peer ownership check failed"});
    }
#else
    (void)descriptor;
    return std::unexpected(std::string{"control peer verification is unsupported"});
#endif
    return {};
}

auto connect_socket(const std::filesystem::path& path) -> result<unique_fd> {
    if (auto verified = verify_socket(path); !verified) {
        return std::unexpected(verified.error());
    }
    const auto encoded = path.string();
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (encoded.empty() || encoded.size() >= sizeof(address.sun_path)) {
        return std::unexpected(std::string{"control socket path exceeds platform bounds"});
    }
    std::memcpy(address.sun_path, encoded.c_str(), encoded.size() + 1U);
    unique_fd descriptor{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("create control socket"));
    }
    const timeval timeout{
        .tv_sec = io_timeout.count(),
        .tv_usec = 0,
    };
    if (::setsockopt(descriptor.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(descriptor.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return std::unexpected(system_error("configure control timeout"));
    }
    if (::connect(descriptor.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) !=
        0) {
        return std::unexpected(system_error("connect to gloved"));
    }
    if (auto peer = verify_peer(descriptor.get()); !peer) {
        return std::unexpected(peer.error());
    }
    return std::move(descriptor);
}

auto write_all(int descriptor, const void* buffer, std::size_t size) -> result<void> {
    const auto* bytes = static_cast<const unsigned char*>(buffer);
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto written = ::send(descriptor, bytes + consumed, size - consumed, 0);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return std::unexpected(system_error("write control frame"));
        }
        consumed += static_cast<std::size_t>(written);
    }
    return {};
}

auto read_all(int descriptor, void* buffer, std::size_t size) -> result<void> {
    auto* bytes = static_cast<unsigned char*>(buffer);
    std::size_t consumed = 0;
    while (consumed < size) {
        const auto read = ::recv(descriptor, bytes + consumed, size - consumed, 0);
        if (read < 0 && errno == EINTR) {
            continue;
        }
        if (read <= 0) {
            return std::unexpected(system_error("read control frame"));
        }
        consumed += static_cast<std::size_t>(read);
    }
    return {};
}

auto now_millis() -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch()
    )
                                          .count());
}

auto call(
    const config& service,
    std::string method,
    glz::raw_json payload,
    std::optional<std::string> idempotency_key
) -> result<glz::raw_json> {
    auto secret = owner_only_contents(service.runtime_directory / "bootstrap-secret", 64U);
    if (!secret) {
        return std::unexpected(secret.error());
    }
    auto socket = connect_socket(service.runtime_directory / "gloved.sock");
    if (!socket) {
        return std::unexpected(socket.error());
    }
    const std::string request_id =
        "glove-local-" + std::to_string(::getpid()) + "-" + std::to_string(now_millis());
    auto encoded = glz::write_json(
        control_wire::request{
            .id = request_id,
            .method = std::move(method),
            .params = {
                .bootstrap_secret = std::move(*secret),
                .deadline_ms = now_millis() + 5'000U,
                .idempotency_key = std::move(idempotency_key),
                .payload = std::move(payload),
            },
        }
    );
    if (!encoded || encoded->empty() || encoded->size() > max_frame_bytes) {
        return std::unexpected(std::string{"control request encoding failed or exceeded 1 MiB"});
    }
    const auto length = htonl(static_cast<std::uint32_t>(encoded->size()));
    if (auto sent = write_all(socket->get(), &length, sizeof(length)); !sent) {
        return std::unexpected(sent.error());
    }
    if (auto sent = write_all(socket->get(), encoded->data(), encoded->size()); !sent) {
        return std::unexpected(sent.error());
    }
    std::uint32_t response_length = 0;
    if (auto received = read_all(socket->get(), &response_length, sizeof(response_length));
        !received) {
        return std::unexpected(received.error());
    }
    const auto response_size = static_cast<std::size_t>(ntohl(response_length));
    if (response_size == 0 || response_size > max_frame_bytes) {
        return std::unexpected(std::string{"control response frame is invalid"});
    }
    std::string response_json(response_size, '\0');
    if (auto received = read_all(socket->get(), response_json.data(), response_json.size());
        !received) {
        return std::unexpected(received.error());
    }
    control_wire::response response;
    if (const auto error = glz::read<strict_read_options>(response, response_json);
        error || response.jsonrpc != "2.0" || response.id != request_id ||
        response.result.has_value() == response.error.has_value()) {
        return std::unexpected(std::string{"control response contract is invalid"});
    }
    if (response.error) {
        return std::unexpected(
            "gloved rejected the request [" + response.error->code + "]: " + response.error->message
        );
    }
    return std::move(*response.result);
}

auto mode_for(const project_enrollment& request) -> control_wire::exposure_mode {
    switch (request.access) {
    case project_access::read:
        return {
            .access = "read",
            .materialization = "bind",
            .max_bytes = 0,
            .cleanup_policy = "retain",
        };
    case project_access::ephemeral_write:
        return {
            .access = "ephemeral_write",
            .materialization = "copy",
            .max_bytes = request.max_bytes,
            .cleanup_policy = "remove",
        };
    case project_access::retained_write:
        return {
            .access = "retained_write",
            .materialization = "copy",
            .max_bytes = request.max_bytes,
            .cleanup_policy = "retain",
        };
    }
    return {};
}

} // namespace

auto supervisor_health(const config& service) -> result<void> {
    auto response = call(service, "capabilities", glz::raw_json{"null"}, std::nullopt);
    if (!response) {
        return std::unexpected(response.error());
    }
    return {};
}

auto enroll_project(const config& service, const project_enrollment& request)
    -> result<project_exposure> {
    if (!request.project.is_absolute() || !valid_identifier(request.exposure_id) ||
        !valid_identifier(request.root_id) || request.display_label.empty() ||
        request.display_label.size() > 256U || request.ttl_secs == 0 ||
        request.runtime_template_ids.empty() || !valid_identifier(request.idempotency_key) ||
        !std::ranges::all_of(request.runtime_template_ids, valid_identifier) ||
        (request.access == project_access::read && request.max_bytes != 0) ||
        (request.access != project_access::read &&
         request.max_bytes < std::uint64_t{32} * 1024U * 1024U)) {
        return std::unexpected(std::string{"project enrollment request is invalid"});
    }
    std::error_code error;
    const auto canonical_project = std::filesystem::canonical(request.project, error);
    if (error || !std::filesystem::is_directory(canonical_project)) {
        return std::unexpected(std::string{"project must be an existing directory"});
    }
    auto payload = glz::write_json(
        control_wire::create_exposure{
            .exposure_id = request.exposure_id,
            .root_id = request.root_id,
            .host_path = canonical_project.string(),
            .display_label = request.display_label,
            .allowed_modes = {mode_for(request)},
            .ttl_secs = request.ttl_secs,
            .allowed_runtime_template_ids = request.runtime_template_ids,
        }
    );
    if (!payload) {
        return std::unexpected(std::string{"project enrollment encoding failed"});
    }
    auto response = call(
        service, "create_path_exposure", glz::raw_json{std::move(*payload)}, request.idempotency_key
    );
    if (!response) {
        return std::unexpected(response.error());
    }
    control_wire::exposure_result decoded;
    if (const auto parse = glz::read<strict_read_options>(decoded, response->str);
        parse || decoded.schema_version != 1 || decoded.exposure.schema_version != 1 ||
        decoded.exposure.exposure_id != request.exposure_id || decoded.exposure.generation == 0 ||
        decoded.exposure.scope_digest.size() != 64U || decoded.exposure.state != "active") {
        return std::unexpected(std::string{"project enrollment response is invalid"});
    }
    return project_exposure{
        .exposure_id = std::move(decoded.exposure.exposure_id),
        .generation = decoded.exposure.generation,
        .scope_digest = std::move(decoded.exposure.scope_digest),
        .expires_at_ms = decoded.exposure.expires_at_ms,
    };
}

} // namespace glove::host
