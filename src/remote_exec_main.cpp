#include "../include/glove/container/digest.hpp"
#include "../include/glove/control/remote_protocol.hpp"
#include "control/remote_validation_executor.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <mach-o/dyld.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

constexpr auto channel_timeout = std::chrono::milliseconds{glove::control::max_remote_deadline_ms};

[[nodiscard]] auto identity_config_path() noexcept -> std::string_view {
    return "/etc/glove/remote-executor.identity";
}

constexpr std::uint64_t max_identity_config_bytes = std::uint64_t{16U} * 1024U;
constexpr std::uint64_t max_executor_bytes = std::uint64_t{128U} * 1024U * 1024U;

struct loaded_executor_config {
    glove::control::remote_executor_identity identity;
    bool validation_available = false;
    glove::control::remote_validation_executor_config validation;
};

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

[[nodiscard]] auto system_error(std::string_view operation, int error_number = errno)
    -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

[[nodiscard]] auto valid_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.substr(0, 7U) == "sha256:" &&
           std::all_of(value.begin() + 7, value.end(), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto take_line(std::string_view& contents, std::string_view key)
    -> std::expected<std::string, std::string> {
    if (contents.size() < key.size() || contents.substr(0, key.size()) != key) {
        return std::unexpected(std::string{"invalid remote executor identity config"});
    }
    contents.remove_prefix(key.size());
    const auto end = contents.find('\n');
    if (end == std::string_view::npos) {
        return std::unexpected(std::string{"invalid remote executor identity config"});
    }
    std::string value{contents.substr(0, end)};
    contents.remove_prefix(end + 1U);
    if (value.empty() || value.find_first_of("\r\n") != std::string::npos ||
        value.find('\0') != std::string::npos) {
        return std::unexpected(std::string{"invalid remote executor identity config"});
    }
    return value;
}

[[nodiscard]] auto parse_u64(std::string_view value) -> std::expected<std::uint64_t, std::string> {
    std::uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()) {
        return std::unexpected(std::string{"invalid remote executor numeric config"});
    }
    return parsed;
}

[[nodiscard]] auto parse_identity_config(std::string_view contents)
    -> std::expected<loaded_executor_config, std::string> {
    auto schema = take_line(contents, "schema_version=");
    if (!schema || (*schema != "1" && *schema != "2")) {
        return std::unexpected(std::string{"invalid remote executor identity config"});
    }
    auto executor_digest = take_line(contents, "executor_digest=");
    if (!executor_digest) {
        return std::unexpected(executor_digest.error());
    }
    if (*schema == "1") {
        auto image_digest = take_line(contents, "container_image_digest=");
        if (!image_digest || !contents.empty() || !valid_digest(*executor_digest) ||
            !valid_digest(*image_digest)) {
            return std::unexpected(std::string{"invalid remote executor identity config"});
        }
        return loaded_executor_config{
            .identity =
                {
                    .executor_digest = std::move(*executor_digest),
                    .container_image_digest = std::move(*image_digest),
                    .workerd_digest = {},
                    .descriptor_digest = {},
                },
            .validation_available = false,
            .validation = {},
        };
    }

    auto image = take_line(contents, "container_image=");
    auto image_digest = take_line(contents, "container_image_digest=");
    auto workerd_digest = take_line(contents, "workerd_digest=");
    auto descriptor_digest = take_line(contents, "descriptor_digest=");
    auto staging_root = take_line(contents, "staging_root=");
    auto max_sessions = take_line(contents, "max_sessions=");
    auto max_ttl_ms = take_line(contents, "max_ttl_ms=");
    auto docker_executable = take_line(contents, "docker_executable=");
    auto docker_digest = take_line(contents, "docker_executable_digest=");
    if (!image || !image_digest || !workerd_digest || !descriptor_digest || !staging_root ||
        !max_sessions || !max_ttl_ms || !docker_executable || !docker_digest || !contents.empty() ||
        !valid_digest(*executor_digest) || !valid_digest(*image_digest) ||
        !valid_digest(*workerd_digest) || !valid_digest(*descriptor_digest) ||
        !valid_digest(*docker_digest)) {
        return std::unexpected(std::string{"invalid remote validation executor config"});
    }
    auto parsed_sessions = parse_u64(*max_sessions);
    auto parsed_ttl = parse_u64(*max_ttl_ms);
    if (!parsed_sessions || *parsed_sessions > std::numeric_limits<std::uint32_t>::max() ||
        !parsed_ttl) {
        return std::unexpected(std::string{"invalid remote validation executor limits"});
    }
    loaded_executor_config loaded{
        .identity =
            {
                .executor_digest = *executor_digest,
                .container_image_digest = *image_digest,
                .workerd_digest = *workerd_digest,
                .descriptor_digest = *descriptor_digest,
            },
        .validation_available = true,
        .validation = glove::control::remote_validation_executor_config{
            .executor_digest = std::move(*executor_digest),
            .container_image = std::move(*image),
            .container_image_digest = std::move(*image_digest),
            .workerd_digest = std::move(*workerd_digest),
            .descriptor_digest = std::move(*descriptor_digest),
            .staging_root = std::move(*staging_root),
            .max_sessions = static_cast<std::uint32_t>(*parsed_sessions),
            .max_ttl_ms = *parsed_ttl,
            .docker_executable = std::move(*docker_executable),
            .docker_executable_digest = std::move(*docker_digest),
        },
    };
    return loaded;
}

[[nodiscard]] auto read_bounded_file(int descriptor, std::size_t size)
    -> std::expected<std::string, std::string> {
    std::string contents(size, '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto count =
            ::read(descriptor, contents.data() + consumed, contents.size() - consumed);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return std::unexpected(system_error("read remote executor identity config"));
        }
        consumed += static_cast<std::size_t>(count);
    }
    std::array<char, 1> trailing{};
    if (::read(descriptor, trailing.data(), trailing.size()) != 0) {
        return std::unexpected(
            std::string{"remote executor identity config changed while reading"}
        );
    }
    return contents;
}

[[nodiscard]] auto executable_descriptor() -> std::expected<unique_fd, std::string> {
#if defined(__linux__)
    unique_fd descriptor{::open("/proc/self/exe", O_RDONLY | O_CLOEXEC)};
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    (void)::_NSGetExecutablePath(nullptr, &size);
    if (size == 0U || size > 64U * 1024U) {
        return std::unexpected(std::string{"resolve remote executor path"});
    }
    std::vector<char> path(size);
    if (::_NSGetExecutablePath(path.data(), &size) != 0) {
        return std::unexpected(std::string{"resolve remote executor path"});
    }
    unique_fd descriptor{::open(path.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
#else
    return std::unexpected(std::string{"remote executor identity measurement is unsupported"});
#endif
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open remote executor executable"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 || std::cmp_greater(metadata.st_size, max_executor_bytes)) {
        return std::unexpected(
            std::string{"remote executor executable is not a bounded regular file"}
        );
    }
    return unique_fd{std::move(descriptor)};
}

[[nodiscard]] auto
load_verified_config(const std::filesystem::path& path, uid_t expected_owner, bool local_mode)
    -> std::expected<loaded_executor_config, std::string> {
    const unique_fd config_descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (config_descriptor.get() < 0) {
        return std::unexpected(system_error("open remote executor identity config"));
    }
    struct stat before{};
    if (::fstat(config_descriptor.get(), &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != expected_owner || before.st_nlink != 1 ||
        (static_cast<unsigned int>(before.st_mode) & 022U) != 0U ||
        (local_mode && (static_cast<unsigned int>(before.st_mode) & 0777U) != 0600U) ||
        before.st_size <= 0 || std::cmp_greater(before.st_size, max_identity_config_bytes)) {
        return std::unexpected(
            std::string{"remote executor identity config has unsafe ownership or mode"}
        );
    }
    auto contents =
        read_bounded_file(config_descriptor.get(), static_cast<std::size_t>(before.st_size));
    if (!contents) {
        return std::unexpected(contents.error());
    }
    struct stat after{};
    if (::fstat(config_descriptor.get(), &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtime != after.st_mtime || before.st_ctime != after.st_ctime) {
        return std::unexpected(
            std::string{"remote executor identity config changed while reading"}
        );
    }
    auto configured = parse_identity_config(*contents);
    if (!configured) {
        return std::unexpected(configured.error());
    }
    auto executable = executable_descriptor();
    if (!executable) {
        return std::unexpected(executable.error());
    }
    auto measured = glove::container::sha256_fd_hex(executable->get(), max_executor_bytes);
    if (!measured || "sha256:" + *measured != configured->identity.executor_digest) {
        return std::unexpected(std::string{"remote executor identity digest mismatch"});
    }
    return configured;
}

void print_usage() {
    std::cerr << "usage: glove-remote-exec --stdio\n"
                 "       glove-remote-exec --local-validation-stdio /absolute/config\n";
}

void cleanup_validator(glove::control::remote_validation_executor* validator) {
    if (validator != nullptr) {
        validator->disconnect_cleanup();
    }
}

auto executor_error(glove::control::remote_validation_executor* validator, std::string_view message)
    -> int {
    cleanup_validator(validator);
    std::cerr << "glove-remote-exec: " << message << '\n';
    return 1;
}

auto run_stdio(
    const loaded_executor_config& configured, glove::control::remote_validation_executor* validator
) -> int {
    while (true) {
        const auto receive_started_at = std::chrono::steady_clock::now();
        const auto channel_deadline = receive_started_at + channel_timeout;
        auto request = glove::control::read_remote_frame(STDIN_FILENO, channel_deadline);
        if (!request) {
            if (request.error() == "remote frame input closed") {
                cleanup_validator(validator);
                return 0;
            }
            return executor_error(validator, request.error());
        }
        const auto received_at = std::chrono::steady_clock::now();
        auto request_deadline =
            glove::control::remote_request_deadline(*request, receive_started_at, received_at);
        if (!request_deadline) {
            return executor_error(validator, request_deadline.error());
        }
        auto response =
            validator != nullptr
                ? validator->handle(*request, *request_deadline)
                : glove::control::handle_remote_executor_request(*request, configured.identity);
        if (!response) {
            return executor_error(validator, response.error());
        }
        if (std::chrono::steady_clock::now() >= *request_deadline) {
            return executor_error(validator, "remote protocol deadline exceeded");
        }
        if (auto wrote =
                glove::control::write_remote_frame(STDOUT_FILENO, *response, *request_deadline);
            !wrote) {
            return executor_error(validator, wrote.error());
        }
    }
}

auto run_main(int argc, char** argv) -> int {
    (void)::umask(0077);
    std::filesystem::path config_path;
    uid_t expected_owner = 0;
    bool local_mode = false;
    if (argc == 2 && std::string_view{argv[1]} == "--stdio") {
        config_path = identity_config_path();
    } else if (argc == 3 && std::string_view{argv[1]} == "--local-validation-stdio") {
        config_path = argv[2];
        expected_owner = ::geteuid();
        local_mode = true;
        if (!config_path.is_absolute() || config_path == config_path.root_path() ||
            config_path.lexically_normal() != config_path) {
            print_usage();
            return 2;
        }
    } else {
        print_usage();
        return 2;
    }

    auto configured = load_verified_config(config_path, expected_owner, local_mode);
    if (!configured) {
        std::cerr << "glove-remote-exec: " << configured.error() << '\n';
        return 1;
    }
    std::unique_ptr<glove::control::remote_validation_executor> validator;
    if (configured->validation_available) {
        auto created = glove::control::remote_validation_executor::create(configured->validation);
        if (!created) {
            std::cerr << "glove-remote-exec: " << created.error() << '\n';
            return 1;
        }
        validator = std::move(*created);
    }
    return run_stdio(*configured, validator.get());
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        return run_main(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "glove-remote-exec: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "glove-remote-exec: unexpected executor failure\n";
        return 1;
    }
}
