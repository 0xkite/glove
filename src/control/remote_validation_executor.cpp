#include "remote_validation_executor.hpp"

#include "glove/container/digest.hpp"
#include "glove/container/image_identity.hpp"
#include "glove/control/remote_validation.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace glove::control {
namespace {

constexpr std::string_view production_docker_path = "/usr/bin/docker";
constexpr std::string_view marker_label = "io.sage.glove.remote-validation=1";
constexpr std::string_view executor_label_prefix = "io.sage.glove.executor=";
constexpr std::string_view session_label_prefix = "io.sage.glove.session=";
constexpr std::string_view epoch_label_prefix = "io.sage.glove.epoch=";
constexpr std::string_view descriptor_label_prefix = "io.sage.glove.descriptor=";
constexpr std::string_view validation_entrypoint = "/opt/glove/bin/validate-workerd";
constexpr std::size_t max_docker_output_bytes = max_remote_validation_output_bytes;
constexpr auto cleanup_command_timeout = std::chrono::seconds{2};

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

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    int descriptor_ = -1;
};

struct docker_result {
    int exit_code = -1;
    std::string output;
};

[[nodiscard]] auto system_error(std::string_view operation, int error_number = errno)
    -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

[[nodiscard]] auto valid_digest(std::string_view value) -> bool {
    return value.size() == 71U && value.starts_with("sha256:") &&
           std::ranges::all_of(value.substr(7), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto valid_absolute_path(const std::filesystem::path& path) -> bool {
    return path.is_absolute() && path != path.root_path() && path.lexically_normal() == path;
}

[[nodiscard]] auto verify_regular_digest(
    const std::filesystem::path& path,
    std::string_view expected_digest,
    std::optional<uid_t> expected_owner
) -> std::expected<void, std::string> {
    const unique_fd descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open digest-pinned Docker executable"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 || metadata.st_nlink != 1 ||
        (expected_owner && metadata.st_uid != *expected_owner) ||
        (static_cast<unsigned int>(metadata.st_mode) & 022U) != 0U) {
        return std::unexpected(std::string{"Docker executable is not an immutable regular file"});
    }
    auto measured = container::sha256_fd_hex(descriptor.get(), std::uint64_t{256U} * 1024U * 1024U);
    if (!measured || "sha256:" + *measured != expected_digest) {
        return std::unexpected(std::string{"Docker executable digest mismatch"});
    }
    return {};
}

[[nodiscard]] auto open_staging_root(const std::filesystem::path& root)
    -> std::expected<unique_fd, std::string> {
    unique_fd descriptor{::open(root.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)};
    if (descriptor.get() < 0) {
        return std::unexpected(system_error("open remote validation staging root"));
    }
    struct stat metadata{};
    if (::fstat(descriptor.get(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"remote validation staging root must be an opened owner-only directory"}
        );
    }
    return descriptor;
}

[[nodiscard]] auto trim_line_endings(std::string value) -> std::string {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    return value;
}

[[nodiscard]] auto split_bounded_lines(std::string_view value, std::size_t maximum)
    -> std::expected<std::vector<std::string>, std::string> {
    std::vector<std::string> lines;
    while (!value.empty()) {
        const auto end = value.find('\n');
        auto line = value.substr(0, end);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1U);
        }
        if (!line.empty()) {
            if (lines.size() >= maximum || line.size() > 128U) {
                return std::unexpected(
                    std::string{"Docker reconciliation output exceeded its bound"}
                );
            }
            lines.emplace_back(line);
        }
        if (end == std::string_view::npos) {
            break;
        }
        value.remove_prefix(end + 1U);
    }
    return lines;
}

[[nodiscard]] auto valid_container_id(std::string_view value) -> bool {
    return value.size() >= 12U && value.size() <= 64U && std::ranges::all_of(value, [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto valid_stage_name(std::string_view value) -> bool {
    return value.size() == 34U && value.starts_with("s-") &&
           std::ranges::all_of(value.substr(2), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

[[nodiscard]] auto payload_binding(const remote_validation_payload& payload)
    -> const remote_operation_binding& {
    return std::visit(
        [](const auto& value) -> const remote_operation_binding& { return value.binding; }, payload
    );
}

[[nodiscard]] auto digest_text(std::string_view value) -> std::expected<std::string, std::string> {
    auto digest = container::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(value.data()), value.size()
        }
    );
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return *digest;
}

[[nodiscard]] auto process_wait_status(int status) -> int {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

void kill_process_group(pid_t child) noexcept {
    if (child > 0) {
        (void)::kill(-child, SIGKILL);
        (void)::kill(child, SIGKILL);
    }
}

} // namespace

class remote_validation_executor::implementation {
public:
    struct session_state {
        std::string session_id;
        std::string epoch;
        std::string stage_name;
        std::string container_name;
        std::string state = "prepared";
        std::chrono::steady_clock::time_point deadline;
        std::string output;
        std::optional<int> exit_code;
        bool container_started = false;
    };

    struct tombstone {
        std::string session_id;
        std::string epoch;
        std::string state;
        std::string output;
        std::optional<int> exit_code;
    };

    struct replay_entry {
        remote_method method = remote_method::remote_health;
        std::string payload_digest;
        remote_validation_result result;
    };

    struct watchdog_record {
        std::string session_id;
        std::string container_name;
        std::chrono::steady_clock::time_point deadline;
    };

    implementation(remote_validation_executor_config configured, unique_fd staging_root)
        : configured_{std::move(configured)}, staging_root_{std::move(staging_root)} {}

    implementation(const implementation&) = delete;
    auto operator=(const implementation&) -> implementation& = delete;
    implementation(implementation&&) = delete;
    auto operator=(implementation&&) -> implementation& = delete;

    ~implementation() {
        watchdog_.request_stop();
        if (watchdog_.joinable()) {
            watchdog_.join();
        }
        try {
            disconnect_cleanup();
        } catch (...) {
            watchdog_failed_.store(true);
        }
    }

    [[nodiscard]] static auto
    create(remote_validation_executor_config configured, bool allow_test_path)
        -> std::expected<std::unique_ptr<implementation>, std::string> {
        if (!valid_digest(configured.executor_digest) ||
            !container::valid_immutable_container_image(
                configured.container_image, configured.container_image_digest
            ) ||
            !valid_digest(configured.workerd_digest) ||
            !valid_digest(configured.descriptor_digest) ||
            !valid_digest(configured.docker_executable_digest) ||
            !valid_absolute_path(configured.staging_root) ||
            !valid_absolute_path(configured.docker_executable) || configured.max_sessions == 0U ||
            configured.max_sessions > 64U || configured.max_ttl_ms < 100U ||
            configured.max_ttl_ms > max_remote_deadline_ms ||
            (!allow_test_path && configured.docker_executable != production_docker_path)) {
            return std::unexpected(std::string{"invalid remote validation executor configuration"});
        }
        if (auto verified = verify_regular_digest(
                configured.docker_executable,
                configured.docker_executable_digest,
                allow_test_path ? std::nullopt : std::optional<uid_t>{0}
            );
            !verified) {
            return std::unexpected(verified.error());
        }
        auto staging_root = open_staging_root(configured.staging_root);
        if (!staging_root) {
            return std::unexpected(staging_root.error());
        }
        auto state =
            std::make_unique<implementation>(std::move(configured), std::move(*staging_root));
        if (auto reconciled = state->reconcile_startup(); !reconciled) {
            return std::unexpected(reconciled.error());
        }
        state->watchdog_ = std::jthread{[owner = state.get()](const std::stop_token& stop) {
            try {
                owner->watchdog_loop(stop);
            } catch (...) {
                owner->watchdog_failed_.store(true);
                try {
                    owner->disconnect_cleanup();
                } catch (...) {
                    owner->watchdog_failed_.store(true);
                }
            }
        }};
        return state;
    }

    [[nodiscard]] auto identity() const -> remote_executor_identity {
        return {
            .executor_digest = configured_.executor_digest,
            .container_image_digest = configured_.container_image_digest,
            .workerd_digest = configured_.workerd_digest,
            .descriptor_digest = configured_.descriptor_digest,
        };
    }

    [[nodiscard]] auto
    handle(std::string_view frame, std::chrono::steady_clock::time_point request_deadline)
        -> std::expected<std::string, std::string> {
        if (watchdog_failed_.load()) {
            return std::unexpected(std::string{"remote validation watchdog is unavailable"});
        }
        auto header = decode_remote_request_header(frame);
        if (!header) {
            return std::unexpected(header.error());
        }
        if (header->method == remote_method::remote_health) {
            if (header->payload_json != "null") {
                return std::unexpected(std::string{"remote health payload must be null"});
            }
            return encode_remote_validation_health(header->id, identity());
        }
        if (header->method == remote_method::remote_write_input ||
            header->method == remote_method::remote_resize ||
            header->method == remote_method::remote_signal) {
            return encode_remote_validation_error(
                header->id, "method_not_found", "interactive remote methods are unavailable"
            );
        }
        auto request = decode_remote_validation_request(frame);
        if (!request) {
            return std::unexpected(request.error());
        }
        if (std::chrono::steady_clock::now() >= request_deadline) {
            return encode_remote_validation_error(
                request->id, "deadline_exceeded", "remote validation request expired"
            );
        }
        return dispatch(*request, request_deadline);
    }

    void disconnect_cleanup() {
        const std::scoped_lock lock{mutex_};
        std::vector<std::string> session_ids;
        session_ids.reserve(sessions_.size());
        for (const auto& [session_id, ignored] : sessions_) {
            (void)ignored;
            session_ids.push_back(session_id);
        }
        for (const auto& session_id : session_ids) {
            auto candidate = sessions_.find(session_id);
            if (candidate != sessions_.end()) {
                cleanup_container(candidate->second);
                remove_stage(candidate->second);
                add_tombstone(candidate->second, "disconnected");
                sessions_.erase(candidate);
            }
        }
    }

private:
    [[nodiscard]] auto run_docker(
        const std::vector<std::string>& arguments, std::chrono::steady_clock::time_point deadline
    ) const -> std::expected<docker_result, std::string> {
        std::array<int, 2> output_pipe{-1, -1};
        if (::pipe(output_pipe.data()) != 0) {
            return std::unexpected(system_error("create Docker output pipe"));
        }
        unique_fd read_end{output_pipe[0]};
        unique_fd write_end{output_pipe[1]};
        if (::fcntl(read_end.get(), F_SETFL, O_NONBLOCK) != 0) {
            return std::unexpected(system_error("bound Docker output pipe"));
        }

        posix_spawn_file_actions_t actions{};
        int spawn_error = ::posix_spawn_file_actions_init(&actions);
        if (spawn_error != 0) {
            return std::unexpected(system_error("initialize Docker process actions", spawn_error));
        }
        const std::array action_results{
            ::posix_spawn_file_actions_adddup2(&actions, write_end.get(), STDOUT_FILENO),
            ::posix_spawn_file_actions_adddup2(&actions, write_end.get(), STDERR_FILENO),
            ::posix_spawn_file_actions_addclose(&actions, read_end.get()),
            ::posix_spawn_file_actions_addclose(&actions, write_end.get()),
        };
        if (const auto failed =
                std::ranges::find_if(action_results, [](int result) { return result != 0; });
            failed != action_results.end()) {
            (void)::posix_spawn_file_actions_destroy(&actions);
            return std::unexpected(system_error("configure Docker process actions", *failed));
        }

        posix_spawnattr_t attributes{};
        spawn_error = ::posix_spawnattr_init(&attributes);
        const bool attributes_initialized = spawn_error == 0;
        if (spawn_error == 0) {
            spawn_error = ::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
        }
        if (spawn_error == 0) {
            spawn_error = ::posix_spawnattr_setpgroup(&attributes, 0);
        }
        if (spawn_error != 0) {
            (void)::posix_spawn_file_actions_destroy(&actions);
            if (attributes_initialized) {
                (void)::posix_spawnattr_destroy(&attributes);
            }
            return std::unexpected(system_error("configure Docker process group", spawn_error));
        }

        std::vector<std::string> owned_argv;
        owned_argv.reserve(arguments.size() + 1U);
        owned_argv.push_back(configured_.docker_executable.string());
        owned_argv.insert(owned_argv.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        argv.reserve(owned_argv.size() + 1U);
        for (auto& argument : owned_argv) {
            argv.push_back(argument.data());
        }
        argv.push_back(nullptr);
        std::array<char*, 1> empty_environment{nullptr};
        pid_t child = -1;
        spawn_error = ::posix_spawn(
            &child,
            configured_.docker_executable.c_str(),
            &actions,
            &attributes,
            argv.data(),
            empty_environment.data()
        );
        (void)::posix_spawn_file_actions_destroy(&actions);
        (void)::posix_spawnattr_destroy(&attributes);
        if (spawn_error != 0) {
            return std::unexpected(
                system_error("start digest-pinned Docker executable", spawn_error)
            );
        }
        // The parent must close its writer before waiting for EOF.
        if (::close(write_end.release()) != 0) {
            kill_process_group(child);
        }

        std::string output;
        int status = 0;
        bool exited = false;
        while (!exited) {
            std::array<char, 4096> chunk{};
            while (true) {
                const auto count = ::read(read_end.get(), chunk.data(), chunk.size());
                if (count > 0) {
                    if (output.size() + static_cast<std::size_t>(count) > max_docker_output_bytes) {
                        kill_process_group(child);
                        (void)::waitpid(child, &status, 0);
                        return std::unexpected(
                            std::string{"Docker output exceeded validation cap"}
                        );
                    }
                    output.append(chunk.data(), static_cast<std::size_t>(count));
                    continue;
                }
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    kill_process_group(child);
                    (void)::waitpid(child, &status, 0);
                    return std::unexpected(system_error("read Docker command output"));
                }
                break;
            }
            const auto waited = ::waitpid(child, &status, WNOHANG);
            if (waited == child) {
                exited = true;
                continue;
            }
            if (waited < 0 && errno != EINTR) {
                kill_process_group(child);
                return std::unexpected(system_error("wait for Docker command"));
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                kill_process_group(child);
                (void)::waitpid(child, &status, 0);
                return std::unexpected(std::string{"Docker command deadline exceeded"});
            }
            pollfd descriptor{.fd = read_end.get(), .events = POLLIN, .revents = 0};
            (void)::poll(&descriptor, 1, 5);
        }
        // Drain bytes written immediately before exit.
        std::array<char, 4096> trailing{};
        while (true) {
            const auto count = ::read(read_end.get(), trailing.data(), trailing.size());
            if (count <= 0) {
                break;
            }
            if (output.size() + static_cast<std::size_t>(count) > max_docker_output_bytes) {
                return std::unexpected(std::string{"Docker output exceeded validation cap"});
            }
            output.append(trailing.data(), static_cast<std::size_t>(count));
        }
        return docker_result{.exit_code = process_wait_status(status), .output = std::move(output)};
    }

    [[nodiscard]] auto checked_docker(
        const std::vector<std::string>& arguments, std::chrono::steady_clock::time_point deadline
    ) const -> std::expected<std::string, std::string> {
        auto result = run_docker(arguments, deadline);
        if (!result) {
            return std::unexpected(result.error());
        }
        if (result->exit_code != 0) {
            return std::unexpected(std::string{"Docker command failed"});
        }
        return std::move(result->output);
    }

    [[nodiscard]] auto reconcile_startup() -> std::expected<void, std::string> {
        const auto executor_label =
            std::string{executor_label_prefix} + configured_.executor_digest.substr(7);
        auto listed = checked_docker(
            {
                "ps",
                "-aq",
                "--filter",
                std::string{"label="} + std::string{marker_label},
                "--filter",
                "label=" + executor_label,
            },
            std::chrono::steady_clock::now() + cleanup_command_timeout
        );
        if (!listed) {
            return std::unexpected(
                std::string{"reconcile Glove validation containers: "} + listed.error()
            );
        }
        auto candidates =
            split_bounded_lines(*listed, static_cast<std::size_t>(configured_.max_sessions) * 2U);
        if (!candidates) {
            return std::unexpected(candidates.error());
        }
        for (const auto& candidate : *candidates) {
            if (!valid_container_id(candidate)) {
                return std::unexpected(std::string{"invalid Docker reconciliation container id"});
            }
            auto labels = checked_docker(
                {
                    "inspect",
                    "--format",
                    "{{index .Config.Labels \"io.sage.glove.remote-validation\"}}|"
                    "{{index .Config.Labels \"io.sage.glove.executor\"}}",
                    candidate,
                },
                std::chrono::steady_clock::now() + cleanup_command_timeout
            );
            if (!labels) {
                return std::unexpected(
                    std::string{"inspect Glove validation labels: "} + labels.error()
                );
            }
            if (trim_line_endings(std::move(*labels)) !=
                "1|" + configured_.executor_digest.substr(7)) {
                continue;
            }
            auto killed = checked_docker(
                {"kill", candidate}, std::chrono::steady_clock::now() + cleanup_command_timeout
            );
            auto removed = checked_docker(
                {"rm", "-f", candidate}, std::chrono::steady_clock::now() + cleanup_command_timeout
            );
            if (!killed || !removed) {
                return std::unexpected(
                    std::string{"failed to reconcile Glove validation container"}
                );
            }
        }
        return reconcile_staging();
    }

    [[nodiscard]] auto reconcile_staging() -> std::expected<void, std::string> {
        const int duplicate = ::fcntl(staging_root_.get(), F_DUPFD_CLOEXEC, 0);
        if (duplicate < 0) {
            return std::unexpected(system_error("duplicate validation staging root"));
        }
        const std::unique_ptr<DIR, decltype(&::closedir)> entries{
            ::fdopendir(duplicate), &::closedir
        };
        if (!entries) {
            (void)::close(duplicate);
            return std::unexpected(system_error("open validation staging directory stream"));
        }
        std::size_t removed = 0;
        errno = 0;
        while (const auto* entry = ::readdir(entries.get())) {
            const std::string_view name{entry->d_name};
            if (!valid_stage_name(name)) {
                continue;
            }
            if (removed >= static_cast<std::size_t>(configured_.max_sessions) * 2U) {
                return std::unexpected(
                    std::string{"stale validation staging entries exceed bound"}
                );
            }
            if (::unlinkat(staging_root_.get(), entry->d_name, AT_REMOVEDIR) != 0) {
                return std::unexpected(system_error("remove stale validation staging directory"));
            }
            ++removed;
        }
        if (errno != 0) {
            return std::unexpected(system_error("read validation staging directory"));
        }
        return {};
    }

    [[nodiscard]] auto dispatch(
        const remote_validation_request& request,
        std::chrono::steady_clock::time_point request_deadline
    ) -> std::expected<std::string, std::string> {
        const auto& binding = payload_binding(request.payload);
        if (binding.descriptor_digest != configured_.descriptor_digest) {
            return encode_remote_validation_error(
                request.id, "descriptor_mismatch", "fixed validation descriptor mismatch"
            );
        }
        const std::scoped_lock lock{mutex_};
        const auto replay_key =
            binding.session_id + "\n" + binding.session_epoch + "\n" + binding.idempotency_key;
        if (const auto replay = replays_.find(replay_key); replay != replays_.end()) {
            if (replay->second.method == request.method &&
                replay->second.payload_digest == binding.payload_digest) {
                return encode_remote_validation_result(request.id, replay->second.result);
            }
            return encode_remote_validation_error(
                request.id, "idempotency_conflict", "idempotency key was reused with new content"
            );
        }
        if (replays_.size() >= (static_cast<std::size_t>(configured_.max_sessions) * 8U) + 16U) {
            return encode_remote_validation_error(
                request.id, "capacity_exceeded", "bounded idempotency state is full"
            );
        }

        auto result = execute(request, request_deadline);
        if (!result) {
            return encode_remote_validation_error(
                request.id, result.error().first, result.error().second
            );
        }
        auto response = encode_remote_validation_result(request.id, *result);
        if (!response) {
            return std::unexpected(response.error());
        }
        replays_.emplace(
            replay_key,
            replay_entry{
                .method = request.method,
                .payload_digest = binding.payload_digest,
                .result = *result,
            }
        );
        return response;
    }

    using operation_error = std::pair<std::string, std::string>;

    [[nodiscard]] auto execute(
        const remote_validation_request& request,
        std::chrono::steady_clock::time_point request_deadline
    ) -> std::expected<remote_validation_result, operation_error> {
        switch (request.method) {
        case remote_method::remote_prepare:
            return prepare(request);
        case remote_method::remote_start:
            return start(request, request_deadline);
        case remote_method::remote_read:
            return read_output(request, request_deadline);
        case remote_method::remote_wait:
            return wait(request, request_deadline);
        case remote_method::remote_stop:
            return stop(request);
        case remote_method::remote_cleanup:
            return cleanup(request);
        case remote_method::remote_health:
        case remote_method::remote_write_input:
        case remote_method::remote_resize:
        case remote_method::remote_signal:
            return std::unexpected(
                operation_error{"method_not_found", "remote method unavailable"}
            );
        }
        return std::unexpected(operation_error{"method_not_found", "remote method unavailable"});
    }

    [[nodiscard]] auto prepare(const remote_validation_request& request)
        -> std::expected<remote_validation_result, operation_error> {
        const auto& binding = payload_binding(request.payload);
        if (const auto existing = sessions_.find(binding.session_id); existing != sessions_.end()) {
            if (existing->second.epoch != binding.session_epoch) {
                return std::unexpected(
                    operation_error{"session_conflict", "session epoch conflict"}
                );
            }
            return project(existing->second);
        }
        if (sessions_.size() >= configured_.max_sessions) {
            return std::unexpected(
                operation_error{"capacity_exceeded", "validation session cap reached"}
            );
        }
        auto name_digest = digest_text(binding.session_id + "\n" + binding.session_epoch);
        if (!name_digest) {
            return std::unexpected(
                operation_error{"internal_error", "derive validation session name"}
            );
        }
        session_state created{
            .session_id = binding.session_id,
            .epoch = binding.session_epoch,
            .stage_name = "s-" + name_digest->substr(0, 32U),
            .container_name = "glove-v-" + name_digest->substr(0, 32U),
        };
        if (::mkdirat(staging_root_.get(), created.stage_name.c_str(), 0700) != 0) {
            return std::unexpected(
                operation_error{"staging_error", "create validation staging directory"}
            );
        }
        const unique_fd stage{::openat(
            staging_root_.get(),
            created.stage_name.c_str(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW
        )};
        struct stat metadata{};
        if (stage.get() < 0 || ::fstat(stage.get(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            metadata.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0700U) {
            (void)::unlinkat(staging_root_.get(), created.stage_name.c_str(), AT_REMOVEDIR);
            return std::unexpected(
                operation_error{"staging_error", "verify validation staging directory"}
            );
        }
        auto [position, inserted] = sessions_.emplace(created.session_id, std::move(created));
        if (!inserted) {
            return std::unexpected(
                operation_error{"session_conflict", "validation session already exists"}
            );
        }
        return project(position->second);
    }

    [[nodiscard]] auto start(
        const remote_validation_request& request,
        std::chrono::steady_clock::time_point request_deadline
    ) -> std::expected<remote_validation_result, operation_error> {
        auto session = matching_session(request);
        if (!session) {
            return std::unexpected(session.error());
        }
        if ((*session)->state != "prepared") {
            return std::unexpected(
                operation_error{"invalid_state", "validation session is not prepared"}
            );
        }
        const auto executor_label =
            std::string{executor_label_prefix} + configured_.executor_digest.substr(7);
        const std::vector<std::string> arguments{
            "run",
            "--detach",
            "--pull",
            "never",
            "--name",
            (*session)->container_name,
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "65532:65532",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--pids-limit",
            "64",
            "--cpus",
            "1.0",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16777216,mode=0700",
            "--log-driver",
            "local",
            "--log-opt",
            "max-size=64k",
            "--log-opt",
            "max-file=1",
            "--label",
            std::string{marker_label},
            "--label",
            executor_label,
            "--label",
            std::string{session_label_prefix} + (*session)->session_id,
            "--label",
            std::string{epoch_label_prefix} + (*session)->epoch,
            "--label",
            std::string{descriptor_label_prefix} + configured_.descriptor_digest.substr(7),
            "--entrypoint",
            std::string{validation_entrypoint},
            configured_.container_image,
            "--expected-workerd-digest",
            configured_.workerd_digest,
            "--expected-descriptor-digest",
            configured_.descriptor_digest,
        };
        (*session)->state = "starting";
        auto started = checked_docker(arguments, request_deadline);
        if (!started) {
            cleanup_container(**session);
            return std::unexpected(operation_error{"docker_failure", started.error()});
        }
        const auto container_id = trim_line_endings(std::move(*started));
        if (!valid_container_id(container_id)) {
            cleanup_container(**session);
            return std::unexpected(
                operation_error{"docker_failure", "invalid Docker container identity"}
            );
        }
        (*session)->container_started = true;
        (*session)->state = "running";
        const auto configured_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{configured_.max_ttl_ms};
        (*session)->deadline = std::min(request_deadline, configured_deadline);
        watch_session(**session);
        return project(**session);
    }

    [[nodiscard]] auto read_output(
        const remote_validation_request& request,
        std::chrono::steady_clock::time_point request_deadline
    ) -> std::expected<remote_validation_result, operation_error> {
        auto session = matching_session(request);
        if (!session) {
            if (const auto* terminal = matching_tombstone(request); terminal != nullptr) {
                return project(*terminal, std::get<remote_read_payload>(request.payload));
            }
            return std::unexpected(session.error());
        }
        if ((*session)->container_started && (*session)->state == "running") {
            auto logs = checked_docker({"logs", (*session)->container_name}, request_deadline);
            if (!logs) {
                if (logs.error().contains("output exceeded")) {
                    cleanup_container(**session);
                    (*session)->state = "output_limited";
                    return std::unexpected(
                        operation_error{"output_limit", "validation output cap exceeded"}
                    );
                }
                return std::unexpected(operation_error{"docker_failure", logs.error()});
            }
            (*session)->output = std::move(*logs);
        }
        return project(**session, std::get<remote_read_payload>(request.payload));
    }

    [[nodiscard]] auto wait(
        const remote_validation_request& request,
        std::chrono::steady_clock::time_point request_deadline
    ) -> std::expected<remote_validation_result, operation_error> {
        auto session = matching_session(request);
        if (!session) {
            if (const auto* terminal = matching_tombstone(request); terminal != nullptr) {
                return project(*terminal);
            }
            return std::unexpected(session.error());
        }
        if ((*session)->state != "running") {
            return project(**session);
        }
        if (std::chrono::steady_clock::now() >= (*session)->deadline) {
            cleanup_container(**session);
            (*session)->state = "timed_out";
            return project(**session);
        }
        auto inspected = checked_docker(
            {"inspect",
             "--format",
             "{{.State.Running}} {{.State.ExitCode}}",
             (*session)->container_name},
            request_deadline
        );
        if (!inspected) {
            return std::unexpected(operation_error{"docker_failure", inspected.error()});
        }
        const auto status = trim_line_endings(std::move(*inspected));
        if (status.starts_with("false ")) {
            int exit_code = 0;
            const auto encoded = std::string_view{status}.substr(6U);
            const auto [end, error] =
                std::from_chars(encoded.data(), encoded.data() + encoded.size(), exit_code);
            if (error != std::errc{} || end != encoded.data() + encoded.size()) {
                return std::unexpected(
                    operation_error{"docker_failure", "invalid Docker exit state"}
                );
            }
            (*session)->exit_code = exit_code;
            (*session)->state = "finished";
            cleanup_container(**session);
            return project(**session);
        }
        if (status != "true 0") {
            return std::unexpected(
                operation_error{"docker_failure", "invalid Docker running state"}
            );
        }
        return project(**session);
    }

    [[nodiscard]] auto stop(const remote_validation_request& request)
        -> std::expected<remote_validation_result, operation_error> {
        auto session = matching_session(request);
        if (!session) {
            if (const auto* terminal = matching_tombstone(request); terminal != nullptr) {
                return project(*terminal);
            }
            return std::unexpected(session.error());
        }
        cleanup_container(**session);
        (*session)->state = "stopped";
        return project(**session);
    }

    [[nodiscard]] auto cleanup(const remote_validation_request& request)
        -> std::expected<remote_validation_result, operation_error> {
        auto session = matching_session(request);
        if (!session) {
            if (const auto* terminal = matching_tombstone(request); terminal != nullptr) {
                return project(*terminal);
            }
            return std::unexpected(session.error());
        }
        cleanup_container(**session);
        remove_stage(**session);
        (*session)->state = "cleaned";
        auto result = project(**session);
        add_tombstone(**session, "cleaned");
        sessions_.erase((*session)->session_id);
        return result;
    }

    [[nodiscard]] auto matching_session(const remote_validation_request& request)
        -> std::expected<session_state*, operation_error> {
        const auto& binding = payload_binding(request.payload);
        const auto found = sessions_.find(binding.session_id);
        if (found == sessions_.end()) {
            return std::unexpected(operation_error{"not_found", "validation session not found"});
        }
        if (found->second.epoch != binding.session_epoch) {
            return std::unexpected(
                operation_error{"session_conflict", "validation epoch mismatch"}
            );
        }
        return &found->second;
    }

    [[nodiscard]] auto matching_tombstone(const remote_validation_request& request) const
        -> const tombstone* {
        const auto& binding = payload_binding(request.payload);
        const auto found = std::ranges::find_if(tombstones_, [&](const tombstone& candidate) {
            return candidate.session_id == binding.session_id &&
                   candidate.epoch == binding.session_epoch;
        });
        return found == tombstones_.end() ? nullptr : &*found;
    }

    [[nodiscard]] static auto project(const session_state& session) -> remote_validation_result {
        return {
            .session_id = session.session_id,
            .session_epoch = session.epoch,
            .state = session.state,
            .cursor = 0,
            .next_cursor = 0,
            .eof = session.state != "running",
            .bytes = {},
            .exit_code = session.exit_code,
        };
    }

    [[nodiscard]] static auto project(const tombstone& terminal) -> remote_validation_result {
        return {
            .session_id = terminal.session_id,
            .session_epoch = terminal.epoch,
            .state = terminal.state,
            .cursor = 0,
            .next_cursor = 0,
            .eof = true,
            .bytes = {},
            .exit_code = terminal.exit_code,
        };
    }

    [[nodiscard]] static auto project(const session_state& session, const remote_read_payload& read)
        -> std::expected<remote_validation_result, operation_error> {
        if (read.cursor > session.output.size()) {
            return std::unexpected(operation_error{"invalid_cursor", "read cursor exceeds output"});
        }
        const auto available = session.output.size() - static_cast<std::size_t>(read.cursor);
        const auto count = std::min(available, read.max_bytes);
        return remote_validation_result{
            .session_id = session.session_id,
            .session_epoch = session.epoch,
            .state = session.state,
            .cursor = read.cursor,
            .next_cursor = read.cursor + count,
            .eof = session.state != "running" && count == available,
            .bytes = session.output.substr(static_cast<std::size_t>(read.cursor), count),
            .exit_code = session.exit_code,
        };
    }

    [[nodiscard]] static auto project(const tombstone& terminal, const remote_read_payload& read)
        -> std::expected<remote_validation_result, operation_error> {
        if (read.cursor > terminal.output.size()) {
            return std::unexpected(operation_error{"invalid_cursor", "read cursor exceeds output"});
        }
        const auto available = terminal.output.size() - static_cast<std::size_t>(read.cursor);
        const auto count = std::min(available, read.max_bytes);
        return remote_validation_result{
            .session_id = terminal.session_id,
            .session_epoch = terminal.epoch,
            .state = terminal.state,
            .cursor = read.cursor,
            .next_cursor = read.cursor + count,
            .eof = count == available,
            .bytes = terminal.output.substr(static_cast<std::size_t>(read.cursor), count),
            .exit_code = terminal.exit_code,
        };
    }

    void cleanup_container_name(std::string_view container_name) {
        const auto deadline = [] {
            return std::chrono::steady_clock::now() + cleanup_command_timeout;
        };
        const auto stop_result =
            run_docker({"stop", "--time", "1", std::string{container_name}}, deadline());
        const auto kill_result = run_docker({"kill", std::string{container_name}}, deadline());
        const auto remove_result =
            run_docker({"rm", "-f", std::string{container_name}}, deadline());
        (void)stop_result;
        (void)kill_result;
        (void)remove_result;
    }

    void watch_session(const session_state& session) {
        const std::scoped_lock lock{watchdog_mutex_};
        watchdog_records_.push_back({
            .session_id = session.session_id,
            .container_name = session.container_name,
            .deadline = session.deadline,
        });
    }

    void unwatch_session(std::string_view container_name) {
        const std::scoped_lock lock{watchdog_mutex_};
        std::erase_if(watchdog_records_, [&](const watchdog_record& candidate) {
            return candidate.container_name == container_name;
        });
    }

    void cleanup_container(session_state& session) {
        if (!session.container_started && session.state == "prepared") {
            return;
        }
        unwatch_session(session.container_name);
        cleanup_container_name(session.container_name);
        session.container_started = false;
    }

    void remove_stage(const session_state& session) noexcept {
        (void)::unlinkat(staging_root_.get(), session.stage_name.c_str(), AT_REMOVEDIR);
    }

    void add_tombstone(const session_state& session, std::string state) {
        tombstones_.push_back({
            .session_id = session.session_id,
            .epoch = session.epoch,
            .state = std::move(state),
            .output = session.output,
            .exit_code = session.exit_code,
        });
        while (tombstones_.size() > static_cast<std::size_t>(configured_.max_sessions) * 2U) {
            tombstones_.pop_front();
        }
    }

    void watchdog_loop(const std::stop_token& stop) {
        while (!stop.stop_requested()) {
            std::vector<watchdog_record> expired;
            {
                const std::scoped_lock lock{watchdog_mutex_};
                const auto now = std::chrono::steady_clock::now();
                for (const auto& record : watchdog_records_) {
                    if (now >= record.deadline) {
                        expired.push_back(record);
                    }
                }
                std::erase_if(watchdog_records_, [&](const watchdog_record& record) {
                    return now >= record.deadline;
                });
            }
            for (const auto& record : expired) {
                cleanup_container_name(record.container_name);
                const std::scoped_lock lock{mutex_};
                if (auto session = sessions_.find(record.session_id);
                    session != sessions_.end() && session->second.state == "running" &&
                    session->second.container_name == record.container_name) {
                    session->second.container_started = false;
                    session->second.state = "timed_out";
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }

    remote_validation_executor_config configured_;
    unique_fd staging_root_;
    mutable std::mutex mutex_;
    std::mutex watchdog_mutex_;
    std::vector<watchdog_record> watchdog_records_;
    std::unordered_map<std::string, session_state> sessions_;
    std::deque<tombstone> tombstones_;
    std::unordered_map<std::string, replay_entry> replays_;
    std::jthread watchdog_;
    std::atomic<bool> watchdog_failed_{false};
};

remote_validation_executor::remote_validation_executor(std::unique_ptr<implementation> state)
    : state_{std::move(state)} {}

remote_validation_executor::~remote_validation_executor() = default;

auto remote_validation_executor::create(remote_validation_executor_config configured)
    -> std::expected<std::unique_ptr<remote_validation_executor>, std::string> {
    auto state = implementation::create(std::move(configured), false);
    if (!state) {
        return std::unexpected(state.error());
    }
    return std::unique_ptr<remote_validation_executor>{
        new remote_validation_executor{std::move(*state)}
    };
}

auto remote_validation_executor::create_for_testing(remote_validation_executor_config configured)
    -> std::expected<std::unique_ptr<remote_validation_executor>, std::string> {
    auto state = implementation::create(std::move(configured), true);
    if (!state) {
        return std::unexpected(state.error());
    }
    return std::unique_ptr<remote_validation_executor>{
        new remote_validation_executor{std::move(*state)}
    };
}

auto remote_validation_executor::handle(
    std::string_view frame, std::chrono::steady_clock::time_point request_deadline
) -> std::expected<std::string, std::string> {
    return state_->handle(frame, request_deadline);
}

void remote_validation_executor::disconnect_cleanup() {
    state_->disconnect_cleanup();
}

auto remote_validation_executor::identity() const -> remote_executor_identity {
    return state_->identity();
}

} // namespace glove::control
