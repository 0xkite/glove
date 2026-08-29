#include "apple_container_session_runtime.hpp"

#include "glove/audit/event.hpp"
#include "glove/container/digest.hpp"
#include "glove/container/image_identity.hpp"
#include "glove/net/egress_proxy.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"
#include "glove/supervisor/sage_bundle_projection.hpp"

#include "../container/linux/pty_session_channel.hpp"
#include "../container/resource_monitor.hpp"
#include "apple_worker_start.hpp"

#include <fcntl.h>
#include <glaze/glaze.hpp>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

extern char** environ;

namespace glove::control::apple_detail {

struct image_inspection_wire {
    std::string digest;
    std::map<std::string, std::string> labels;
};

struct instance_image_wire {
    std::string digest;
};

struct instance_inspection_wire {
    std::string name;
    instance_image_wire image;
    std::map<std::string, std::string> labels;
};

namespace {

constexpr std::size_t max_command_output_bytes = std::size_t{1024} * 1024U;
constexpr std::size_t max_idempotency_namespace_bytes = 112U;
constexpr std::size_t transcript_bytes = std::size_t{4} * 1024U * 1024U;
constexpr std::uint64_t max_secret_file_bytes = std::uint64_t{1024} * 1024U;
constexpr std::uint64_t max_command_runtime_ms = 60'000U;
constexpr std::size_t max_json_nesting = 32U;
constexpr std::string_view lifecycle_unavailable_error =
    "Apple Container managed lifecycle is unavailable";
constexpr std::string_view sage_projection_root = "/run/glove-projections/sage-bundles/";
constexpr glz::opts strict_json_options{
    .null_terminated = false,
    .error_on_unknown_keys = true,
};
constexpr std::uint64_t stats_command_runtime_ms = 5'000U;
constexpr auto stats_sample_interval = std::chrono::milliseconds{100};

auto current_epoch_ms() -> std::uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count()
    );
}

auto valid_identifier(std::string_view value, std::size_t max_bytes = 128U) -> bool {
    return !value.empty() && value.size() <= max_bytes &&
           std::ranges::all_of(value, [](char character) {
               const auto byte = static_cast<unsigned char>(character);
               return std::isalnum(byte) != 0 || character == '-' || character == '_' ||
                      character == ':' || character == '.';
           });
}

auto valid_digest(std::string_view value) -> bool {
    return value.size() == 64U && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

class duplicate_key_guard {
public:
    explicit duplicate_key_guard(std::string_view input) : input_{input} {}

    [[nodiscard]] auto valid() -> bool {
        skip_space();
        return value(0U) && (skip_space(), position_ == input_.size());
    }

private:
    void skip_space() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\n' || input_[position_] == '\r')) {
            ++position_;
        }
    }

    [[nodiscard]] auto string_value() -> std::optional<std::string> {
        if (position_ >= input_.size() || input_[position_] != '"') {
            return std::nullopt;
        }
        const auto begin = position_++;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_[position_++]);
            if (byte == static_cast<unsigned char>('"')) {
                std::string decoded;
                if (const auto error = glz::read<strict_json_options>(
                        decoded, input_.substr(begin, position_ - begin)
                    );
                    error) {
                    return std::nullopt;
                }
                return decoded;
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

    [[nodiscard]] auto literal(std::string_view text) -> bool {
        if (input_.substr(position_, text.size()) != text) {
            return false;
        }
        position_ += text.size();
        return true;
    }

    [[nodiscard]] auto number() -> bool {
        const auto begin = position_;
        if (position_ < input_.size() && input_[position_] == '-') {
            ++position_;
        }
        if (position_ >= input_.size()) {
            return false;
        }
        if (input_[position_] == '0') {
            ++position_;
        } else {
            if (input_[position_] < '1' || input_[position_] > '9') {
                return false;
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const auto digits = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (position_ == digits) {
                return false;
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            const auto digits = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (position_ == digits) {
                return false;
            }
        }
        return position_ != begin;
    }

    [[nodiscard]] auto object(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        std::set<std::string> keys;
        if (position_ < input_.size() && input_[position_] == '}') {
            ++position_;
            return true;
        }
        for (;;) {
            auto key = string_value();
            if (!key || !keys.insert(*key).second) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size() || input_[position_++] != ':') {
                return false;
            }
            skip_space();
            if (!value(depth + 1U)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == '}') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto array(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        if (position_ < input_.size() && input_[position_] == ']') {
            ++position_;
            return true;
        }
        for (;;) {
            if (!value(depth + 1U)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == ']') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto value(std::size_t depth) -> bool {
        if (depth > max_json_nesting || position_ >= input_.size()) {
            return false;
        }
        switch (input_[position_]) {
        case '{':
            return object(depth);
        case '[':
            return array(depth);
        case '"':
            return string_value().has_value();
        case 't':
            return literal("true");
        case 'f':
            return literal("false");
        case 'n':
            return literal("null");
        default:
            return number();
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
};

[[nodiscard]] auto exact_label(
    const std::map<std::string, std::string>& labels,
    std::string_view key,
    std::string_view expected
) -> bool {
    const auto found = labels.find(std::string{key});
    return found != labels.end() && found->second == expected;
}

[[nodiscard]] auto
inspection_input_valid(std::string_view standard_output, std::string_view standard_error) -> bool {
    return standard_output.size() <= max_command_output_bytes && standard_error.empty() &&
           duplicate_key_guard{standard_output}.valid();
}

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    ~unique_fd() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto release() noexcept -> int { return std::exchange(descriptor_, -1); }

private:
    int descriptor_ = -1;
};

struct credential_commitment {
    std::string handle;
    std::string runtime_id;
    std::string target_path;
    std::string content_digest;
};

class credential_lease_bundle {
public:
    credential_lease_bundle() = default;
    credential_lease_bundle(const credential_lease_bundle&) = delete;
    auto operator=(const credential_lease_bundle&) -> credential_lease_bundle& = delete;
    credential_lease_bundle(credential_lease_bundle&&) noexcept = default;
    auto operator=(credential_lease_bundle&&) -> credential_lease_bundle& = delete;

    ~credential_lease_bundle() {
        locks_.clear();
        if (!directory_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(directory_, ignored);
        }
    }

    void preserve() noexcept { directory_.clear(); }

    std::filesystem::path directory_;
    std::vector<unique_fd> locks_;
    std::vector<credential_commitment> commitments_;
};

class egress_broker_bundle {
public:
    egress_broker_bundle() = default;
    egress_broker_bundle(const egress_broker_bundle&) = delete;
    auto operator=(const egress_broker_bundle&) -> egress_broker_bundle& = delete;
    egress_broker_bundle(egress_broker_bundle&&) noexcept = default;
    auto operator=(egress_broker_bundle&&) -> egress_broker_bundle& = delete;

    ~egress_broker_bundle() {
        proxy_.reset();
        if (!directory_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(directory_, ignored);
        }
    }

    void preserve() noexcept { directory_.clear(); }

    std::filesystem::path directory_;
    std::unique_ptr<net::egress_proxy> proxy_;
};

class projection_lease_bundle {
public:
    projection_lease_bundle() = default;
    projection_lease_bundle(const projection_lease_bundle&) = delete;
    auto operator=(const projection_lease_bundle&) -> projection_lease_bundle& = delete;
    projection_lease_bundle(projection_lease_bundle&&) noexcept = default;
    auto operator=(projection_lease_bundle&&) -> projection_lease_bundle& = delete;

    // The pathname-based cleanup added with the latent Apple lifecycle was not
    // descriptor-owned. While lifecycle is structurally unavailable, the
    // fallback deliberately preserves this lease; explicit descriptor-relative
    // cleanup remains an activation blocker.
    ~projection_lease_bundle() noexcept = default;

    void preserve() noexcept { directory_.clear(); }

    std::filesystem::path directory_;
    std::string mount_name_;
    std::optional<std::string> digest_;
};

struct command_result {
    int exit_code = -1;
    std::string standard_output;
    std::string standard_error;
};

void bounded_reap_after_kill(::pid_t child) noexcept {
    static_cast<void>(::killpg(child, SIGKILL));
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        const auto waited = ::waitpid(child, nullptr, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return;
        }
        if (waited < 0 && errno != EINTR) {
            return;
        }
        timespec delay{.tv_sec = 0, .tv_nsec = 10'000'000};
        while (::nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
    }
}

[[nodiscard]] auto make_nonblocking(int descriptor) -> bool {
    const int flags = ::fcntl(descriptor, F_GETFL, 0);
    return flags >= 0 && ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

[[nodiscard]] auto append_command_output(int descriptor, std::string& destination, bool& closed)
    -> std::expected<void, std::string> {
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto count = ::read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            if (static_cast<std::size_t>(count) > max_command_output_bytes - destination.size()) {
                return std::unexpected(
                    std::string{"Apple Container command output exceeds its bound"}
                );
            }
            destination.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) {
            closed = true;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return std::unexpected(system_error("read Apple Container command output"));
        }
        return {};
    }
}

auto run_command(
    const std::filesystem::path& executable,
    const std::vector<std::string>& arguments,
    std::uint64_t timeout_ms = max_command_runtime_ms
) -> std::expected<command_result, std::string> {
    std::array<int, 2> stdout_descriptors = {-1, -1};
    std::array<int, 2> stderr_descriptors = {-1, -1};
    if (::pipe(stdout_descriptors.data()) != 0 || ::pipe(stderr_descriptors.data()) != 0) {
        const auto error = system_error("create Apple Container command pipe");
        for (const auto descriptor :
             {stdout_descriptors[0],
              stdout_descriptors[1],
              stderr_descriptors[0],
              stderr_descriptors[1]}) {
            if (descriptor >= 0) {
                static_cast<void>(::close(descriptor));
            }
        }
        return std::unexpected(error);
    }
    unique_fd stdout_read{stdout_descriptors[0]};
    unique_fd stdout_write{stdout_descriptors[1]};
    unique_fd stderr_read{stderr_descriptors[0]};
    unique_fd stderr_write{stderr_descriptors[1]};
    const auto child = ::fork();
    if (child < 0) {
        return std::unexpected(system_error("fork Apple Container command"));
    }
    if (child == 0) {
        if (::setpgid(0, 0) != 0 || ::dup2(stdout_write.get(), STDOUT_FILENO) < 0 ||
            ::dup2(stderr_write.get(), STDERR_FILENO) < 0) {
            _exit(126);
        }
        static_cast<void>(::close(stdout_read.get()));
        static_cast<void>(::close(stderr_read.get()));
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 2U);
        argv.push_back(const_cast<char*>(executable.c_str()));
        for (const auto& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        ::execve(executable.c_str(), argv.data(), environ);
        _exit(127);
    }
    static_cast<void>(::setpgid(child, child));
    static_cast<void>(::close(stdout_write.release()));
    static_cast<void>(::close(stderr_write.release()));
    if (!make_nonblocking(stdout_read.get()) || !make_nonblocking(stderr_read.get())) {
        const auto error = system_error("protect Apple Container command output");
        bounded_reap_after_kill(child);
        return std::unexpected(error);
    }

    command_result result;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    bool stdout_closed = false;
    bool stderr_closed = false;
    bool child_finished = false;
    int status = 0;
    while (!stdout_closed || !stderr_closed || !child_finished) {
        if (auto read =
                append_command_output(stdout_read.get(), result.standard_output, stdout_closed);
            !read) {
            bounded_reap_after_kill(child);
            return std::unexpected(read.error());
        }
        if (auto read =
                append_command_output(stderr_read.get(), result.standard_error, stderr_closed);
            !read) {
            bounded_reap_after_kill(child);
            return std::unexpected(read.error());
        }
        if (!child_finished) {
            const auto waited = ::waitpid(child, &status, WNOHANG);
            if (waited == child) {
                child_finished = true;
            } else if (waited < 0 && errno != EINTR) {
                const auto error = system_error("wait for Apple Container command");
                bounded_reap_after_kill(child);
                return std::unexpected(error);
            }
        }
        if (stdout_closed && stderr_closed && child_finished) {
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            bounded_reap_after_kill(child);
            return std::unexpected(std::string{"Apple Container command deadline exceeded"});
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const int wait_ms = static_cast<int>(std::min<std::int64_t>(remaining, 100));
        std::array<pollfd, 2> descriptors{{
            {.fd = stdout_closed ? -1 : stdout_read.get(),
             .events = POLLIN | POLLHUP,
             .revents = 0},
            {.fd = stderr_closed ? -1 : stderr_read.get(),
             .events = POLLIN | POLLHUP,
             .revents = 0},
        }};
        const auto polled = ::poll(descriptors.data(), descriptors.size(), wait_ms);
        if (polled < 0 && errno != EINTR) {
            const auto error = system_error("poll Apple Container command output");
            bounded_reap_after_kill(child);
            return std::unexpected(error);
        }
    }
    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = 128 + WTERMSIG(status);
    }
    return result;
}

[[nodiscard]] auto command_diagnostic(const command_result& result) -> std::string;

struct apple_container_stats {
    std::string id;
    std::uint64_t memoryUsageBytes = 0;
    std::uint64_t memoryLimitBytes = 0;
    std::uint64_t cpuUsageUsec = 0;
    std::uint64_t networkRxBytes = 0;
    std::uint64_t networkTxBytes = 0;
    std::uint64_t blockReadBytes = 0;
    std::uint64_t blockWriteBytes = 0;
    std::uint64_t numProcesses = 0;

    struct glaze {
        using T = apple_container_stats;
        static constexpr auto value = glz::object(
            "id",
            &T::id,
            "memoryUsageBytes",
            &T::memoryUsageBytes,
            "memoryLimitBytes",
            &T::memoryLimitBytes,
            "cpuUsageUsec",
            &T::cpuUsageUsec,
            "networkRxBytes",
            &T::networkRxBytes,
            "networkTxBytes",
            &T::networkTxBytes,
            "blockReadBytes",
            &T::blockReadBytes,
            "blockWriteBytes",
            &T::blockWriteBytes,
            "numProcesses",
            &T::numProcesses
        );
    };
};

auto sample_resource_usage(
    const apple_container_runtime_config& config,
    std::string_view instance_id,
    std::uint64_t expected_memory_limit
) -> std::expected<container::resource_usage, std::string> {
    auto sampled = run_command(
        config.container_cli,
        {"stats", "--format", "json", "--no-stream", std::string{instance_id}},
        stats_command_runtime_ms
    );
    if (!sampled || sampled->exit_code != 0) {
        return std::unexpected(
            sampled
                ? std::string{"sample Apple Container resources: "} + command_diagnostic(*sampled)
                : sampled.error()
        );
    }
    if (!sampled->standard_error.empty()) {
        return std::unexpected(std::string{"Apple Container resource sample wrote stderr"});
    }
    auto decoded = parse_apple_container_stats(sampled->standard_output, instance_id);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    if (decoded->memory_limit_bytes != expected_memory_limit) {
        return std::unexpected(std::string{"Apple Container memory limit observation mismatch"});
    }
    return container::resource_usage{
        .cpu_time_ms = decoded->cpu_usage_usec / 1'000U,
        .peak_memory_bytes = decoded->memory_usage_bytes,
        .peak_pids = decoded->num_processes,
        .wall_time_ms = 0,
        // Cumulative block writes are I/O volume, not current filesystem
        // occupancy. They remain available in the parsed observation but must
        // not authenticate disk enforcement or a disk-usage receipt.
        .disk_bytes = 0,
        .terminal_output_bytes = 0,
    };
}

void merge_resource_sample(
    container::resource_usage& aggregate, const container::resource_usage& sample
) noexcept {
    aggregate.cpu_time_ms = std::max(aggregate.cpu_time_ms, sample.cpu_time_ms);
    aggregate.peak_memory_bytes = std::max(aggregate.peak_memory_bytes, sample.peak_memory_bytes);
    aggregate.peak_pids = std::max(aggregate.peak_pids, sample.peak_pids);
    aggregate.disk_bytes = std::max(aggregate.disk_bytes, sample.disk_bytes);
}

[[nodiscard]] auto command_diagnostic(const command_result& result) -> std::string {
    if (!result.standard_error.empty()) {
        return result.standard_error;
    }
    return result.standard_output;
}

auto inspect_instance(
    const apple_container_runtime_config& config,
    const apple_instance_ownership_expectation& expected
) -> std::expected<std::optional<command_result>, std::string> {
    auto inspected = run_command(config.container_cli, {"inspect", expected.instance_name});
    if (!inspected) {
        return std::unexpected(inspected.error());
    }
    if (inspected->exit_code != 0) {
        return std::unexpected(
            std::string{"inspect Apple Container instance failed: "} +
            command_diagnostic(*inspected)
        );
    }
    if (auto valid = validate_instance_inspection_json(
            inspected->standard_output, inspected->standard_error, expected
        );
        !valid) {
        return std::unexpected(valid.error());
    }
    return std::optional<command_result>{std::move(*inspected)};
}

auto kill_instance_owned(
    const apple_container_runtime_config& config,
    const apple_instance_ownership_expectation& expected
) -> std::expected<void, std::string> {
    auto owned = inspect_instance(config, expected);
    if (!owned || !owned->has_value()) {
        return std::unexpected(
            owned ? std::string{"Apple Container instance ownership is absent"} : owned.error()
        );
    }
    auto killed = run_command(config.container_cli, {"kill", expected.instance_name});
    if (!killed || killed->exit_code != 0) {
        return std::unexpected(
            killed ? std::string{"kill Apple Container session: "} + command_diagnostic(*killed)
                   : killed.error()
        );
    }
    return {};
}

auto delete_instance_owned(
    const apple_container_runtime_config& config,
    const apple_instance_ownership_expectation& expected
) -> std::expected<void, std::string> {
    // This inspection is intentionally independent of any earlier proof. A
    // bounded name can be reused between kill and delete.
    auto owned = inspect_instance(config, expected);
    if (!owned || !owned->has_value()) {
        return std::unexpected(
            owned ? std::string{"Apple Container instance ownership is absent"} : owned.error()
        );
    }
    auto removed = run_command(config.container_cli, {"delete", "--force", expected.instance_name});
    if (!removed || removed->exit_code != 0) {
        return std::unexpected(
            removed ? std::string{"delete Apple Container session: "} + command_diagnostic(*removed)
                    : removed.error()
        );
    }
    return {};
}

auto destroy_instance_owned(
    const apple_container_runtime_config& config,
    const apple_instance_ownership_expectation& expected
) -> std::expected<void, std::string> {
    if (auto killed = kill_instance_owned(config, expected); !killed) {
        return std::unexpected(killed.error());
    }
    return delete_instance_owned(config, expected);
}

auto remove_owner_only_directory(
    const std::filesystem::path& root, const std::filesystem::path& directory
) -> std::expected<void, std::string> {
    struct stat root_status{};
    if (::lstat(root.c_str(), &root_status) != 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(system_error("inspect Apple Container artifact root"));
    }
    if (!S_ISDIR(root_status.st_mode) || root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"Apple Container artifact root is not an owner-only directory: "} +
            root.string()
        );
    }
    struct stat directory_status{};
    if (::lstat(directory.c_str(), &directory_status) != 0) {
        if (errno == ENOENT) {
            return {};
        }
        return std::unexpected(system_error("inspect Apple Container artifact lease"));
    }
    if (!S_ISDIR(directory_status.st_mode) || directory_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(directory_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"Apple Container artifact lease is not an owner-only directory: "} +
            directory.string()
        );
    }
    std::error_code filesystem_error;
    for (std::filesystem::directory_iterator iterator{directory, filesystem_error}, end;
         !filesystem_error && iterator != end;
         iterator.increment(filesystem_error)) {
        struct stat child_status{};
        if (::lstat(iterator->path().c_str(), &child_status) != 0) {
            return std::unexpected(system_error("inspect Apple Container artifact child"));
        }
        if (S_ISDIR(child_status.st_mode)) {
            const auto mode = static_cast<unsigned int>(child_status.st_mode) & 0777U;
            unique_fd child{
                ::open(iterator->path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            };
            struct stat opened_status{};
            if (child_status.st_uid != ::geteuid() || (mode != 0700U && mode != 0555U) ||
                child.get() < 0 || ::fstat(child.get(), &opened_status) != 0 ||
                opened_status.st_dev != child_status.st_dev ||
                opened_status.st_ino != child_status.st_ino || !S_ISDIR(opened_status.st_mode) ||
                ::fchmod(child.get(), 0700) != 0) {
                return std::unexpected(
                    std::string{"Apple Container artifact child directory is unsafe"}
                );
            }
        }
    }
    if (filesystem_error) {
        return std::unexpected(
            std::string{"inspect Apple Container artifact lease: "} + filesystem_error.message()
        );
    }
    const auto removed = std::filesystem::remove_all(directory, filesystem_error);
    if (filesystem_error || removed == 0U) {
        return std::unexpected(
            std::string{"remove Apple Container artifact lease: "} +
            (filesystem_error ? filesystem_error.message() : "lease was not removed")
        );
    }
    return {};
}

auto remove_managed_artifacts(
    const apple_container_runtime_config& config, std::string_view instance_id
) -> std::expected<void, std::string> {
    if (!valid_identifier(instance_id) || !instance_id.starts_with("glove-") ||
        instance_id.size() < 16U) {
        return std::unexpected(std::string{"invalid Apple Container artifact identity"});
    }
    const std::string instance{instance_id};
    for (const auto& [root, leaf] : std::array{
             std::pair{config.session_root / ".credential-leases", instance},
             std::pair{config.session_root / ".projections", instance},
             std::pair{config.session_root / ".e", instance.substr(0, 16)},
         }) {
        if (auto removed = remove_owner_only_directory(root, root / leaf); !removed) {
            return removed;
        }
    }
    return {};
}

auto append_u64(std::vector<unsigned char>& material, std::uint64_t value) -> void {
    for (int shift = 56; shift >= 0; shift -= 8) {
        material.push_back(static_cast<unsigned char>((value >> shift) & 0xffU));
    }
}

auto append_string(std::vector<unsigned char>& material, std::string_view value) -> bool {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    const auto size = static_cast<std::uint32_t>(value.size());
    for (int shift = 24; shift >= 0; shift -= 8) {
        material.push_back(static_cast<unsigned char>((size >> shift) & 0xffU));
    }
    material.insert(material.end(), value.begin(), value.end());
    return true;
}

auto write_all_at(int destination, int source, std::uint64_t size)
    -> std::expected<void, std::string> {
    std::array<unsigned char, 16U * 1024U> buffer{};
    std::uint64_t offset = 0;
    while (offset < size) {
        const auto requested =
            static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), size - offset));
        const auto read = ::pread(source, buffer.data(), requested, static_cast<off_t>(offset));
        if (read <= 0) {
            return std::unexpected(system_error("read credential source"));
        }
        std::size_t written = 0;
        while (written < static_cast<std::size_t>(read)) {
            const auto count = ::pwrite(
                destination,
                buffer.data() + written,
                static_cast<std::size_t>(read) - written,
                static_cast<off_t>(offset + written)
            );
            if (count <= 0) {
                return std::unexpected(system_error("write Apple Container credential lease"));
            }
            written += static_cast<std::size_t>(count);
        }
        offset += static_cast<std::uint64_t>(read);
    }
    if (::ftruncate(destination, static_cast<off_t>(size)) != 0 || ::fsync(destination) != 0) {
        return std::unexpected(system_error("commit Apple Container credential lease"));
    }
    return {};
}

auto resolve_credential_leases(
    const std::vector<supervisor::secret_mount_policy>& policies,
    const apple_container_runtime_config& config,
    std::string_view instance_id
) -> std::expected<credential_lease_bundle, std::string> {
    credential_lease_bundle result;
    if (policies.empty()) {
        return result;
    }
    const auto root = config.session_root / ".credential-leases";
    std::error_code filesystem_error;
    const bool root_created = std::filesystem::create_directory(root, filesystem_error);
    if (!root_created && filesystem_error && filesystem_error != std::errc::file_exists) {
        return std::unexpected(
            std::string{"create Apple Container credential root: "} + filesystem_error.message()
        );
    }
    if (root_created && ::chmod(root.c_str(), 0700) != 0) {
        return std::unexpected(system_error("protect Apple Container credential root"));
    }
    struct stat root_status{};
    if (::lstat(root.c_str(), &root_status) != 0 || !S_ISDIR(root_status.st_mode) ||
        root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"Apple Container credential root is not an owner-only directory"}
        );
    }
    result.directory_ = root / std::string{instance_id};
    if (!std::filesystem::create_directory(result.directory_, filesystem_error) ||
        ::chmod(result.directory_.c_str(), 0700) != 0) {
        return std::unexpected(
            filesystem_error ? std::string{"create Apple Container credential lease: "} +
                                   filesystem_error.message()
                             : system_error("protect Apple Container credential lease")
        );
    }
    result.locks_.reserve(policies.size());
    result.commitments_.reserve(policies.size());
    for (const auto& policy : policies) {
        unique_fd source{::open(policy.source_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
        struct stat before{};
        if (source.get() < 0 || ::fstat(source.get(), &before) != 0 || !S_ISREG(before.st_mode) ||
            before.st_uid != ::geteuid() || before.st_nlink != 1 ||
            (static_cast<unsigned int>(before.st_mode) & 0777U) != 0600U || before.st_size <= 0 ||
            static_cast<std::uint64_t>(before.st_size) > max_secret_file_bytes) {
            return std::unexpected(
                std::string{"credential handle is not an owner-only bounded regular file: "} +
                policy.handle
            );
        }
        auto source_digest = container::sha256_fd_hex(source.get(), max_secret_file_bytes);
        if (!source_digest) {
            return std::unexpected(source_digest.error());
        }
        const auto lease_path = result.directory_ / policy.handle;
        unique_fd lease{
            ::open(lease_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)
        };
        if (lease.get() < 0 || ::flock(lease.get(), LOCK_EX | LOCK_NB) != 0) {
            return std::unexpected(system_error("create Apple Container credential lease"));
        }
        if (auto copied =
                write_all_at(lease.get(), source.get(), static_cast<std::uint64_t>(before.st_size));
            !copied) {
            return std::unexpected(copied.error());
        }
        struct stat after{};
        auto lease_digest = container::sha256_fd_hex(lease.get(), max_secret_file_bytes);
        if (!lease_digest || *lease_digest != *source_digest ||
            ::fstat(source.get(), &after) != 0 || before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
            before.st_size != after.st_size) {
            return std::unexpected(
                std::string{"credential source changed while importing handle: "} + policy.handle
            );
        }
        result.commitments_.push_back({
            .handle = policy.handle,
            .runtime_id = policy.runtime_id,
            .target_path = policy.target_path,
            .content_digest = *lease_digest,
        });
        result.locks_.push_back(std::move(lease));
    }
    return result;
}

auto start_egress_broker(
    const session_start_inputs& inputs,
    const apple_container_runtime_config& config,
    std::string_view instance_id
) -> std::expected<egress_broker_bundle, std::string> {
    egress_broker_bundle result;
    if (inputs.launch.egress_targets.empty()) {
        return result;
    }
    if (!config.egress_audit || !config.harness_closure_digest) {
        return std::unexpected(
            std::string{
                "online Apple Container session requires a managed closure and durable audit"
            }
        );
    }
    const auto root = config.session_root / ".e";
    std::error_code filesystem_error;
    const bool root_created = std::filesystem::create_directory(root, filesystem_error);
    if ((!root_created && filesystem_error && filesystem_error != std::errc::file_exists) ||
        (root_created && ::chmod(root.c_str(), 0700) != 0)) {
        return std::unexpected(
            filesystem_error
                ? std::string{"create Apple egress root: "} + filesystem_error.message()
                : system_error("protect Apple egress root")
        );
    }
    struct stat root_status{};
    if (::lstat(root.c_str(), &root_status) != 0 || !S_ISDIR(root_status.st_mode) ||
        root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"Apple egress root is not owner-only"});
    }
    result.directory_ = root / std::string{instance_id.substr(0, 16)};
    if (!std::filesystem::create_directory(result.directory_, filesystem_error) ||
        ::chmod(result.directory_.c_str(), 0700) != 0) {
        return std::unexpected(
            filesystem_error
                ? std::string{"create Apple egress lease: "} + filesystem_error.message()
                : system_error("protect Apple egress lease")
        );
    }
    net::egress_options options;
    options.allow.reserve(inputs.launch.egress_targets.size());
    for (const auto& target : inputs.launch.egress_targets) {
        options.allow.push_back({
            .host = target.host,
            .port = target.port,
            .allow_private = target.allow_private,
        });
    }
    options.on_event = [sink = config.egress_audit,
                        session_id = inputs.session.session_id,
                        policy_id = inputs.launch.egress_policy_id](
                           const net::egress_event& event
                       ) -> std::expected<void, std::string> {
        return sink->record({
            .what = audit::action::egress,
            .tool_name =
                session_id + ":" + policy_id + ":" + event.host + ":" + std::to_string(event.port),
            .arguments_json = {},
            .status = event.allowed ? mcp::tool_call_status::ok
                                    : mcp::tool_call_status::invalid_arguments,
            .error_message = event.detail,
        });
    };
    auto proxy =
        net::start_egress_proxy_on_unix_socket(std::move(options), result.directory_ / "s", 31'820);
    if (!proxy) {
        return std::unexpected(std::string{"start Apple audited egress broker: "} + proxy.error());
    }
    result.proxy_ = std::move(*proxy);
    return result;
}

auto resolve_projection_lease(
    const session_start_inputs& inputs,
    const apple_container_runtime_config& config,
    std::string_view instance_id,
    const std::optional<supervisor::native_skill_runtime_adapter>& adapter
) -> std::expected<projection_lease_bundle, std::string> {
    projection_lease_bundle result;
    if (inputs.library_projections.empty()) {
        return result;
    }
    const bool sage_guest = inputs.launch.runtime_id == supervisor::sage_guest_runtime_id;
    std::optional<supervisor::native_skill_runtime_projection> native_projection;
    if (sage_guest) {
        if (!config.sage_guest || config.sage_guest->library_projection_schema !=
                                      supervisor::sage_bundle_projection_schema) {
            return std::unexpected(
                std::string{"Apple Container Sage guest projection identity is unavailable"}
            );
        }
        for (const auto& projection : inputs.library_projections) {
            if (auto valid = validate_sage_projection_target(
                    projection.destination_alias,
                    projection.target_path,
                    projection.bundle.content_digest()
                );
                !valid) {
                return std::unexpected(valid.error());
            }
        }
        auto digest = supervisor::sage_bundle_projection_digest(inputs.library_projections);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        std::vector<unsigned char> target_commitment;
        if (!append_string(target_commitment, "glove.apple-sage-projection-targets.v1") ||
            !append_string(target_commitment, *digest)) {
            return std::unexpected(
                std::string{"Apple Container Sage projection target commitment exceeds its bound"}
            );
        }
        for (const auto& projection : inputs.library_projections) {
            if (!append_string(target_commitment, projection.target_path)) {
                return std::unexpected(
                    std::string{
                        "Apple Container Sage projection target commitment exceeds its bound"
                    }
                );
            }
        }
        auto committed = container::sha256_hex(
            std::span<const unsigned char>{target_commitment.data(), target_commitment.size()}
        );
        if (!committed) {
            return std::unexpected(committed.error());
        }
        result.digest_ = std::move(*committed);
        result.mount_name_ = supervisor::sage_bundle_projection_mount;
    } else {
        if (!adapter || inputs.launch.runtime_id == "codex") {
            return std::unexpected(
                std::string{"Apple Container library projection requires a managed harness adapter"}
            );
        }
        auto projection = supervisor::resolve_native_skill_runtime_projection(
            *adapter, inputs.library_projections
        );
        if (!projection) {
            return std::unexpected(projection.error());
        }
        if (supervisor::native_skill_runtime_projection_requires_raw_bundle(*projection)) {
            return std::unexpected(
                std::string{
                    "Apple Container native projection cannot preserve known non-skill entries"
                }
            );
        }
        auto digest = supervisor::native_skill_runtime_projection_digest(*adapter, *projection);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        result.digest_ = std::move(*digest);
        result.mount_name_ = "home";
        native_projection = std::move(*projection);
    }
    const auto root = config.session_root / ".projections";
    std::error_code filesystem_error;
    const bool root_created = std::filesystem::create_directory(root, filesystem_error);
    if ((!root_created && filesystem_error && filesystem_error != std::errc::file_exists) ||
        (root_created && ::chmod(root.c_str(), 0700) != 0)) {
        return std::unexpected(
            filesystem_error
                ? std::string{"create Apple projection root: "} + filesystem_error.message()
                : system_error("protect Apple projection root")
        );
    }
    struct stat root_status{};
    if (::lstat(root.c_str(), &root_status) != 0 || !S_ISDIR(root_status.st_mode) ||
        root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(std::string{"Apple projection root is not owner-only"});
    }
    result.directory_ = root / std::string{instance_id};
    const auto projection_root = result.directory_ / result.mount_name_;
    if (!std::filesystem::create_directory(result.directory_, filesystem_error) ||
        ::chmod(result.directory_.c_str(), 0700) != 0 ||
        !std::filesystem::create_directory(projection_root, filesystem_error) ||
        ::chmod(projection_root.c_str(), 0700) != 0) {
        return std::unexpected(
            filesystem_error
                ? std::string{"create Apple projection lease: "} + filesystem_error.message()
                : system_error("protect Apple projection lease")
        );
    }
    unique_fd projection_descriptor{
        ::open(projection_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    };
    if (projection_descriptor.get() < 0) {
        return std::unexpected(system_error("open Apple projection directory"));
    }
    if (sage_guest) {
        if (auto materialized = supervisor::materialize_sage_bundle_projection(
                projection_descriptor.get(), inputs.library_projections
            );
            !materialized) {
            return std::unexpected(materialized.error());
        }
    } else {
        if (auto materialized = supervisor::materialize_native_skill_runtime_projection(
                projection_descriptor.get(), *adapter, *native_projection
            );
            !materialized) {
            return std::unexpected(materialized.error());
        }
    }
    return result;
}

auto profile_digest(
    const session_start_inputs& inputs,
    const apple_container_runtime_config& config,
    const std::vector<credential_commitment>& credentials,
    const std::optional<std::string>& projection_digest
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    constexpr std::string_view domain = "glove.apple-container-profile.v1";
    if (!append_string(material, domain) ||
        !append_string(material, inputs.session.plan_content_digest) ||
        !append_string(material, config.image_reference) ||
        !append_string(material, config.image_digest) ||
        !append_string(material, inputs.launch.runtime_id) ||
        !append_string(material, inputs.launch.adapter_command_digest) ||
        !append_string(material, inputs.launch.egress_policy_id) ||
        !append_string(material, projection_digest.value_or(""))) {
        return std::unexpected(std::string{"Apple Container profile field exceeds its bound"});
    }
    if (inputs.launch.runtime_id == supervisor::sage_guest_runtime_id) {
        if (!config.sage_guest || !append_string(material, config.sage_guest->binary_digest) ||
            !append_string(material, config.sage_guest->source_revision) ||
            !append_string(material, config.sage_guest->library_projection_schema)) {
            return std::unexpected(
                std::string{"Apple Container Sage guest profile identity is unavailable"}
            );
        }
        append_u64(material, config.sage_guest->policy_schema_version);
    }
    append_u64(material, credentials.size());
    for (const auto& credential : credentials) {
        if (!append_string(material, credential.handle) ||
            !append_string(material, credential.runtime_id) ||
            !append_string(material, credential.target_path) ||
            !append_string(material, credential.content_digest)) {
            return std::unexpected(
                std::string{"Apple Container credential commitment exceeds its bound"}
            );
        }
    }
    for (const auto& collection : {inputs.launch.argv, inputs.launch.environment}) {
        append_u64(material, collection.size());
        for (const auto& value : collection) {
            if (!append_string(material, value)) {
                return std::unexpected(
                    std::string{"Apple Container launch field exceeds its bound"}
                );
            }
        }
    }
    append_u64(material, inputs.launch.egress_targets.size());
    for (const auto& target : inputs.launch.egress_targets) {
        if (!append_string(material, target.host)) {
            return std::unexpected(std::string{"Apple Container egress target exceeds its bound"});
        }
        append_u64(material, target.port);
        append_u64(material, target.allow_private ? 1U : 0U);
    }
    append_u64(material, inputs.launch.limits.cpu_time_ms);
    append_u64(material, inputs.launch.limits.memory_bytes);
    append_u64(material, inputs.launch.limits.pids);
    append_u64(material, inputs.launch.limits.wall_time_ms);
    append_u64(material, inputs.launch.limits.disk_bytes);
    append_u64(material, inputs.launch.limits.terminal_output_bytes);
    return container::sha256_hex(material);
}

auto instance_identity(std::string_view session_id) -> std::expected<std::string, std::string> {
    const auto* first = std::bit_cast<const unsigned char*>(session_id.data());
    auto digest = container::sha256_hex(std::span<const unsigned char>{first, session_id.size()});
    return digest ? std::expected<std::string, std::string>{"glove-" + digest->substr(0, 32)}
                  : std::unexpected(digest.error());
}

auto launch_identity(
    std::string_view instance_id, std::string_view image_digest, std::string_view profile
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    if (!append_string(material, "glove.apple-container-launch.v1") ||
        !append_string(material, instance_id) || !append_string(material, image_digest) ||
        !append_string(material, profile)) {
        return std::unexpected(std::string{"Apple Container launch identity exceeds its bound"});
    }
    return container::sha256_hex(material);
}

auto capabilities() noexcept -> container::resource_enforcement_capabilities {
    return {
        .cpu_time = container::enforcement_mechanism::rlimit,
        .memory = container::enforcement_mechanism::cgroup_v2,
        .pids = container::enforcement_mechanism::rlimit,
        .wall_time = container::enforcement_mechanism::watchdog,
        // Bounded tmpfs mounts do not prove an aggregate writable-byte quota
        // for the complete Apple Container filesystem.
        .disk = container::enforcement_mechanism::unavailable,
        .terminal_output = container::enforcement_mechanism::byte_counter,
        .receipt_schema_version = 0,
    };
}

auto converted_limits(const supervisor::resource_limits& limits) -> container::resource_limits {
    return {
        .cpu_time_ms = limits.cpu_time_ms,
        .memory_bytes = limits.memory_bytes,
        .pids = limits.pids,
        .wall_time_ms = limits.wall_time_ms,
        .disk_bytes = limits.disk_bytes,
        .terminal_output_bytes = limits.terminal_output_bytes,
    };
}

auto projection_receipts(
    std::span<const supervisor::resolved_library_projection> projections,
    std::string_view runtime_id
) -> std::vector<container::library_projection_receipt> {
    if (runtime_id != supervisor::sage_guest_runtime_id) {
        // Native harness adapters transform bundle entries into SKILL.md trees.
        // The original bundle target is not an effective guest path and must
        // not appear in an authenticated receipt.
        return {};
    }
    std::vector<container::library_projection_receipt> receipts;
    receipts.reserve(projections.size());
    for (const auto& projection : projections) {
        receipts.push_back({
            .projection_id = projection.projection_id,
            .destination_alias = projection.destination_alias,
            .target_path = projection.target_path,
            .content_digest = std::string{projection.bundle.content_digest()},
        });
    }
    return receipts;
}

auto registry_error(std::string_view operation, const session_registry_error& error)
    -> std::string {
    return std::string{operation} + ": " + error.message;
}

} // namespace

auto parse_apple_container_stats(std::string_view json, std::string_view expected_instance_id)
    -> std::expected<apple_container_stats_observation, std::string> {
    std::vector<apple_container_stats> decoded;
    if (const auto error = glz::read<strict_json_options>(decoded, json); error) {
        return std::unexpected(
            std::string{"decode Apple Container resource sample: "} + glz::format_error(error, json)
        );
    }
    if (decoded.size() != 1U || decoded.front().id != expected_instance_id ||
        decoded.front().numProcesses > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"Apple Container resource sample identity is invalid"});
    }
    return apple_container_stats_observation{
        .cpu_usage_usec = decoded.front().cpuUsageUsec,
        .memory_usage_bytes = decoded.front().memoryUsageBytes,
        .memory_limit_bytes = decoded.front().memoryLimitBytes,
        .num_processes = static_cast<std::uint32_t>(decoded.front().numProcesses),
        .block_write_bytes = decoded.front().blockWriteBytes,
    };
}

auto apple_container_tmpfs_sizes(std::uint64_t disk_bytes)
    -> std::expected<std::pair<std::uint64_t, std::uint64_t>, std::string> {
    if (disk_bytes < 2U) {
        return std::unexpected(
            std::string{
                "Apple Container writable-byte limit is too small for isolated tmpfs mounts"
            }
        );
    }
    const auto temp_bytes = disk_bytes / 2U;
    const auto home_bytes = disk_bytes - temp_bytes;
    return std::pair{temp_bytes, home_bytes};
}

class apple_live_session final {
public:
    apple_live_session(
        session_registry& registry,
        container::receipt_audit_producer& producer,
        container::receipt_audit_producer::terminal_reservation reservation,
        managed_session_running_commitment running,
        session_failure_commitment failure,
        apple_container_runtime_config config,
        std::unique_ptr<container::linux_detail::pty_session_channel> channel,
        std::shared_ptr<container::detail::wall_output_monitor> monitor,
        ::pid_t attach_pid,
        supervisor::resource_limits limits,
        container::resource_usage initial_resource_usage,
        std::uint64_t started_at_ms,
        std::string idempotency_namespace,
        credential_lease_bundle credential_leases,
        egress_broker_bundle egress_broker,
        projection_lease_bundle projection_lease,
        std::vector<container::library_projection_receipt> library_projections
    )
        : registry_{&registry},
          producer_{&producer},
          reservation_{std::move(reservation)},
          running_{std::move(running)},
          failure_{std::move(failure)},
          config_{std::move(config)},
          channel_{std::move(channel)},
          monitor_{std::move(monitor)},
          attach_pid_{attach_pid},
          limits_{limits},
          resource_usage_{initial_resource_usage},
          started_at_ms_{started_at_ms},
          idempotency_namespace_{std::move(idempotency_namespace)},
          credential_leases_{std::move(credential_leases)},
          egress_broker_{std::move(egress_broker)},
          projection_lease_{std::move(projection_lease)},
          library_projections_{std::move(library_projections)} {}

    apple_live_session(const apple_live_session&) = delete;
    auto operator=(const apple_live_session&) -> apple_live_session& = delete;

    // No public path can construct a live session while lifecycle_operational()
    // is false. This fallback performs no container or filesystem cleanup and
    // preserves leases; descriptor-owned explicit cleanup is an activation
    // blocker rather than a destructor claim.
    ~apple_live_session() noexcept {
        credential_leases_.preserve();
        egress_broker_.preserve();
        projection_lease_.preserve();
    }

    auto start_finalizer() -> std::expected<void, std::string> {
        auto launch = []<typename Body>(Body&& body) -> std::jthread {
            return std::jthread{std::forward<Body>(body)};
        };
        auto started = detail::start_sampler_then_finalizer(
            sampler_,
            finalizer_,
            launch,
            [this](std::stop_token stop_token) {
                try {
                    while (!stop_token.stop_requested()) {
                        auto sample = sample_resource_usage(
                            config_, running_.runtime_identity.instance_id, limits_.memory_bytes
                        );
                        if (sample) {
                            merge_resource_sample(resource_usage_, *sample);
                        }
                        for (int count = 0; count < 10 && !stop_token.stop_requested(); ++count) {
                            std::this_thread::sleep_for(stats_sample_interval / 10);
                        }
                    }
                } catch (...) {
                    // The required initial sample already proved observation
                    // availability. A later sampler allocation failure cannot
                    // erase that evidence or escape the worker thread.
                }
            },
            [this] { finalize(); }
        );
        if (!started) {
            return std::unexpected(
                std::string{"start Apple Container session finalizer: "} + started.error()
            );
        }
        return {};
    }

    auto read(std::uint64_t cursor, std::size_t max_bytes) const
        -> std::expected<session_transcript_read, std::string> {
        auto result = channel_->read(cursor, max_bytes);
        if (!result) {
            return std::unexpected(result.error());
        }
        return session_transcript_read{
            .oldest_cursor = result->oldest_cursor,
            .next_cursor = result->next_cursor,
            .truncated = result->truncated,
            .eof = result->eof,
            .bytes = std::move(result->bytes),
        };
    }

    auto wait_read(std::uint64_t cursor, std::size_t max_bytes, std::uint64_t timeout_ms)
        -> std::expected<session_transcript_read, std::string> {
        auto result = channel_->wait_read(cursor, max_bytes, timeout_ms);
        if (!result) {
            return std::unexpected(result.error());
        }
        return session_transcript_read{
            .oldest_cursor = result->oldest_cursor,
            .next_cursor = result->next_cursor,
            .truncated = result->truncated,
            .eof = result->eof,
            .bytes = std::move(result->bytes),
        };
    }

    auto write_input(std::string_view bytes) -> std::expected<void, std::string> {
        return channel_->write_input(bytes);
    }

    auto resize(std::uint16_t rows, std::uint16_t columns) -> std::expected<void, std::string> {
        return channel_->resize(rows, columns);
    }

    auto signal(session_signal requested) -> std::expected<void, std::string> {
        container::linux_detail::pty_session_signal translated;
        switch (requested) {
        case session_signal::interrupt:
            translated = container::linux_detail::pty_session_signal::interrupt;
            break;
        case session_signal::terminate:
            translated = container::linux_detail::pty_session_signal::terminate;
            break;
        case session_signal::hangup:
            translated = container::linux_detail::pty_session_signal::hangup;
            break;
        }
        return channel_->signal(translated);
    }

    auto stop(std::string_view idempotency_key) -> std::expected<void, std::string> {
        std::lock_guard transition_lock{transition_mutex_};
        {
            std::lock_guard state_lock{state_mutex_};
            if (finished_) {
                return {};
            }
        }
        auto stopping = registry_->mark_managed_stopping(
            running_, idempotency_key, std::max(current_epoch_ms(), started_at_ms_)
        );
        if (!stopping && stopping.error().code != session_registry_error_code::invalid_state) {
            return std::unexpected(
                registry_error("persist Apple Container stopping intent", stopping.error())
            );
        }
        const apple_instance_ownership_expectation expected_identity{
            .instance_name = running_.runtime_identity.instance_id,
            .image_digest = config_.image_digest,
            .launch_identity_digest = running_.runtime_identity.launch_identity_digest,
        };
        auto killed = kill_instance_owned(config_, expected_identity);
        if (!killed) {
            credential_leases_.preserve();
            egress_broker_.preserve();
            projection_lease_.preserve();
            static_cast<void>(::killpg(attach_pid_, SIGTERM));
            return std::unexpected(killed.error());
        }
        static_cast<void>(::killpg(attach_pid_, SIGTERM));
        return {};
    }

    auto wait() -> std::expected<session_terminal_record, std::string> {
        std::unique_lock lock{state_mutex_};
        state_changed_.wait(lock, [this] { return finished_; });
        if (!error_.empty()) {
            return std::unexpected(error_);
        }
        if (!result_.has_value()) {
            return std::unexpected(std::string{"internal error"});
        }
        return *result_;
    }

    auto finished() const -> bool {
        std::lock_guard lock{state_mutex_};
        return finished_;
    }

    void preserve_credential_leases() noexcept { credential_leases_.preserve(); }

    void preserve_egress_lease() noexcept { egress_broker_.preserve(); }

    void preserve_projection_lease() noexcept { projection_lease_.preserve(); }

private:
    void publish_error(std::string message) noexcept {
        try {
            std::lock_guard lock{state_mutex_};
            error_ = std::move(message);
            finished_ = true;
            state_changed_.notify_all();
        } catch (...) {
            std::lock_guard lock{state_mutex_};
            finished_ = true;
            state_changed_.notify_all();
        }
    }

    void close_failed(std::string message) noexcept {
        try {
            std::lock_guard transition_lock{transition_mutex_};
            auto failed = registry_->mark_managed_failed(
                failure_,
                idempotency_namespace_ + ".failed",
                std::max(current_epoch_ms(), started_at_ms_)
            );
            if (!failed) {
                credential_leases_.preserve();
                egress_broker_.preserve();
                projection_lease_.preserve();
            }
        } catch (...) {
            credential_leases_.preserve();
            egress_broker_.preserve();
            projection_lease_.preserve();
        }
        publish_error(std::move(message));
    }

    void finalize() noexcept {
        try {
            int status = 0;
            while (::waitpid(attach_pid_, &status, 0) < 0) {
                if (errno != EINTR) {
                    sampler_.request_stop();
                    if (sampler_.joinable()) {
                        sampler_.join();
                    }
                    credential_leases_.preserve();
                    egress_broker_.preserve();
                    projection_lease_.preserve();
                    publish_error(system_error("wait for Apple Container attach process"));
                    return;
                }
            }
            sampler_.request_stop();
            if (sampler_.joinable()) {
                sampler_.join();
            }
            monitor_->finish();
            static_cast<void>(channel_->finish_draining());
            const auto snapshot = monitor_->snapshot();
            const apple_instance_ownership_expectation expected_identity{
                .instance_name = running_.runtime_identity.instance_id,
                .image_digest = config_.image_digest,
                .launch_identity_digest = running_.runtime_identity.launch_identity_digest,
            };
            auto removed = delete_instance_owned(config_, expected_identity);
            if (!removed) {
                credential_leases_.preserve();
                egress_broker_.preserve();
                projection_lease_.preserve();
                publish_error(removed.error());
                return;
            }
            const auto finished_at_ms = std::max(current_epoch_ms(), started_at_ms_);
            container::resource_termination_cause cause = snapshot.forced_cause.value_or(
                WIFEXITED(status) ? container::resource_termination_cause::exited
                                  : container::resource_termination_cause::signaled
            );
            std::optional<int> exit_code;
            if (cause == container::resource_termination_cause::exited && WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
            }
            container::resource_enforcement_receipt receipt{
                .schema_version = 1,
                .profile_digest = running_.profile_digest,
                .backend = container::sandbox_backend::apple_container,
                .backend_id = "apple-container:" + config_.image_digest,
                .configured_limits = converted_limits(limits_),
                .mechanisms = capabilities(),
                .observed =
                    {
                        .cpu_time_ms = resource_usage_.cpu_time_ms,
                        .peak_memory_bytes = resource_usage_.peak_memory_bytes,
                        .peak_pids = resource_usage_.peak_pids,
                        .wall_time_ms = snapshot.wall_time_ms,
                        .disk_bytes = resource_usage_.disk_bytes,
                        .terminal_output_bytes = snapshot.terminal_output_bytes,
                    },
                .termination_cause = cause,
                .exit_code = exit_code,
                .started_at_ms = started_at_ms_,
                .finished_at_ms = finished_at_ms,
                .library_projections = library_projections_,
                .retained_changes = {},
            };
            auto terminal = producer_->commit_terminal(
                std::move(reservation_),
                running_.session_id,
                running_.controller_plan_digest,
                receipt
            );
            if (!terminal) {
                close_failed(
                    std::string{"commit Apple Container terminal receipt: "} + terminal.error()
                );
                return;
            }
            auto exited = registry_->mark_managed_exited(
                *terminal, *producer_, idempotency_namespace_ + ".exited"
            );
            if (!exited) {
                publish_error(
                    registry_error("project Apple Container terminal receipt", exited.error())
                );
                return;
            }
            session_terminal_record projected{
                .session = exited->lifecycle.session,
                .profile_digest = exited->lifecycle.profile_digest,
                .starting_at_ms = exited->lifecycle.starting_at_ms,
                .running_at_ms = exited->lifecycle.running_at_ms,
                .stopping_at_ms = exited->lifecycle.stopping_at_ms,
                .finished_at_ms = exited->finished_at_ms,
                .receipt_key_id = exited->receipt_key_id,
                .receipt_sequence = exited->receipt_sequence,
                .receipt_digest = exited->receipt_digest,
                .receipt_hmac = exited->receipt_hmac,
                .termination_cause = exited->termination_cause,
                .exit_code = exited->exit_code,
            };
            std::lock_guard lock{state_mutex_};
            result_ = std::move(projected);
            finished_ = true;
            state_changed_.notify_all();
        } catch (...) {
            // This fallback is deliberately non-reporting: constructing a
            // diagnostic here could throw inside noexcept. The unavailable
            // lifecycle preserves every lease and leaves durable recovery as
            // the only future activation path. The sampler must not outlive
            // finalization even on this path (bad_alloc in the pre-join
            // waitpid-error branch can land here), and wait() must observe a
            // well-formed terminal state, so a static error string is set
            // when allocation permits.
            try {
                sampler_.request_stop();
                if (sampler_.joinable()) {
                    sampler_.join();
                }
            } catch (...) {}
            credential_leases_.preserve();
            egress_broker_.preserve();
            projection_lease_.preserve();
            try {
                std::lock_guard lock{state_mutex_};
                error_ = "internal error";
                finished_ = true;
                state_changed_.notify_all();
            } catch (...) {
                std::lock_guard lock{state_mutex_};
                finished_ = true;
                state_changed_.notify_all();
            }
        }
    }

    session_registry* registry_;
    container::receipt_audit_producer* producer_;
    container::receipt_audit_producer::terminal_reservation reservation_;
    managed_session_running_commitment running_;
    session_failure_commitment failure_;
    apple_container_runtime_config config_;
    std::unique_ptr<container::linux_detail::pty_session_channel> channel_;
    std::shared_ptr<container::detail::wall_output_monitor> monitor_;
    ::pid_t attach_pid_ = -1;
    supervisor::resource_limits limits_;
    container::resource_usage resource_usage_;
    std::uint64_t started_at_ms_ = 0;
    std::string idempotency_namespace_;
    credential_lease_bundle credential_leases_;
    egress_broker_bundle egress_broker_;
    projection_lease_bundle projection_lease_;
    std::vector<container::library_projection_receipt> library_projections_;
    std::mutex transition_mutex_;
    mutable std::mutex state_mutex_;
    std::condition_variable state_changed_;
    bool finished_ = false;
    std::optional<session_terminal_record> result_;
    std::string error_;
    std::jthread sampler_;
    std::jthread finalizer_;
};

struct apple_container_session_runtime::implementation {
    implementation(session_registry& registry, apple_container_runtime_config config)
        : registry{&registry}, config{std::move(config)} {}

    session_registry* registry;
    apple_container_runtime_config config;
    std::map<std::string, std::shared_ptr<apple_live_session>, std::less<>> sessions;
    std::optional<session_reconciliation_report> reconciliation;
    mutable std::mutex sessions_mutex;
    std::mutex start_mutex;
};

namespace {

auto lookup(
    const apple_container_session_runtime::implementation& state, std::string_view session_id
) -> std::expected<std::shared_ptr<apple_live_session>, std::string> {
    std::lock_guard lock{state.sessions_mutex};
    const auto found = state.sessions.find(session_id);
    return found != state.sessions.end()
               ? std::expected<std::shared_ptr<apple_live_session>, std::string>{found->second}
               : std::unexpected(std::string{"Apple Container session is not live"});
}

auto validate_config(const apple_container_runtime_config& config)
    -> std::expected<void, std::string> {
    if (!config.container_cli.is_absolute() || !config.session_root.is_absolute() ||
        !container::valid_immutable_container_image(config.image_reference, config.image_digest) ||
        config.max_sessions == 0 || config.max_sessions > 1024U) {
        return std::unexpected(std::string{"invalid Apple Container runtime configuration"});
    }
    if (config.harness_closure_digest &&
        (config.harness_closure_digest->size() != 71U ||
         !config.harness_closure_digest->starts_with("sha256:") ||
         !valid_digest(std::string_view{*config.harness_closure_digest}.substr(7)))) {
        return std::unexpected(std::string{"invalid Apple Container harness closure digest"});
    }
    if (config.sage_guest &&
        (!config.harness_closure_digest || config.sage_guest->binary_digest.size() != 71U ||
         !config.sage_guest->binary_digest.starts_with("sha256:") ||
         !valid_digest(std::string_view{config.sage_guest->binary_digest}.substr(7)) ||
         (config.sage_guest->source_revision != "unknown" &&
          (config.sage_guest->source_revision.size() != 40U ||
           !std::ranges::all_of(
               config.sage_guest->source_revision,
               [](char byte) {
                   return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
               }
           ))) ||
         config.sage_guest->policy_schema_version != 1U ||
         config.sage_guest->library_projection_schema !=
             supervisor::sage_bundle_projection_schema)) {
        return std::unexpected(std::string{"invalid Apple Container Sage guest identity"});
    }
    struct stat cli_status{};
    struct stat root_status{};
    if (::stat(config.container_cli.c_str(), &cli_status) != 0 || !S_ISREG(cli_status.st_mode) ||
        (cli_status.st_mode & 0111U) == 0 ||
        ::lstat(config.session_root.c_str(), &root_status) != 0 || !S_ISDIR(root_status.st_mode) ||
        root_status.st_uid != ::geteuid() ||
        (static_cast<unsigned int>(root_status.st_mode) & 0777U) != 0700U) {
        return std::unexpected(
            std::string{"Apple Container CLI or owner-only session root is unavailable"}
        );
    }
    return {};
}

auto validate_live_image_identity(const apple_container_runtime_config& config)
    -> std::expected<void, std::string> {
    auto inspected =
        run_command(config.container_cli, {"image", "inspect", config.image_reference});
    if (!inspected || inspected->exit_code != 0) {
        return std::unexpected(
            inspected ? std::string{"reviewed Apple Container image identity is unavailable: "} +
                            command_diagnostic(*inspected)
                      : inspected.error()
        );
    }
    return validate_image_inspection_json(
        inspected->standard_output,
        inspected->standard_error,
        {
            .image_digest = config.image_digest,
            .harness_closure_digest = config.harness_closure_digest,
            .sage_guest = config.sage_guest,
        }
    );
}

auto spawn_attach(
    const apple_container_runtime_config& config,
    std::string_view instance_id,
    const std::shared_ptr<container::detail::wall_output_monitor>& monitor
)
    -> std::expected<
        std::pair<::pid_t, std::unique_ptr<container::linux_detail::pty_session_channel>>,
        std::string> {
    auto pair = container::linux_detail::open_pty_pair();
    if (!pair) {
        return std::unexpected(pair.error());
    }
    const auto child = ::fork();
    if (child < 0) {
        return std::unexpected(system_error("fork Apple Container attach process"));
    }
    if (child == 0) {
        static_cast<void>(::setsid());
        static_cast<void>(::ioctl(pair->slave_fd(), TIOCSCTTY, 0));
        static_cast<void>(::dup2(pair->slave_fd(), STDIN_FILENO));
        static_cast<void>(::dup2(pair->slave_fd(), STDOUT_FILENO));
        static_cast<void>(::dup2(pair->slave_fd(), STDERR_FILENO));
        pair->close_slave();
        std::array<char*, 6> argv = {
            const_cast<char*>(config.container_cli.c_str()),
            const_cast<char*>("start"),
            const_cast<char*>("--attach"),
            const_cast<char*>("--interactive"),
            const_cast<char*>(instance_id.data()),
            nullptr,
        };
        ::execve(config.container_cli.c_str(), argv.data(), environ);
        _exit(127);
    }
    pair->close_slave();
    auto channel = container::linux_detail::pty_session_channel::create({
        .master_fd = pair->release_master(),
        .transcript_bytes = transcript_bytes,
        .max_read_bytes = std::size_t{64} * 1024U,
        .max_input_frame_bytes = std::size_t{64} * 1024U,
        .input_timeout_ms = 1'000,
        .monitor = monitor,
        .refinement_evaluator = nullptr,
    });
    if (!channel) {
        static_cast<void>(::killpg(child, SIGKILL));
        static_cast<void>(::waitpid(child, nullptr, 0));
        return std::unexpected(channel.error());
    }
    return std::pair{child, std::move(*channel)};
}

} // namespace

auto validate_image_inspection_json(
    std::string_view standard_output,
    std::string_view standard_error,
    const apple_image_ownership_expectation& expected
) -> std::expected<void, std::string> {
    if (!inspection_input_valid(standard_output, standard_error)) {
        return std::unexpected(
            std::string{"Apple Container image inspection is not one bounded stdout JSON value"}
        );
    }
    image_inspection_wire decoded;
    std::string buffer{standard_output};
    if (const auto error = glz::read<strict_json_options>(decoded, buffer); error) {
        return std::unexpected(std::string{"malformed Apple Container image inspection"});
    }
    if (decoded.digest != expected.image_digest) {
        return std::unexpected(std::string{"Apple Container image digest mismatch"});
    }
    if (expected.harness_closure_digest &&
        (!exact_label(decoded.labels, "dev.sage.glove.harness-closure-schema", "1") ||
         !exact_label(
             decoded.labels,
             "dev.sage.glove.harness-closure-digest",
             std::string_view{*expected.harness_closure_digest}.substr(7)
         ))) {
        return std::unexpected(std::string{"Apple Container harness closure label mismatch"});
    }
    if (expected.sage_guest &&
        (!exact_label(
             decoded.labels,
             "dev.sage.glove.sage-guest-binary-digest",
             expected.sage_guest->binary_digest
         ) ||
         !exact_label(
             decoded.labels,
             "dev.sage.glove.sage-source-revision",
             expected.sage_guest->source_revision
         ) ||
         !exact_label(decoded.labels, "dev.sage.glove.sage-guest-policy-schema", "1") ||
         !exact_label(
             decoded.labels,
             "dev.sage.glove.library-projection-schema",
             supervisor::sage_bundle_projection_schema
         ))) {
        return std::unexpected(std::string{"Apple Container Sage guest label mismatch"});
    }
    return {};
}

auto validate_sage_projection_target(
    std::string_view destination_alias,
    std::string_view target_path,
    std::string_view content_digest
) -> std::expected<void, std::string> {
    const auto expected_target =
        std::string{sage_projection_root} + std::string{content_digest} + ".json";
    if (destination_alias != supervisor::sage_bundle_projection_mount ||
        target_path != expected_target) {
        return std::unexpected(
            std::string{"Apple Container Sage projection target does not match owner policy"}
        );
    }
    return {};
}

auto validate_instance_inspection_json(
    std::string_view standard_output,
    std::string_view standard_error,
    const apple_instance_ownership_expectation& expected
) -> std::expected<void, std::string> {
    if (!inspection_input_valid(standard_output, standard_error)) {
        return std::unexpected(
            std::string{"Apple Container instance inspection is not one bounded stdout JSON value"}
        );
    }
    instance_inspection_wire decoded;
    std::string buffer{standard_output};
    if (const auto error = glz::read<strict_json_options>(decoded, buffer); error) {
        return std::unexpected(std::string{"malformed Apple Container instance inspection"});
    }
    if (decoded.name != expected.instance_name || decoded.image.digest != expected.image_digest ||
        !exact_label(
            decoded.labels, "dev.sage.glove.launch-digest", expected.launch_identity_digest
        )) {
        return std::unexpected(std::string{"Apple Container instance ownership mismatch"});
    }
    return {};
}

apple_container_session_runtime::apple_container_session_runtime(
    [[maybe_unused]] construction_token token, std::unique_ptr<implementation> state
)
    : state_{std::move(state)} {}

apple_container_session_runtime::~apple_container_session_runtime() = default;

auto apple_container_session_runtime::create(
    session_registry& registry, apple_container_runtime_config config
) -> std::expected<std::unique_ptr<apple_container_session_runtime>, std::string> {
    if (auto valid = validate_config(config); !valid) {
        return std::unexpected(valid.error());
    }
    try {
        auto state = std::make_unique<implementation>(registry, std::move(config));
        auto runtime = std::make_unique<apple_container_session_runtime>(
            construction_token{}, std::move(state)
        );
        if (runtime->lifecycle_operational()) {
            if (auto valid = validate_live_image_identity(runtime->state_->config); !valid) {
                return std::unexpected(valid.error());
            }
        }
        return runtime;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::string{"allocate Apple Container session runtime"});
    }
}

auto apple_container_session_runtime::resource_capabilities() const noexcept
    -> container::resource_enforcement_capabilities {
    return capabilities();
}

auto apple_container_session_runtime::agent_runtime_adapter_schema_version() const noexcept
    -> std::uint8_t {
    return lifecycle_operational() && state_ && state_->config.harness_closure_digest ? 1 : 0;
}

auto apple_container_session_runtime::managed_runtime_ids() const -> std::vector<std::string> {
    if (!lifecycle_operational() || !state_ || !state_->config.harness_closure_digest) {
        return {};
    }
    std::vector<std::string> runtime_ids{"claude-code", "pi", "copilot", "opencode"};
    if (state_->config.sage_guest) {
        runtime_ids.emplace_back(supervisor::sage_guest_runtime_id);
    }
    return runtime_ids;
}

auto apple_container_session_runtime::reconcile(
    container::receipt_audit_producer& receipt_producer, std::uint64_t now_ms
) -> std::expected<session_reconciliation_report, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    if (!state_ || now_ms == 0) {
        return std::unexpected(std::string{"invalid Apple Container reconciliation"});
    }
    std::lock_guard start_lock{state_->start_mutex};
    if (state_->reconciliation) {
        return *state_->reconciliation;
    }
    auto candidates = state_->registry->managed_recovery_candidates();
    if (!candidates) {
        return std::unexpected(
            registry_error("read Apple Container recovery candidates", candidates.error())
        );
    }
    session_reconciliation_report report;
    for (const auto& candidate : *candidates) {
        ++report.inspected;
        const apple_instance_ownership_expectation expected_identity{
            .instance_name = candidate.runtime_identity.instance_id,
            .image_digest = state_->config.image_digest,
            .launch_identity_digest = candidate.runtime_identity.launch_identity_digest,
        };
        auto inspected = inspect_instance(state_->config, expected_identity);
        if (!inspected) {
            return std::unexpected(inspected.error());
        }
        auto terminal = receipt_producer.terminal_for_execution(
            candidate.session.session_id,
            candidate.session.controller_plan_digest,
            candidate.profile_digest
        );
        if (!terminal) {
            return std::unexpected(
                std::string{"read recovered Apple Container terminal receipt: "} + terminal.error()
            );
        }
        if (*terminal) {
            // A terminal receipt is emitted only after verified deletion. A
            // still-present instance contradicts that evidence and must never
            // be touched merely because its bounded name matches.
            if (inspected->has_value()) {
                report.identity_mismatch_session_ids.push_back(candidate.session.session_id);
                report.unresolved_running_session_ids.push_back(candidate.session.session_id);
                continue;
            }
            if (auto removed = remove_managed_artifacts(
                    state_->config, candidate.runtime_identity.instance_id
                );
                !removed) {
                return std::unexpected(removed.error());
            }
            auto exited = state_->registry->mark_managed_exited(
                **terminal,
                receipt_producer,
                "apple-reconcile-terminal." + candidate.session.session_id
            );
            if (!exited) {
                return std::unexpected(
                    registry_error("recover Apple Container terminal receipt", exited.error())
                );
            }
            ++report.recovered_exited;
            continue;
        }
        auto code = session_failure_code::recovered_without_process;
        if (inspected->has_value()) {
            auto removed = destroy_instance_owned(state_->config, expected_identity);
            if (!removed) {
                report.unresolved_running_session_ids.push_back(candidate.session.session_id);
                continue;
            }
            code = session_failure_code::recovered_terminated;
            ++report.recovered_terminated;
        }
        if (auto removed =
                remove_managed_artifacts(state_->config, candidate.runtime_identity.instance_id);
            !removed) {
            return std::unexpected(removed.error());
        }
        auto failed = state_->registry->mark_managed_failed(
            {
                .schema_version = 1,
                .session_id = candidate.session.session_id,
                .controller_plan_digest = candidate.session.controller_plan_digest,
                .plan_content_digest = candidate.session.plan_content_digest,
                .authorization_id = candidate.authorization_id,
                .profile_digest = candidate.profile_digest,
                .code = code,
            },
            "apple-reconcile." + candidate.session.session_id,
            now_ms
        );
        if (!failed) {
            return std::unexpected(
                registry_error("close recovered Apple Container session", failed.error())
            );
        }
        ++report.recovered_failed;
    }
    if (!report.unresolved_running_session_ids.empty() ||
        !report.identity_mismatch_session_ids.empty()) {
        return std::unexpected(
            std::string{"Apple Container reconciliation left unresolved instance ownership"}
        );
    }
    state_->reconciliation = report;
    return report;
}

auto apple_container_session_runtime::start(
    container::receipt_audit_producer& receipt_producer,
    const session_start_authorization& authorization,
    std::string_view idempotency_namespace,
    std::uint64_t now_ms
) -> std::expected<session_record, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    if (!state_ || !valid_identifier(idempotency_namespace, max_idempotency_namespace_bytes) ||
        now_ms == 0) {
        return std::unexpected(std::string{"invalid Apple Container start request"});
    }
    std::lock_guard start_lock{state_->start_mutex};
    if (!state_->reconciliation) {
        return std::unexpected(
            std::string{"Apple Container runtime requires startup reconciliation"}
        );
    }
    auto reserved = state_->registry->reserve_start(
        authorization, std::string{idempotency_namespace} + ".reserve", now_ms
    );
    if (!reserved) {
        return std::unexpected(registry_error("reserve Apple Container session", reserved.error()));
    }
    auto current = state_->registry->status(authorization.session_id);
    if (!current) {
        return std::unexpected(
            registry_error("read reserved Apple Container session", current.error())
        );
    }
    if (current->state != session_state::preparing) {
        return *current;
    }
    {
        std::lock_guard lock{state_->sessions_mutex};
        if (state_->sessions.contains(authorization.session_id)) {
            return std::unexpected(
                std::string{"Apple Container live-session index is inconsistent"}
            );
        }
        if (state_->sessions.size() >= state_->config.max_sessions) {
            return std::unexpected(std::string{"Apple Container live-session capacity exhausted"});
        }
    }
    auto inputs = state_->registry->resolve_start_inputs(
        authorization.session_id, authorization.authorization_id, now_ms
    );
    if (!inputs) {
        return std::unexpected(
            registry_error("resolve Apple Container start inputs", inputs.error())
        );
    }
    const auto managed_adapter =
        supervisor::native_skill_runtime_adapter_for(inputs->launch.runtime_id);
    const bool managed_closure = state_->config.harness_closure_digest &&
                                 ((managed_adapter && inputs->launch.runtime_id != "codex") ||
                                  inputs->launch.runtime_id == "glove-egress-probe" ||
                                  (inputs->launch.runtime_id == supervisor::sage_guest_runtime_id &&
                                   state_->config.sage_guest));
    const bool online = !inputs->launch.egress_targets.empty();
    const bool sage_guest = inputs->launch.runtime_id == supervisor::sage_guest_runtime_id;
    if (sage_guest &&
        (online || inputs->launch.egress_policy_id != "no-network" ||
         !inputs->launch.secret_mounts.empty() || !inputs->launch.environment.empty() ||
         inputs->launch.argv.size() != 1U || inputs->library_projections.empty() ||
         inputs->adoption ||
         !std::ranges::all_of(inputs->library_projections, [](const auto& projection) {
             return projection.destination_alias == supervisor::sage_bundle_projection_mount;
         }))) {
        return std::unexpected(
            std::string{"Apple Container Sage guest requires fixed read-only bundles without "
                        "arguments, environment, secrets, adoption, or egress"}
        );
    }
    if (inputs->launch.backend != supervisor::sandbox_backend::apple_container ||
        (online ? (!managed_closure || inputs->launch.egress_policy_id == "no-network")
                : inputs->launch.egress_policy_id != "no-network") ||
        !inputs->path_grants.empty() ||
        (!inputs->library_projections.empty() && !managed_closure) ||
        !inputs->launch.read_only_paths.empty() || inputs->launch.argv.empty() ||
        !std::filesystem::path{inputs->launch.argv.front()}.is_absolute() ||
        (!inputs->launch.secret_mounts.empty() && !managed_closure)) {
        return std::unexpected(
            std::string{
                "Apple Container managed launch currently requires an image-contained no-network "
                "closure without host path or library projections"
            }
        );
    }
    auto instance = instance_identity(authorization.session_id);
    if (!instance) {
        return std::unexpected(instance.error());
    }
    auto credential_leases =
        resolve_credential_leases(inputs->launch.secret_mounts, state_->config, *instance);
    if (!credential_leases) {
        return std::unexpected(credential_leases.error());
    }
    auto egress_broker = start_egress_broker(*inputs, state_->config, *instance);
    if (!egress_broker) {
        return std::unexpected(egress_broker.error());
    }
    auto projection_lease =
        resolve_projection_lease(*inputs, state_->config, *instance, managed_adapter);
    if (!projection_lease) {
        return std::unexpected(projection_lease.error());
    }
    auto library_projections =
        projection_receipts(inputs->library_projections, inputs->launch.runtime_id);
    auto profile = profile_digest(
        *inputs, state_->config, credential_leases->commitments_, projection_lease->digest_
    );
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto launch = launch_identity(*instance, state_->config.image_digest, *profile);
    if (!launch) {
        return std::unexpected(launch.error());
    }
    const managed_runtime_recovery_identity runtime_identity{
        .schema_version = 1,
        .backend = "apple_container",
        .instance_id = *instance,
        .launch_identity_digest = *launch,
    };
    const apple_instance_ownership_expectation expected_identity{
        .instance_name = runtime_identity.instance_id,
        .image_digest = state_->config.image_digest,
        .launch_identity_digest = runtime_identity.launch_identity_digest,
    };
    auto existing_container = inspect_instance(state_->config, expected_identity);
    if (!existing_container) {
        return std::unexpected(existing_container.error());
    }
    if (existing_container->has_value()) {
        return std::unexpected(
            std::string{"Apple Container instance identity already exists; reconciliation required"}
        );
    }
    auto reservation = receipt_producer.reserve_terminal(
        authorization.session_id, authorization.controller_plan_digest, *profile
    );
    if (!reservation) {
        return std::unexpected(
            std::string{"reserve Apple Container terminal receipt: "} + reservation.error()
        );
    }
    auto tmpfs_sizes = apple_container_tmpfs_sizes(inputs->launch.limits.disk_bytes);
    if (!tmpfs_sizes) {
        return std::unexpected(tmpfs_sizes.error());
    }
    const auto [temp_bytes, home_bytes] = *tmpfs_sizes;
    constexpr std::uint64_t mebibyte = std::uint64_t{1024} * 1024U;
    if (inputs->launch.limits.cpu_time_ms % 1'000U != 0U ||
        inputs->launch.limits.memory_bytes % mebibyte != 0U) {
        return std::unexpected(
            std::string{"Apple Container CPU and memory limits exceed native granularity"}
        );
    }
    const auto cpu_seconds =
        std::max<std::uint64_t>(1U, (inputs->launch.limits.cpu_time_ms + 999U) / 1'000U);
    std::vector<std::string> create_arguments{
        "create",
        "--name",
        runtime_identity.instance_id,
        "--label",
        "dev.sage.glove.launch-digest=" + runtime_identity.launch_identity_digest,
        "--init",
        "--interactive",
        "--tty",
        "--network",
        "none",
        "--no-dns",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--memory",
        std::to_string(inputs->launch.limits.memory_bytes),
        "--ulimit",
        "cpu=" + std::to_string(cpu_seconds) + ":" + std::to_string(cpu_seconds),
        "--ulimit",
        "nproc=" + std::to_string(inputs->launch.limits.pids) + ":" +
            std::to_string(inputs->launch.limits.pids),
        "--tmpfs",
        "/tmp:size=" + std::to_string(temp_bytes) + ",mode=1777",
        "--tmpfs",
        "/home/agent:size=" + std::to_string(home_bytes) + ",mode=0700",
    };
    if (!managed_closure) {
        create_arguments.push_back("--uid");
        create_arguments.push_back("65534");
        create_arguments.push_back("--gid");
        create_arguments.push_back("65534");
    } else {
        // The fixed image entrypoint uses only these two capabilities to copy
        // owner-only leases into tmpfs and irrevocably drop to the agent UID.
        create_arguments.push_back("--cap-add");
        create_arguments.push_back("SETUID");
        create_arguments.push_back("--cap-add");
        create_arguments.push_back("SETGID");
        create_arguments.push_back("--cap-add");
        create_arguments.push_back("CHOWN");
    }
    for (const auto& credential : credential_leases->commitments_) {
        create_arguments.push_back("--volume");
        create_arguments.push_back(
            (credential_leases->directory_ / credential.handle).string() + ":/run/glove-secrets/" +
            credential.handle + ":ro"
        );
    }
    if (egress_broker->proxy_) {
        create_arguments.push_back("--volume");
        create_arguments.push_back(
            (egress_broker->directory_ / "s").string() + ":/run/glove-services/egress.sock"
        );
        create_arguments.push_back("--env");
        create_arguments.push_back("GLOVE_EGRESS_PROXY_URL=" + egress_broker->proxy_->proxy_url());
    }
    if (projection_lease->digest_) {
        create_arguments.push_back("--volume");
        create_arguments.push_back(
            (projection_lease->directory_ / projection_lease->mount_name_).string() +
            ":/run/glove-projections/" + projection_lease->mount_name_ + ":ro"
        );
    }
    for (const auto& environment : inputs->launch.environment) {
        create_arguments.push_back("--env");
        create_arguments.push_back(environment);
    }
    create_arguments.push_back("--env");
    create_arguments.push_back(managed_closure ? "HOME=/home/agent" : "HOME=/tmp");
    create_arguments.push_back(state_->config.image_reference);
    if (managed_closure) {
        create_arguments.push_back(inputs->launch.runtime_id);
        for (const auto& credential : credential_leases->commitments_) {
            create_arguments.push_back("--secret");
            create_arguments.push_back("/run/glove-secrets/" + credential.handle);
            create_arguments.push_back(credential.target_path);
        }
        create_arguments.push_back("--");
        create_arguments.insert(
            create_arguments.end(),
            std::next(inputs->launch.argv.begin()),
            inputs->launch.argv.end()
        );
    } else {
        create_arguments.insert(
            create_arguments.end(), inputs->launch.argv.begin(), inputs->launch.argv.end()
        );
    }
    auto created = run_command(state_->config.container_cli, create_arguments);
    if (!created || created->exit_code != 0) {
        auto inspected_after_failure = inspect_instance(state_->config, expected_identity);
        std::string cleanup_error;
        if (!inspected_after_failure) {
            credential_leases->preserve();
            egress_broker->preserve();
            projection_lease->preserve();
            cleanup_error =
                "; partial create state could not be inspected: " + inspected_after_failure.error();
        } else if (inspected_after_failure->has_value()) {
            auto removed = delete_instance_owned(state_->config, expected_identity);
            if (!removed) {
                credential_leases->preserve();
                egress_broker->preserve();
                projection_lease->preserve();
                cleanup_error = "; " + removed.error();
            }
        }
        return std::unexpected(
            (created ? std::string{"create Apple Container session: "} + created->standard_output
                     : created.error()) +
            cleanup_error
        );
    }
    const auto remove_created_instance = [&]() -> std::optional<std::string> {
        auto removed = delete_instance_owned(state_->config, expected_identity);
        if (!removed) {
            credential_leases->preserve();
            egress_broker->preserve();
            projection_lease->preserve();
            return removed.error();
        }
        return std::nullopt;
    };
    auto inspected = inspect_instance(state_->config, expected_identity);
    if (!inspected || !inspected->has_value()) {
        auto cleanup_error = remove_created_instance();
        return std::unexpected(
            std::string{"created Apple Container identity proof mismatch"} +
            (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    const managed_session_execution_binding binding{
        .schema_version = 1,
        .session_id = authorization.session_id,
        .controller_plan_digest = authorization.controller_plan_digest,
        .plan_content_digest = authorization.plan_content_digest,
        .authorization_id = authorization.authorization_id,
        .profile_digest = *profile,
        .runtime_identity = runtime_identity,
    };
    auto starting = state_->registry->mark_managed_starting(
        binding, *reservation, std::string{idempotency_namespace} + ".starting", now_ms
    );
    if (!starting) {
        auto cleanup_error = remove_created_instance();
        return std::unexpected(
            registry_error("persist Apple Container starting state", starting.error()) +
            (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    const auto close_starting_failure = [&](std::string message) {
        auto failed = state_->registry->mark_managed_failed(
            {
                .schema_version = 1,
                .session_id = binding.session_id,
                .controller_plan_digest = binding.controller_plan_digest,
                .plan_content_digest = binding.plan_content_digest,
                .authorization_id = binding.authorization_id,
                .profile_digest = binding.profile_digest,
                .code = session_failure_code::launch_failed,
            },
            std::string{idempotency_namespace} + ".failed",
            std::max(current_epoch_ms(), now_ms)
        );
        if (!failed) {
            message += "; failed to close registry: " + failed.error().message;
        }
        return std::unexpected(std::move(message));
    };
    auto attach_owner = std::make_shared<std::atomic<::pid_t>>(-1);
    auto monitor = container::detail::wall_output_monitor::create(
        inputs->launch.limits.wall_time_ms,
        inputs->launch.limits.terminal_output_bytes,
        [attach_owner](container::resource_termination_cause) {
            const auto attach_pid = attach_owner->load();
            if (attach_pid > 1) {
                static_cast<void>(::killpg(attach_pid, SIGTERM));
            }
        }
    );
    if (!monitor) {
        auto cleanup_error = remove_created_instance();
        return close_starting_failure(
            monitor.error() + (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    auto attached = spawn_attach(state_->config, runtime_identity.instance_id, *monitor);
    if (!attached) {
        auto cleanup_error = remove_created_instance();
        return close_starting_failure(
            attached.error() + (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    const auto attach_pid = attached->first;
    attach_owner->store(attach_pid);
    std::optional<container::resource_usage> initial_resource_usage;
    std::string resource_sample_error;
    const auto sample_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (!initial_resource_usage && std::chrono::steady_clock::now() < sample_deadline) {
        auto sample = sample_resource_usage(
            state_->config, runtime_identity.instance_id, inputs->launch.limits.memory_bytes
        );
        if (sample) {
            initial_resource_usage = *sample;
            break;
        }
        resource_sample_error = sample.error();
        std::this_thread::sleep_for(stats_sample_interval);
    }
    if (!initial_resource_usage) {
        static_cast<void>(::killpg(attach_pid, SIGKILL));
        static_cast<void>(::waitpid(attach_pid, nullptr, 0));
        auto cleanup_error = remove_created_instance();
        return close_starting_failure(
            resource_sample_error + (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    const managed_session_running_commitment running{
        .schema_version = 1,
        .session_id = binding.session_id,
        .controller_plan_digest = binding.controller_plan_digest,
        .plan_content_digest = binding.plan_content_digest,
        .authorization_id = binding.authorization_id,
        .profile_digest = binding.profile_digest,
        .runtime_identity = binding.runtime_identity,
    };
    auto running_record = state_->registry->mark_managed_running(
        running,
        *reservation,
        std::string{idempotency_namespace} + ".running",
        std::max(current_epoch_ms(), now_ms)
    );
    if (!running_record) {
        static_cast<void>(::killpg(attach_pid, SIGKILL));
        static_cast<void>(::waitpid(attach_pid, nullptr, 0));
        auto cleanup_error = remove_created_instance();
        return close_starting_failure(
            registry_error("persist Apple Container running state", running_record.error()) +
            (cleanup_error ? "; " + *cleanup_error : "")
        );
    }
    auto session = std::make_shared<apple_live_session>(
        *state_->registry,
        receipt_producer,
        std::move(*reservation),
        running,
        session_failure_commitment{
            .schema_version = 1,
            .session_id = binding.session_id,
            .controller_plan_digest = binding.controller_plan_digest,
            .plan_content_digest = binding.plan_content_digest,
            .authorization_id = binding.authorization_id,
            .profile_digest = binding.profile_digest,
            .code = session_failure_code::supervisor_error,
        },
        state_->config,
        std::move(attached->second),
        std::move(*monitor),
        attach_pid,
        inputs->launch.limits,
        *initial_resource_usage,
        starting->starting_at_ms,
        std::string{idempotency_namespace},
        std::move(*credential_leases),
        std::move(*egress_broker),
        std::move(*projection_lease),
        std::move(library_projections)
    );
    if (auto finalizer = session->start_finalizer(); !finalizer) {
        static_cast<void>(session->stop(std::string{idempotency_namespace} + ".finalizer-stop"));
        static_cast<void>(::waitpid(attach_pid, nullptr, 0));
        auto removed = delete_instance_owned(state_->config, expected_identity);
        if (!removed) {
            session->preserve_credential_leases();
            session->preserve_egress_lease();
            session->preserve_projection_lease();
        }
        auto failed = state_->registry->mark_managed_failed(
            {
                .schema_version = 1,
                .session_id = binding.session_id,
                .controller_plan_digest = binding.controller_plan_digest,
                .plan_content_digest = binding.plan_content_digest,
                .authorization_id = binding.authorization_id,
                .profile_digest = binding.profile_digest,
                .code = session_failure_code::supervisor_error,
            },
            std::string{idempotency_namespace} + ".failed",
            std::max(current_epoch_ms(), now_ms)
        );
        if (!failed) {
            return std::unexpected(
                finalizer.error() + (removed ? "" : "; " + removed.error()) +
                "; failed to close registry: " + failed.error().message
            );
        }
        return std::unexpected(finalizer.error() + (removed ? "" : "; " + removed.error()));
    }
    {
        std::lock_guard lock{state_->sessions_mutex};
        state_->sessions.emplace(authorization.session_id, session);
    }
    return running_record->session;
}

auto apple_container_session_runtime::list() const
    -> std::expected<std::vector<std::string>, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    if (!state_) {
        return std::unexpected(std::string{"Apple Container runtime is empty"});
    }
    std::lock_guard lock{state_->sessions_mutex};
    std::vector<std::string> result;
    result.reserve(state_->sessions.size());
    for (const auto& [session_id, session] : state_->sessions) {
        result.push_back(session_id);
    }
    return result;
}

auto apple_container_session_runtime::read(
    std::string_view session_id, std::uint64_t cursor, std::size_t max_bytes
) const -> std::expected<session_transcript_read, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->read(cursor, max_bytes)
                   : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::wait_read(
    std::string_view session_id,
    std::uint64_t cursor,
    std::size_t max_bytes,
    std::uint64_t timeout_ms
) -> std::expected<session_transcript_read, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->wait_read(cursor, max_bytes, timeout_ms)
                   : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::write_input(
    std::string_view session_id, std::string_view bytes
) -> std::expected<void, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->write_input(bytes) : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::resize(
    std::string_view session_id, std::uint16_t rows, std::uint16_t columns
) -> std::expected<void, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->resize(rows, columns)
                   : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::signal(std::string_view session_id, session_signal requested)
    -> std::expected<void, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->signal(requested) : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::stop([[maybe_unused]] std::string_view session_id)
    -> std::expected<void, std::string> {
    return std::unexpected(std::string{lifecycle_unavailable_error});
}

auto apple_container_session_runtime::stop(
    std::string_view session_id, std::string_view idempotency_key
) -> std::expected<void, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->stop(idempotency_key)
                   : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::wait(std::string_view session_id)
    -> std::expected<session_terminal_record, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    auto session = lookup(*state_, session_id);
    return session ? (*session)->wait() : std::unexpected(std::move(session.error()));
}

auto apple_container_session_runtime::cleanup(std::string_view session_id)
    -> std::expected<void, std::string> {
    if (!lifecycle_operational()) {
        return std::unexpected(std::string{lifecycle_unavailable_error});
    }
    if (!state_ || !valid_identifier(session_id)) {
        return std::unexpected(std::string{"invalid Apple Container cleanup request"});
    }
    std::lock_guard lock{state_->sessions_mutex};
    const auto found = state_->sessions.find(session_id);
    if (found == state_->sessions.end()) {
        return std::unexpected(std::string{"Apple Container session is not live"});
    }
    if (!found->second->finished()) {
        return std::unexpected(
            std::string{"Apple Container session has not reached terminal state"}
        );
    }
    auto durable = state_->registry->managed_lifecycle_status(session_id);
    if (!durable || (durable->session.state != session_state::exited &&
                     durable->session.state != session_state::failed)) {
        return std::unexpected(
            std::string{"Apple Container session requires durable recovery before cleanup"}
        );
    }
    state_->sessions.erase(found);
    return {};
}

} // namespace glove::control::apple_detail
