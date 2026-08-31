#pragma once

#include "glove/container/profile.hpp"

#include <sys/types.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace glove::container::linux_detail {

enum class linux_session_prerequisite : std::uint8_t {
    available,
    user_namespace_unavailable,
    cgroup_v2_unavailable,
    cgroup_controllers_unavailable,
    cgroup_delegation_unavailable,
};

// Read-only host probe for tests and diagnostics. Only a returned unavailable
// state is suitable for an environment skip; probe errors remain failures.
[[nodiscard]] auto probe_linux_session_prerequisite()
    -> std::expected<linux_session_prerequisite, std::string>;

struct cgroup_observation {
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t peak_memory_bytes = 0;
    std::uint32_t peak_pids = 0;
    bool memory_limit_hit = false;
    bool pid_limit_hit = false;
};

enum class cgroup_limit_event : std::uint8_t {
    cpu_time,
    memory,
    pids,
};

using cgroup_limit_result = std::expected<std::optional<cgroup_limit_event>, std::string>;

class cgroup_v2_session {
public:
    cgroup_v2_session() = default;
    cgroup_v2_session(const cgroup_v2_session&) = delete;
    auto operator=(const cgroup_v2_session&) -> cgroup_v2_session& = delete;
    cgroup_v2_session(cgroup_v2_session&& other) noexcept;
    auto operator=(cgroup_v2_session&& other) -> cgroup_v2_session& = delete;
    ~cgroup_v2_session();

    [[nodiscard]] auto directory_fd() const noexcept -> int { return directory_fd_; }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

    [[nodiscard]] auto attach(::pid_t pid) const -> std::expected<void, std::string>;
    [[nodiscard]] auto observe() const -> std::expected<cgroup_observation, std::string>;
    [[nodiscard]] cgroup_limit_result triggered_limit(const resource_limits& limits) const;
    [[nodiscard]] auto kill_all() const -> std::expected<void, std::string>;
    auto cleanup() -> std::expected<void, std::string>;

private:
    friend class cgroup_v2_root;

    cgroup_v2_session(
        int parent_fd, int directory_fd, std::filesystem::path path, std::string directory_name
    );

    void close_descriptors() noexcept;

    int parent_fd_ = -1;
    int directory_fd_ = -1;
    std::filesystem::path path_;
    std::string directory_name_;
};

using cgroup_session_result = std::expected<cgroup_v2_session, std::string>;

class cgroup_v2_root {
public:
    cgroup_v2_root() = default;
    cgroup_v2_root(const cgroup_v2_root&) = delete;
    auto operator=(const cgroup_v2_root&) -> cgroup_v2_root& = delete;
    cgroup_v2_root(cgroup_v2_root&& other) noexcept;
    auto operator=(cgroup_v2_root&& other) -> cgroup_v2_root& = delete;
    ~cgroup_v2_root();

    static auto prepare_for_current_process() -> std::expected<cgroup_v2_root, std::string>;

    [[nodiscard]] cgroup_session_result
    create_session(std::string_view session_id, const resource_limits& limits) const;

    // Reopens an abandoned deterministic session directory only when its
    // kernel identity matches the durable process commitment. The caller must
    // still prove the complete process identity before signaling members.
    [[nodiscard]] cgroup_session_result adopt_session(
        std::string_view session_id, std::uint64_t expected_device, std::uint64_t expected_inode
    ) const;

    [[nodiscard]] auto cleanup_session_if_matches(
        std::string_view session_id, std::uint64_t expected_device, std::uint64_t expected_inode
    ) const -> std::expected<void, std::string>;

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    cgroup_v2_root(
        int directory_fd,
        std::filesystem::path path,
        std::string host_leaf_name,
        bool enabled_controllers
    );

    void release();

    int directory_fd_ = -1;
    std::filesystem::path path_;
    std::string host_leaf_name_;
    bool enabled_controllers_ = false;
};

} // namespace glove::container::linux_detail
