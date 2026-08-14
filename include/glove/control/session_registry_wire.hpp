#pragma once

#include "glove/control/session_registry.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control::wire {

// Wire representation of a persisted session registry record. This must stay
// byte-for-byte stable with the on-disk registry format.
struct persisted_session {
    std::uint8_t schema_version = 0;
    std::uint64_t sequence = 0;
    std::string operation;
    std::string idempotency_key;
    std::string session_id;
    std::string controller_plan_digest;
    std::string request_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::string authorization_id;
    std::uint64_t authorized_at_ms = 0;
    std::uint64_t authorization_expires_at_ms = 0;
    std::string launch_profile_digest;
    std::uint64_t starting_at_ms = 0;
    std::uint64_t running_at_ms = 0;
    std::uint64_t stopping_at_ms = 0;
    std::uint8_t process_identity_schema_version = 0;
    std::uint32_t process_pid = 0;
    std::string process_boot_id;
    std::uint64_t process_start_time_ticks = 0;
    std::uint64_t process_cgroup_device = 0;
    std::uint64_t process_cgroup_inode = 0;
    std::string process_cgroup_path_digest;
    std::optional<linux_cgroup_recovery_identity> cgroup_identity;
    std::optional<linux_filesystem_recovery_identity> filesystem_identity;
    std::optional<managed_runtime_recovery_identity> managed_runtime_identity;
    std::string failure_code;
    std::uint64_t finished_at_ms = 0;
    std::uint64_t receipt_started_at_ms = 0;
    std::string receipt_key_id;
    std::uint64_t receipt_sequence = 0;
    std::string receipt_digest;
    std::string receipt_previous_hmac;
    std::string receipt_hmac;
    std::string termination_cause;
    std::optional<int> exit_code;
    std::string canonical_plan_json;
    std::string previous_hash;
    std::string this_hash;
};

struct plan_runtime_header {
    std::string runtime_template_id;
};

// Low-level wire codec primitives.
auto append_u32(std::vector<unsigned char>& output, std::uint32_t value) -> void;
auto append_u64(std::vector<unsigned char>& output, std::uint64_t value) -> void;
auto append_string(std::vector<unsigned char>& output, std::string_view value) -> bool;
auto append_filesystem_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_filesystem_recovery_identity>& identity
) -> std::expected<void, std::string>;
auto append_cgroup_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_cgroup_recovery_identity>& identity
) -> void;
auto append_managed_runtime_identity(
    std::vector<unsigned char>& output,
    const std::optional<managed_runtime_recovery_identity>& identity
) -> std::expected<void, std::string>;
auto decode_u32(std::span<const unsigned char, 4> input) noexcept -> std::uint32_t;

} // namespace glove::control::wire
