#include "glove/control/session_registry_wire.hpp"

#include <limits>

namespace glove::control::wire {

auto append_u32(std::vector<unsigned char>& output, std::uint32_t value) -> void {
    output.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

auto append_u64(std::vector<unsigned char>& output, std::uint64_t value) -> void {
    output.push_back(static_cast<unsigned char>((value >> 56U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 48U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 40U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 32U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

auto append_string(std::vector<unsigned char>& output, std::string_view value) -> bool {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return true;
}

auto append_filesystem_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_filesystem_recovery_identity>& identity
) -> std::expected<void, std::string> {
    output.push_back(identity.has_value() ? 1U : 0U);
    if (!identity) {
        return {};
    }
    output.push_back(identity->schema_version);
    append_u64(output, identity->disk_limit_bytes);
    append_u32(output, static_cast<std::uint32_t>(identity->partitions.size()));
    for (const auto& partition : identity->partitions) {
        if (!append_string(output, partition.alias)) {
            return std::unexpected(std::string{"filesystem recovery alias exceeds its hash bound"});
        }
        append_u64(output, partition.quota_bytes);
    }
    return {};
}

auto append_cgroup_identity(
    std::vector<unsigned char>& output,
    const std::optional<linux_cgroup_recovery_identity>& identity
) -> void {
    output.push_back(identity.has_value() ? 1U : 0U);
    if (!identity) {
        return;
    }
    output.push_back(identity->schema_version);
    append_u64(output, identity->device);
    append_u64(output, identity->inode);
}

auto append_managed_runtime_identity(
    std::vector<unsigned char>& output,
    const std::optional<managed_runtime_recovery_identity>& identity
) -> std::expected<void, std::string> {
    if (!identity) {
        return {};
    }
    constexpr std::string_view extension_domain = "glove.managed-runtime-identity.v1";
    output.push_back(1U);
    if (!append_string(output, extension_domain)) {
        return std::unexpected(std::string{"managed runtime hash domain is invalid"});
    }
    output.push_back(identity->schema_version);
    for (const auto value : {
             std::string_view{identity->backend},
             std::string_view{identity->instance_id},
             std::string_view{identity->launch_identity_digest},
         }) {
        if (!append_string(output, value)) {
            return std::unexpected(std::string{"managed runtime identity exceeds its hash bound"});
        }
    }
    return {};
}

auto decode_u32(std::span<const unsigned char, 4> input) noexcept -> std::uint32_t {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) | static_cast<std::uint32_t>(input[3]);
}

} // namespace glove::control::wire
