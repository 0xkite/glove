#include "glove/control/session_registry_wire.hpp"

#include "glove/container/digest.hpp"

#include <bit>
#include <limits>

namespace glove::control::wire {

namespace {

auto disposition_name(intent_disposition disposition) noexcept -> std::string_view {
    switch (disposition) {
    case intent_disposition::pending:
        return "pending";
    case intent_disposition::accepted:
        return "accepted";
    case intent_disposition::rejected:
        return "rejected";
    case intent_disposition::expired:
        return "expired";
    }
    return {};
}

} // namespace

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

auto record_material(const persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string> {
    std::vector<unsigned char> material;
    material.reserve(record.canonical_plan_json.size() + 512U);
    constexpr std::string_view domain = "glove.session-registry.record";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"session registry hash domain is invalid"});
    }
    material.push_back(record.schema_version);
    append_u64(material, record.sequence);
    for (const auto value : {
             std::string_view{record.operation},
             std::string_view{record.idempotency_key},
             std::string_view{record.session_id},
             std::string_view{record.controller_plan_digest},
             std::string_view{record.request_digest},
             std::string_view{record.plan_content_digest},
             std::string_view{record.state},
             std::string_view{record.authorization_id},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"session registry hash field exceeds its bound"});
        }
    }
    append_u64(material, record.policy_revision);
    append_u64(material, record.expires_at_ms);
    append_u64(material, record.created_at_ms);
    append_u64(material, record.authorized_at_ms);
    append_u64(material, record.authorization_expires_at_ms);
    if (record.state == "starting" || record.state == "running" || record.state == "stopping" ||
        record.state == "exited" || record.state == "failed") {
        if (!append_string(material, record.launch_profile_digest)) {
            return std::unexpected(
                std::string{"session registry launch profile exceeds its hash bound"}
            );
        }
        append_u64(material, record.starting_at_ms);
        append_cgroup_identity(material, record.cgroup_identity);
        if (auto appended = append_filesystem_identity(material, record.filesystem_identity);
            !appended) {
            return std::unexpected(appended.error());
        }
        if (auto appended =
                append_managed_runtime_identity(material, record.managed_runtime_identity);
            !appended) {
            return std::unexpected(appended.error());
        }
    }
    if (record.state == "running" || record.state == "stopping" || record.state == "exited" ||
        record.state == "failed") {
        append_u64(material, record.running_at_ms);
        material.push_back(record.process_identity_schema_version);
        append_u32(material, record.process_pid);
        if (!append_string(material, record.process_boot_id)) {
            return std::unexpected(
                std::string{"session registry process boot identity exceeds its hash bound"}
            );
        }
        append_u64(material, record.process_start_time_ticks);
        append_u64(material, record.process_cgroup_device);
        append_u64(material, record.process_cgroup_inode);
        if (!append_string(material, record.process_cgroup_path_digest)) {
            return std::unexpected(
                std::string{"session registry process cgroup identity exceeds its hash bound"}
            );
        }
    }
    if (record.state == "stopping" || record.state == "exited" || record.state == "failed") {
        append_u64(material, record.stopping_at_ms);
    }
    if (record.state == "failed") {
        if (!append_string(material, record.failure_code)) {
            return std::unexpected(
                std::string{"session registry failure code exceeds its hash bound"}
            );
        }
        append_u64(material, record.finished_at_ms);
    }
    if (record.state == "exited") {
        for (const auto value : {
                 std::string_view{record.receipt_key_id},
                 std::string_view{record.receipt_digest},
                 std::string_view{record.receipt_previous_hmac},
                 std::string_view{record.receipt_hmac},
                 std::string_view{record.termination_cause},
             }) {
            if (!append_string(material, value)) {
                return std::unexpected(
                    std::string{"session registry terminal field exceeds its hash bound"}
                );
            }
        }
        append_u64(material, record.receipt_sequence);
        append_u64(material, record.receipt_started_at_ms);
        append_u64(material, record.finished_at_ms);
        material.push_back(record.exit_code.has_value() ? 1U : 0U);
        if (record.exit_code) {
            append_u32(material, static_cast<std::uint32_t>(*record.exit_code));
        }
    }
    if (record.observation_intent) {
        constexpr std::string_view extension_domain =
            "glove.session-registry.observation-intent.v1";
        if (!append_string(material, extension_domain)) {
            return std::unexpected(std::string{"observation intent hash domain is invalid"});
        }
        const auto& intent = *record.observation_intent;
        material.push_back(intent.schema_version);
        for (const auto value : {
                 std::string_view{intent.schema},
                 std::string_view{intent.intent_id},
                 std::string_view{intent.observation},
                 std::string_view{intent.value_digest},
                 std::string_view{intent.intent_digest},
                 std::string_view{intent.profile_digest},
                 std::string_view{intent.runtime_id},
                 std::string_view{intent.projection_digest},
                 std::string_view{intent.channel_id},
                 std::string_view{intent.disposition},
             }) {
            if (!append_string(material, value)) {
                return std::unexpected(
                    std::string{"session registry observation intent exceeds its hash bound"}
                );
            }
        }
        append_u64(material, intent.item_count);
        append_u64(material, intent.channel_generation);
        append_u64(material, intent.issued_at_ms);
        append_u64(material, intent.expires_at_ms);
        append_u64(material, intent.decided_at_ms);
    }
    if (!append_string(material, record.canonical_plan_json) ||
        !append_string(material, record.previous_hash)) {
        return std::unexpected(std::string{"session registry plan exceeds its hash bound"});
    }
    return material;
}

auto hash_record(const persisted_session& record) -> std::expected<std::string, std::string> {
    auto material = record_material(record);
    if (!material) {
        return std::unexpected(material.error());
    }
    return container::sha256_hex(*material);
}

auto hash_plan(std::string_view plan) -> std::expected<std::string, std::string> {
    return container::sha256_hex(
        std::span<const unsigned char>{
            std::bit_cast<const unsigned char*>(plan.data()), plan.size()
        }
    );
}

auto hash_start_authorization(const session_start_authorization& authorization)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-start-authorization";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"start authorization hash domain is invalid"});
    }
    material.push_back(authorization.schema_version);
    for (const auto value : {
             std::string_view{authorization.authorization_id},
             std::string_view{authorization.session_id},
             std::string_view{authorization.controller_plan_digest},
             std::string_view{authorization.plan_content_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"start authorization field exceeds its bound"});
        }
    }
    append_u64(material, authorization.approved_at_ms);
    append_u64(material, authorization.expires_at_ms);
    return container::sha256_hex(material);
}

auto hash_execution_binding(const session_execution_binding& binding)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-execution-binding";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"execution binding hash domain is invalid"});
    }
    material.push_back(binding.schema_version);
    for (const auto value : {
             std::string_view{binding.session_id},
             std::string_view{binding.controller_plan_digest},
             std::string_view{binding.plan_content_digest},
             std::string_view{binding.authorization_id},
             std::string_view{binding.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"execution binding field exceeds its bound"});
        }
    }
    append_cgroup_identity(material, binding.cgroup_identity);
    if (auto appended = append_filesystem_identity(material, binding.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_running_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-running-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"running commitment hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"running commitment field exceeds its bound"});
        }
    }
    material.push_back(running.process_identity.schema_version);
    append_u32(material, running.process_identity.pid);
    if (!append_string(material, running.process_identity.boot_id)) {
        return std::unexpected(std::string{"running process boot identity exceeds its bound"});
    }
    append_u64(material, running.process_identity.start_time_ticks);
    append_u64(material, running.process_identity.cgroup_device);
    append_u64(material, running.process_identity.cgroup_inode);
    if (!append_string(material, running.process_identity.cgroup_path_digest)) {
        return std::unexpected(std::string{"running process cgroup identity exceeds its bound"});
    }
    if (auto appended = append_filesystem_identity(material, running.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_stopping_commitment(const session_running_commitment& running)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-stopping-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"stopping commitment hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"stopping commitment field exceeds its bound"});
        }
    }
    material.push_back(running.process_identity.schema_version);
    append_u32(material, running.process_identity.pid);
    if (!append_string(material, running.process_identity.boot_id)) {
        return std::unexpected(std::string{"stopping process boot identity exceeds its bound"});
    }
    append_u64(material, running.process_identity.start_time_ticks);
    append_u64(material, running.process_identity.cgroup_device);
    append_u64(material, running.process_identity.cgroup_inode);
    if (!append_string(material, running.process_identity.cgroup_path_digest)) {
        return std::unexpected(std::string{"stopping process cgroup identity exceeds its bound"});
    }
    if (auto appended = append_filesystem_identity(material, running.filesystem_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_managed_execution_binding(const managed_session_execution_binding& binding)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.managed-session-execution-binding";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"managed execution binding hash domain is invalid"});
    }
    material.push_back(binding.schema_version);
    for (const auto value : {
             std::string_view{binding.session_id},
             std::string_view{binding.controller_plan_digest},
             std::string_view{binding.plan_content_digest},
             std::string_view{binding.authorization_id},
             std::string_view{binding.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(
                std::string{"managed execution binding field exceeds its bound"}
            );
        }
    }
    if (auto appended = append_managed_runtime_identity(material, binding.runtime_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto hash_managed_running_commitment(
    const managed_session_running_commitment& running, std::string_view domain
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"managed lifecycle hash domain is invalid"});
    }
    material.push_back(running.schema_version);
    for (const auto value : {
             std::string_view{running.session_id},
             std::string_view{running.controller_plan_digest},
             std::string_view{running.plan_content_digest},
             std::string_view{running.authorization_id},
             std::string_view{running.profile_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"managed lifecycle field exceeds its bound"});
        }
    }
    if (auto appended = append_managed_runtime_identity(material, running.runtime_identity);
        !appended) {
        return std::unexpected(appended.error());
    }
    return container::sha256_hex(material);
}

auto termination_cause_name(container::resource_termination_cause cause) -> std::string_view {
    switch (cause) {
    case container::resource_termination_cause::exited:
        return "exited";
    case container::resource_termination_cause::signaled:
        return "signaled";
    case container::resource_termination_cause::cpu_time_limit:
        return "cpu_time_limit";
    case container::resource_termination_cause::memory_limit:
        return "memory_limit";
    case container::resource_termination_cause::pid_limit:
        return "pid_limit";
    case container::resource_termination_cause::wall_time_limit:
        return "wall_time_limit";
    case container::resource_termination_cause::disk_limit:
        return "disk_limit";
    case container::resource_termination_cause::terminal_output_limit:
        return "terminal_output_limit";
    case container::resource_termination_cause::supervisor_error:
        return "supervisor_error";
    }
    return {};
}

auto termination_cause_from_wire(std::string_view value)
    -> std::optional<container::resource_termination_cause> {
    using cause = container::resource_termination_cause;
    if (value == "exited") {
        return cause::exited;
    }
    if (value == "signaled") {
        return cause::signaled;
    }
    if (value == "cpu_time_limit") {
        return cause::cpu_time_limit;
    }
    if (value == "memory_limit") {
        return cause::memory_limit;
    }
    if (value == "pid_limit") {
        return cause::pid_limit;
    }
    if (value == "wall_time_limit") {
        return cause::wall_time_limit;
    }
    if (value == "disk_limit") {
        return cause::disk_limit;
    }
    if (value == "terminal_output_limit") {
        return cause::terminal_output_limit;
    }
    if (value == "supervisor_error") {
        return cause::supervisor_error;
    }
    return std::nullopt;
}

auto hash_terminal_reference(const terminal_reference& terminal)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(768U);
    constexpr std::string_view domain = "glove.session-terminal-envelope";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"terminal envelope hash domain is invalid"});
    }
    material.push_back(terminal.schema_version);
    append_u64(material, terminal.sequence);
    for (const auto value : {
             terminal.key_id,
             terminal.session_id,
             terminal.controller_plan_digest,
             terminal.profile_digest,
             terminal.receipt_digest,
             terminal.previous_hmac,
             terminal.this_hmac,
             termination_cause_name(terminal.termination_cause),
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"terminal envelope hash field exceeds its bound"});
        }
    }
    append_u64(material, terminal.started_at_ms);
    append_u64(material, terminal.finished_at_ms);
    material.push_back(terminal.exit_code.has_value() ? 1U : 0U);
    if (terminal.exit_code) {
        append_u32(material, static_cast<std::uint32_t>(*terminal.exit_code));
    }
    return container::sha256_hex(material);
}

auto hash_terminal_envelope(const container::authenticated_resource_enforcement_receipt& terminal)
    -> std::expected<std::string, std::string> {
    return hash_terminal_reference(
        terminal_reference{
            .schema_version = terminal.schema_version,
            .sequence = terminal.sequence,
            .key_id = terminal.key_id,
            .session_id = terminal.session_id,
            .controller_plan_digest = terminal.controller_plan_digest,
            .profile_digest = terminal.receipt.profile_digest,
            .receipt_digest = terminal.receipt_digest,
            .previous_hmac = terminal.previous_hmac,
            .this_hmac = terminal.this_hmac,
            .termination_cause = terminal.receipt.termination_cause,
            .started_at_ms = terminal.receipt.started_at_ms,
            .finished_at_ms = terminal.receipt.finished_at_ms,
            .exit_code = terminal.receipt.exit_code,
        }
    );
}

auto hash_terminal_envelope(const container::authenticated_refinement_evaluation_receipt& terminal)
    -> std::expected<std::string, std::string> {
    return hash_terminal_reference(
        terminal_reference{
            .schema_version = terminal.schema_version,
            .sequence = terminal.sequence,
            .key_id = terminal.key_id,
            .session_id = terminal.session_id,
            .controller_plan_digest = terminal.controller_plan_digest,
            .profile_digest = terminal.receipt.resource_receipt.profile_digest,
            .receipt_digest = terminal.receipt_digest,
            .previous_hmac = terminal.previous_hmac,
            .this_hmac = terminal.this_hmac,
            .termination_cause = terminal.receipt.resource_receipt.termination_cause,
            .started_at_ms = terminal.receipt.resource_receipt.started_at_ms,
            .finished_at_ms = terminal.receipt.resource_receipt.finished_at_ms,
            .exit_code = terminal.receipt.resource_receipt.exit_code,
        }
    );
}

auto failure_code_name(session_failure_code code) -> std::string_view {
    switch (code) {
    case session_failure_code::authorization_expired:
        return "authorization_expired";
    case session_failure_code::launch_failed:
        return "launch_failed";
    case session_failure_code::supervisor_error:
        return "supervisor_error";
    case session_failure_code::recovered_without_process:
        return "recovered_without_process";
    case session_failure_code::recovered_terminated:
        return "recovered_terminated";
    }
    return "supervisor_error";
}

auto failure_code_from_wire(std::string_view value) -> std::optional<session_failure_code> {
    if (value == "authorization_expired") {
        return session_failure_code::authorization_expired;
    }
    if (value == "launch_failed") {
        return session_failure_code::launch_failed;
    }
    if (value == "supervisor_error") {
        return session_failure_code::supervisor_error;
    }
    if (value == "recovered_without_process") {
        return session_failure_code::recovered_without_process;
    }
    if (value == "recovered_terminated") {
        return session_failure_code::recovered_terminated;
    }
    return std::nullopt;
}

auto hash_failure_commitment(const session_failure_commitment& failure)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.session-failure-commitment";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"failure commitment hash domain is invalid"});
    }
    material.push_back(failure.schema_version);
    for (const auto value : {
             std::string_view{failure.session_id},
             std::string_view{failure.controller_plan_digest},
             std::string_view{failure.plan_content_digest},
             std::string_view{failure.authorization_id},
             std::string_view{failure.profile_digest},
             failure_code_name(failure.code),
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"failure commitment field exceeds its bound"});
        }
    }
    return container::sha256_hex(material);
}

auto hash_observation_intent_body(const glove_observation_body& body)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    // Opaque, harness-neutral hash domain for observation body commitments.
    constexpr std::string_view domain = "glove.observation-body.v1";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"observation intent hash domain is invalid"});
    }
    for (const auto value : {
             std::string_view{body.schema},
             std::string_view{body.intent_id},
             std::string_view{body.observation},
             std::string_view{body.value_digest},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"observation intent field exceeds its hash bound"});
        }
    }
    append_u64(material, body.item_count);
    return container::sha256_hex(material);
}

auto hash_observation_intent_request(
    const glove_observation_body& body, const observation_intent_context& context
) -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(768U);
    constexpr std::string_view domain = "glove.observation-intent-enqueue.v1";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"observation enqueue hash domain is invalid"});
    }
    for (const auto value : {
             std::string_view{body.schema},
             std::string_view{body.intent_id},
             std::string_view{body.observation},
             std::string_view{body.value_digest},
             std::string_view{context.session_id},
             std::string_view{context.controller_plan_digest},
             std::string_view{context.profile_digest},
             std::string_view{context.runtime_id},
             std::string_view{context.projection_digest},
             std::string_view{context.channel_id},
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(std::string{"observation enqueue field exceeds its hash bound"});
        }
    }
    append_u64(material, body.item_count);
    append_u64(material, context.policy_revision);
    append_u64(material, context.channel_generation);
    append_u64(material, context.issued_at_ms);
    append_u64(material, context.expires_at_ms);
    return container::sha256_hex(material);
}

auto hash_observation_intent_disposition(const observation_intent_disposition& disposition)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    material.reserve(512U);
    constexpr std::string_view domain = "glove.observation-intent-disposition.v1";
    if (!append_string(material, domain)) {
        return std::unexpected(std::string{"observation disposition hash domain is invalid"});
    }
    for (const auto value : {
             std::string_view{disposition.session_id},
             std::string_view{disposition.intent_id},
             std::string_view{disposition.intent_digest},
             disposition_name(disposition.disposition),
         }) {
        if (!append_string(material, value)) {
            return std::unexpected(
                std::string{"observation disposition field exceeds its hash bound"}
            );
        }
    }
    append_u64(material, disposition.channel_generation);
    append_u64(material, disposition.decided_at_ms);
    return container::sha256_hex(material);
}

auto state_from_wire(std::string_view state) -> std::optional<session_state> {
    if (state == "created") {
        return session_state::created;
    }
    if (state == "preparing") {
        return session_state::preparing;
    }
    if (state == "starting") {
        return session_state::starting;
    }
    if (state == "running") {
        return session_state::running;
    }
    if (state == "stopping") {
        return session_state::stopping;
    }
    if (state == "exited") {
        return session_state::exited;
    }
    if (state == "failed") {
        return session_state::failed;
    }
    return std::nullopt;
}

auto encode_record(const persisted_session& record)
    -> std::expected<std::vector<unsigned char>, std::string> {
    auto payload = glz::write_json(record);
    if (!payload) {
        return std::unexpected(std::string{"encode session registry record failed"});
    }
    if (payload->empty() || payload->size() > max_record_payload_bytes) {
        return std::unexpected(std::string{"session registry record exceeds its bound"});
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(payload->size() + 8U);
    append_u32(bytes, static_cast<std::uint32_t>(payload->size()));
    bytes.insert(bytes.end(), payload->begin(), payload->end());
    append_u32(bytes, static_cast<std::uint32_t>(payload->size()));
    return bytes;
}

auto decode_record(std::string_view payload) -> std::expected<persisted_session, std::string> {
    persisted_session record;
    if (const auto error = glz::read<strict_read_options>(record, payload); error) {
        return std::unexpected(std::string{"decode session registry record failed"});
    }
    return record;
}

} // namespace glove::control::wire
