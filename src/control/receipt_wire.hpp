#pragma once

#include "glove/container/receipt_chain.hpp"
#include "glove/control/session_registry.hpp"

#include <glaze/glaze.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::control::wire {

struct rpc_request {
    std::string jsonrpc;
    std::string id;
    std::string method;
    glz::raw_json params;
};

struct rpc_params {
    std::uint8_t schema_version = 0;
    std::string bootstrap_secret;
    std::uint64_t deadline_ms = 0;
    std::optional<std::string> idempotency_key;
    glz::raw_json payload;
};

struct rpc_error {
    std::string code;
    std::string message;
};

struct rpc_response {
    std::string jsonrpc = "2.0";
    std::string id;
    std::optional<glz::raw_json> result;
    std::optional<rpc_error> error;
};

struct page_request {
    container::receipt_audit_anchor sage_anchor;
    std::size_t limit = 0;
};

struct page_result {
    std::uint8_t schema_version = 1;
    std::vector<container::authenticated_resource_enforcement_receipt> envelopes;
    std::vector<container::authenticated_refinement_evaluation_receipt> refinement_envelopes;
    bool has_more = false;
    container::receipt_audit_anchor local_anchor;
};

struct acknowledgement_request {
    container::receipt_audit_anchor anchor;
};

struct acknowledgement_result {
    std::uint8_t schema_version = 1;
    container::receipt_audit_anchor acknowledged_anchor;
};

struct create_session_request {
    std::string session_id;
    std::string controller_plan_digest;
    glz::raw_json plan;
};

struct session_status_request {
    std::string session_id;
};

struct start_session_request {
    session_start_authorization authorization;
};

struct stop_session_request {
    std::string session_id;
};

struct attach_request {
    std::string session_id;
    std::uint64_t cursor = 0;
    std::size_t max_bytes = 0;
};

struct transcript_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::uint64_t oldest_cursor = 0;
    std::uint64_t next_cursor = 0;
    bool truncated = false;
    bool eof = false;
    std::vector<std::uint8_t> bytes;
};

struct write_stdin_request {
    std::string session_id;
    std::vector<std::uint8_t> bytes;
};

struct resize_request {
    std::string session_id;
    std::uint16_t rows = 0;
    std::uint16_t columns = 0;
};

struct signal_request {
    std::string session_id;
    std::string signal;
};

struct detach_request {
    std::string session_id;
    std::uint64_t transcript_cursor = 0;
};

struct session_cursor_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::uint64_t transcript_cursor = 0;
};

struct session_mutation_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
};

struct session_record_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t policy_revision = 0;
    std::uint64_t expires_at_ms = 0;
    std::uint64_t created_at_ms = 0;
    std::optional<std::string> profile_digest;
};

struct path_exposure_mode {
    std::string access;
    std::string materialization;
    std::uint64_t max_bytes = 0;
    std::string cleanup_policy;
};

struct path_exposure_projection {
    std::uint8_t schema_version = 1;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::string> allowed_runtime_template_ids;
    std::string state;
};

struct create_path_exposure_request {
    std::string exposure_id;
    std::string root_id;
    std::string host_path;
    std::string display_label;
    std::vector<path_exposure_mode> allowed_modes;
    std::uint64_t ttl_secs = 0;
    std::vector<std::string> allowed_runtime_template_ids;
};

struct revoke_path_exposure_request {
    std::string exposure_id;
    std::uint64_t generation = 0;
};

struct path_exposure_result {
    std::uint8_t schema_version = 1;
    path_exposure_projection exposure;
};

struct path_exposure_list_result {
    std::uint8_t schema_version = 1;
    std::vector<path_exposure_projection> exposures;
};

struct retained_change_inspect_request {
    std::string session_id;
    std::string exposure_id;
    std::uint64_t offset = 0;
    std::uint32_t limit = 0;
};

struct retained_change_entry {
    std::string kind;
    std::string path;
    std::string previous_path;
    std::string before_digest;
    std::string after_digest;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::uint32_t before_mode = 0;
    std::uint32_t after_mode = 0;
    bool directory = false;
};

struct retained_change_inspect_result {
    std::uint8_t schema_version = 1;
    std::string session_id;
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string source_identity_digest;
    std::uint64_t max_bytes = 0;
    bool directory = false;
    std::string baseline_tree_digest;
    std::string staged_tree_digest;
    std::string manifest_digest;
    std::uint64_t created = 0;
    std::uint64_t modified = 0;
    std::uint64_t renamed = 0;
    std::uint64_t removed = 0;
    std::uint64_t before_bytes = 0;
    std::uint64_t after_bytes = 0;
    std::uint64_t total_changes = 0;
    std::optional<std::uint64_t> next_offset;
    std::vector<retained_change_entry> changes;
};

struct receipt_audit_capabilities {
    std::uint8_t envelope_schema_version = 1;
    std::string algorithm = "hmac_sha256";
    std::string key_id;
};

struct session_control_capabilities {
    bool validate_plan = false;
    bool create_session = false;
    bool start_session = false;
    bool session_status = false;
    bool attach = false;
    bool resize = false;
    bool write_stdin = false;
    bool signal = false;
    bool detach = false;
    bool stop_session = false;
    bool cleanup_session = false;
};

struct resource_enforcement_capabilities {
    container::enforcement_mechanism cpu_time = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism memory = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism pids = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism wall_time = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism disk = container::enforcement_mechanism::unavailable;
    container::enforcement_mechanism terminal_output =
        container::enforcement_mechanism::unavailable;
    std::uint8_t receipt_schema_version = 0;
};

struct backend_capabilities {
    std::string backend;
    resource_enforcement_capabilities resource_enforcement;
};

struct page_observation_intents_request {
    std::uint64_t after_sequence = 0;
    std::size_t limit = 0;
};

struct observation_intent_body_wire {
    std::string schema;
    std::string intent_id;
    std::string observation;
    std::string value_digest;
    std::uint64_t item_count = 0;
};

struct observation_intent_context_wire {
    std::string session_id;
    std::string controller_plan_digest;
    std::string profile_digest;
    std::string runtime_id;
    std::string projection_digest;
    std::uint64_t policy_revision = 0;
    std::string channel_id;
    std::uint64_t channel_generation = 0;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
};

struct observation_intent_queue_item_wire {
    std::uint64_t sequence = 0;
    observation_intent_body_wire body;
    observation_intent_context_wire context;
    std::string intent_digest;
    std::string disposition;
    std::uint64_t decided_at_ms = 0;
};

struct page_observation_intents_result {
    std::uint8_t schema_version = 1;
    std::vector<observation_intent_queue_item_wire> items;
    std::optional<std::uint64_t> next_after_sequence;
};

struct set_observation_intent_disposition_request {
    std::string session_id;
    std::uint64_t channel_generation = 0;
    std::string intent_id;
    std::string intent_digest;
    std::string disposition;
    std::uint64_t decided_at_ms = 0;
};

struct observation_intent_disposition_result {
    std::uint8_t schema_version = 1;
    observation_intent_queue_item_wire item;
};

struct supervisor_capabilities {
    std::uint8_t schema_version = 1;
    receipt_audit_capabilities receipt_audit;
    session_control_capabilities session_control;
    // Zero until Glove creates a private agent home and expands exact Sage
    // bundles into the selected harness's native discovery locations.
    std::uint8_t agent_runtime_adapter_schema_version = 0;
    std::vector<std::string> managed_runtime_ids;
    std::uint8_t path_exposure_admin_schema_version = 0;
    std::uint8_t path_exposure_catalog_schema_version = 0;
    std::uint8_t retained_write_schema_version = 0;
    std::uint8_t change_manifest_schema_version = 0;
    std::uint8_t change_apply_authorization_schema_version = 0;
    std::uint8_t refinement_evaluation_protocol_schema_version = 0;
    std::uint8_t observation_intent_channel_schema_version = 0;
    std::vector<backend_capabilities> backends;
};

struct supervisor_health {
    std::uint8_t schema_version = 1;
    std::string status = "ready";
};

[[nodiscard]] auto decode_rpc_request(std::string_view input)
    -> std::expected<rpc_request, std::string>;
[[nodiscard]] auto decode_rpc_params(std::string_view input)
    -> std::expected<rpc_params, std::string>;
[[nodiscard]] auto encode_rpc_response(const rpc_response& response)
    -> std::expected<std::string, std::string>;

} // namespace glove::control::wire
