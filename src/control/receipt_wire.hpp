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

[[nodiscard]] auto decode_rpc_request(std::string_view input)
    -> std::expected<rpc_request, std::string>;
[[nodiscard]] auto decode_rpc_params(std::string_view input)
    -> std::expected<rpc_params, std::string>;
[[nodiscard]] auto encode_rpc_response(const rpc_response& response)
    -> std::expected<std::string, std::string>;

} // namespace glove::control::wire
