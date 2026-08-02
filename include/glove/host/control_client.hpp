#pragma once

#include "glove/host/config.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace glove::host {

enum class project_access : unsigned char {
    read,
    ephemeral_write,
    retained_write,
};

struct project_enrollment {
    std::filesystem::path project;
    std::string exposure_id;
    std::string root_id;
    std::string display_label;
    project_access access = project_access::read;
    std::uint64_t max_bytes = 0;
    std::uint64_t ttl_secs = 3'600;
    std::vector<std::string> runtime_template_ids;
    std::string idempotency_key;
};

struct project_exposure {
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::uint64_t expires_at_ms = 0;
};

// Redacted, remote-safe workspace inventory. It intentionally omits the
// protected root, canonical host path, and source filesystem identity.
struct workspace_exposure {
    std::string exposure_id;
    std::uint64_t generation = 0;
    std::string scope_digest;
    std::string display_label;
    std::uint64_t expires_at_ms = 0;
    std::string state;
};

// A local session create request is not launch authorization. The controller
// still supplies the bounded authorization required by Gloved to start work.
struct workspace_session_create_request {
    std::string session_id;
    std::string controller_plan_digest;
    std::string canonical_plan_json;
    std::string idempotency_key;
};

struct workspace_session_status {
    std::string session_id;
    std::string controller_plan_digest;
    std::string plan_content_digest;
    std::string state;
    std::uint64_t expires_at_ms = 0;
};

[[nodiscard]] auto supervisor_health(const config& service) -> result<void>;
[[nodiscard]] auto enroll_project(const config& service, const project_enrollment& request)
    -> result<project_exposure>;
[[nodiscard]] auto list_workspace_exposures(const config& service)
    -> result<std::vector<workspace_exposure>>;
[[nodiscard]] auto
create_workspace_session(const config& service, const workspace_session_create_request& request)
    -> result<workspace_session_status>;
[[nodiscard]] auto workspace_session_status_for(const config& service, std::string_view session_id)
    -> result<workspace_session_status>;

} // namespace glove::host
