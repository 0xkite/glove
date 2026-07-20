#pragma once

#include "glove/host/config.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
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

[[nodiscard]] auto supervisor_health(const config& service) -> result<void>;
[[nodiscard]] auto enroll_project(const config& service, const project_enrollment& request)
    -> result<project_exposure>;

} // namespace glove::host
