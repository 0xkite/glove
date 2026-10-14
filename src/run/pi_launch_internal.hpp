#pragma once

#include "glove/audit/sink.hpp"
#include "glove/container/profile.hpp"
#include "glove/host/config.hpp"
#include "glove/net/credentialed_endpoint.hpp"
#include "glove/run/pi_launch.hpp"

#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <stop_token>
#include <string>
#include <vector>

namespace glove::run::detail {

// Host policy constructs this context; it is not an operator/guest override
// surface. Synthetic fixtures replace boundary calls, not the typed request.
struct pi_launch_context {
    host::directories directories;
    std::vector<std::filesystem::path> protected_auth_roots;
    std::function<std::expected<std::string, std::string>(pi_provider)> credential;
    std::function<std::expected<std::unique_ptr<net::credentialed_endpoint>, std::string>(
        net::credentialed_endpoint_options
    )>
        start_endpoint;
    std::function<std::expected<int, std::string>(
        const container::profile&, const std::vector<std::string>&, std::stop_token
    )>
        execute_owned;
    std::shared_ptr<audit::sink> audit;
};

[[nodiscard]] auto launch_pi_with_context(
    const pi_launch_request& request, const pi_launch_context& context, std::stop_token stop = {}
) -> std::expected<int, std::string>;

} // namespace glove::run::detail
