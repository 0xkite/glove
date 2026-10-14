#pragma once

#include "glove/audit/sink.hpp"
#include "glove/container/profile.hpp"
#include "glove/host/config.hpp"

#include "native_harness_adapter.hpp"
#include "native_runtime_binding.hpp"

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>

namespace glove::run::detail {

struct native_launch_binding {
    host::staged_runtime_harness runtime;
    net::endpoint_provider provider = net::endpoint_provider::openai;
    std::string model;
    std::vector<std::string> arguments;
};

struct native_launch_assets {
    std::string catalog_json;
    std::vector<std::string> library_environment;
};

struct native_launch_authority {
    native_launch_binding binding;
    native_launch_assets assets;
};

enum class native_launch_backend { macos, unsupported };

// Constructed only by compiled host composition, never an operator/project/plugin
// configuration surface. Callbacks implement host admission, not harness startup;
// the core controls their ordering and compares owned bindings/assets on recheck.
// Context and callback borrows remain synchronous through this launch call.
struct native_launch_context {
    host::directories directories;
    std::vector<std::filesystem::path> protected_auth_roots;
    std::optional<std::filesystem::path> workspace;
    std::filesystem::path runs;
    native_startup_policy policy;
    std::string display_name;
    native_launch_backend backend = native_launch_backend::macos;
    std::function<std::expected<native_launch_binding, std::string>()> admit_runtime;
    std::function<std::expected<native_launch_assets, std::string>(const native_launch_binding&)>
        admit_assets;
    std::function<std::expected<native_launch_authority, std::string>()> revalidate;
    std::function<std::expected<std::string, std::string>(net::endpoint_provider)> credential;
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

[[nodiscard]] auto admit_native_operator_stdio() -> std::expected<void, std::string>;

[[nodiscard]] auto launch_native_with_context(
    const native_launch_context& context,
    const native_harness_adapter& adapter,
    std::stop_token stop = {}
) -> std::expected<int, std::string>;

} // namespace glove::run::detail
