#pragma once

#include "glove/host/runtime_policy.hpp"
#include "glove/net/credentialed_endpoint.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

struct native_private_paths {
    std::filesystem::path home;
    std::filesystem::path agent;
    std::filesystem::path sessions;
};

// The core materializes these sources from its owned private run. An adapter
// cannot return an arbitrary environment value or point it at a host directory.
enum class native_private_location { agent, config, state, data, cache };

// Typed value sources. private_location materializes an owned private path;
// endpoint_base_url/endpoint_nonce materialize the host-bound endpoint for the
// selected provider under that provider's exact documented variable name;
// literal carries a short closed token selected by host policy. No source can
// name an arbitrary host path, credential, or operator-supplied value.
enum class native_environment_source {
    private_location,
    endpoint_base_url,
    endpoint_nonce,
    literal
};

struct native_environment_binding {
    std::string name;
    native_private_location location = native_private_location::agent;
    native_environment_source source = native_environment_source::private_location;
    std::string literal;

    auto operator==(const native_environment_binding&) const -> bool = default;
};

// A leaf is sealed read-only unless the host policy lists it as writable;
// a writable leaf is generated once per generation and then owned by the
// harness (never identity-tracked, never a credential).
struct native_configuration_file {
    std::string name;
    std::string bytes;
    bool writable = false;
};

[[nodiscard]] auto
validate_native_configuration_files(std::span<const native_configuration_file> configuration)
    -> std::expected<void, std::string>;

// conversation_selector emits the harness's start-or-resume flag chosen by the
// core from the launch mode; conversation_id emits the exact host-admitted
// conversation identity. Neither accepts an operator path or ambient lookup.
enum class native_argument_source {
    literal,
    provider_name,
    model,
    session_directory,
    forwarded_arguments,
    conversation_selector,
    conversation_id
};

struct native_argument_binding {
    native_argument_source source = native_argument_source::literal;
    std::string literal;
    // conversation_selector only: the flag emitted for a resumed generation.
    std::string resume_literal;

    auto operator==(const native_argument_binding&) const -> bool = default;
};

// Selected independently by trusted host composition, never supplied by a guest
// or returned by the encoder. Ordered requirements forbid additions, omissions
// and remappings; typed argv slots do not confer pathname or environment grants.
struct native_startup_policy {
    std::string runtime_id;
    std::vector<std::string> configuration_names;
    // Subset of configuration_names materialized writable (0600) instead of sealed.
    std::vector<std::string> writable_configuration_names;
    std::vector<native_environment_binding> environment;
    std::vector<std::string> reserved_entries;
    std::vector<native_argument_binding> arguments;
};

// Borrowed inputs are valid only for the synchronous encode_startup call. Their
// syntax checks below do not replace host descriptor/snapshot/catalog admission.
// A nonce is endpoint authority, never the real host provider credential.
struct native_startup_input {
    const host::staged_runtime_harness& runtime;
    const native_startup_policy& policy;
    net::endpoint_provider provider = net::endpoint_provider::openai;
    std::string_view model;
    std::span<const std::string> arguments;
    std::string_view catalog_json;
    std::uint16_t endpoint_port = 0;
    std::string_view nonce;
    native_private_paths paths;
    // Host-admitted conversation identity and launch mode for harnesses whose
    // policy binds conversation slots. Empty/false for Pi's closed projection.
    std::string_view conversation_id{};
    bool resume = false;
    // Canonical host-admitted workspace, for harnesses whose configuration
    // must name the working directory (e.g. per-project trust). Never a grant.
    std::string_view workspace{};
};

// All results own their bytes. Configuration names are leaves below the owned
// agent directory; reserved entries are absent leaves below the workspace.
// No profile, grant, credential, endpoint, executor or cleanup handle is exposed.
struct native_startup_recipe {
    std::vector<std::string> argv;
    std::vector<native_configuration_file> configuration;
    std::vector<native_environment_binding> environment;
    std::vector<std::string> reserved_entries;
    std::string base_url;
};

class native_harness_adapter {
public:
    virtual ~native_harness_adapter() = default;
    [[nodiscard]] virtual auto encode_startup(const native_startup_input& input) const
        -> std::expected<native_startup_recipe, std::string> = 0;
};

[[nodiscard]] auto validate_native_startup_policy(const native_startup_policy& policy)
    -> std::expected<void, std::string>;

// Semantic startup-policy identity: harness, provider, model, configuration
// leaves, environment sources, reservations and ordered argument slots. It
// excludes fresh nonce/port/private-path spellings and the launch mode, so a
// checkpoint produced by a start generation binds its resume generation.
[[nodiscard]] auto native_startup_policy_digest(
    const native_startup_policy& policy, net::endpoint_provider provider, std::string_view model
) -> std::expected<std::string, std::string>;

[[nodiscard]] auto valid_conversation_id(std::string_view value)
    -> bool; // lowercase RFC 4122 text form

// Structural and closed-manifest admission, not executable/model authorization
// or configuration-format interpretation. The compiled encoder remains the
// trusted owner of harness-specific bytes. The core must admit recipes before
// effects and perform descriptor/identity rechecks before execution. Errors
// contain no input bytes.
[[nodiscard]] auto validate_native_startup_recipe(
    const native_startup_input& input, const native_startup_recipe& recipe
) -> std::expected<void, std::string>;

} // namespace glove::run::detail
