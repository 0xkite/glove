#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/run/pi_provider_share.hpp"

#include "provider_endpoint.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace {
auto check_surface(
    glove::run::detail::provider_surface surface,
    glove::net::endpoint_provider provider,
    const std::string& prefix,
    const std::string& host,
    const std::vector<std::string>& paths
) -> bool {
    bool observed = false;
    auto options = glove::run::detail::make_provider_endpoint_options(
        surface,
        "host-secret-sentinel",
        "glove-session-fixture",
        [&observed](const glove::net::endpoint_event&) -> std::expected<void, std::string> {
            observed = true;
            return std::unexpected(std::string{"audit fixture refusal"});
        }
    );
    if (!options || options->endpoints.size() != 1 || !options->forward || !options->on_event ||
        options->upstream_deadline_ms != 600000) {
        return false;
    }
    const auto& rule = options->endpoints.front();
    if (rule.provider != provider || rule.path_prefix != prefix || rule.upstream_host != host ||
        rule.upstream_port != 443 || rule.allowed_methods != std::vector<std::string>{"POST"} ||
        rule.allowed_paths != paths || rule.secret_token != "host-secret-sentinel" ||
        rule.session_nonce != "glove-session-fixture") {
        return false;
    }
    auto event_result = options->on_event({});
    if (!observed || event_result || event_result.error() != "audit fixture refusal") {
        return false;
    }
    // A wrong upstream must be refused before DNS or socket activity. The test
    // never sends a request to the selected live provider.
    glove::net::upstream_request request;
    request.upstream_host = "fixture.invalid";
    request.upstream_port = 443;
    auto denied =
        options->forward(request, {}, std::chrono::steady_clock::now() + std::chrono::seconds{1});
    return !denied && denied.error() == "upstream not in the forwarder allowlist";
}

// The decision record keeps its old shape; the outcome record carries the
// exchange's duration, sizes and upstream status.
auto check_records() -> bool {
    using namespace std::chrono_literals;
    auto sink = glove::audit::make_memory_sink();
    const glove::net::endpoint_event decision{
        .method = "POST",
        .path = "/p/one/chat/completions",
        .allowed = true,
        .detail = "allowed",
    };
    auto outcome = decision;
    outcome.detail = "completed";
    outcome.request_bytes = 120;
    outcome.response_bytes = 4096;
    outcome.upstream_duration = 1500ms;
    outcome.upstream_status = 200;
    outcome.input_tokens = 900;
    outcome.output_tokens = 57;
    outcome.tokens_reported = true;
    auto failed = decision;
    failed.detail = "upstream_error";
    failed.request_bytes = 7;
    failed.upstream_duration = 20ms;
    auto denied = decision;
    denied.allowed = false;
    denied.detail = "invalid_session_nonce";
    for (const auto& event : {decision, outcome, failed, denied}) {
        if (!glove::run::detail::record_endpoint_event(sink, event)) {
            return false;
        }
    }
    const auto records = sink->take();
    if (records.size() != 4) {
        return false;
    }
    for (const auto& record : records) {
        if (record.what != glove::audit::action::egress ||
            record.tool_name != "POST /p/one/chat/completions") {
            return false;
        }
    }
    return records[0].arguments_json.empty() && records[0].latency == 0ns &&
           records[0].error_message == "allowed" &&
           records[0].status == glove::mcp::tool_call_status::ok &&
           records[1].arguments_json ==
               R"({"upstream_status":200,"request_bytes":120,"response_bytes":4096,"input_tokens":900,"output_tokens":57})" &&
           records[1].latency == 1500ms && records[1].error_message == "completed" &&
           records[2].arguments_json ==
               R"({"upstream_status":0,"request_bytes":7,"response_bytes":0})" &&
           records[2].latency == 20ms && records[2].error_message == "upstream_error" &&
           records[3].arguments_json.empty() && records[3].latency == 0ns &&
           records[3].status == glove::mcp::tool_call_status::invalid_arguments &&
           glove::run::detail::record_endpoint_event(nullptr, outcome).has_value();
}
} // namespace

auto main() -> int {
    if (!check_records()) {
        std::fputs("endpoint event records are wrong\n", stderr);
        return 1;
    }
    using glove::net::endpoint_provider;
    using glove::run::detail::make_provider_endpoint_options;
    using glove::run::detail::provider_surface;
    if (!check_surface(
            provider_surface::legacy_anthropic,
            endpoint_provider::anthropic,
            "/anthropic",
            "api.anthropic.com",
            {"/v1/messages", "/v1/messages/count_tokens"}
        ) ||
        !check_surface(
            provider_surface::legacy_openai,
            endpoint_provider::openai,
            "/openai",
            "api.openai.com",
            {"/v1/chat/completions", "/v1/responses", "/v1/models"}
        ) ||
        !check_surface(
            provider_surface::pi_anthropic,
            endpoint_provider::anthropic,
            "/anthropic",
            "api.anthropic.com",
            {"/v1/messages"}
        ) ||
        !check_surface(
            provider_surface::pi_openai,
            endpoint_provider::openai,
            "/openai",
            "api.openai.com",
            {"/v1/responses"}
        )) {
        std::fprintf(stderr, "fixed provider surface mismatch\n");
        return 1;
    }
    // A shared Pi provider becomes one client-placed rule whose upstream and
    // paths come from the resolved provider data, never from a provider table.
    {
        glove::run::pi_shared_provider shared{
            .name = "google",
            .host = "generativelanguage.googleapis.com",
            .port = 443,
            .base_path = "/v1beta",
            .allowed_paths = {"/v1beta/models/*"},
            .origin_from_models_json = false,
            .catalog_hosts = {},
        };
        auto shared_options = glove::run::detail::make_shared_provider_endpoint_options(
            shared, "host-secret-sentinel", "glove-session-fixture"
        );
        if (!shared_options || shared_options->endpoints.size() != 1 || !shared_options->forward) {
            std::fprintf(stderr, "shared provider endpoint missing\n");
            return 1;
        }
        const auto& rule = shared_options->endpoints.front();
        if (rule.provider != endpoint_provider::client_placed || rule.path_prefix != "/p/google" ||
            rule.upstream_host != "generativelanguage.googleapis.com" ||
            rule.upstream_port != 443 || rule.allowed_paths != shared.allowed_paths ||
            rule.allowed_methods != std::vector<std::string>{"POST"} ||
            rule.secret_token != "host-secret-sentinel" ||
            rule.session_nonce != "glove-session-fixture") {
            std::fprintf(stderr, "shared provider rule mismatch\n");
            return 1;
        }
        glove::net::upstream_request elsewhere;
        elsewhere.upstream_host = "api.anthropic.com";
        elsewhere.upstream_port = 443;
        auto denied = shared_options->forward(
            elsewhere, {}, std::chrono::steady_clock::now() + std::chrono::seconds{1}
        );
        if (denied || denied.error() != "upstream not in the forwarder allowlist") {
            std::fprintf(stderr, "shared provider forwarder is not pinned\n");
            return 1;
        }
        auto no_paths = shared;
        no_paths.allowed_paths.clear();
        if (glove::run::detail::make_shared_provider_endpoint_options(no_paths, "s", "n")) {
            std::fprintf(stderr, "shared provider without paths accepted\n");
            return 1;
        }
    }
    if (make_provider_endpoint_options(static_cast<provider_surface>(255), "secret", "nonce") ||
        make_provider_endpoint_options(provider_surface::pi_openai, "", "nonce") ||
        make_provider_endpoint_options(provider_surface::pi_openai, "secret", "") ||
        make_provider_endpoint_options(
            provider_surface::pi_openai, std::string{"x\0y", 3}, "nonce"
        ) ||
        make_provider_endpoint_options(
            provider_surface::pi_openai, "secret", std::string{"x\0y", 3}
        )) {
        std::fprintf(stderr, "invalid provider endpoint authority accepted\n");
        return 1;
    }
    return 0;
}
