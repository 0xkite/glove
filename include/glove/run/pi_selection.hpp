#pragma once

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run {

// Harness identity is independent of the API-key provider. OAuth and arbitrary
// endpoints require separate host-owned authentication and admission contracts.
enum class pi_provider { openai, anthropic };

struct pi_model_selection {
    pi_provider provider = pi_provider::openai;
    std::string model;

    auto operator==(const pi_model_selection&) const -> bool = default;
};

struct pi_launch_options {
    std::optional<std::string> provider{};
    std::optional<std::string> model{};
    std::vector<std::string> arguments{};
};

struct pi_launch_selection {
    pi_model_selection model;
    std::vector<std::string> arguments;
};

[[nodiscard]] auto pi_provider_name(pi_provider provider) -> std::string_view;

// Versioned canonical records contain only the model choice, never credentials
// or executable paths. The host must load/store them through protected files.
[[nodiscard]] auto encode_pi_model_selection(const pi_model_selection& selection)
    -> std::expected<std::string, std::string>;
[[nodiscard]] auto decode_pi_model_selection(std::string_view json)
    -> std::expected<pi_model_selection, std::string>;

// `configured` must come from the operator-owned selection, never project
// settings. This pure validation step performs no discovery, I/O or execution.
// Endpoint, authentication, resources and session storage remain adapter-owned.
[[nodiscard]] auto select_pi_launch(
    const pi_launch_options& options,
    const std::optional<pi_model_selection>& configured = std::nullopt
) -> std::expected<pi_launch_selection, std::string>;

} // namespace glove::run
