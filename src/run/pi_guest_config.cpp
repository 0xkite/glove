#include "pi_guest_config.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace glove::run::detail {
namespace pi_guest_wire {

struct catalog_model {
    std::string id;
    std::string provider;
    std::string api;
    std::string type;
};

using catalog_group = std::map<std::string, catalog_model>;
using catalog = std::map<std::string, catalog_group>;

struct provider_override {
    std::string baseUrl;
    std::string apiKey;
};

struct models_config {
    std::map<std::string, provider_override> providers;
};

struct settings_config {
    std::string defaultProvider;
    std::string defaultModel;
    std::vector<std::string> packages;
    std::vector<std::string> extensions;
    std::vector<std::string> skills;
    std::vector<std::string> promptTemplates;
    std::vector<std::string> themes;
};

} // namespace pi_guest_wire

namespace {
using pi_guest_wire::catalog;
using pi_guest_wire::models_config;
using pi_guest_wire::settings_config;

constexpr std::size_t max_catalog_bytes = 1024 * 1024;
constexpr std::size_t max_groups = 16;
constexpr std::size_t max_entries = 4096;
constexpr std::size_t max_json_depth = 64;

// Reject duplicates (including escaped aliases), trailing data and excessive
// nesting before typed map decoding can overwrite keys or allocate its maps.
// Byte/count/depth bounds are logical parsing bounds, not filesystem or memory
// quotas. Key sets and decoded strings still allocate within the byte bound;
// allocator failure remains the enclosing application's containment concern.
class catalog_guard {
public:
    explicit catalog_guard(std::string_view input) : input_{input} {}

    [[nodiscard]] auto valid() -> bool {
        skip_space();
        return value(0) && (skip_space(), position_ == input_.size());
    }

private:
    void skip_space() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\n' || input_[position_] == '\r')) {
            ++position_;
        }
    }

    [[nodiscard]] auto string_value() -> std::optional<std::string> {
        if (position_ >= input_.size() || input_[position_] != '"') {
            return std::nullopt;
        }
        const auto begin = position_++;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_[position_++]);
            if (byte == static_cast<unsigned char>('"')) {
                std::string decoded;
                if (const auto error =
                        glz::read_json(decoded, input_.substr(begin, position_ - begin));
                    error) {
                    return std::nullopt;
                }
                return decoded;
            }
            if (byte < 0x20U) {
                return std::nullopt;
            }
            if (byte == static_cast<unsigned char>('\\')) {
                if (position_ >= input_.size()) {
                    return std::nullopt;
                }
                ++position_;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto literal(std::string_view text) -> bool {
        if (input_.substr(position_, text.size()) != text) {
            return false;
        }
        position_ += text.size();
        return true;
    }

    [[nodiscard]] auto number() -> bool {
        if (position_ < input_.size() && input_[position_] == '-') {
            ++position_;
        }
        if (position_ >= input_.size()) {
            return false;
        }
        if (input_[position_] == '0') {
            ++position_;
        } else {
            if (input_[position_] < '1' || input_[position_] > '9') {
                return false;
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const auto digits = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (position_ == digits) {
                return false;
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            const auto digits = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (position_ == digits) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto object(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        std::set<std::string> keys;
        if (position_ < input_.size() && input_[position_] == '}') {
            ++position_;
            return true;
        }
        for (;;) {
            // Check before decoding/inserting the next key. Deeper metadata
            // objects also get a finite member bound without retaining values.
            if ((depth == 0 && keys.size() == max_groups) || keys.size() == max_entries ||
                (depth == 1 && entries_ == max_entries)) {
                return false;
            }
            auto key = string_value();
            if (!key || !keys.insert(std::move(*key)).second) {
                return false;
            }
            if (depth == 1) {
                ++entries_;
            }
            skip_space();
            if (position_ >= input_.size() || input_[position_++] != ':') {
                return false;
            }
            skip_space();
            if (!value(depth + 1)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == '}') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto array(std::size_t depth) -> bool {
        ++position_;
        skip_space();
        if (position_ < input_.size() && input_[position_] == ']') {
            ++position_;
            return true;
        }
        for (;;) {
            if (!value(depth + 1)) {
                return false;
            }
            skip_space();
            if (position_ >= input_.size()) {
                return false;
            }
            const auto delimiter = input_[position_++];
            if (delimiter == ']') {
                return true;
            }
            if (delimiter != ',') {
                return false;
            }
            skip_space();
        }
    }

    [[nodiscard]] auto value(std::size_t depth) -> bool {
        if (depth > max_json_depth || position_ >= input_.size()) {
            return false;
        }
        switch (input_[position_]) {
        case '{':
            return object(depth);
        case '[':
            return array(depth);
        case '"':
            return string_value().has_value();
        case 't':
            return literal("true");
        case 'f':
            return literal("false");
        case 'n':
            return literal("null");
        default:
            return number();
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
    std::size_t entries_ = 0;
};

auto valid_nonce(std::string_view nonce) -> bool {
    constexpr std::string_view prefix = "glove-session-";
    return nonce.size() == prefix.size() + 48 && nonce.starts_with(prefix) &&
           std::ranges::all_of(nonce.substr(prefix.size()), [](char byte) {
               return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
           });
}

// select_pi_launch owns the forwarding policy. These cheap size checks avoid
// copying unbounded arguments into its options before invoking that policy.
auto arguments_bounded(const std::vector<std::string>& arguments) -> bool {
    if (arguments.size() > 32) {
        return false;
    }
    std::size_t total = 0;
    for (const auto& argument : arguments) {
        if (argument.size() > 16 * 1024 || argument.size() > 64 * 1024 - total) {
            return false;
        }
        total += argument.size();
    }
    return true;
}

} // namespace

auto make_pi_guest_config(
    const pi_launch_selection& selection,
    std::uint16_t endpoint_port,
    std::string_view nonce,
    std::string_view catalog_json
) -> std::expected<pi_guest_config, std::string> {
    if (endpoint_port == 0 || !valid_nonce(nonce)) {
        return std::unexpected(std::string{"invalid Pi endpoint port or session nonce"});
    }
    if (pi_provider_name(selection.model.provider).empty() || selection.model.model.size() > 128 ||
        !arguments_bounded(selection.arguments)) {
        return std::unexpected(std::string{"invalid or oversized Pi launch selection"});
    }
    auto checked = select_pi_launch({.arguments = selection.arguments}, selection.model);
    if (!checked) {
        return std::unexpected(checked.error());
    }
    if (catalog_json.empty() || catalog_json.size() > max_catalog_bytes ||
        !catalog_guard{catalog_json}.valid()) {
        return std::unexpected(std::string{"malformed or oversized Pi catalog"});
    }
    catalog models;
    constexpr glz::opts catalog_options{
        .error_on_unknown_keys = false, .error_on_missing_keys = true
    };
    if (const auto error = glz::read<catalog_options>(models, catalog_json); error) {
        return std::unexpected(std::string{"malformed Pi catalog model fields"});
    }
    const auto provider = pi_provider_name(checked->model.provider);
    const std::string_view required_api =
        checked->model.provider == pi_provider::openai ? "openai-responses" : "anthropic-messages";
    const std::string exact_key = "chat:" + checked->model.model;
    std::size_t matches = 0;
    for (const auto& [group, entries] : models) {
        for (const auto& [key, model] : entries) {
            const auto colon = key.find(':');
            const auto key_id = colon == std::string::npos
                                    ? std::string_view{key}
                                    : std::string_view{key}.substr(colon + 1);
            if (key_id != checked->model.model && model.id != checked->model.model) {
                continue;
            }
            // A selected id under any other key/group is a collision, not an
            // alias or a fallback. Never fuzzy-match Pi's model identifiers.
            if (++matches != 1 || key != exact_key || model.id != checked->model.model ||
                group != required_api || model.provider != provider || model.api != required_api ||
                model.type != "chat") {
                return std::unexpected(std::string{"conflicting Pi catalog model identity"});
            }
        }
    }
    if (matches != 1) {
        return std::unexpected(std::string{"unknown Pi catalog model"});
    }
    pi_guest_config result;
    result.base_url =
        "http://127.0.0.1:" + std::to_string(endpoint_port) +
        (checked->model.provider == pi_provider::openai ? "/openai/v1" : "/anthropic");
    // Only provider endpoint/auth overrides: Pi preserves builtin metadata.
    // A models/modelOverrides entry would replace or alter that metadata.
    const models_config overrides{
        .providers = {
            {std::string{provider}, {.baseUrl = result.base_url, .apiKey = std::string{nonce}}}
        }
    };
    const settings_config settings{
        .defaultProvider = std::string{provider},
        .defaultModel = checked->model.model,
        .packages = {},
        .extensions = {},
        .skills = {},
        .promptTemplates = {},
        .themes = {},
    };
    if (const auto error = glz::write_json(overrides, result.models_json); error) {
        return std::unexpected(std::string{"could not encode Pi provider configuration"});
    }
    if (const auto error = glz::write_json(settings, result.settings_json); error) {
        return std::unexpected(std::string{"could not encode Pi settings"});
    }
    result.arguments = {
        "--provider",
        std::string{provider},
        "--model",
        checked->model.model,
        "--offline",
        "--no-approve",
        "--no-extensions",
        "--no-mcp",
        "--no-skills",
        "--no-prompt-templates",
        "--no-themes",
        "--no-context-files"
    };
    result.arguments.insert(
        result.arguments.end(), checked->arguments.begin(), checked->arguments.end()
    );
    return result;
}

} // namespace glove::run::detail
