#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::policy {

namespace {

constexpr glz::opts lenient_read_opts{.error_on_unknown_keys = false};

class jsonpath_engine final : public engine {
public:
    explicit jsonpath_engine(jsonpath_options opts) : opts_{std::move(opts)} {}

    auto check(std::string_view tool_name, std::string_view arguments_json) const
        -> outcome override {
        if (contains(opts_.deny, tool_name)) {
            return outcome{
                .verdict = decision::deny,
                .reason = std::string{"tool '"} + std::string{tool_name} + "' is in deny list",
            };
        }

        const bool name_allowed = contains(opts_.allow, tool_name);
        if (!name_allowed) {
            if (opts_.default_decision == decision::allow) {
                return outcome{
                    .verdict = decision::allow,
                    .reason = std::string{"default allow"},
                };
            }
            return outcome{
                .verdict = decision::deny,
                .reason = std::string{"tool '"} + std::string{tool_name} +
                          "' not in allow list (default deny)",
            };
        }

        // Tool is allowed by name. Now apply any argument-level rules
        // that target this tool. Absent rules → allow.
        std::vector<const argument_prefix_rule*> applicable;
        applicable.reserve(opts_.prefix_rules.size());
        for (const auto& r : opts_.prefix_rules) {
            if (r.tool_name == tool_name) {
                applicable.push_back(&r);
            }
        }
        if (applicable.empty()) {
            return outcome{
                .verdict = decision::allow,
                .reason = std::string{"tool '"} + std::string{tool_name} + "' allowed by name",
            };
        }

        // Parse arguments. Empty / non-object args fail any prefix rule
        // since there's nothing to read the field from.
        // `arguments_json` is an untrusted byte span. Give Glaze a mutable,
        // resizable buffer so its padded parsing path owns the boundary.
        std::string parse_buffer{arguments_json};
        glz::generic parsed;
        if (auto ec = glz::read<lenient_read_opts>(parsed, parse_buffer); ec) {
            return outcome{
                .verdict = decision::deny,
                .reason = std::string{"argument JSON unparseable"},
            };
        }
        if (parsed.holds<glz::generic::null_t>() || !parsed.is_object()) {
            return outcome{
                .verdict = decision::deny,
                .reason = std::string{"arguments must be a JSON object"},
            };
        }

        for (const auto* rule : applicable) {
            const auto& obj = parsed.get_object();
            auto it = obj.find(rule->field);
            if (it == obj.end()) {
                return outcome{
                    .verdict = decision::deny,
                    .reason = std::string{"argument '"} + rule->field + "' missing",
                };
            }
            if (!it->second.is_string()) {
                return outcome{
                    .verdict = decision::deny,
                    .reason = std::string{"argument '"} + rule->field + "' is not a string",
                };
            }
            const std::string& value = it->second.get_string();
            if (!matches_prefix(value, rule->required_prefix)) {
                return outcome{
                    .verdict = decision::deny,
                    .reason = std::string{"argument '"} + rule->field + "' must start with '" +
                              rule->required_prefix + "'",
                };
            }
        }

        return outcome{
            .verdict = decision::allow,
            .reason =
                std::string{"tool '"} + std::string{tool_name} + "' passed all argument rules",
        };
    }

    auto visible(std::string_view tool_name) const -> bool override {
        return !contains(opts_.deny, tool_name) &&
               (contains(opts_.allow, tool_name) || opts_.default_decision == decision::allow);
    }

private:
    static auto contains(const std::vector<std::string>& list, std::string_view name) -> bool {
        return std::any_of(list.begin(), list.end(), [name](const std::string& s) {
            return s == name;
        });
    }

    static auto starts_with(std::string_view s, std::string_view prefix) -> bool {
        return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
    }

    static auto canonical_or_lexical(const std::filesystem::path& path) -> std::filesystem::path {
        auto input = path;
        if (input != input.root_path() && !input.has_filename()) {
            input = input.parent_path();
        }
        std::error_code ec;
        auto canonical = std::filesystem::weakly_canonical(input, ec);
        return ec ? input.lexically_normal() : canonical.lexically_normal();
    }

    static auto
    path_within(const std::filesystem::path& candidate, const std::filesystem::path& root) -> bool {
        const auto normal_candidate = canonical_or_lexical(candidate);
        const auto normal_root = canonical_or_lexical(root);
        const auto mismatch = std::mismatch(
            normal_root.begin(), normal_root.end(), normal_candidate.begin(), normal_candidate.end()
        );
        return mismatch.first == normal_root.end();
    }

    // Absolute prefixes are filesystem boundaries, not byte prefixes. This
    // rejects sibling-prefix tricks, parent traversal, and existing symlink
    // escapes. Other values retain ordinary string-prefix semantics.
    static auto matches_prefix(std::string_view value, std::string_view prefix) -> bool {
        const std::filesystem::path candidate{value};
        const std::filesystem::path root{prefix};
        if (root.is_absolute()) {
            return candidate.is_absolute() && path_within(candidate, root);
        }
        return starts_with(value, prefix);
    }

    jsonpath_options opts_;
};

} // namespace

auto make_jsonpath_engine(jsonpath_options opts) -> std::unique_ptr<engine> {
    return std::make_unique<jsonpath_engine>(std::move(opts));
}

} // namespace glove::policy
