#include "glove/run/secret_reference.hpp"

#include <algorithm>

namespace glove::run {
namespace {

auto printable(std::string_view text) -> bool {
    return std::ranges::none_of(text, [](char ch) {
        const auto byte = static_cast<unsigned char>(ch);
        return byte < 0x20U || byte == 0x7FU;
    });
}

auto env_name(std::string_view name) -> bool {
    if (name.empty() || name.size() > 128U || (name.front() >= '0' && name.front() <= '9')) {
        return false;
    }
    return std::ranges::all_of(name, [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
               ch == '_';
    });
}

auto keychain_word(std::string_view word) -> bool {
    return !word.empty() && word.size() <= 255U && std::ranges::all_of(word, [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
               ch == '.' || ch == '_' || ch == '-' || ch == '@' || ch == '+';
    });
}

} // namespace

auto parse_secret_reference(std::string_view text) -> std::expected<secret_reference, std::string> {
    if (text.size() > max_secret_reference || !printable(text)) {
        return std::unexpected(std::string{"secret reference is too long or unprintable"});
    }
    if (text.starts_with("env://")) {
        const auto name = text.substr(6);
        if (!env_name(name)) {
            return std::unexpected(std::string{"env:// needs a variable name"});
        }
        return secret_reference{
            .source = secret_source::env, .locator = std::string{name}, .account = {}
        };
    }
    if (text.starts_with("file://")) {
        const auto path = text.substr(7);
        if (path.size() < 2 || (path.front() != '/' && !path.starts_with("~/")) ||
            path.ends_with('/')) {
            return std::unexpected(
                std::string{"file:// needs an absolute path (file:///...) or file://~/..."}
            );
        }
        return secret_reference{
            .source = secret_source::file, .locator = std::string{path}, .account = {}
        };
    }
    if (text.starts_with("keychain://")) {
        const auto rest = text.substr(11);
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos || !keychain_word(rest.substr(0, slash)) ||
            !keychain_word(rest.substr(slash + 1))) {
            return std::unexpected(std::string{"keychain:// needs service/account"});
        }
        return secret_reference{
            .source = secret_source::keychain,
            .locator = std::string{rest.substr(0, slash)},
            .account = std::string{rest.substr(slash + 1)},
        };
    }
    return std::unexpected(
        std::string{"unsupported secret reference; use env://, file://, or keychain://"}
    );
}

auto format_secret_reference(const secret_reference& reference) -> std::string {
    switch (reference.source) {
    case secret_source::env:
        return "env://" + reference.locator;
    case secret_source::file:
        return "file://" + reference.locator;
    case secret_source::keychain:
        return "keychain://" + reference.locator + "/" + reference.account;
    }
    return {};
}

} // namespace glove::run
