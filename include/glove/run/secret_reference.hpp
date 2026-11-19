#pragma once

// Where a secret lives, named the way secret stores name things, so a
// profile carries the reference and never the value:
//
//   env://NAME                  a host environment variable
//   file:///abs/path            an owner-only file holding one token
//   file://~/path               the same, under the account's home
//   keychain://service/account  a macOS Keychain generic password
//
// Glove resolves a reference on the host at launch. The value goes only to
// the host side of the credentialed endpoint; the sandbox sees a session
// nonce.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace glove::run {

inline constexpr std::size_t max_secret_reference = 1024;
inline constexpr std::size_t max_secret_bytes = 16UZ * 1024UZ;

enum class secret_source : std::uint8_t { env, file, keychain };

struct secret_reference {
    secret_source source = secret_source::env;
    std::string locator; // variable name, path, or keychain service
    std::string account; // keychain account; empty otherwise

    auto operator==(const secret_reference&) const -> bool = default;
};

// Strict parse; never touches the environment, filesystem, or keychain.
[[nodiscard]] auto parse_secret_reference(std::string_view text)
    -> std::expected<secret_reference, std::string>;

// The reference's text form; parse_secret_reference(format(r)) == r.
[[nodiscard]] auto format_secret_reference(const secret_reference& reference) -> std::string;

} // namespace glove::run
