#pragma once

#include <string_view>

namespace glove::container {

// Accept only a canonical immutable OCI/Docker-style reference. The reference
// must be an untagged lowercase name followed by the exact separately supplied
// sha256 digest: <name>@sha256:<64 lowercase hex characters>.
[[nodiscard]] auto
valid_immutable_container_image(std::string_view reference, std::string_view digest) noexcept
    -> bool;

} // namespace glove::container
