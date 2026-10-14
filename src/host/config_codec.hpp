#pragma once

#include "glove/host/config.hpp"

#include <string_view>

namespace glove::host::detail {

// Pure codec only. The caller separately admits and bounds its source bytes;
// decoding grants no path, file, credential or launch authority.
[[nodiscard]] auto decode_config(std::string_view contents) -> result<config>;

} // namespace glove::host::detail
