#pragma once

#include <span>

namespace glove::run {

// `glove profile list|new|edit|show|check|path`.
auto profile_command(std::span<char* const> arguments) -> int;

} // namespace glove::run
