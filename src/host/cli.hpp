#pragma once

#include <span>

namespace glove::host {

auto setup_command(std::span<char* const> arguments) -> int;
auto doctor_command(std::span<char* const> arguments) -> int;
auto config_command(std::span<char* const> arguments) -> int;
auto init_command(std::span<char* const> arguments) -> int;

} // namespace glove::host
