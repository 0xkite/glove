#pragma once

#include "glove/container/denial_telemetry.hpp"

#include "sandbox_denial_log.hpp"

#include <string_view>

namespace glove::container::detail {

[[nodiscard]] auto denial_kind_name(denial_class kind) noexcept -> std::string_view;

[[nodiscard]] auto to_sandbox_denial(const denial_event& event) -> glove::container::sandbox_denial;

} // namespace glove::container::detail
