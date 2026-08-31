#pragma once

#include "glove/control/receipt_audit_unix_server.hpp"

#include <sys/types.h>

#include <expected>
#include <string>
#include <string_view>

namespace glove::control::detail {

// Private test seam for the mandatory same-owner peer-credential check. The
// production listener always supplies its effective uid; callers cannot
// configure or bypass that authority boundary.
[[nodiscard]] auto verify_peer_owner(int descriptor, ::uid_t expected_owner)
    -> std::expected<void, std::string>;

// Private test seam for connection-scoped delivery degradation. Called only
// after `handle_frame` authenticated and applied a request whose response
// could not be written back to the client. Degrades the request's session
// (tears down a guest launched by `start_session`) and records one bounded
// structured `control` audit event; never throws and never fails the daemon.
auto degrade_failed_delivery(
    const receipt_audit_unix_server_config& config,
    std::string_view frame,
    std::string_view transport_error
) -> void;

} // namespace glove::control::detail
