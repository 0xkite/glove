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
// could not be written back to the client. Acts ONLY on the structured
// authenticated/applied outcome metadata produced by the real dispatch: a
// genuinely applied `start_session` is degraded (guest torn down through the
// normal stop path); every other outcome records one bounded structured
// `control` audit event and never touches session state. Never throws and
// never fails the daemon.
auto degrade_failed_delivery(
    const receipt_audit_unix_server_config& config,
    const receipt_control_outcome& outcome,
    std::string_view transport_error
) -> void;

} // namespace glove::control::detail
