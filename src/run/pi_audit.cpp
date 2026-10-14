#include "pi_audit.hpp"

namespace glove::run::detail {

auto make_pi_audit_sink(std::size_t max_events, std::size_t max_bytes)
    -> std::expected<std::shared_ptr<audit::sink>, std::string> {
    return make_native_audit_sink(max_events, max_bytes, "Pi");
}

} // namespace glove::run::detail
