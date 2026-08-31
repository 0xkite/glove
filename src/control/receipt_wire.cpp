#include "receipt_wire.hpp"

#include "receipt_audit_wire.hpp"

#include <glaze/glaze.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace glove::control::wire {

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

template<typename Value>
auto decode_strict(std::string_view input) -> std::expected<Value, std::string> {
    Value value{};
    if (const auto error = glz::read<strict_read_options>(value, input); error) {
        return std::unexpected(glz::format_error(error, input));
    }
    return value;
}

} // namespace

auto decode_rpc_request(std::string_view input) -> std::expected<rpc_request, std::string> {
    return decode_strict<rpc_request>(input);
}

auto decode_rpc_params(std::string_view input) -> std::expected<rpc_params, std::string> {
    return decode_strict<rpc_params>(input);
}

auto encode_rpc_response(const rpc_response& response) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(response);
    if (!encoded) {
        return std::unexpected(
            std::string{"control response encode: "} +
            glz::format_error(encoded.error(), std::string{})
        );
    }
    return std::move(*encoded);
}

} // namespace glove::control::wire
