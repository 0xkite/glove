#include "policy_wire.hpp"

#include <glaze/glaze.hpp>

#include <string>
#include <utility>

namespace glove::host::policy_wire {

namespace {

template<typename Report> auto encode_json(const Report& report) -> result<std::string> {
    auto encoded = glz::write_json(report);
    if (!encoded) {
        return std::unexpected(std::string{"encode policy report"});
    }
    return std::move(*encoded);
}

} // namespace

auto encode(const detection_report& report) -> result<std::string> {
    return encode_json(report);
}

auto encode(const stage_report& report) -> result<std::string> {
    return encode_json(report);
}

auto encode(const pi_adoption_report& report) -> result<std::string> {
    return encode_json(report);
}

auto encode(const validation_report& report) -> result<std::string> {
    return encode_json(report);
}

auto encode(const prepared_policy_report& report) -> result<std::string> {
    return encode_json(report);
}

auto encode(const onboarding_plan_report& report) -> result<std::string> {
    return encode_json(report);
}

} // namespace glove::host::policy_wire
