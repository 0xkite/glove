#include "doctor_wire.hpp"

#include <glaze/glaze.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace glove::host::doctor_wire {

namespace {

auto status_name(doctor_status value) -> std::string_view {
    switch (value) {
    case doctor_status::passed:
        return "passed";
    case doctor_status::warning:
        return "warning";
    case doctor_status::failed:
        return "failed";
    }
    return "failed";
}

} // namespace

auto encode_report(const doctor_report& report) -> result<std::string> {
    doctor_report_wire encoded{
        .config_path = report.config_path.string(),
        .healthy = report.healthy(),
        .checks = {},
    };
    encoded.checks.reserve(report.checks.size());
    for (const auto& check : report.checks) {
        encoded.checks.push_back({
            .code = check.code,
            .status = std::string{status_name(check.status)},
            .message = check.message,
            .recovery = check.recovery,
        });
    }
    auto output = glz::write_json(encoded);
    if (!output) {
        return std::unexpected(std::string{"encode doctor report"});
    }
    return std::move(*output);
}

} // namespace glove::host::doctor_wire
