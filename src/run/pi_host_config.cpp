#include "glove/run/pi_host_config.hpp"

namespace glove::run {

auto pi_local_package_sources(
    std::string_view, const std::filesystem::path&, const std::filesystem::path&
) -> std::expected<std::vector<pi_local_package>, std::string> {
    return std::unexpected(std::string{"not implemented"});
}

auto pi_package_exposure(
    const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&
) -> std::expected<std::filesystem::path, std::string> {
    return std::unexpected(std::string{"not implemented"});
}

auto rewrite_pi_settings_packages(std::string_view, const std::map<std::string, std::string>&)
    -> std::expected<std::string, std::string> {
    return std::unexpected(std::string{"not implemented"});
}

auto scrub_pi_models_credentials(std::string_view) -> std::expected<std::string, std::string> {
    return std::unexpected(std::string{"not implemented"});
}

} // namespace glove::run
