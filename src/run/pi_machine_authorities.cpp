#include "pi_machine_authorities.hpp"

#include "../host/config_codec.hpp"
#include "pi_runtime_internal.hpp"

#if defined(__APPLE__)
#    include <mach-o/dyld.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>

namespace glove::run::detail {
namespace {
auto bounded_authority(const std::filesystem::path& path) -> bool {
    return !path.empty() && path.is_absolute() && path != path.root_path() &&
           path.lexically_normal() == path && path.native().size() <= 4096U &&
           !path.native().contains('\0');
}
} // namespace

auto pi_source_authorities(
    const host::directories& directories, std::span<const std::filesystem::path> additional
) -> std::expected<std::vector<std::filesystem::path>, std::string> {
    if (additional.size() > 64U || !std::ranges::all_of(additional, bounded_authority)) {
        return std::unexpected("Pi machine authorities exceed bounds");
    }
    std::vector<std::filesystem::path> roots{
        directories.config,
        directories.state,
        directories.data,
        directories.cache,
        directories.runtime
    };
    roots.insert(roots.end(), additional.begin(), additional.end());
    std::ranges::sort(roots);
    const auto repeated = std::ranges::unique(roots);
    roots.erase(repeated.begin(), repeated.end());
    if (roots.size() > 64U || !std::ranges::all_of(roots, bounded_authority)) {
        return std::unexpected("Pi machine authorities exceed bounds");
    }
    return roots;
}

auto load_pi_machine_authorities(const host::directories& directories)
    -> std::expected<std::vector<std::filesystem::path>, std::string> {
    std::vector<std::filesystem::path> roots;
#if defined(__APPLE__)
    // Native Pi cannot copy the running kernel even if it lies outside HOME.
    std::array<char, 4096> executable{};
    auto size = static_cast<std::uint32_t>(executable.size());
    if (::_NSGetExecutablePath(executable.data(), &size) != 0) {
        return std::unexpected("cannot bound the host executable authority");
    }
    std::error_code error;
    auto canonical = std::filesystem::canonical(executable.data(), error);
    if (error || !bounded_authority(canonical)) {
        return std::unexpected("cannot resolve the host executable authority");
    }
    roots.push_back(std::move(canonical));
#endif
    auto contents = read_pi_operator_file(host::default_config_path(directories));
    if (!contents) {
        return std::unexpected("unsafe host control configuration: " + contents.error());
    }
    if (*contents) {
        auto config = host::detail::decode_config(**contents);
        if (!config) {
            return std::unexpected("unsafe host control configuration: " + config.error());
        }
        roots.insert(
            roots.end(), {config->runtime_directory, config->audit_key, config->receipt_journal}
        );
        for (const auto* optional :
             {&config->session_policy,
              &config->session_store,
              &config->materialization_root,
              &config->library_bundle_root,
              &config->path_exposure_policy,
              &config->path_exposure_journal}) {
            if (*optional) {
                roots.push_back(**optional);
            }
        }
        if (config->remote_backend) {
            roots.push_back(config->remote_backend->identity_file);
            roots.push_back(config->remote_backend->staging_root);
        }
        if (config->apple_container) {
            roots.push_back(config->apple_container->cli);
        }
        if (config->local_service_proxy) {
            for (const auto& endpoint : config->local_service_proxy->endpoints) {
                roots.push_back(endpoint.socket_path);
            }
        }
    }
    return pi_source_authorities(directories, roots);
}

} // namespace glove::run::detail
