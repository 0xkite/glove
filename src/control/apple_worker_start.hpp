#pragma once

#include <exception>
#include <expected>
#include <functional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

namespace glove::control::apple_detail::detail {

template<typename Launcher, typename SamplerBody, typename FinalizerBody>
[[nodiscard]] auto start_sampler_then_finalizer(
    std::jthread& sampler,
    std::jthread& finalizer,
    Launcher& launch,
    SamplerBody&& sampler_body,
    FinalizerBody&& finalizer_body
) -> std::expected<void, std::string> {
    const auto stop_and_join = [&] {
        sampler.request_stop();
        if (sampler.joinable()) {
            sampler.join();
        }
        if (finalizer.joinable()) {
            finalizer.join();
        }
    };
    try {
        sampler = std::invoke(launch, std::forward<SamplerBody>(sampler_body));
        finalizer = std::invoke(launch, std::forward<FinalizerBody>(finalizer_body));
        return {};
    } catch (const std::exception& error) {
        stop_and_join();
        return std::unexpected(error.what());
    } catch (...) {
        stop_and_join();
        return std::unexpected(std::string{"unknown Apple worker launch failure"});
    }
}

} // namespace glove::control::apple_detail::detail
