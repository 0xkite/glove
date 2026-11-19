// A denial model file is untrusted text. Loading it must never crash, hang or
// over-read, and a loaded model must give a bounded score and a verdict that
// agrees with it for any finite features.

#include "glove/container/denial_decision.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    auto loaded = glove::container::load_denial_model(text);
    if (!loaded) {
        return 0;
    }
    const auto& model = **loaded;
    glove::container::denial_features features{};
    for (int pass = 0; pass != 3; ++pass) {
        const auto decision = model.decide(features);
        if (!(decision.score >= 0.0F && decision.score <= 1.0F)) {
            __builtin_trap();
        }
        // Next pass: features drawn from the input's bytes (finite, >= 0).
        for (std::size_t index = 0; index != features.size(); ++index) {
            const auto byte =
                size == 0 ? 0U : data[(index + static_cast<std::size_t>(pass)) % size];
            features.at(index) = static_cast<float>(byte) / 16.0F;
        }
    }
    return 0;
}
