// A launch profile is operator-authored but still untrusted text. Parsing
// must never crash, hang, or over-read, and any profile that parses must
// encode to text that parses back to an equal profile and encodes the same
// way again, so `glove profile show` never prints a policy glove would read
// differently.

#include "glove/run/launch_profile.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    const auto parsed = glove::run::parse_launch_profile(text);
    if (!parsed) {
        return 0;
    }
    const auto encoded = glove::run::encode_launch_profile(*parsed);
    const auto reparsed = glove::run::parse_launch_profile(encoded);
    if (!reparsed || !(*reparsed == *parsed) ||
        glove::run::encode_launch_profile(*reparsed) != encoded) {
        __builtin_trap();
    }
    return 0;
}
