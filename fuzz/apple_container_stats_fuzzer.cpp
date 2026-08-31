#include "apple_container_session_runtime.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    static_cast<void>(glove::control::apple_detail::parse_apple_container_stats(
        std::string_view{reinterpret_cast<const char*>(data), size}, "apple-unit"
    ));
    return 0;
}
