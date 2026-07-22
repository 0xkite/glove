#include "glove/supervisor/change_manifest.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

constexpr std::size_t maximum_manifest_bytes = 1024U * 1024U;

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_manifest_bytes) {
        return 0;
    }

    // Pass the untrusted span directly to the public decoder. The decoder is
    // responsible for creating any storage the parser requires.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view manifest_json{reinterpret_cast<const char*>(data), size};
    static_cast<void>(glove::supervisor::decode_retained_change_manifest_json(manifest_json));
    return 0;
}
