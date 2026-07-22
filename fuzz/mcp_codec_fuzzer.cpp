#include "src/mcp/codec.hpp"
#include "src/mcp/jsonrpc.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

constexpr std::size_t maximum_frame_bytes = 1024U * 1024U;

void exercise_response(std::string_view frame) {
    auto response = glove::mcp::codec::decode_response(frame);
    if (!response) {
        return;
    }

    static_cast<void>(glove::mcp::codec::parse_initialize_result(*response));
    static_cast<void>(glove::mcp::codec::parse_tools_list_result(*response));
    static_cast<void>(glove::mcp::codec::parse_tools_call_result(*response));
    static_cast<void>(glove::mcp::codec::parse_resources_list_result(*response));
    static_cast<void>(glove::mcp::codec::parse_prompts_list_result(*response));
}

void exercise_request(std::string_view frame) {
    static_cast<void>(glove::mcp::codec::decode_request(frame));
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_frame_bytes) {
        return 0;
    }

    // libFuzzer owns this byte span for the duration of the callback. The view
    // is non-owning and cannot escape either parser exercise.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view frame{reinterpret_cast<const char*>(data), size};
    exercise_response(frame);
    exercise_request(frame);
    return 0;
}
