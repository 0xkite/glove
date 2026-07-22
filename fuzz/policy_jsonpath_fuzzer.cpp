#include "glove/policy/engine.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace {

constexpr std::size_t maximum_arguments_bytes = 1024U * 1024U;

auto constrained_engine() -> const glove::policy::engine& {
    static const auto instance = glove::policy::make_jsonpath_engine({
        .allow = {"fs.read_file"},
        .deny = {},
        .prefix_rules = {
            {
                .tool_name = "fs.read_file",
                .field = "path",
                .required_prefix = "/workspace/",
            },
        },
    });
    return *instance;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_arguments_bytes) {
        return 0;
    }

    // libFuzzer owns this byte span for the callback. Pass the untrusted span
    // directly to the policy boundary to verify its parser owns its input.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view arguments_json{reinterpret_cast<const char*>(data), size};
    static_cast<void>(constrained_engine().check("fs.read_file", arguments_json));
    return 0;
}
