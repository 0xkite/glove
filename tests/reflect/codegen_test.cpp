#include "glove/reflect/codegen.hpp"

#include <cassert>

#if defined(GLOVE_HAS_REFLECTION)
#    include <cstdint>
#    include <optional>
#    include <string>
#    include <vector>

namespace {

struct[[= glove::reflect::tool_meta{"read_elf", "Inspect ELF headers of a pinned binary"}]]
    read_elf_args {
    [[= glove::reflect::param_meta{
        "path", "Read-only quarantined artifact path", true
    }]] std::string path;
    [[= glove::reflect::param_meta{"sections", "Include section table", false}]] bool sections =
        false;
    [[= glove::reflect::param_meta{
        "max_symbols", "Maximum symbol entries", false
    }]] std::optional<std::uint32_t>
        max_symbols;
    std::vector<std::string> extra_flags;
};

} // namespace
#endif

int main() {
#if defined(GLOVE_HAS_REFLECTION)
    static_assert(glove::reflect::reflection_available);

    const auto descriptor = glove::reflect::descriptor_of<read_elf_args>();
    assert(descriptor.name == "read_elf");
    assert(descriptor.description == "Inspect ELF headers of a pinned binary");

    const std::string expected_schema =
        R"({"type":"object","properties":{"path":{"type":"string","description":"Read-only quarantined artifact path"},"sections":{"type":"boolean","description":"Include section table"},"max_symbols":{"type":"integer","description":"Maximum symbol entries"},"extra_flags":{"type":"array","items":{"type":"string"}}},"required":["path","extra_flags"]})";
    assert(descriptor.input_schema_json == expected_schema);
    assert(glove::reflect::input_schema_of<read_elf_args>() == expected_schema);
#else
    static_assert(!glove::reflect::reflection_available);
#endif
    return 0;
}
