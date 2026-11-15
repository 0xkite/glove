#include "glove/reflect/codegen.hpp"

#include <iostream>

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
    auto require = [](bool cond, const char* expr) {
        if (!cond) {
            std::cerr << "reflect_codegen_test failed: " << expr << '\n';
            return false;
        }
        return true;
    };
#if defined(GLOVE_HAS_REFLECTION)
    static_assert(glove::reflect::reflection_available);

    const auto descriptor = glove::reflect::descriptor_of<read_elf_args>();
    if (!require(descriptor.name == "read_elf", "descriptor.name == read_elf")) {
        return 1;
    }
    if (!require(
            descriptor.description == "Inspect ELF headers of a pinned binary",
            "descriptor.description"
        )) {
        return 1;
    }

    const std::string expected_schema =
        R"({"type":"object","properties":{"path":{"type":"string","description":"Read-only quarantined artifact path"},"sections":{"type":"boolean","description":"Include section table"},"max_symbols":{"type":"integer","description":"Maximum symbol entries"},"extra_flags":{"type":"array","items":{"type":"string"}}},"required":["path","extra_flags"]})";
    if (!require(
            descriptor.input_schema_json == expected_schema,
            "descriptor.input_schema_json == expected_schema"
        )) {
        return 1;
    }
    if (!require(
            glove::reflect::input_schema_of<read_elf_args>() == expected_schema,
            "input_schema_of == expected_schema"
        )) {
        return 1;
    }
#else
    static_assert(!glove::reflect::reflection_available);
    (void)require;
#endif
    return 0;
}
