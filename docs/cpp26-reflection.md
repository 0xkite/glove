# C++26 P2996/P3394 Reflection in Glove (Offline Reference)

Glove uses C++26 static reflection (`P2996` + `P3394` annotations) in
`include/glove/reflect/codegen.hpp` to synthesize MCP `tool_descriptor`s and
JSON-Schema objects directly from annotated C++ argument structs, without
maintaining hand-written schema strings.

## Build Configuration (`GLOVE_REFLECTION`)

`GLOVE_REFLECTION` accepts `AUTO` (default), `ON`, or `OFF`:

- `AUTO` (default): `CMakeLists.txt` sets `CMAKE_CXX_STANDARD=26` and probes
  `-freflection` (GCC 16+) and `-freflection-latest` (clang-p2996) by compiling
  a `<meta>` / `<experimental/meta>` `std::meta::is_type(^^int)` check.
  - When supported, `GLOVE_HAS_REFLECTION=1` is defined and
    `glove::reflect::reflection_available` is `true`.
  - When unsupported (for example Clang 18 on `ubuntu-24.04` or Apple Clang on
    `macos-15`), CMake logs a status message and cleanly disables reflection
    (`glove::reflect::reflection_available` is `false`).
- `ON`: requires a P2996-capable compiler and fails CMake configuration if `<meta>`
  is unavailable.
- `OFF`: forces reflection off even when the host compiler supports it.

## Compiler & Standard-Library Requirements

Tested against **GCC 16.2.1** (`g++ -std=c++26 -freflection`):

1. **Header**: standard C++26 ships `<meta>` (`__has_include(<meta>)`); older
   experimental forks used `<experimental/meta>`.
2. **Access context**: `std::meta::nonstatic_data_members_of(^^T, ctx)` requires
   an explicit `std::meta::access_context::current()` argument.
3. **Member types**: `std::meta::type_of(member)` returns the reflected type
   (spliced via `typename[:std::meta::type_of(member):]`).
4. **Structural annotation types (P3394)**: every `[[=...]]` annotation value
   must have a structural type. `std::string_view` is **not** structural in
   `libstdc++` because its `_M_len` / `_M_str` fields are private. Use
   `glove::reflect::fixed_string<N>` (`char data[N]` public aggregate) with
   CTAD (`tool_meta{"name", "desc"}`, `param_meta{"label", "desc", required}`).
5. **Annotation inspection**: `std::meta::annotations_of(target)` returns
   `std::vector<std::meta::info>`. In `template for`, wrap it in
   `std::define_static_array(...)`, check `std::meta::has_template_arguments`
   and `std::meta::template_of(type_of(ann)) == ^^param_meta`, and extract the
   typed annotation via `std::meta::extract<typename[:ann_type:]>(ann)`. Never
   return a `std::string_view` into a temporary returned by `extract`—copy into
   `std::string` or use `std::define_static_string`.

## Authoring a Reflected MCP Tool Struct

```cpp
#include "glove/reflect/codegen.hpp"

struct [[= glove::reflect::tool_meta{"read_elf", "Inspect ELF headers"}]]
read_elf_args {
    [[= glove::reflect::param_meta{"path", "Pinned artifact path", true}]]
    std::string path;
    [[= glove::reflect::param_meta{"sections", "Include section table", false}]]
    bool sections = false;
    std::optional<std::uint32_t> max_symbols;
};

#if defined(GLOVE_HAS_REFLECTION)
auto desc = glove::reflect::descriptor_of<read_elf_args>();
#endif
```

Supported C++ field types in `input_schema_of<T>()`:
- `bool` -> `{"type":"boolean"}`
- integral types -> `{"type":"integer"}`
- floating-point types -> `{"type":"number"}`
- `std::string`, `std::string_view` -> `{"type":"string"}`
- `std::optional<U>` -> unwraps `U` and defaults `required` to `false`
- `std::vector<U>` -> `{"type":"array","items":<schema of U>}`
- other aggregates -> `{"type":"object"}`

## Local Verification (Offline)

```sh
cmake -S . -B build/refl-dev -G Ninja \
  -DCMAKE_CXX_COMPILER=/usr/bin/g++ \
  -DGLOVE_REFLECTION=ON
cmake --build build/refl-dev --target reflect_codegen_test
ctest --test-dir build/refl-dev --output-on-failure -R '^reflect_codegen$'
```
