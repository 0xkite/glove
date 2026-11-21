---
name: cpp26-p2996-reflection
description: Author, build, and verify C++26 P2996/P3394 reflection-driven MCP tool bindings in Glove offline using GCC 16+ (-std=c++26 -freflection) or fallback C++23 hosts.
---

# C++26 P2996/P3394 Reflection in Glove

Use this skill whenever adding or modifying reflection-driven MCP tool descriptors,
annotations, or CMake reflection detection in this repository.

## Offline Reference
- Canonical repo doc: `docs/cpp26-reflection.md`
- Header: `include/glove/reflect/codegen.hpp`
- Test: `tests/reflect/codegen_test.cpp` (`reflect_codegen`)

## Rules (Verified on GCC 16.2.1 + Clang 23.1.5)
1. **Tri-state CMake option**: Keep `GLOVE_REFLECTION` as `AUTO|ON|OFF` (default `OFF`).
   - `AUTO` probes `-freflection` (GCC 16+) and `-freflection-latest` (clang-p2996)
     under `CMAKE_CXX_STANDARD=26` with `#include <meta>` / `<experimental/meta>`.
   - Hosts without P2996 (Clang 18, Apple Clang) must still configure and pass
     `reflect_codegen` via the `!glove::reflect::reflection_available` fallback.
2. **Structural annotations only (P3394)**:
   - Never put `std::string_view` or `std::string` inside `[[=...]]` annotation structs
     (`libstdc++` `string_view` has private `_M_len` and fails structural-type checks).
   - Use `glove::reflect::fixed_string<N>` + CTAD (`tool_meta`, `param_meta`).
3. **Standard `<meta>` API**:
   - Use `std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::current())`.
   - Use `std::meta::type_of(m)` (not `typename_of`).
   - Expand `std::meta::annotations_of(target)` via `std::define_static_array(...)`
     inside `template for`, match `std::meta::template_of(type_of(ann))`, and copy
     extracted strings into `std::string` (never return a `std::string_view` to an
     `extract` temporary).

## Verification Commands
1. **Reflection-enabled lane (GCC 16+)**:
   ```sh
   cmake -S <glove-src> -B <build-refl> -G Ninja \
     -DCMAKE_CXX_COMPILER=/usr/bin/g++ -DGLOVE_REFLECTION=ON \
     -DFETCHCONTENT_SOURCE_DIR_GLAZE=<local-glaze-src>
   cmake --build <build-refl> --target reflect_codegen_test --parallel 2
   ctest --test-dir <build-refl> --output-on-failure -R '^reflect_codegen$'
   ```
2. **Fallback lane (Clang / non-P2996)**:
   ```sh
   cmake -S <glove-src> -B <build-clang> -G Ninja \
     -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DGLOVE_REFLECTION=AUTO \
     -DFETCHCONTENT_SOURCE_DIR_GLAZE=<local-glaze-src>
   cmake --build <build-clang> --target reflect_codegen_test --parallel 2
   ctest --test-dir <build-clang> --output-on-failure -R '^reflect_codegen$'
   ```
