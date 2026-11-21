cmake_minimum_required(VERSION 3.28)

project(glove
    VERSION 0.0.1
    DESCRIPTION "Reflection-driven LLM agent sandbox"
    LANGUAGES CXX
)

include(GNUInstallDirs)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

# --- Global toolchain defaults ----------------------------------------------

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# Out-of-source enforcement
if(CMAKE_BINARY_DIR STREQUAL CMAKE_SOURCE_DIR)
    message(FATAL_ERROR
        "In-source builds are forbidden. Use a build/ subdir or a CMake preset.")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(ProjectOptions)
include(CompilerWarnings)
include(Sanitizers)
include(Hardening)

# Position-independent executables, so address-space layout randomization
# covers the program image. Directory scope: it must precede every target.
if(GLOVE_HARDENING)
    include(CheckPIESupported)
    check_pie_supported(LANGUAGES CXX)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
include(Dependencies)

# Optional ccache speedup
find_program(CCACHE_EXE ccache)
if(CCACHE_EXE)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXE}")
endif()

# --- Targets ----------------------------------------------------------------

# libc++ 18 exposes std::stop_token behind its supported experimental-library
# switch. Probe the facility first and add that switch only when required.
check_cxx_source_compiles(
    "#include <stop_token>\nint main() { std::stop_source source; return source.stop_possible() ? 0 : 1; }"
    GLOVE_HAS_STD_STOP_TOKEN
)
set(GLOVE_STOP_TOKEN_COMPILE_OPTION "")
if(NOT GLOVE_HAS_STD_STOP_TOKEN)
    check_cxx_compiler_flag("-fexperimental-library" GLOVE_HAS_EXPERIMENTAL_LIBRARY_FLAG)
    if(GLOVE_HAS_EXPERIMENTAL_LIBRARY_FLAG)
        set(_glove_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
        string(APPEND CMAKE_REQUIRED_FLAGS " -fexperimental-library")
        check_cxx_source_compiles(
            "#include <stop_token>\nint main() { std::stop_source source; return source.stop_possible() ? 0 : 1; }"
            GLOVE_HAS_EXPERIMENTAL_STD_STOP_TOKEN
        )
        set(CMAKE_REQUIRED_FLAGS "${_glove_saved_required_flags}")
    endif()
    if(NOT GLOVE_HAS_EXPERIMENTAL_STD_STOP_TOKEN)
        message(FATAL_ERROR "The configured C++ standard library does not provide std::stop_token")
    endif()
    set(GLOVE_STOP_TOKEN_COMPILE_OPTION "-fexperimental-library")
endif()

# Shared compile options carrier; INTERFACE so consumers inherit it
add_library(glove_options INTERFACE)
if(GLOVE_STOP_TOKEN_COMPILE_OPTION)
    target_compile_options(glove_options INTERFACE "${GLOVE_STOP_TOKEN_COMPILE_OPTION}")
endif()
glove_set_warnings(glove_options)
glove_apply_sanitizers(glove_options)
glove_apply_hardening(glove_options)
target_compile_features(glove_options INTERFACE cxx_std_23)

string(TOUPPER "${GLOVE_REFLECTION}" _glove_reflection_mode)
if(_glove_reflection_mode STREQUAL "1" OR _glove_reflection_mode STREQUAL "TRUE" OR _glove_reflection_mode STREQUAL "YES")
    set(_glove_reflection_mode "ON")
elseif(_glove_reflection_mode STREQUAL "0" OR _glove_reflection_mode STREQUAL "FALSE" OR _glove_reflection_mode STREQUAL "NO" OR _glove_reflection_mode STREQUAL "")
    set(_glove_reflection_mode "OFF")
elseif(NOT (_glove_reflection_mode STREQUAL "AUTO" OR _glove_reflection_mode STREQUAL "ON" OR _glove_reflection_mode STREQUAL "OFF"))
    message(FATAL_ERROR "GLOVE_REFLECTION must be AUTO, ON, or OFF (got '${GLOVE_REFLECTION}')")
endif()

set(GLOVE_REFLECTION_ENABLED OFF)
if(_glove_reflection_mode STREQUAL "AUTO" OR _glove_reflection_mode STREQUAL "ON")
    set(_glove_saved_cxx_standard "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 26)
    set(GLOVE_REFLECTION_COMPILE_OPTION "")
    foreach(_glove_refl_flag IN ITEMS "-freflection" "-freflection-latest")
        string(MAKE_C_IDENTIFIER "${_glove_refl_flag}" _glove_refl_id)
        check_cxx_compiler_flag("${_glove_refl_flag}" "GLOVE_HAS_FLAG_${_glove_refl_id}")
        if(GLOVE_HAS_FLAG_${_glove_refl_id})
            set(_glove_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
            string(APPEND CMAKE_REQUIRED_FLAGS " ${_glove_refl_flag}")
            check_cxx_source_compiles(
                "#if __has_include(<meta>)\n#include <meta>\n#else\n#include <experimental/meta>\n#endif\ntemplate<int N> struct probe_ann { int v = N; };\nstruct [[= probe_ann<1>{}]] probe_s { int x; };\nconsteval bool probe_ok() {\n  constexpr auto ms = std::define_static_array(std::meta::nonstatic_data_members_of(^^probe_s, std::meta::access_context::current()));\n  constexpr auto as = std::define_static_array(std::meta::annotations_of(^^probe_s));\n  if (ms.size() != 1 || as.size() != 1) return false;\n  return (std::meta::type_of(ms[0]) == ^^int) && std::meta::has_template_arguments(std::meta::type_of(as[0])) && (std::meta::template_of(std::meta::type_of(as[0])) == ^^probe_ann) && std::meta::extract<probe_ann<1>>(as[0]).v == 1;\n}\nint main() { return probe_ok() ? 0 : 1; }"
                "GLOVE_HAS_META_${_glove_refl_id}"
            )
            set(CMAKE_REQUIRED_FLAGS "${_glove_saved_required_flags}")
            if(GLOVE_HAS_META_${_glove_refl_id})
                set(GLOVE_REFLECTION_COMPILE_OPTION "${_glove_refl_flag}")
                break()
            endif()
        endif()
    endforeach()
    if(GLOVE_REFLECTION_COMPILE_OPTION)
        set(GLOVE_REFLECTION_ENABLED ON)
        target_compile_features(glove_options INTERFACE cxx_std_26)
        target_compile_options(glove_options INTERFACE "${GLOVE_REFLECTION_COMPILE_OPTION}")
        target_compile_definitions(glove_options INTERFACE GLOVE_HAS_REFLECTION=1)
    else()
        set(CMAKE_CXX_STANDARD "${_glove_saved_cxx_standard}")
        if(_glove_reflection_mode STREQUAL "ON")
            message(FATAL_ERROR
                "GLOVE_REFLECTION=ON requires C++26 P2996 reflection (-freflection on GCC 16+ or -freflection-latest on clang-p2996) with <meta>")
        else()
            message(STATUS "C++26 P2996 reflection not supported by ${CMAKE_CXX_COMPILER_ID}; disabling reflection")
        endif()
    endif()
endif()

add_subdirectory(src)

install(TARGETS glove RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(TARGET gloved)
    install(TARGETS gloved RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(TARGET glove-remote-exec)
    install(TARGETS glove-remote-exec RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
endif()
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
    FILES packaging/systemd/sage-gloved.service.in
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glove/packaging/systemd
)
install(
    FILES packaging/launchd/org.sage-protocol.gloved.plist.in
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glove/packaging/launchd
)
configure_file(
    packaging/compatibility.json.in
    ${CMAKE_CURRENT_BINARY_DIR}/compatibility.json
    @ONLY
)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/compatibility.json
        docs/host-setup.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glove
)
install(
    PROGRAMS scripts/apple-container-session.sh
    DESTINATION ${CMAKE_INSTALL_DATADIR}/glove/scripts
)

# --- Tests ------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# --- Benchmarks -------------------------------------------------------------

if(GLOVE_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# --- Fuzzers ----------------------------------------------------------------

if(GLOVE_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# --- Status ------------------------------------------------------------------

message(STATUS "glove ${PROJECT_VERSION}")
message(STATUS "  build type           : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard         : ${CMAKE_CXX_STANDARD}")
message(STATUS "  GLOVE_REFLECTION     : ${GLOVE_REFLECTION}")
message(STATUS "  GLOVE_WITH_GHOSTTY   : ${GLOVE_WITH_GHOSTTY}")
message(STATUS "  GLOVE_ENABLE_SAGE_INTEROP_TEST : ${GLOVE_ENABLE_SAGE_INTEROP_TEST}")
message(STATUS "  GLOVE_BUILD_BENCHMARKS : ${GLOVE_BUILD_BENCHMARKS}")
message(STATUS "  GLOVE_BUILD_FUZZERS  : ${GLOVE_BUILD_FUZZERS}")
message(STATUS "  GLOVE_SANITIZER      : ${GLOVE_SANITIZER}")
message(STATUS "  GLOVE_WARNINGS_AS_ERRORS : ${GLOVE_WARNINGS_AS_ERRORS}")
message(STATUS "  GLOVE_HARDENING      : ${GLOVE_HARDENING_APPLIED}")
