cmake_minimum_required(VERSION 3.28)

project(glove
    VERSION 0.0.1
    DESCRIPTION "Reflection-driven LLM agent sandbox"
    LANGUAGES CXX
)

include(GNUInstallDirs)

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
include(Dependencies)

# Optional ccache speedup
find_program(CCACHE_EXE ccache)
if(CCACHE_EXE)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXE}")
endif()

# --- Targets ----------------------------------------------------------------

# Shared compile options carrier; INTERFACE so consumers inherit it
add_library(glove_options INTERFACE)
glove_set_warnings(glove_options)
glove_apply_sanitizers(glove_options)
target_compile_features(glove_options INTERFACE cxx_std_23)

if(GLOVE_REFLECTION)
    target_compile_features(glove_options INTERFACE cxx_std_26)
    target_compile_definitions(glove_options INTERFACE GLOVE_HAS_REFLECTION=1)
endif()

add_subdirectory(src)

install(TARGETS glove RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(TARGET gloved)
    install(TARGETS gloved RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
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
