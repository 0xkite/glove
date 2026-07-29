add_library(glove_container STATIC
    output_pump.cpp
    profile.cpp
    receipt_chain.cpp
    receipt_journal.cpp
    receipt_producer.cpp
    resource_monitor.cpp
)
add_library(glove::container ALIAS glove_container)

target_link_libraries(glove_container PUBLIC glove_options glove_digest PRIVATE glaze::glaze)
target_include_directories(glove_container
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

if(APPLE)
    target_sources(glove_container PRIVATE macos/sandbox_spawner.cpp)

    # Sanitized test agents load one compiler runtime dylib before main().  A
    # deny-default sandbox must grant that exact image or the loader terminates
    # the child before the transport is established.  Keep this build-only
    # exception narrower than the compiler resource directory.
    if(GLOVE_SANITIZER MATCHES "^address")
        set(glove_sanitizer_runtime_name "libclang_rt.asan_osx_dynamic.dylib")
    elseif(GLOVE_SANITIZER STREQUAL "thread")
        set(glove_sanitizer_runtime_name "libclang_rt.tsan_osx_dynamic.dylib")
    endif()
    if(DEFINED glove_sanitizer_runtime_name)
        execute_process(
            COMMAND ${CMAKE_CXX_COMPILER} -print-resource-dir
            OUTPUT_VARIABLE glove_compiler_resource_dir
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE glove_resource_dir_result
        )
        if(NOT glove_resource_dir_result EQUAL 0)
            message(FATAL_ERROR "Unable to locate the compiler sanitizer runtime")
        endif()
        set(glove_sanitizer_runtime
            "${glove_compiler_resource_dir}/lib/darwin/${glove_sanitizer_runtime_name}"
        )
        if(NOT EXISTS "${glove_sanitizer_runtime}")
            message(FATAL_ERROR "Sanitizer runtime not found: ${glove_sanitizer_runtime}")
        endif()
        target_compile_definitions(glove_container
            PRIVATE GLOVE_SANITIZER_RUNTIME_PATH="${glove_sanitizer_runtime}"
        )
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(glove_container PRIVATE
        linux/cgroup_v2.cpp
        linux/clone_spawner.cpp
        linux/linux_egress_bridge.cpp
        linux/linux_resource_lifecycle.cpp
        linux/managed_launch_binding.cpp
        linux/pty_session_channel.cpp
    )
    target_link_libraries(glove_container PRIVATE glove_supervisor)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSECCOMP REQUIRED libseccomp)
    target_include_directories(glove_container PRIVATE ${LIBSECCOMP_INCLUDE_DIRS})
    target_link_libraries(glove_container PRIVATE ${LIBSECCOMP_LIBRARIES})
    target_link_directories(glove_container PRIVATE ${LIBSECCOMP_LIBRARY_DIRS})
    message(STATUS "  libseccomp           : ${LIBSECCOMP_VERSION}")
endif()

# The synthetic agent is its own executable, used by container tests as a
# trivial agent that reads MCP frames from stdin and writes responses to
# stdout. The platform spawner contains it; direct macOS test launches retain
# a deny-all-except-pipe fallback.
add_executable(glove_synthetic_agent synthetic_agent.cpp)
target_link_libraries(glove_synthetic_agent PRIVATE glove_options)
