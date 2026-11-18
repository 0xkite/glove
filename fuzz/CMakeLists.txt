if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "GLOVE_BUILD_FUZZERS requires Clang libFuzzer support")
endif()

set(GLOVE_FUZZER_COMPILE_FLAG "-fsanitize=fuzzer")
set(GLOVE_FUZZER_LINK_FLAG "-fsanitize=fuzzer")
set(GLOVE_FUZZER_RUNTIME_LIBRARIES)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_FLAGS MATCHES "-stdlib=libc\\+\\+")
    # Ubuntu packages libFuzzer with libstdc++, while Glove uses libc++ there
    # for complete C++23 support. Place the runtime before its ABI dependency;
    # Clang's automatic insertion otherwise puts it after all user libraries.
    set(GLOVE_FUZZER_COMPILE_FLAG "-fsanitize=fuzzer-no-link")
    set(GLOVE_FUZZER_LINK_FLAG)
    set(glove_fuzzer_runtime_name
        "libclang_rt.fuzzer-${CMAKE_SYSTEM_PROCESSOR}.a"
    )
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=${glove_fuzzer_runtime_name}
        OUTPUT_VARIABLE glove_fuzzer_runtime
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE glove_fuzzer_runtime_result
    )
    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=libstdc++.so
        OUTPUT_VARIABLE glove_fuzzer_libstdcxx
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE glove_fuzzer_libstdcxx_result
    )
    if(NOT glove_fuzzer_runtime_result EQUAL 0 OR NOT EXISTS "${glove_fuzzer_runtime}")
        message(FATAL_ERROR "unable to locate ${glove_fuzzer_runtime_name}")
    endif()
    if(NOT glove_fuzzer_libstdcxx_result EQUAL 0 OR NOT EXISTS "${glove_fuzzer_libstdcxx}")
        message(FATAL_ERROR "unable to locate libstdc++.so")
    endif()
    list(APPEND GLOVE_FUZZER_RUNTIME_LIBRARIES
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,${glove_fuzzer_runtime}>"
        "${glove_fuzzer_libstdcxx}"
    )
endif()

function(glove_configure_fuzzer target)
    target_compile_options(${target} PRIVATE "${GLOVE_FUZZER_COMPILE_FLAG}")
    if(GLOVE_FUZZER_LINK_FLAG)
        target_link_options(${target} PRIVATE "${GLOVE_FUZZER_LINK_FLAG}")
    endif()
    if(GLOVE_FUZZER_RUNTIME_LIBRARIES)
        target_link_libraries(${target} PRIVATE ${GLOVE_FUZZER_RUNTIME_LIBRARIES})
    endif()
endfunction()

add_library(glove_mcp_codec_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/mcp/codec.cpp
)
target_link_libraries(glove_mcp_codec_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_mcp_codec_fuzz_support PRIVATE glaze::glaze)
target_include_directories(glove_mcp_codec_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
target_compile_options(glove_mcp_codec_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_mcp_codec_fuzzer mcp_codec_fuzzer.cpp)
target_link_libraries(
    glove_mcp_codec_fuzzer
    PRIVATE glove_mcp_codec_fuzz_support glaze::glaze
)
target_include_directories(glove_mcp_codec_fuzzer PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
glove_configure_fuzzer(glove_mcp_codec_fuzzer)

add_library(glove_policy_jsonpath_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/policy/jsonpath_engine.cpp
)
target_link_libraries(glove_policy_jsonpath_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_policy_jsonpath_fuzz_support PRIVATE glaze::glaze)
target_include_directories(glove_policy_jsonpath_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_policy_jsonpath_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_policy_jsonpath_fuzzer policy_jsonpath_fuzzer.cpp)
target_link_libraries(
    glove_policy_jsonpath_fuzzer
    PRIVATE glove_policy_jsonpath_fuzz_support glaze::glaze
)
glove_configure_fuzzer(glove_policy_jsonpath_fuzzer)

add_library(glove_change_manifest_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/supervisor/change_manifest.cpp
)
target_link_libraries(glove_change_manifest_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_change_manifest_fuzz_support PRIVATE glaze::glaze glove_digest)
target_include_directories(glove_change_manifest_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_change_manifest_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_change_manifest_fuzzer change_manifest_fuzzer.cpp)
target_link_libraries(
    glove_change_manifest_fuzzer
    PRIVATE glove_change_manifest_fuzz_support glaze::glaze glove_digest
)
glove_configure_fuzzer(glove_change_manifest_fuzzer)

add_library(glove_session_plan_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/supervisor/session_plan.cpp
)
target_link_libraries(glove_session_plan_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_session_plan_fuzz_support PRIVATE glaze::glaze glove_supervisor)
target_include_directories(glove_session_plan_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_session_plan_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_session_plan_fuzzer session_plan_fuzzer.cpp)
target_link_libraries(
    glove_session_plan_fuzzer
    PRIVATE glove_session_plan_fuzz_support glove_supervisor glaze::glaze
)
glove_configure_fuzzer(glove_session_plan_fuzzer)

add_library(glove_change_apply_journal_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/supervisor/change_apply_journal.cpp
)
target_link_libraries(glove_change_apply_journal_fuzz_support PUBLIC glove_options)
target_link_libraries(
    glove_change_apply_journal_fuzz_support
    PRIVATE glaze::glaze glove_digest
)
target_include_directories(glove_change_apply_journal_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_change_apply_journal_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_change_apply_journal_fuzzer change_apply_journal_fuzzer.cpp)
target_link_libraries(
    glove_change_apply_journal_fuzzer
    PRIVATE glove_change_apply_journal_fuzz_support glaze::glaze glove_digest
)
glove_configure_fuzzer(glove_change_apply_journal_fuzzer)

add_library(glove_library_bundle_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/supervisor/library_bundle.cpp
)
target_link_libraries(glove_library_bundle_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_library_bundle_fuzz_support PRIVATE glove_digest)
target_include_directories(glove_library_bundle_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_library_bundle_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_library_bundle_fuzzer library_bundle_fuzzer.cpp)
target_link_libraries(
    glove_library_bundle_fuzzer
    PRIVATE glove_library_bundle_fuzz_support glove_digest
)
glove_configure_fuzzer(glove_library_bundle_fuzzer)

add_executable(glove_http_syntax_fuzzer http_syntax_fuzzer.cpp)
target_link_libraries(glove_http_syntax_fuzzer PRIVATE glove_options)
target_include_directories(glove_http_syntax_fuzzer PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
glove_configure_fuzzer(glove_http_syntax_fuzzer)

add_executable(glove_egress_proxy_fuzzer egress_proxy_fuzzer.cpp)
target_link_libraries(glove_egress_proxy_fuzzer PRIVATE glove_options)
target_include_directories(glove_egress_proxy_fuzzer PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
glove_configure_fuzzer(glove_egress_proxy_fuzzer)

add_library(glove_container_profile_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/container/profile.cpp
)
target_link_libraries(glove_container_profile_fuzz_support PUBLIC glove_options)
target_include_directories(glove_container_profile_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_compile_options(glove_container_profile_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_container_profile_fuzzer container_profile_fuzzer.cpp)
target_link_libraries(
    glove_container_profile_fuzzer
    PRIVATE glove_container_profile_fuzz_support
)
glove_configure_fuzzer(glove_container_profile_fuzzer)

add_library(glove_kernel_server_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/kernel/server.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/registry.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/mcp_extension.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/reflect_json_codec.cpp
    ${CMAKE_SOURCE_DIR}/src/policy/jsonpath_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/policy/allow_list_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/mcp/codec.cpp
    ${CMAKE_SOURCE_DIR}/src/mcp/client.cpp
    ${CMAKE_SOURCE_DIR}/src/mcp/jsonrpc_client.cpp
    ${CMAKE_SOURCE_DIR}/src/mcp/in_memory_transport.cpp
    ${CMAKE_SOURCE_DIR}/src/audit/memory_sink.cpp
)
target_link_libraries(glove_kernel_server_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_kernel_server_fuzz_support PRIVATE glaze::glaze)
target_include_directories(glove_kernel_server_fuzz_support
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
target_compile_options(glove_kernel_server_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_kernel_server_fuzzer kernel_server_fuzzer.cpp)
target_link_libraries(
    glove_kernel_server_fuzzer
    PRIVATE glove_kernel_server_fuzz_support glaze::glaze
)
target_include_directories(glove_kernel_server_fuzzer PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
glove_configure_fuzzer(glove_kernel_server_fuzzer)

add_library(glove_sandbox_denial_log_fuzz_support STATIC
    ${CMAKE_SOURCE_DIR}/src/container/sandbox_denial_log.cpp
)
target_link_libraries(glove_sandbox_denial_log_fuzz_support PUBLIC glove_options)
target_link_libraries(glove_sandbox_denial_log_fuzz_support PRIVATE glaze::glaze)
target_compile_options(glove_sandbox_denial_log_fuzz_support PRIVATE -fsanitize=fuzzer-no-link)

add_executable(glove_sandbox_denial_log_fuzzer sandbox_denial_log_fuzzer.cpp)
target_link_libraries(
    glove_sandbox_denial_log_fuzzer
    PRIVATE glove_sandbox_denial_log_fuzz_support
)
target_include_directories(glove_sandbox_denial_log_fuzzer PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container>
)
glove_configure_fuzzer(glove_sandbox_denial_log_fuzzer)

# The Apple Container stats parser is compiled only on Apple platforms
# (src/control/CMakeLists.txt), so this fuzzer only links there.
if(APPLE)
    add_executable(glove_apple_container_stats_fuzzer apple_container_stats_fuzzer.cpp)
    target_link_libraries(
        glove_apple_container_stats_fuzzer
        PRIVATE glove_control glaze::glaze
    )
    target_include_directories(glove_apple_container_stats_fuzzer PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
    )
    glove_configure_fuzzer(glove_apple_container_stats_fuzzer)
endif()
