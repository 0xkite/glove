if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "GLOVE_BUILD_FUZZERS requires Clang libFuzzer support")
endif()

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
target_compile_options(glove_mcp_codec_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_mcp_codec_fuzzer PRIVATE -fsanitize=fuzzer)

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
target_compile_options(glove_policy_jsonpath_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_policy_jsonpath_fuzzer PRIVATE -fsanitize=fuzzer)

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
target_compile_options(glove_change_manifest_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_change_manifest_fuzzer PRIVATE -fsanitize=fuzzer)

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
target_compile_options(glove_session_plan_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_session_plan_fuzzer PRIVATE -fsanitize=fuzzer)

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
target_compile_options(glove_change_apply_journal_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_change_apply_journal_fuzzer PRIVATE -fsanitize=fuzzer)

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
target_compile_options(glove_library_bundle_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(glove_library_bundle_fuzzer PRIVATE -fsanitize=fuzzer)
