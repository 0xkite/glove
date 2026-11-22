include_guard(GLOBAL)

# glove_apply_coverage(<interface-target>)
#
# Clang source-based coverage for scripts/coverage.sh. It measures which
# regions the tests execute; it says nothing about whether they are checked.
function(glove_apply_coverage target)
    if(NOT GLOVE_COVERAGE)
        return()
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "GLOVE_COVERAGE requires Clang (llvm-cov source-based coverage)")
    endif()
    if(GLOVE_SANITIZER AND NOT GLOVE_SANITIZER STREQUAL "none")
        message(FATAL_ERROR "GLOVE_COVERAGE cannot be combined with GLOVE_SANITIZER")
    endif()
    set(flags -fprofile-instr-generate -fcoverage-mapping)
    target_compile_options(${target} INTERFACE ${flags})
    target_link_options(${target} INTERFACE ${flags})
endfunction()
