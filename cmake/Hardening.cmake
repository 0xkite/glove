include_guard(GLOBAL)

include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckLinkerFlag)

# glove_apply_hardening(<interface-target>)
#
# Adds exploit mitigations and standard-library precondition checks when
# GLOVE_HARDENING is ON. Every flag is probed, so an unsupported one is left
# out and reported instead of failing the build. docs/toolchain.md lists what
# each flag does.
#
# With a sanitizer only the library checks are added: the sanitizers already
# instrument the stack, _FORTIFY_SOURCE conflicts with ASan's interceptors,
# and zero-initialized locals would hide what MemorySanitizer looks for.
function(glove_apply_hardening target)
    set(applied "")
    if(NOT GLOVE_HARDENING)
        set(GLOVE_HARDENING_APPLIED "off" PARENT_SCOPE)
        return()
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "GLOVE_HARDENING ignored: unsupported compiler")
        set(GLOVE_HARDENING_APPLIED "none (unsupported compiler)" PARENT_SCOPE)
        return()
    endif()

    # Library precondition checks: out-of-bounds operator[], front() on an
    # empty container, and similar, abort instead of being undefined.
    check_cxx_source_compiles(
        "#include <version>\n#ifndef _LIBCPP_VERSION\n#error not libc++\n#endif\nint main() { return 0; }"
        GLOVE_STDLIB_IS_LIBCXX
    )
    if(GLOVE_STDLIB_IS_LIBCXX)
        set(_glove_saved_definitions "${CMAKE_REQUIRED_DEFINITIONS}")
        list(APPEND CMAKE_REQUIRED_DEFINITIONS
            "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST")
        check_cxx_source_compiles(
            "#include <vector>\n#if _LIBCPP_HARDENING_MODE != _LIBCPP_HARDENING_MODE_FAST\n#error hardening mode not applied\n#endif\nint main() { std::vector<int> v{1}; return v[0] - 1; }"
            GLOVE_HAS_LIBCXX_HARDENING_MODE
        )
        set(CMAKE_REQUIRED_DEFINITIONS "${_glove_saved_definitions}")
        if(GLOVE_HAS_LIBCXX_HARDENING_MODE)
            target_compile_definitions(${target} INTERFACE
                _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST)
            list(APPEND applied "libc++ hardening (fast)")
        endif()
    else()
        target_compile_definitions(${target} INTERFACE _GLIBCXX_ASSERTIONS)
        list(APPEND applied "_GLIBCXX_ASSERTIONS")
    endif()

    if(GLOVE_SANITIZER AND NOT GLOVE_SANITIZER STREQUAL "none")
        list(JOIN applied ", " applied_text)
        set(GLOVE_HARDENING_APPLIED "${applied_text} (sanitizer build)" PARENT_SCOPE)
        return()
    endif()

    foreach(flag IN ITEMS
            -fstack-protector-strong
            -fstack-clash-protection
            -ftrivial-auto-var-init=zero
            -fcf-protection=full
            -mbranch-protection=standard)
        string(MAKE_C_IDENTIFIER "GLOVE_HAS_FLAG_${flag}" flag_id)
        # -Werror turns "argument unused on this target" into a failed probe.
        set(_glove_saved_flags "${CMAKE_REQUIRED_FLAGS}")
        string(APPEND CMAKE_REQUIRED_FLAGS " -Werror")
        check_cxx_compiler_flag("${flag}" ${flag_id})
        set(CMAKE_REQUIRED_FLAGS "${_glove_saved_flags}")
        if(${flag_id})
            target_compile_options(${target} INTERFACE "${flag}")
            list(APPEND applied "${flag}")
        endif()
    endforeach()

    # glibc's checked libc calls need optimization; Apple's SDK sets its own
    # level. A toolchain default is undefined first so ours is not a
    # redefinition.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(${target} INTERFACE
            "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>"
            "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
        list(APPEND applied "_FORTIFY_SOURCE=3 (optimized builds)")

        foreach(flag IN ITEMS "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack")
            string(MAKE_C_IDENTIFIER "GLOVE_HAS_LINK_FLAG_${flag}" flag_id)
            check_linker_flag(CXX "${flag}" ${flag_id})
            if(${flag_id})
                target_link_options(${target} INTERFACE "${flag}")
                list(APPEND applied "${flag}")
            endif()
        endforeach()
    endif()

    list(JOIN applied ", " applied_text)
    set(GLOVE_HARDENING_APPLIED "${applied_text}" PARENT_SCOPE)
endfunction()
