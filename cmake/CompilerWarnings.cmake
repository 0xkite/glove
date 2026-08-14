include_guard(GLOBAL)

include(CheckCXXCompilerFlag)

# glove_set_warnings(<target>)
# Attach the project warning set to <target>. <target> may be INTERFACE.
function(glove_set_warnings target)
    set(clang_warnings
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wmissing-declarations
        -Wzero-as-null-pointer-constant
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        check_cxx_compiler_flag(
            "-Wmissing-designated-field-initializers"
            GLOVE_HAS_MISSING_DESIGNATED_FIELD_INITIALIZERS
        )
        if(GLOVE_HAS_MISSING_DESIGNATED_FIELD_INITIALIZERS)
            list(APPEND clang_warnings -Wmissing-designated-field-initializers)
        else()
            list(APPEND clang_warnings -Wmissing-field-initializers)
        endif()
    endif()

    set(gcc_warnings
        ${clang_warnings}
        -Wmisleading-indentation
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
        -Wuseless-cast
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(warnings ${clang_warnings})
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(warnings ${gcc_warnings})
    else()
        set(warnings "")
    endif()

    if(GLOVE_WARNINGS_AS_ERRORS)
        list(APPEND warnings -Werror)
    endif()

    get_target_property(target_type ${target} TYPE)
    if(target_type STREQUAL "INTERFACE_LIBRARY")
        target_compile_options(${target} INTERFACE ${warnings})
    else()
        target_compile_options(${target} PRIVATE ${warnings})
    endif()
endfunction()
