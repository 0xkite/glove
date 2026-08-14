include_guard(GLOBAL)

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
        -Wmissing-designated-field-initializers
        -Wzero-as-null-pointer-constant
    )

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
