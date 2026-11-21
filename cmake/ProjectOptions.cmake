include_guard(GLOBAL)

# OFF by default so every host compiles the same language standard (C++23).
# AUTO and ON compile every target as C++26 where the compiler supports it.
set(GLOVE_REFLECTION "OFF" CACHE STRING
    "C++26 P2996 reflection mode: OFF|AUTO|ON (AUTO enables when compiler supports <meta>)")
set_property(CACHE GLOVE_REFLECTION PROPERTY STRINGS AUTO ON OFF)
option(GLOVE_WITH_GHOSTTY     "Build the libghostty terminal frontend"                       OFF)
option(GLOVE_WARNINGS_AS_ERRORS "Treat warnings as errors"                                   OFF)
option(GLOVE_ENABLE_SAGE_INTEROP_TEST
    "Run the Sage Rust client against the real Glove receipt server fixture"
    OFF
)
option(GLOVE_BUILD_BENCHMARKS
    "Build reproducible research-facing benchmark executables"
    OFF
)
option(GLOVE_BUILD_FUZZERS
    "Build sanitizer-backed libFuzzer targets"
    OFF
)

set(GLOVE_SANITIZER "none" CACHE STRING
    "Sanitizer to enable: none|address|address+undefined|thread|memory")
set_property(CACHE GLOVE_SANITIZER PROPERTY STRINGS
    none address "address+undefined" thread memory)
