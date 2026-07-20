include_guard(GLOBAL)

include(FetchContent)

# glaze: header-only JSON / JSON-RPC library used by glove_mcp.
# Pinned by tag for reproducibility. SYSTEM downgrades glaze's own warnings so
# the project's -Werror does not pick them up.
FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG        v7.5.0
    GIT_SHALLOW    TRUE
    SYSTEM
    EXCLUDE_FROM_ALL
)

FetchContent_MakeAvailable(glaze)
