include_guard(GLOBAL)

include(FetchContent)

# glaze: header-only JSON / JSON-RPC library used by glove_mcp.
# Pinned by commit: a tag can be moved upstream, a commit cannot. This is
# the commit tag v7.5.0 named when it was pinned. No GIT_SHALLOW, because a
# shallow clone cannot be relied on to contain an arbitrary commit. SYSTEM
# downgrades glaze's own warnings so the project's -Werror does not pick
# them up.
FetchContent_Declare(
    glaze
    GIT_REPOSITORY https://github.com/stephenberry/glaze.git
    GIT_TAG        8b60d82c66311c145c4d03be3b556b555a9cb111 # v7.5.0
    SYSTEM
    EXCLUDE_FROM_ALL
)

FetchContent_MakeAvailable(glaze)
