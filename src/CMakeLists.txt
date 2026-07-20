add_subdirectory(term)
add_subdirectory(mcp)
add_subdirectory(policy)
add_subdirectory(audit)
add_subdirectory(net)
add_subdirectory(host)

# Dependency-free content commitments are shared by supervisor planning and
# container receipts without joining their higher-level dependency graph.
add_library(glove_digest STATIC
    container/digest.cpp
    container/sha256.cpp
)
add_library(glove::digest ALIAS glove_digest)
target_link_libraries(glove_digest PUBLIC glove_options)
target_include_directories(glove_digest
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/container>
)

add_subdirectory(supervisor)
add_subdirectory(container)
add_subdirectory(control)
add_subdirectory(kernel)
add_subdirectory(run)

# glove_kernel is the umbrella the executable links against. It re-exports the
# module libraries via PUBLIC so each test can link a single target. Future
# modules (policy, extension) get added here.
add_library(glove_kernel INTERFACE)
target_link_libraries(glove_kernel
    INTERFACE
        glove_options
        glove::term
        glove::mcp
        glove::policy
        glove::audit
        glove::net
        glove::host
        glove::supervisor
        glove::container
        glove::control
        glove::kernel
        glove::run
)

add_executable(glove main.cpp)
target_link_libraries(glove PRIVATE glove_kernel)

if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(gloved gloved_main.cpp)
    target_link_libraries(gloved PRIVATE glove_control glove_host)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_include_directories(gloved PRIVATE
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
        )
    endif()
endif()
