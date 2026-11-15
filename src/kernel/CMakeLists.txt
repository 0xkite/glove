add_library(glove_kernel_lib STATIC
    registry.cpp
    server.cpp
    mcp_extension.cpp
    reflect_json_codec.cpp
)
add_library(glove::kernel ALIAS glove_kernel_lib)

target_link_libraries(glove_kernel_lib
    PUBLIC
        glove_options
        glove::mcp
        glove::policy
        glove::audit
)
target_link_libraries(glove_kernel_lib PRIVATE glaze::glaze)
target_include_directories(glove_kernel_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
