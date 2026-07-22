add_executable(glove_mcp_benchmark mcp_benchmark.cpp)
target_link_libraries(glove_mcp_benchmark PRIVATE glove_mcp glaze::glaze)
target_include_directories(glove_mcp_benchmark PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>
)
