add_library(glove_net STATIC
    credentialed_endpoint.cpp
    egress_proxy.cpp
    http1_client.cpp
)
add_library(glove::net ALIAS glove_net)

target_link_libraries(glove_net
    PUBLIC
        glove_options
)
target_include_directories(glove_net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
