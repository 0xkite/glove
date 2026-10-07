add_library(glove_net STATIC
    credentialed_endpoint.cpp
    egress_proxy.cpp
    http1_client.cpp
    tls_forwarder.cpp
)
add_library(glove::net ALIAS glove_net)

# The provider transport uses the platform's own TLS stack and trust store:
# Network.framework on macOS, the system OpenSSL elsewhere. Both stay PRIVATE
# so the public net headers carry no TLS dependency.
if(APPLE)
    target_sources(glove_net PRIVATE tls_stream_apple.cpp)
    target_link_libraries(glove_net PRIVATE "-framework Network" "-framework Security")
else()
    find_package(OpenSSL 3 REQUIRED)
    target_sources(glove_net PRIVATE tls_stream_openssl.cpp)
    target_link_libraries(glove_net PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_link_libraries(glove_net
    PUBLIC
        glove_options
)
target_include_directories(glove_net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
