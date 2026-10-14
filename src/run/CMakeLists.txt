add_library(glove_run STATIC
    runner.cpp
    provider_endpoint.cpp
    pi_selection.cpp
    pi_guest_config.cpp
    pi_catalog.cpp
    pi_private_state.cpp
    pi_runtime.cpp
    pi_launch.cpp
    pi_audit.cpp
    pi_cli.cpp
    pi_machine_authorities.cpp
)
add_library(glove::run ALIAS glove_run)

target_link_libraries(glove_run
    PUBLIC
        glove_options
        glove::container
        glove::kernel
        glove::mcp
        glove::policy
        glove::audit
        glove::net
    PRIVATE
        glaze::glaze
        glove_host
)
target_include_directories(glove_run
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
