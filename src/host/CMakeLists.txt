add_library(glove_host STATIC
    cli.cpp
    config.cpp
    control_client.cpp
    daemon.cpp
    doctor.cpp
    operator_experience.cpp
    runtime_policy.cpp
    setup.cpp
)
add_library(glove::host ALIAS glove_host)

target_link_libraries(glove_host
    PUBLIC glove_options
    PRIVATE glaze::glaze glove_supervisor
)
target_include_directories(glove_host
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
