add_library(glove_host STATIC
    ../../include/glove/host/onboarding_plan.hpp
    cli.cpp
    config.cpp
    control_client.cpp
    daemon.cpp
    doctor.cpp
    doctor_wire.cpp
    operator_experience.cpp
    onboarding_plan.cpp
    remote_backend.cpp
    runtime_policy.cpp
    runtime_snapshot.cpp
    setup.cpp
)
add_library(glove::host ALIAS glove_host)

target_link_libraries(glove_host
    PUBLIC glove_options
    PRIVATE glaze::glaze glove_supervisor glove_digest
)
target_include_directories(glove_host
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
