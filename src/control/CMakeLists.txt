add_library(glove_control STATIC
    receipt_audit_protocol.cpp
    receipt_audit_unix_server.cpp
    session_reconciliation.cpp
    session_registry.cpp
)
add_library(glove::control ALIAS glove_control)

if(APPLE)
    target_sources(glove_control PRIVATE
        apple_container_session_runtime.cpp
    )
    target_include_directories(glove_control PRIVATE
        ${CMAKE_SOURCE_DIR}/src/container
        ${CMAKE_SOURCE_DIR}/src/container/linux
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(glove_control PRIVATE
        linux_process_identity.cpp
        linux_session_recovery.cpp
        linux_session_executor.cpp
        linux_session_preparation.cpp
    )
    target_include_directories(glove_control PRIVATE
        ${CMAKE_SOURCE_DIR}/src/container/linux
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

target_link_libraries(glove_control
    PUBLIC
        glove_options
        glove_container
        glove_supervisor
        glove::audit
        glove::net
    PRIVATE
        glaze::glaze
)
target_include_directories(glove_control
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
