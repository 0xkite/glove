add_library(glove_supervisor STATIC
    change_apply_authorization.cpp
    change_apply_exchange.cpp
    change_apply_gate.cpp
    change_apply_journal.cpp
    change_apply_receipt.cpp
    change_apply_recovery.cpp
    change_apply_trust_policy.cpp
    change_manifest.cpp
    codex_runtime_adapter.cpp
    harness_adoption.cpp
    native_skill_runtime_adapter.cpp
    library_bundle.cpp
    path_alias.cpp
    path_exposure.cpp
    path_exposure_journal.cpp
    path_exposure_policy.cpp
    sage_bundle_projection.cpp
    session_plan.cpp
)
add_library(glove::supervisor ALIAS glove_supervisor)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(glove_supervisor PRIVATE
        linux/ephemeral_copy.cpp
        linux/persistent_quota_image.cpp
        linux/session_filesystem.cpp
    )
endif()

target_link_libraries(glove_supervisor PUBLIC glove_options PRIVATE glaze::glaze glove_digest)
target_include_directories(glove_supervisor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
